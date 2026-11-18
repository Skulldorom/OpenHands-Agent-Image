#!/usr/bin/env python3
"""Inspect every saved layer, including files hidden by later whiteouts."""
import re
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
import subprocess
import sys
import tarfile


CREDENTIAL = re.compile(rb"(?P<private_key>-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)|(?P<github_installation>ghs_[A-Za-z0-9]+_[A-Za-z0-9_.-]{36,})|(?P<github_token>gh[pousr]_[A-Za-z0-9]{36,})|(?P<github_pat>github_pat_[A-Za-z0-9_]{50,})|(?P<aws_access_key>(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9]))")


# A PEM boundary alone is a public format constant, not private key material.
# Work on bytes, including binary files; never discard NULs or decoding errors.
# Normalize JSON/JavaScript escaped line endings so serialized keys still block.
AWS_SUBSTRING = re.compile(rb"AKIA[0-9A-Z]{16}")

PEM_PAYLOAD = re.compile(rb"[ \t\r\n]*(?:(?:[A-Za-z0-9+/=][ \t\r\n]*){16}|Proc-Type:[ \t]*4,ENCRYPTED)")


POLICY_PATH = Path(__file__).resolve().parents[1] / "security/credential-policy.json"


def normalize(raw):
    raw = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
    # C/JS adjacent string literals; joining cannot hide subsequent detections.
    return re.sub(rb"['\"]\s*(?:\+\s*)?['\"]", b"", raw)


def credential_classification(record, now, policy=None):
    """Reproduce a decision from metadata; public test material keeps its narrow source scope."""
    policy = policy or json.loads(POLICY_PATH.read_text())
    if record["credential_rule"] == "private_key":
        for fixture in policy["public_private_keys"]:
            if all(record.get(k) == fixture[k] for k in ("kind", "payload_sha256", "payload_length", "diff_id", "file")):
                return {"classification": "public-cryptographic-test-material", **fixture}
    return None


def pem_material(raw, match):
    """Fingerprint the complete payload, never merely a shared PEM header."""
    kind = match.group()[len(b"-----BEGIN "):-len(b"-----")]
    footer = b"-----END " + kind + b"-----"
    end = raw.find(footer, match.end())
    rest = raw[match.end():end if end >= 0 else None]
    if end >= 0 and re.fullmatch(rb"[A-Za-z0-9+/=\s]+", rest):
        payload = re.sub(rb"\s+", b"", rest)
        if len(payload) >= 16:
            return {"kind": kind.decode(), "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "payload_length": len(payload)}, raw[match.start():end+len(footer)]
    return {}, match.group() + rest[:65536]


def credential_matches(normalized, classified=None, final=True):
    for match in CREDENTIAL.finditer(normalized):
        if (not final and match.lastgroup != "private_key" and match.end() == len(normalized)
                and len(match.group()) < 4096):
            continue
        if match.lastgroup != "private_key" or PEM_PAYLOAD.match(normalized, match.end()):
            yield match


def scan_file(source, credential_file=False, chunk_size=1024 * 1024, classified=None, detected=None,
              diff_id=None, now=None, policy=None, file_name=None):
    """Inspect every match; public material never exempts the containing file."""
    now = now or datetime.now(timezone.utc)
    tail = b""
    first_rule = None
    reported = set()
    collisions = set()
    while True:
        chunk = source.read(chunk_size)
        final = not chunk
        if final and not tail:
            return first_rule
        if credential_file and chunk.strip():
            first_rule = first_rule or "credential_file"
        raw = tail + chunk
        normalized = normalize(raw)
        raw_cursor = 0
        for match in credential_matches(normalized, final=final):
            raw_start = raw.find(match.group(), raw_cursor)
            if raw_start >= 0:
                raw_cursor = raw_start + len(match.group())
            material, value = pem_material(normalized, match) if match.lastgroup == "private_key" else ({}, match.group())
            # Retain a bounded incomplete PEM until its footer or EOF arrives.
            if (not final and match.lastgroup == "private_key" and not material
                    and len(normalized)-match.start() < 65536):
                continue
            digest = hashlib.sha256(value).hexdigest()
            if (match.lastgroup, digest) in reported:
                continue
            reported.add((match.lastgroup, digest))
            record = {"credential_rule": match.lastgroup, "match_sha256": digest,
                      "match_length": len(value), "diff_id": diff_id, "file": file_name,
                      "file_offset": source.tell() - len(raw) + raw_start if raw_start >= 0 else None,
                      "token_family": match.group()[:4].decode("ascii") if match.lastgroup.startswith("github") else None,
                      "standalone": not re.search(rb"[A-Za-z0-9_]$", normalized[:match.start()])
                          and not re.match(rb"[A-Za-z0-9_]", normalized[match.end():]), **material}
            decision = credential_classification(record, now, policy)
            if decision:
                record["decision"] = decision
                if classified is not None:
                    classified.append(record)
            else:
                first_rule = first_rule or match.lastgroup
                if detected is not None:
                    detected.append(record)
            print(json.dumps(record))  # Metadata only; never bytes or context.
        for candidate in AWS_SUBSTRING.finditer(raw):
            before = raw[max(0, candidate.start()-1):candidate.start()]
            after = raw[candidate.end():candidate.end()+1]
            digest = hashlib.sha256(candidate.group()).hexdigest()
            if digest not in collisions and ((before and re.fullmatch(rb"[A-Za-z0-9]", before)) or (after and re.fullmatch(rb"[A-Za-z0-9]", after))):
                collisions.add(digest)
                print(json.dumps({"credential_rule": "aws_access_key", "classification": "substring_of_longer_alphanumeric_sequence",
                                  "match_sha256": digest}))
        if final:
            return first_rule
        tail = raw[-65536:]
        for candidate in re.finditer(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", normalized):
            rest = normalized[candidate.end():]
            compact = re.sub(rb"[ \t\r\n]+", b" ", rest)
            partial = re.fullmatch(rb"[ \t\r\n]+(?:[A-Za-z0-9+/=][ \t\r\n]*){0,15}", rest)
            if partial or (compact.startswith(b" ") and b"Proc-Type: 4,ENCRYPTED".startswith(compact[1:])):
                tail = candidate.group() + compact


class CredentialFindings(AssertionError):
    def __init__(self, layers, findings):
        self.layers = layers
        self.findings = findings
        super().__init__("; ".join(
            f"Credential pattern recoverable in layer {row['layer']}: {row['file']}; rule={row['rule']}; archive_member={row['archive_member']}"
            for row in findings))


class HashingReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        value = self.source.read(size)
        self.digest.update(value)
        return value


def check_layers(stream, classified=None, policy=None, inspected=None):
    count = 0
    errors = []
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if not member.isfile() or not (member.name.endswith("/layer.tar") or member.name.startswith("blobs/sha256/")):
                continue
            try:
                hashed = HashingReader(archive.extractfile(member))
                layer = tarfile.open(fileobj=hashed, mode="r|*")
            except tarfile.ReadError:
                if member.name.endswith("/layer.tar"):
                    raise
                continue
            count += 1
            with layer:
                for entry in layer:
                    name = entry.name.lstrip("/")
                    while name.startswith("./"):
                        name = name[2:]
                    if name in {"etc/ssl/private/ssl-cert-snakeoil.key", "etc/ssl/certs/ssl-cert-snakeoil.pem"}:
                        errors.append({"layer": count, "file": name, "rule": "snakeoil", "archive_member": member.name, "patterns": []})
                    if entry.isfile():
                        protected = ("/.git-credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.aws/credentials", "/.docker/config.json", "/.env")
                        credential_file = any(name == suffix.lstrip("/") or name.endswith(suffix) for suffix in protected)
                        detected = []
                        file_classified = []
                        diff_id = "sha256:" + member.name.split("/")[-1] if member.name.startswith("blobs/sha256/") else None
                        rule = scan_file(layer.extractfile(entry), credential_file, classified=file_classified, detected=detected,
                                         diff_id=diff_id, policy=policy, file_name=name)
                        if classified is not None:
                            classified.extend(dict(row, file=name, archive_member=member.name) for row in file_classified)
                        if rule:
                            # Rule and location only; never matched bytes or context.
                            errors.append({"layer": count, "file": name, "rule": rule, "archive_member": member.name, "patterns": detected})
            while hashed.read(1024 * 1024):
                pass
            if member.name.startswith("blobs/sha256/"):
                assert hashed.digest.hexdigest() == member.name.split("/")[-1], "Saved layer digest mismatch"
                if inspected is not None:
                    inspected.append("sha256:" + hashed.digest.hexdigest())
    assert count, "No Docker archive layers inspected"
    if errors:
        raise CredentialFindings(count, errors)
    return count


def scan_image(ref):
    process = subprocess.Popen(["docker", "image", "save", ref], stdout=subprocess.PIPE)
    classified = []
    findings = []
    inspected = []
    try:
        try:
            count = check_layers(process.stdout, classified, inspected=inspected)
        except CredentialFindings as error:
            count, findings = error.layers, error.findings
        assert process.wait(timeout=30) == 0, "docker save failed"
        return {"candidate": ref, "layers": count, "layer_diff_ids": inspected, "classifications": classified,
                "unclassified_detections": sum(max(1, len(r["patterns"])) for r in findings),
                "unclassified_findings": findings}
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)


IDENTITY_FIELDS = ("archive_member", "file", "credential_rule", "match_sha256", "match_length",
                   "file_offset", "token_family", "kind", "payload_sha256", "payload_length")


def finding_identity(row):
    # The verified layer hash + member path bind the entire file, including bytes
    # outside the detected span. A changed file/layer is never inherited by guess.
    return tuple(row.get(k) for k in IDENTITY_FIELDS)


def finding_fingerprint(row):
    return hashlib.sha256(json.dumps(finding_identity(row), separators=(",", ":")).encode()).hexdigest()


def flatten(report):
    result = [dict(row, status="non-sensitive") for row in report["classifications"]]
    for file in report["unclassified_findings"]:
        for row in file["patterns"] or [{"credential_rule": file["rule"], "match_sha256": None}]:
            result.append(dict(row, file=file["file"], archive_member=file["archive_member"], status="unclassified"))
    return result


def inventory_fingerprint(report):
    identities = sorted(json.dumps(finding_identity(row), separators=(",", ":")) for row in flatten(report))
    return hashlib.sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest()


def confirmed_dangerous(row, policy):
    return any(finding_fingerprint(row) == item["finding_sha256"] for item in policy["confirmed_dangerous"])


def compare_findings(upstream, candidate, policy=None):
    policy = policy if policy is not None else json.loads(POLICY_PATH.read_text())
    before = {finding_identity(r): r for r in flatten(upstream)}
    after = {finding_identity(r): r for r in flatten(candidate)}
    return {"inherited_non_sensitive": [r for k, r in after.items() if k in before and r["status"] == "non-sensitive" and not confirmed_dangerous(r, policy)],
            "inherited_confirmed_credentials": [r for k, r in after.items() if k in before and confirmed_dangerous(r, policy)],
            "inherited_unclassified": [r for k, r in after.items() if k in before and r["status"] == "unclassified" and not confirmed_dangerous(r, policy)],
            "introduced": [r for k, r in after.items() if k not in before],
            "removed": [r for k, r in before.items() if k not in after]}


def validate_inventory(scan, now, policy):
    assert type(scan["layers"]) is int and scan["layers"] > 0
    assert len(scan["layer_diff_ids"]) == scan["layers"]
    assert len(set(scan["layer_diff_ids"])) == scan["layers"], "Duplicate saved layers"
    assert all(re.fullmatch(r"sha256:[a-f0-9]{64}", d) for d in scan["layer_diff_ids"])
    assert type(scan["unclassified_detections"]) is int
    assert scan["unclassified_detections"] == sum(max(1, len(r["patterns"])) for r in scan["unclassified_findings"]), "Detection count mismatch"
    rows = flatten(scan)
    assert len({finding_identity(r) for r in rows}) == len(rows), "Duplicate finding evidence"
    for row in rows:
        assert isinstance(row["file"], str) and row["file"] and not row["file"].startswith("/")
        assert row["archive_member"].startswith("blobs/sha256/")
        diff_id = "sha256:" + row["archive_member"].split("/")[-1]
        assert diff_id in scan["layer_diff_ids"], "Finding layer missing from inventory"
        if row["match_sha256"] is not None:
            assert re.fullmatch(r"[a-f0-9]{64}", row["match_sha256"])
            assert type(row["match_length"]) is int and row["match_length"] > 0
            assert row["diff_id"] == diff_id, "Finding layer evidence mismatch"
        else:
            assert row["credential_rule"] in {"credential_file", "snakeoil"}, "Missing finding fingerprint"
        if row["status"] == "non-sensitive":
            assert credential_classification(row, now, policy) == row["decision"], "Unknown public-material classification"
        else:
            assert "decision" not in row, "Unclassified finding carries a classification"
    return rows


def credential_gate(upstream, candidate, now=None, policy=None):
    """One reviewed upstream inventory; no per-token approvals or safety claims."""
    now = now or datetime.now(timezone.utc)
    policy = policy if policy is not None else json.loads(POLICY_PATH.read_text())
    assert policy["schema"] == 2 and set(policy) == {"schema", "public_private_keys", "accepted_upstream", "confirmed_dangerous"}
    accepted = policy["accepted_upstream"]
    assert set(accepted) == {"upstream", "inventory_sha256", "finding_count", "decision", "evidence"}
    assert re.fullmatch(r"ghcr.io/openhands/agent-server@sha256:[a-f0-9]{64}", accepted["upstream"])
    assert re.fullmatch(r"[a-f0-9]{64}", accepted["inventory_sha256"])
    assert type(accepted["finding_count"]) is int and accepted["finding_count"] >= 0
    assert accepted["decision"] == "accept-unchanged-unclassified-upstream-risk"
    assert accepted["evidence"].startswith("https://github.com/")
    for item in policy["confirmed_dangerous"]:
        assert set(item) == {"finding_sha256", "reason", "evidence"}
        assert re.fullmatch(r"[a-f0-9]{64}", item["finding_sha256"])
        assert item["reason"].strip() and item["evidence"].startswith("https://")
    before = validate_inventory(upstream, now, policy)
    after = validate_inventory(candidate, now, policy)
    assert set(upstream["layer_diff_ids"]) <= set(candidate["layer_diff_ids"]), "Upstream layer inventory changed"
    comparison = compare_findings(upstream, candidate, policy)
    baseline_changed = (upstream["candidate"] != accepted["upstream"] or
                        inventory_fingerprint(upstream) != accepted["inventory_sha256"] or
                        len(before) != accepted["finding_count"])
    dangerous = [r for r in before + after if confirmed_dangerous(r, policy) or
                 (r["status"] != "non-sensitive" and r["credential_rule"] in {"private_key", "credential_file", "snakeoil"})]
    reasons = []
    if baseline_changed:
        reasons.append("Official credential baseline changed; review upstream digest and complete finding inventory")
    if comparison["introduced"]:
        reasons.append("Credential findings introduced or materially changed by customization")
    if comparison["removed"]:
        reasons.append("Inherited historical finding evidence missing from candidate")
    if dangerous:
        reasons.append("Confirmed dangerous credential or exposed private-key/credential-file material")
    return {"pass": not reasons, "baseline_changed": baseline_changed, "blockers": reasons,
            "dangerous_findings": dangerous, "accepted_inherited_unclassified": len(comparison["inherited_unclassified"]) if not baseline_changed else 0}


if __name__ == "__main__":
    candidate = sys.argv[1]
    upstream = sys.argv[2] if len(sys.argv) > 2 else subprocess.check_output(
        ["docker", "inspect", "-f", '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}', candidate], text=True).strip()
    if upstream.startswith("sha256:"):
        upstream = "ghcr.io/openhands/agent-server@" + upstream
    assert re.fullmatch(r"ghcr.io/openhands/agent-server@sha256:[a-f0-9]{64}", upstream), "Exact official base required"
    subprocess.run(["docker", "pull", upstream], check=True)
    def rootfs(ref):
        return json.loads(subprocess.check_output(["docker", "inspect", ref]))[0]["RootFS"]["Layers"]
    base, custom = rootfs(upstream), rootfs(candidate)
    assert custom[:len(base)] == base, "Candidate upstream layers differ"
    before, after = scan_image(upstream), scan_image(candidate)
    assert set(before["layer_diff_ids"]) == set(base), "Incomplete upstream archive"
    assert set(after["layer_diff_ids"]) == set(custom), "Incomplete candidate archive"
    image_id = json.loads(subprocess.check_output(["docker", "inspect", candidate]))[0]["Id"]
    report = {**after, "image_id": image_id, "schema": 3, "upstream": before, "comparison": compare_findings(before, after),
              "gate": credential_gate(before, after),
              "scanned_at": datetime.now(timezone.utc).isoformat(),
              "policy_sha256": hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()}
    Path("layer-classifications.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({k: len(v) for k, v in report["comparison"].items()}))
    assert report["gate"]["pass"], "; ".join(report["gate"]["blockers"])
    print("Credential gate: PASS; unchanged unclassified upstream findings remain accepted risk, not verified harmless")
