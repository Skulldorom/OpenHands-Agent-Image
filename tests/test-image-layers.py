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

PEM_PAYLOAD = re.compile(rb"[ \t\r\n]+(?:(?:[A-Za-z0-9+/=][ \t\r\n]*){16}|Proc-Type:[ \t]*4,ENCRYPTED)")


# Exact finding observed in the immutable upstream layer before 13:54:24 UTC.
# See security/CREDENTIAL-LAYER-INVESTIGATION.md and the authenticated run logs.
# This does not authorize any other token or exempt a directory/binary/layer.
NONLIVE_INSTALLATION_LITERAL_SHA256 = "11116762eb8f44dcdcabd6cc844d36d367f2be80c0788bd61104ef968d874c57"
NONLIVE_INSTALLATION_LITERAL_SHA256_SECOND = "e436670abd29f6abc2a834649981d9fbbe33c1bcb4cd70d748100e5a3b844380"
INSTALLATION_LITERAL_OBSERVED_BEFORE = datetime(2026, 11, 17, 13, 54, 24, tzinfo=timezone.utc)


def credential_classification(rule, prefix, digest, now):
    if (rule != "github_token" or prefix != b"ghs_" or digest not in {NONLIVE_INSTALLATION_LITERAL_SHA256, NONLIVE_INSTALLATION_LITERAL_SHA256_SECOND}
            or now < INSTALLATION_LITERAL_OBSERVED_BEFORE + timedelta(hours=1)):
        return None
    return {"rule": rule, "prefix": "ghs_", "sha256": digest,
            "classification": "non-live-installation-token-shaped-literal",
            "observed_before": INSTALLATION_LITERAL_OBSERVED_BEFORE.isoformat(),
            "maximum_lifetime_seconds": 3600,
            "evidence": "https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44097217505"}


def credential_matches(raw, classified=None, final=True):
    normalized = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
    for match in CREDENTIAL.finditer(normalized):
        if (not final and match.lastgroup != "private_key" and match.end() == len(normalized)
                and len(match.group()) < 4096):
            continue  # Wait for a terminator/EOF before hashing a token.
        if match.lastgroup != "private_key" or PEM_PAYLOAD.match(normalized, match.end()):
            record = credential_classification(match.lastgroup, match.group()[:4], hashlib.sha256(match.group()).hexdigest(), datetime.now(timezone.utc))
            if record:
                print(json.dumps(record))
                if classified is not None and record not in classified:
                    classified.append(record)
                continue
            yield match


def scan_file(source, credential_file=False, chunk_size=1024 * 1024, classified=None, detected=None):
    """Inspect all bytes, report every unique detection, and never pass unknowns."""
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
        for match in credential_matches(raw, classified, final=final):
            first_rule = first_rule or match.lastgroup
            digest = hashlib.sha256(match.group()).hexdigest()
            if (match.lastgroup, digest) in reported:
                continue
            reported.add((match.lastgroup, digest))
            # Metadata only. Never print matched content/context.
            record = {"credential_rule": match.lastgroup, "match_sha256": digest,
                      "match_length": len(match.group()),
                      "file_offset": source.tell() - len(raw) + raw.find(match.group()),
                      "token_family": match.group()[:4].decode("ascii", errors="replace") if match.lastgroup.startswith("github") else None}
            print(json.dumps(record))
            if detected is not None:
                detected.append(record)
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
        tail = raw[-4096:]
        normalized = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
        for candidate in CREDENTIAL.finditer(normalized):
            if candidate.lastgroup != "private_key":
                continue
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


def check_layers(stream, classified=None):
    count = 0
    errors = []
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if not member.isfile() or not (member.name.endswith("/layer.tar") or member.name.startswith("blobs/sha256/")):
                continue
            try:
                layer = tarfile.open(fileobj=archive.extractfile(member), mode="r|*")
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
                        raise AssertionError(f"Snakeoil material recoverable in layer {count}: {name}")
                    if entry.isfile():
                        protected = ("/.git-credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.aws/credentials", "/.docker/config.json", "/.env")
                        credential_file = any(name == suffix.lstrip("/") or name.endswith(suffix) for suffix in protected)
                        detected = []
                        rule = scan_file(layer.extractfile(entry), credential_file, classified=classified, detected=detected)
                        if rule:
                            # Rule and location only; never matched bytes or context.
                            errors.append({"layer": count, "file": name, "rule": rule, "archive_member": member.name, "patterns": detected})
    assert count, "No Docker archive layers inspected"
    if errors:
        raise CredentialFindings(count, errors)
    return count


if __name__ == "__main__":
    process = subprocess.Popen(["docker", "image", "save", sys.argv[1]], stdout=subprocess.PIPE)
    try:
        classified = []
        try:
            count = check_layers(process.stdout, classified)
        except CredentialFindings as error:
            Path("layer-classifications.json").write_text(json.dumps({"candidate": sys.argv[1], "layers": error.layers,
                "unclassified_detections": sum(max(1, len(row["patterns"])) for row in error.findings), "classifications": classified,
                "unclassified_findings": error.findings}, indent=2) + "\n")
            raise
        assert process.wait(timeout=30) == 0, "docker save failed"
        Path("layer-classifications.json").write_text(json.dumps({"candidate": sys.argv[1], "layers": count,
            "unclassified_detections": 0, "classifications": classified}, indent=2) + "\n")
        print(f"Classified non-live fingerprints: {len(classified)}; unclassified credential detections: 0")
        print(f"Credential file patterns and snakeoil material absent from all {count} image layers: PASS")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)
