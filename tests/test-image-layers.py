#!/usr/bin/env python3
"""Inspect every saved layer, including files hidden by later whiteouts."""
import re
import hashlib
import struct
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


def credential_matches(raw, classified=None):
    normalized = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
    for match in CREDENTIAL.finditer(normalized):
        if match.lastgroup != "private_key" or PEM_PAYLOAD.match(normalized, match.end()):
            record = credential_classification(match.lastgroup, match.group()[:4], hashlib.sha256(match.group()).hexdigest(), datetime.now(timezone.utc))
            if record:
                print(json.dumps(record))
                if classified is not None and record not in classified:
                    classified.append(record)
                continue
            yield match


def elf_match_scope(source, header, offset):
    # Diagnostic only: section flags are not an exemption for any credential.
    if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01":
        return None
    table = struct.unpack_from("<Q", header, 40)[0]
    width, count = struct.unpack_from("<HH", header, 58)
    if width != 64 or not 0 < count <= 4096 or table < source.tell():
        return None
    try:
        remaining = table - source.tell()
        while remaining:
            chunk = source.read(min(remaining, 1024 * 1024))
            if not chunk:
                return None
            remaining -= len(chunk)
        data = source.read(width * count)
        for index in range(count):
            section = struct.unpack_from("<IIQQQQIIQQ", data, index * width)
            if section[1] != 8 and section[4] <= offset < section[4] + section[5]:
                return {"section_index": index, "section_type": section[1], "section_flags": section[2],
                        "executable_section": bool(section[2] & 4)}
    except (OSError, ValueError, struct.error, tarfile.TarError):
        return None
    return None


def scan_file(source, credential_file=False, chunk_size=1024 * 1024, classified=None):
    """Inspect all bytes with bounded memory, retaining cross-chunk key prefixes."""
    tail = b""
    header = None
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            return None
        if header is None:
            header = chunk[:64]
        if credential_file and chunk.strip():
            return "credential_file"
        raw = tail + chunk
        match = next(credential_matches(raw, classified), None)
        if match:
            # Classification metadata only. Never print matched content/context.
            raw_start = raw.find(match.group())
            offset = source.tell() - len(raw) + raw_start
            before, after = match.string[max(0, match.start()-1):match.start()], match.string[match.end():match.end()+1]
            print(json.dumps({"credential_rule": match.lastgroup,
                              "match_sha256": hashlib.sha256(match.group()).hexdigest(),
                              "match_length": len(match.group()), "file_offset": offset,
                              "token_family": match.group()[:4].decode("ascii", errors="replace") if match.lastgroup.startswith("github") else None,
                              "placeholder_markers": [word for word in ("fake", "example", "placeholder", "dummy", "test", "notreal", "notareal", "invalid", "redacted") if word.encode() in match.group().lower()],
                              "context_markers": [word for word in ("fake", "example", "placeholder", "dummy", "test", "redact", "pattern", "regex") if word.encode() in match.string[max(0, match.start()-128):match.end()+128].lower()],
                              "preceded_by_underscore": before == b"_", "followed_by_underscore": after == b"_",
                              "preceded_by_alphanumeric": bool(before and re.fullmatch(rb"[A-Za-z0-9]", before)),
                              "followed_by_alphanumeric": bool(after and re.fullmatch(rb"[A-Za-z0-9]", after)),
                              "elf_scope": elf_match_scope(source, header, offset),
                              "documented_aws_example": match.group() == b"AKIAIOSFODNN7EXAMPLE"}))
            return match.lastgroup
        # Report a classified lexical collision rather than treating an arbitrary
        # 20-byte slice of a longer identifier/data sequence as an AWS key ID.
        for candidate in AWS_SUBSTRING.finditer(raw):
            before = raw[max(0, candidate.start()-1):candidate.start()]
            after = raw[candidate.end():candidate.end()+1]
            if (before and re.fullmatch(rb"[A-Za-z0-9]", before)) or (after and re.fullmatch(rb"[A-Za-z0-9]", after)):
                print(json.dumps({"credential_rule": "aws_access_key", "classification": "substring_of_longer_alphanumeric_sequence",
                                  "match_sha256": hashlib.sha256(candidate.group()).hexdigest()}))
        tail = raw[-4096:]
        normalized = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
        for candidate in CREDENTIAL.finditer(normalized):
            if candidate.lastgroup != "private_key":
                continue
            rest = normalized[candidate.end():]
            compact = re.sub(rb"[ \t\r\n]+", b" ", rest)
            # Hold even arbitrarily padded/wrapped incomplete PEM payloads;
            # collapsing only payload whitespace keeps memory bounded.
            partial = re.fullmatch(rb"[ \t\r\n]+(?:[A-Za-z0-9+/=][ \t\r\n]*){0,15}", rest)
            if partial or (compact.startswith(b" ") and b"Proc-Type: 4,ENCRYPTED".startswith(compact[1:])):
                tail = candidate.group() + compact


def check_layers(stream, classified=None):
    count = 0
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
                        rule = scan_file(layer.extractfile(entry), credential_file, classified=classified)
                        if rule:
                            # Rule and location only; never matched bytes or context.
                            raise AssertionError(f"Credential pattern recoverable in layer {count}: {name}; rule={rule}; archive_member={member.name}")
    assert count, "No Docker archive layers inspected"
    return count


if __name__ == "__main__":
    process = subprocess.Popen(["docker", "image", "save", sys.argv[1]], stdout=subprocess.PIPE)
    try:
        classified = []
        count = check_layers(process.stdout, classified)
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
