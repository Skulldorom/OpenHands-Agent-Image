#!/usr/bin/env python3
"""Inspect every saved layer, including files hidden by later whiteouts."""
import re
import hashlib
import json
import subprocess
import sys
import tarfile


CREDENTIAL = re.compile(rb"(?P<private_key>-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)|(?P<github_token>gh[pousr]_[A-Za-z0-9]{36,})|(?P<github_pat>github_pat_[A-Za-z0-9_]{50,})|(?P<aws_access_key>AKIA[0-9A-Z]{16})")


# A PEM boundary alone is a public format constant, not private key material.
# Work on bytes, including binary files; never discard NULs or decoding errors.
# Normalize JSON/JavaScript escaped line endings so serialized keys still block.
PEM_PAYLOAD = re.compile(rb"[ \t\r\n]+(?:(?:[A-Za-z0-9+/=][ \t\r\n]*){16}|Proc-Type:[ \t]*4,ENCRYPTED)")


def credential_matches(raw):
    normalized = raw.replace(b"\\r", b"\r").replace(b"\\n", b"\n")
    for match in CREDENTIAL.finditer(normalized):
        if match.lastgroup != "private_key" or PEM_PAYLOAD.match(normalized, match.end()):
            yield match


def scan_file(source, credential_file=False, chunk_size=1024 * 1024):
    """Inspect all bytes with bounded memory, retaining cross-chunk key prefixes."""
    tail = b""
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            return None
        if credential_file and chunk.strip():
            return "credential_file"
        raw = tail + chunk
        match = next(credential_matches(raw), None)
        if match:
            # Classification metadata only. Never print matched content/context.
            print(json.dumps({"credential_rule": match.lastgroup,
                              "match_sha256": hashlib.sha256(match.group()).hexdigest(),
                              "match_length": len(match.group()),
                              "documented_aws_example": match.group() == b"AKIAIOSFODNN7EXAMPLE"}))
            return match.lastgroup
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


def check_layers(stream):
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
                        rule = scan_file(layer.extractfile(entry), credential_file)
                        if rule:
                            # Rule and location only; never matched bytes or context.
                            raise AssertionError(f"Credential pattern recoverable in layer {count}: {name}; rule={rule}; archive_member={member.name}")
    assert count, "No Docker archive layers inspected"
    return count


if __name__ == "__main__":
    process = subprocess.Popen(["docker", "image", "save", sys.argv[1]], stdout=subprocess.PIPE)
    try:
        count = check_layers(process.stdout)
        assert process.wait(timeout=30) == 0, "docker save failed"
        print(f"Credential file patterns and snakeoil material absent from all {count} image layers: PASS")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)
