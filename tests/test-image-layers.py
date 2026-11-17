#!/usr/bin/env python3
"""Inspect every saved layer, including files hidden by later whiteouts."""
import re
import json
import subprocess
import sys
import tarfile


CREDENTIAL = re.compile(rb"(?P<private_key>-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)|(?P<github_token>gh[pousr]_[A-Za-z0-9]{36,})|(?P<github_pat>github_pat_[A-Za-z0-9_]{50,})|(?P<aws_access_key>AKIA[0-9A-Z]{16})")


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
                    name = entry.name.lstrip("./")
                    if name in {"etc/ssl/private/ssl-cert-snakeoil.key", "etc/ssl/certs/ssl-cert-snakeoil.pem"}:
                        raise AssertionError(f"Snakeoil material recoverable in layer {count}: {name}")
                    if entry.isfile() and name.endswith(("/.git-credentials", "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.aws/credentials", "/.docker/config.json", "/.env")):
                        source = layer.extractfile(entry)
                        raw = source.read(1024 * 1024)
                        assert not raw.strip(), f"Credential file recoverable in layer {count}: {name}"
                    elif entry.isfile() and entry.size <= 1024 * 1024 and name.startswith(("home/", "root/", "tmp/", "run/")):
                        raw = layer.extractfile(entry).read()
                        match = CREDENTIAL.search(raw)
                        if match:
                            # Only categorical diagnostics: never matched bytes or context.
                            diagnostic = {
                                "rule": match.lastgroup,
                                "length": len(match.group()),
                                "offset": match.start(),
                                "file_size": len(raw),
                                "file_contains_nul": b"\x00" in raw,
                                "left_ascii_word": match.start() > 0 and raw[match.start()-1:match.start()].isalnum(),
                                "right_ascii_word": raw[match.end():match.end()+1].isalnum(),
                                "distinct_match_bytes": len(set(match.group())),
                            }
                            raise AssertionError(f"Credential pattern recoverable in layer {count}: {name}; " + json.dumps(diagnostic, sort_keys=True))
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
