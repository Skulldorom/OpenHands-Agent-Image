#!/usr/bin/env python3
"""Inspect every saved layer, including files hidden by later whiteouts."""
import subprocess
import sys
import tarfile


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
    assert count, "No Docker archive layers inspected"
    return count


if __name__ == "__main__":
    process = subprocess.Popen(["docker", "image", "save", sys.argv[1]], stdout=subprocess.PIPE)
    try:
        count = check_layers(process.stdout)
        assert process.wait(timeout=30) == 0, "docker save failed"
        print(f"Snakeoil material absent from all {count} image layers: PASS")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)
