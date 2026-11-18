#!/usr/bin/env bash
# Build a current-source audit image and name its real manifest in a loopback registry.
set -euo pipefail
source_sha=${1:?source SHA required}
[[ "$source_sha" =~ ^[a-f0-9]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$source_sha" ]]
git diff --quiet
upstream=$(sed -n 's/^ARG UPSTREAM_IMAGE=//p' Dockerfile)
[[ "$upstream" =~ ^ghcr\.io/openhands/agent-server@sha256:[a-f0-9]{64}$ ]]
upstream_digest=${upstream##*@}
tag="127.0.0.1:5000/openhands-pr-security:$source_sha"
# This service has no host mounts or credentials and listens only on runner loopback.
docker run -d --name pr-security-registry -p 127.0.0.1:5000:5000 \
  registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
curl --fail --silent --show-error --retry 12 --retry-delay 1 --retry-connrefused \
  --retry-max-time 30 --connect-timeout 2 --max-time 2 http://127.0.0.1:5000/v2/ >/dev/null
docker build --pull --build-arg "REVISION=$source_sha" --build-arg "UPSTREAM_IMAGE=$upstream" \
  --build-arg "UPSTREAM_DIGEST=$upstream_digest" --tag "$tag" .
# The only push destination is a fixed runner-local endpoint, never GHCR/production.
docker push "$tag"
python3 - "$tag" "$source_sha" "$upstream_digest" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys
info = json.loads(subprocess.check_output(['docker', 'inspect', sys.argv[1]]))[0]
refs = [r for r in info['RepoDigests'] if re.fullmatch(r'127\.0\.0\.1:5000/openhands-pr-security@sha256:[a-f0-9]{64}', r)]
assert len(refs) == 1, 'Missing/ambiguous immutable local candidate'
assert info['Config']['Labels']['org.opencontainers.image.revision'] == sys.argv[2]
assert info['Config']['Labels']['org.opencontainers.image.base.digest'] == sys.argv[3]
assert re.fullmatch(r'sha256:[a-f0-9]{64}', info['Id'])
Path('candidate-ref.txt').write_text(refs[0]+'\n')
Path('candidate-image-identity.json').write_text(json.dumps(dict(candidate=refs[0], image_id=info['Id'],
    source_commit=sys.argv[2], upstream='ghcr.io/openhands/agent-server@'+sys.argv[3]), indent=2)+'\n')
PY
docker pull "$(cat candidate-ref.txt)"
docker pull "$upstream"
