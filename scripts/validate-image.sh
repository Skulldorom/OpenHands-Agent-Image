#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for test in test-git-identity test-postgresql test-agent-startup; do
 "$root/tests/$test.sh" "$image"
done
