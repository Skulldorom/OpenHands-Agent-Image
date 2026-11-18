#!/usr/bin/env bash
set -euo pipefail
image=${1:?local image required}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

# The raw scanner output can contain secret evidence. Keep it local and only
# print sanitized counts and vulnerability IDs.
trivy fs --scanners secret --skip-dirs .git --ignorefile /dev/null --format json \
    --output "$scratch/source.json" .
flags=(--scanners 'vuln,secret' --image-config-scanners secret --ignorefile /dev/null --format json --timeout 12m)
trivy image "${flags[@]}" --image-src remote --output "$scratch/upstream.json" "${UPSTREAM%:*}@$UPSTREAM_DIGEST"
trivy image "${flags[@]}" --skip-db-update --skip-java-db-update --image-src docker \
    --output "$scratch/candidate.json" "$image"
python3 scripts/compare-scans.py "$scratch" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Verify supported credential types across the exact candidate, including
# inherited layers. Never print the verifier output, which can contain values.
verifier=docker.io/trufflesecurity/trufflehog@sha256:2ec535840f860aa27f11fee20222fb790326ecd66325c96bd49d02ec6af46eca
status=0
docker run --rm --user 0:0 -v /var/run/docker.sock:/var/run/docker.sock:ro "$verifier" \
    docker --image "docker://$image" --results=verified --fail --fail-on-scan-errors --no-update \
    >"$scratch/verified.log" 2>&1 || status=$?
case "$status" in
    0) echo 'Verified credential scan passed.' ;;
    183) echo 'Verified credential detected in candidate. Investigate privately before publishing.' >&2; exit 1 ;;
    *) echo "Credential verifier failed (exit $status). Check scanner availability and compatibility." >&2; exit 1 ;;
esac
