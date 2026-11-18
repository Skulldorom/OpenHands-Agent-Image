#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
export PATH="$tmp:$PATH" GITHUB_OUTPUT="$tmp/output" GITHUB_STEP_SUMMARY="$tmp/summary"
export UPSTREAM=registry.example.invalid/upstream:latest-python IMAGE=registry.example.invalid/custom
export GITHUB_SHA=1111111111111111111111111111111111111111 GITHUB_REF=refs/heads/main
export GITHUB_REPOSITORY=Skulldorom/OpenHands-Agent-Image GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1
export MOCK_ARCHIVE="$tmp/mock-archive" MOCK_WRITES="$tmp/writes"
export MOCK_MANIFEST=upstream-v1 MOCK_MAIN="$GITHUB_SHA" MOCK_PUBLISHED=missing
export MOCK_UPSTREAM_DIGEST='' MOCK_INPUTS=''
printf 'test index' > "$MOCK_ARCHIVE"
IMAGE_DIGEST="sha256:$(sha256sum < "$MOCK_ARCHIVE" | cut -d' ' -f1)"
UPSTREAM_DIGEST="sha256:$(printf '%s' "$MOCK_MANIFEST" | sha256sum | cut -d' ' -f1)"
export IMAGE_DIGEST UPSTREAM_DIGEST

cat > "$tmp/git" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == ls-remote ]]; then
    printf '%s\trefs/heads/main\n' "$MOCK_MAIN"
else
    printf '%s\n' dockerfile-version1
fi
MOCK

cat > "$tmp/skopeo" <<'MOCK'
#!/usr/bin/env bash
ref=${!#}
if [[ "$1" == copy ]]; then
    echo rollback >> "$MOCK_WRITES"
elif [[ "$ref" == "docker://$UPSTREAM" ]]; then
    printf '%s' "$MOCK_MANIFEST"
elif [[ "$ref" == oci-archive:* || -f "$MOCK_WRITES" && "$2" == --raw ]]; then
    cat "$MOCK_ARCHIVE"
elif [[ "$MOCK_PUBLISHED" == exists && "$2" == --no-tags ]]; then
    jq -n --arg upstream "$MOCK_UPSTREAM_DIGEST" --arg inputs "$MOCK_INPUTS" '
        {config: {Labels: {"org.opencontainers.image.base.digest": $upstream, "io.openhands-agent-image.inputs": $inputs}}}
    '
else
    echo 'manifest unknown' >&2
    exit 1
fi
MOCK

cat > "$tmp/docker" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == "buildx imagetools create --tag $IMAGE:latest $IMAGE@$IMAGE_DIGEST" ]] || exit 1
echo latest >> "$MOCK_WRITES"
MOCK
chmod +x "$tmp/"{skopeo,docker,git}

plan() {
    : > "$GITHUB_OUTPUT"
    GITHUB_EVENT_NAME=$1 scripts/registry.sh plan
    grep -qx "build=$2" "$GITHUB_OUTPUT"
}
plan push true
plan pull_request true
plan workflow_dispatch true
plan schedule true
MOCK_PUBLISHED=exists
MOCK_INPUTS=$(sed -n 's/^inputs=//p' "$GITHUB_OUTPUT")
MOCK_UPSTREAM_DIGEST=$UPSTREAM_DIGEST
plan schedule false
MOCK_MANIFEST=upstream-v2
plan schedule true
MOCK_MANIFEST=upstream-v1
MOCK_INPUTS=old-inputs
plan schedule true

if GITHUB_EVENT_NAME=pull_request scripts/registry.sh publish "$MOCK_ARCHIVE"; then exit 1; fi
if MOCK_MAIN=stale GITHUB_EVENT_NAME=push scripts/registry.sh publish "$MOCK_ARCHIVE"; then exit 1; fi
if MOCK_MANIFEST=changed GITHUB_EVENT_NAME=push scripts/registry.sh publish "$MOCK_ARCHIVE"; then exit 1; fi
if IMAGE_DIGEST=$UPSTREAM_DIGEST GITHUB_EVENT_NAME=push scripts/registry.sh publish "$MOCK_ARCHIVE"; then exit 1; fi
[[ ! -e "$MOCK_WRITES" ]]
GITHUB_EVENT_NAME=push scripts/registry.sh publish "$MOCK_ARCHIVE"
[[ $(cat "$MOCK_WRITES") == $'rollback\nlatest' ]]
if GITHUB_EVENT_NAME=push scripts/registry.sh publish "$MOCK_ARCHIVE"; then exit 1; fi
[[ $(cat "$MOCK_WRITES") == $'rollback\nlatest' ]]
echo 'Update decisions and publication guards: PASS'
