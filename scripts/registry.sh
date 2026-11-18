#!/usr/bin/env bash
set -euo pipefail

: "${UPSTREAM:?missing upstream image}" "${IMAGE:?missing destination image}"

registry_digest() {
    local digest
    digest=$(skopeo inspect --raw "docker://$1" | sha256sum | cut -d' ' -f1)
    printf 'sha256:%s\n' "$digest"
}

# An unknown manifest is expected before the first publication. Other
# failures (including registry connectivity and authentication) are errors.
is_missing() {
    grep -Eiq 'manifest unknown|name unknown' <<< "$1"
}

assert_fresh() {
    : "${UPSTREAM_DIGEST:?missing resolved upstream digest}"
    local main
    main=$(git ls-remote --exit-code origin refs/heads/main | cut -f1)
    [[ "$main" == "$GITHUB_SHA" ]] ||
        { echo 'main moved during this run. The newer source must be built.' >&2; return 1; }
    [[ $(registry_digest "$UPSTREAM") == "$UPSTREAM_DIGEST" ]] ||
        { echo 'OpenHands upstream changed during this run. Run a fresh build.' >&2; return 1; }
}

case "${1:-}" in
    plan)
        upstream_digest=$(registry_digest "$UPSTREAM")
        inputs=$(git ls-files -s -- Dockerfile .dockerignore scripts tests .github/workflows/image.yml |
            sha256sum | cut -d' ' -f1)
        build=true
        if [[ "$GITHUB_EVENT_NAME" == schedule ]]; then
            if current=$(skopeo inspect --no-tags --config "docker://$IMAGE:latest" 2>&1); then
                if jq -e --arg upstream "$upstream_digest" --arg inputs "$inputs" '
                    .config.Labels | .["org.opencontainers.image.base.digest"] == $upstream
                        and .["io.openhands-agent-image.inputs"] == $inputs
                ' <<< "$current" >/dev/null; then
                    echo 'Published image already matches upstream and image inputs.'
                    build=false
                fi
            elif ! is_missing "$current"; then
                echo 'Could not read current GHCR latest to plan the scheduled build.' >&2
                exit 1
            fi
        fi
        printf 'upstream=%s\ninputs=%s\nbuild=%s\n' "$upstream_digest" "$inputs" "$build" >> "$GITHUB_OUTPUT"
        ;;
    check-base)
        : "${UPSTREAM_DIGEST:?missing resolved upstream digest}"
        if ! skopeo inspect --no-tags --config "docker://${UPSTREAM%:*}@$UPSTREAM_DIGEST" |
            jq -e '.config | .User == "openhands" and
                .Entrypoint == ["tini", "--", "/usr/local/bin/openhands-agent-server"] and
                ((.Cmd // []) == [])' >/dev/null; then
            echo 'OpenHands startup contract changed (user, entrypoint or command). Review the Dockerfile and wrapper.' >&2
            exit 1
        fi
        ;;
    publish)
        [[ "$GITHUB_REF" == refs/heads/main && "$GITHUB_REPOSITORY" == Skulldorom/OpenHands-Agent-Image ]]
        [[ "$GITHUB_EVENT_NAME" =~ ^(push|schedule|workflow_dispatch)$ ]]
        [[ "$IMAGE_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]
        archive=$2
        tag="$IMAGE:build-${GITHUB_SHA:0:12}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
        assert_fresh
        if current=$(skopeo inspect --raw "docker://$tag" 2>&1); then
            echo 'Rollback tag already exists. Start a new attempt.' >&2
            exit 1
        elif ! is_missing "$current"; then
            echo 'Could not check rollback tag availability in GHCR.' >&2
            exit 1
        fi
        # Check the local archive index before any write and preserve all
        # manifests, including the BuildKit provenance attestation.
        archive_digest=$(skopeo inspect --raw "oci-archive:$archive" | sha256sum | cut -d' ' -f1)
        [[ "sha256:$archive_digest" == "$IMAGE_DIGEST" ]]
        skopeo copy --all --preserve-digests "oci-archive:$archive" "docker://$tag"
        [[ $(registry_digest "$tag") == "$IMAGE_DIGEST" ]]

        assert_fresh
        docker buildx imagetools create --tag "$IMAGE:latest" "$IMAGE@$IMAGE_DIGEST"
        [[ $(registry_digest "$IMAGE:latest") == "$IMAGE_DIGEST" ]]
        # shellcheck disable=SC2016
        printf 'Published `%s` and `%s:latest` at `%s`.\n' "$tag" "$IMAGE" "$IMAGE_DIGEST" >> "$GITHUB_STEP_SUMMARY"
        ;;
    *) echo 'Expected plan, check-base or publish' >&2; exit 64 ;;
esac
