#!/usr/bin/env bash
# Container commands expand in the child, not on the host.
# shellcheck disable=SC2016
set -euo pipefail
IMAGE=ghcr.io/skulldorom/openhands-agent
STATE_DIR=${STATE_DIR:-/var/lib/openhands-image-update}
MIN_FREE_GIB=${MIN_FREE_GIB:-20}
EXTRACT_FACTOR=${EXTRACT_FACTOR:-4}
mode=${1:-check}
if [[ "$mode" == --help ]]; then
 cat <<'HELP'
Usage: update-image.sh [check|rollback]
Stages pending.env only; never activates configuration or restarts services.
STATE_DIR defaults to /var/lib/openhands-image-update. Initialize current.ref with
an existing validated GHCR digest before first use. On first legacy migration,
retain the legacy image manually; no GHCR rollback exists until a release is accepted.
After operator activation, copy the activated pending.ref to current.ref.
MIN_FREE_GIB=20 minimum free Docker filesystem space. EXTRACT_FACTOR=4 multiplies
compressed manifest layer sizes; neither value guarantees capacity. No pruning.
HELP
 exit 0
fi
[[ "$mode" == check || "$mode" == rollback ]] || { echo 'Unknown mode' >&2; exit 64; }
[[ "$MIN_FREE_GIB" =~ ^[0-9]+$ && "$EXTRACT_FACTOR" =~ ^[1-9][0-9]*$ ]] || exit 64
for cmd in docker curl python3 flock timeout; do command -v "$cmd" >/dev/null; done
umask 077
mkdir -p -- "$STATE_DIR"
[[ ! -L "$STATE_DIR" ]] || { echo 'Refusing symlink state directory' >&2; exit 1; }
exec 9>"$STATE_DIR/update.lock"
flock -n 9 || { echo 'Another update is running'; exit 0; }
work=$(mktemp -d "$STATE_DIR/work.XXXXXXXX")
cid=
cleanup() {
 if [[ -n "$cid" ]]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi
 rm -rf -- "$work"
}
trap cleanup EXIT
validate_ref() { [[ "$1" =~ ^ghcr\.io/skulldorom/openhands-agent@sha256:[a-f0-9]{64}$ ]]; }
current=
if [[ -f "$STATE_DIR/current.ref" ]]; then
 read -r current < "$STATE_DIR/current.ref"
 validate_ref "$current" || { echo 'Invalid current.ref' >&2; exit 1; }
 # Pin the configured known-good local image against accidental tag movement.
 docker image inspect "$current" >/dev/null
 docker tag "$current" openhands-agent-rollback:known-good
fi
if [[ "$mode" == rollback ]]; then
 read -r candidate < "$STATE_DIR/previous.ref"
 validate_ref "$candidate" || exit 1
 docker image inspect "$candidate" >/dev/null
else
 # Release state is available only after upstream compatibility, integration and
 # security checks. Never select candidate tags or an arbitrary registry latest.
 curl --fail --silent --show-error --location --max-time 60 \
  https://github.com/Skulldorom/OpenHands-Agent-Image/releases/latest/download/state.json > "$work/release.json"
 candidate=$(python3 - "$work/release.json" <<'PYCODE'
import json,re,sys
s=json.load(open(sys.argv[1]))
assert s['agent_server_version']=='1.62.0', 'Unapproved Agent Server version'
assert re.fullmatch(r'sha256:[0-9a-f]{64}',s['image_digest'])
assert re.fullmatch(r'sha256:[0-9a-f]{64}',s['upstream_digest'])
print('ghcr.io/skulldorom/openhands-agent@'+s['image_digest'])
PYCODE
 )
 validate_ref "$candidate" || exit 1
 if [[ "$candidate" == "$current" ]]; then echo 'Configured validated digest unchanged'; exit 0; fi
 # Manifest operations do not download/extract filesystem layers.
 timeout 90 docker buildx imagetools inspect "$candidate" --raw > "$work/index.json"
 platform_digest=$(python3 - "$work/index.json" <<'PYCODE'
import json,sys
m=json.load(open(sys.argv[1]))
if 'manifests' in m:
 print(next(x['digest'] for x in m['manifests'] if x.get('platform')=={'architecture':'amd64','os':'linux'}))
PYCODE
 )
 if [[ -n "$platform_digest" ]]; then
  [[ "$platform_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 1
  timeout 90 docker buildx imagetools inspect "$IMAGE@$platform_digest" --raw > "$work/manifest.json"
 else cp "$work/index.json" "$work/manifest.json"; fi
 compressed=$(python3 - "$work/manifest.json" <<'PYCODE'
import json,sys
m=json.load(open(sys.argv[1])); n=sum(int(x['size']) for x in m['layers']); assert n>0; print(n)
PYCODE
 )
 docker_root=$(docker info --format '{{.DockerRootDir}}')
 [[ -d "$docker_root" ]] || { echo 'Local Docker storage path unavailable; refusing remote daemon' >&2; exit 1; }
 free=$(df -PB1 "$docker_root" | awk 'NR==2 {print $4}')
 required=$((compressed * EXTRACT_FACTOR + MIN_FREE_GIB * 1024 * 1024 * 1024))
 (( free >= required )) || { echo "Insufficient storage: free=$free required=$required; no cleanup attempted" >&2; exit 1; }
 echo "Capacity preflight: free=$free compressed=$compressed required=$required"
 timeout 1800 docker pull "$candidate"
fi
[[ $(docker inspect -f '{{.Architecture}}' "$candidate") == amd64 ]]
[[ $(docker inspect -f '{{ index .Config.Labels "io.openhands.agent-server.version" }}' "$candidate") == 1.62.0 ]]
[[ $(docker inspect -f '{{json .Config.Entrypoint}}' "$candidate") == '["/usr/local/bin/init-git"]' ]]
if [[ "$mode" == check ]]; then
 expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["upstream_digest"])' "$work/release.json")
 actual=$(docker inspect -f '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}' "$candidate")
 [[ "$actual" == "$expected" ]]
 echo "Validated release upstream=$actual candidate=$candidate configured=${current:-legacy/unrecorded}"
fi
# The candidate has no host mounts, credentials, socket or published network ports.
timeout 90 docker run --rm --network none \
 -e GIT_USER_NAME='Image Validation' -e GIT_USER_EMAIL=validation@example.invalid \
 "$candidate" --exec bash -euo pipefail -c '
 d=$(mktemp -d); trap '\''rm -rf -- "$d"'\'' EXIT; cd "$d"; git init -q
 git -c core.hooksPath=/dev/null commit -qm test --allow-empty
 [[ $(git log -1 --format="%an <%ae>|%cn <%ce>") == "Image Validation <validation@example.invalid>|Image Validation <validation@example.invalid>" ]]
 for cmd in psql pg_dump pg_restore pg_isready initdb pg_ctl postgres; do
  "$cmd" --version | grep -E "PostgreSQL\) 17\."
 done
 test -x /usr/local/bin/openhands-agent-server
'
key=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
cid=$(docker run -d --network none -e "OH_SESSION_API_KEYS_0=$key" "$candidate")
ready=false
for ((i=0;i<60;i++)); do
 if timeout 5 docker exec "$cid" curl -fsS --max-time 3 -H "X-Session-API-Key: $key" http://127.0.0.1:8000/ready >/dev/null 2>&1; then ready=true; break; fi
 sleep 2
done
[[ "$ready" == true ]] || { docker logs "$cid"; exit 1; }
timeout 15 docker exec "$cid" curl -fsS --max-time 10 -H "X-Session-API-Key: $key" http://127.0.0.1:8000/server_info > "$work/info.json"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["version"]=="1.62.0"' "$work/info.json"
processes=$(docker top "$cid" -eo comm)
if grep -Ex 'postgres|postmaster' <<< "$processes"; then exit 1; fi
timeout 30 docker stop -t 15 "$cid" >/dev/null
[[ $(docker inspect -f '{{.State.ExitCode}}' "$cid") != 137 ]]
docker rm "$cid" >/dev/null; cid=
# Atomic staging only. The operator owns activation and current.ref advancement.
if [[ -n "$current" && "$candidate" != "$current" && "$mode" != rollback ]]; then
 printf '%s\n' "$current" > "$work/previous.ref"; mv "$work/previous.ref" "$STATE_DIR/previous.ref"
fi
printf '%s\n' "$candidate" > "$work/pending.ref"
printf 'OH_CONVERSATION_IMAGE=%s\n' "$candidate" > "$work/pending.env"
mv "$work/pending.ref" "$STATE_DIR/pending.ref"
mv "$work/pending.env" "$STATE_DIR/pending.env"
echo "Staged $candidate in $STATE_DIR/pending.env; no host configuration or running containers changed"
