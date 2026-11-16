#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
# Git/package format variables must expand inside the container, not on the runner.
# shellcheck disable=SC2016
timeout 60 docker run --rm "$image" --exec sh -eu -c '
 test -x /usr/local/bin/openhands-agent-server
 command -v tini; command -v chromium
 gh --version
 rootlesskit --version
 docker --version
 docker buildx version
 docker compose version
 dpkg-query -W libxml2
 dpkg-query -W -f="\${binary:Package} \${Depends}\n" | grep -c libxml2 || true
 ldd /usr/lib/chromium/chromium
 test ! -d /var/lib/postgresql/17/main
'
key=$(python3 -c "import secrets; print(secrets.token_hex(24))")
cid=$(docker run -d -e "OH_SESSION_API_KEYS_0=$key" -e OH_ENABLE_VSCODE=false -e OH_ENABLE_BROWSER=0 -p 127.0.0.1::8000 "$image" --host 0.0.0.0 --port 8000)
cleanup() { docker logs "$cid"; docker rm -f "$cid" >/dev/null; }
trap cleanup EXIT
port=$(docker port "$cid" 8000/tcp | cut -d: -f2)
ready=false
for ((i=0;i<90;i++)); do
 if curl -fsS --max-time 2 -H "X-Session-API-Key: $key" "http://127.0.0.1:$port/ready"; then ready=true; break; fi
 sleep 2
done
[[ "$ready" == true ]]
curl -fsS --max-time 10 -H "X-Session-API-Key: $key" "http://127.0.0.1:$port/server_info" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["version"] == "1.62.0", d'
processes=$(docker top "$cid" -eo pid,comm | awk 'NR > 1 {print $2}')
if grep -Ex 'postgres|postmaster' <<< "$processes"; then exit 1; fi
grep -q tini <<< "$processes"
start=$SECONDS
docker stop -t 15 "$cid" >/dev/null
(( SECONDS - start < 15 ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
[[ "$code" != 137 ]]
echo 'Agent Server API and signal handling: PASS'
