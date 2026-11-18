#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
key=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
cid=$(OH_SESSION_API_KEYS_0="$key" docker run -d -e OH_SESSION_API_KEYS_0 \
    -e OH_ENABLE_VSCODE=false -e OH_ENABLE_BROWSER=0 -p 127.0.0.1::8000 \
    "$image" --host 0.0.0.0 --port 8000)
trap 'docker rm -f "$cid" >/dev/null' EXIT
port=$(docker port "$cid" 8000/tcp | cut -d: -f2)

ready=false
for ((attempt=0; attempt<60; attempt++)); do
    if printf 'header = "X-Session-API-Key: %s"\n' "$key" |
        curl --config - -fs --max-time 2 "http://127.0.0.1:$port/ready" >/dev/null; then
        ready=true
        break
    fi
    [[ $(docker inspect -f '{{.State.Running}}' "$cid") == true ]] || break
    sleep 2
done
[[ "$ready" == true ]] || { echo 'Agent Server did not become ready' >&2; exit 1; }
processes=$(docker top "$cid" -eo pid,comm | awk 'NR > 1 {print $2}')
grep -qx tini <<< "$processes"
if grep -Exq 'postgres|postmaster' <<< "$processes"; then
    echo 'PostgreSQL started with the agent' >&2
    exit 1
fi
docker stop -t 15 "$cid" >/dev/null
exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
[[ "$exit_code" == 0 || "$exit_code" == 143 ]]
echo 'Agent Server startup, shutdown and inactive PostgreSQL: PASS'
