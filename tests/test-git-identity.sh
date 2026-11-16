#!/usr/bin/env bash
# Container-side expressions must remain unexpanded by the host shell.
# shellcheck disable=SC2016
set -euo pipefail
image=${1:?image required}
run() { timeout 60 docker run --rm "$@" "$image" --exec sh -eu -c '
 d=$(mktemp -d); trap '\''rm -rf "$d"'\'' EXIT; cd "$d"; git init -q
 git -c core.hooksPath=/dev/null commit -qm test --allow-empty
 test "$(git log -1 --format="%an <%ae>|%cn <%ce>")" = "Example Developer <developer@example.com>|Example Developer <developer@example.com>"
'; }
run -e GIT_USER_NAME='Example Developer' -e GIT_USER_EMAIL=developer@example.com
run -e GIT_USER_NAME='Example Developer' -e GIT_USER_EMAIL=developer@example.com
for args in name email newline injection bademail blank; do
 case "$args" in
 name) envs=(-e GIT_USER_NAME=Example);;
 email) envs=(-e GIT_USER_EMAIL=developer@example.com);;
 newline) envs=(-e $'GIT_USER_NAME=Name\n[user]' -e GIT_USER_EMAIL=developer@example.com);;
 injection) envs=(-e 'GIT_USER_NAME=Name <evil>' -e GIT_USER_EMAIL=developer@example.com);;
 bademail) envs=(-e GIT_USER_NAME=Example -e 'GIT_USER_EMAIL=no email');;
 blank) envs=(-e 'GIT_USER_NAME=   ' -e GIT_USER_EMAIL=developer@example.com);;
 esac
 if timeout 30 docker run --rm "${envs[@]}" "$image" --exec true; then echo "Accepted invalid identity: $args" >&2; exit 1; fi
done
timeout 30 docker run --rm "$image" --exec sh -eu -c '
 test -z "${GIT_CONFIG_SYSTEM:-}"
 if git config --system --get user.name; then exit 1; fi
 if git config --system --get user.email; then exit 1; fi
'
timeout 30 docker run --rm -e GIT_USER_NAME='Example Developer' -e GIT_USER_EMAIL=developer@example.com "$image" --exec sh -eu -c '
 d=$(mktemp -d); trap '\''rm -rf "$d"'\'' EXIT; cd "$d"; git init -q
 git config user.name "Local Developer"; test "$(git config user.name)" = "Local Developer"
 GIT_AUTHOR_NAME="Explicit Author" git var GIT_AUTHOR_IDENT | grep -q "Explicit Author"
 GIT_COMMITTER_NAME="Explicit Committer" git var GIT_COMMITTER_IDENT | grep -q "Explicit Committer"
'
echo 'Git identity integration: PASS'
