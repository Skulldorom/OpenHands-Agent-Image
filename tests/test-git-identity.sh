#!/usr/bin/env bash
# Git variable checks expand inside the helper subprocess.
# shellcheck disable=SC2016
set -euo pipefail
repo=$(mktemp -d)
trap 'rm -rf -- "$repo"' EXIT
helper=$(realpath "${1:-scripts/init-git.sh}")
cd "$repo"
export HOME="$repo" GIT_CONFIG_NOSYSTEM=1
unset GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS EMAIL \
    GIT_USER_NAME GIT_USER_EMAIL GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

git init -q
git config user.name 'Mounted Developer'
git config user.email mounted@example.invalid

check_commit() {
    local expected=$1
    shift
    env "$@" "$helper" --exec git commit -q --allow-empty -m identity
    local actual
    actual=$(git log -1 --format='%an|%ae|%cn|%ce')
    [[ "$actual" == "$expected" ]] || { printf 'Unexpected commit identity: %s\n' "$actual" >&2; exit 1; }
}

# No Git identity is exported by the helper in the absence of overrides.
"$helper" --exec sh -eu -c 'test -z "${GIT_AUTHOR_NAME+x}${GIT_AUTHOR_EMAIL+x}${GIT_COMMITTER_NAME+x}${GIT_COMMITTER_EMAIL+x}"'

check_commit 'Mounted Developer|mounted@example.invalid|Mounted Developer|mounted@example.invalid'
check_commit 'Example Developer|developer@example.invalid|Example Developer|developer@example.invalid' \
    GIT_USER_NAME='Example Developer' GIT_USER_EMAIL=developer@example.invalid
check_commit 'Author Example|developer@example.invalid|Example Developer|committer@example.invalid' \
    GIT_USER_NAME='Example Developer' GIT_USER_EMAIL=developer@example.invalid \
    GIT_AUTHOR_NAME='Author Example' GIT_COMMITTER_EMAIL=committer@example.invalid
check_commit 'Mounted Developer|author@example.invalid|Committer Example|mounted@example.invalid' \
    GIT_AUTHOR_EMAIL=author@example.invalid GIT_COMMITTER_NAME='Committer Example'
check_commit 'Mounted Developer|default@example.invalid|Mounted Developer|default@example.invalid' \
    GIT_USER_EMAIL=default@example.invalid
[[ $(git config user.name) == 'Mounted Developer' ]]
[[ $(git config user.email) == mounted@example.invalid ]]
[[ ! -e "$HOME/.gitconfig" ]]

GIT_USER_NAME='Example Developer' GIT_AUTHOR_NAME='' "$helper" --exec sh -eu -c '
    test "${GIT_AUTHOR_NAME?}" = ""
    test "$GIT_COMMITTER_NAME" = "Example Developer"
'
echo 'Runtime Git identity: PASS'
