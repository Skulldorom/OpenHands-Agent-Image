#!/bin/sh
set -eu

# Only fill unset fields. Git itself handles explicitly supplied values and
# normal configuration. No identity or authentication files are written.
if [ -n "${GIT_USER_NAME:-}" ]; then
    export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME-$GIT_USER_NAME}"
    export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME-$GIT_USER_NAME}"
fi
if [ -n "${GIT_USER_EMAIL:-}" ]; then
    export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL-$GIT_USER_EMAIL}"
    export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL-$GIT_USER_EMAIL}"
fi

if [ "${1:-}" = --exec ]; then
    shift
    : "${1:?--exec requires a command}"
    exec "$@"
fi
exec tini -- /usr/local/bin/openhands-agent-server "$@"
