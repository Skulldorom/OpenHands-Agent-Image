#!/bin/sh
set -eu
name=${GIT_USER_NAME:-}
email=${GIT_USER_EMAIL:-}
if [ -n "$name" ] || [ -n "$email" ]; then
    if [ -z "$name" ] || [ -z "$email" ]; then
        echo 'GIT_USER_NAME and GIT_USER_EMAIL must both be nonempty or both absent' >&2
        exit 64
    fi
    for value in "$name" "$email"; do
        case "$value" in
            *'
'*) echo "Invalid Git identity: newline" >&2; exit 64 ;;
        esac
        if [ "${#value}" -gt 256 ] || printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]<>]'; then
            echo 'Invalid Git identity: control characters, angle brackets, or excessive length' >&2
            exit 64
        fi
        if ! printf '%s' "$value" | LC_ALL=C grep -q '[^[:space:]]'; then
            echo 'Invalid empty Git identity' >&2
            exit 64
        fi
    done
    if ! printf '%s\n' "$email" | LC_ALL=C grep -Eq '^[^[:space:]@]+@[^[:space:]@]+$'; then
        echo 'Invalid GIT_USER_EMAIL' >&2
        exit 64
    fi
    umask 077
    config=$(mktemp /tmp/openhands-git.XXXXXXXX)
    system=${GIT_CONFIG_SYSTEM:-/etc/gitconfig}
    git config --file "$config" include.path "$system"
    git config --file "$config" user.name "$name"
    git config --file "$config" user.email "$email"
    export GIT_CONFIG_SYSTEM="$config"
fi
if [ "${1:-}" = --exec ]; then
    shift
    [ "$#" -gt 0 ] || { echo '--exec requires a command' >&2; exit 64; }
    exec "$@"
fi
exec tini -- /usr/local/bin/openhands-agent-server "$@"
