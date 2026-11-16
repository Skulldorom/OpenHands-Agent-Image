#!/usr/bin/env bash
# Container-side expressions must remain unexpanded by the host shell.
# shellcheck disable=SC2016
set -euo pipefail
image=${1:?image required}
timeout 150 docker run --rm "$image" --exec bash -euo pipefail -c '
 test "$(id -u)" != 0
 for cmd in psql pg_dump pg_restore pg_isready initdb pg_ctl postgres; do
   "$cmd" --version | grep -E "PostgreSQL\) 17\."
 done
 d=$(mktemp -d /tmp/pg-test.XXXXXXXX)
 cleanup() { pg_ctl -D "$d/data" -m immediate -w -t 15 stop >/dev/null 2>&1 || true; rm -rf -- "$d"; }
 trap cleanup EXIT
 initdb -D "$d/data" --auth-local=trust --auth-host=reject --no-locale >/dev/null
 pg_ctl -D "$d/data" -l "$d/log" -o "-k $d -p 55432 -c listen_addresses= -c unix_socket_permissions=0700" -w -t 30 start
 export PGHOST="$d" PGPORT=55432
 createdb image_test
 psql -v ON_ERROR_STOP=1 -d image_test -c "CREATE TABLE sample (id integer PRIMARY KEY, value text); INSERT INTO sample VALUES (1, '\''tested'\'');"
 test "$(psql -At -d image_test -c "SELECT value FROM sample WHERE id=1")" = tested
 pg_dump -Fc -d image_test -f "$d/backup.dump"
 createdb restored_test; pg_restore --exit-on-error -d restored_test "$d/backup.dump"
 test "$(psql -At -d restored_test -c "SELECT count(*) FROM sample")" = 1
 pg_ctl -D "$d/data" -m fast -w -t 15 stop
'
echo 'PostgreSQL 17 integration: PASS'
