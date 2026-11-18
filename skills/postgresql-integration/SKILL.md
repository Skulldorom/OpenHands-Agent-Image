---
name: postgresql-integration
description: Use the bundled PostgreSQL 17 server in an OpenHands Docker conversation for integration tests, migrations, ORM validation, SQL behavior, transactions, and locking.
---

# PostgreSQL Integration Testing

## 1. Choose a test database

Inspect the project's test command, migrations, driver, connection settings,
and any requirements for extensions or database creation. Prefer a
project-provided database when its endpoint, database name, and isolation are
explicitly verified for testing. Keep credentials out of logs and commits.

Otherwise start a disposable cluster using the PostgreSQL 17 tools bundled in
the conversation image. Run as the container's unprivileged user. Agent Server
leaves PostgreSQL stopped at startup, so initialize the cluster when tests need
it.

## 2. Start and verify a disposable cluster

Run the following as a single Bash block inside the conversation. Put the
project's test command at the marked location so it runs before the cleanup
trap. The private Unix socket directory isolates concurrent runs even when
they use the same port number. Local socket authentication is restricted by
the directory's and socket's permissions, and TCP listeners are disabled.

```bash
(
  set -euo pipefail

  if [ "$(id -u)" -eq 0 ]; then
    echo 'Run this as the unprivileged OpenHands container user.' >&2
    exit 1
  fi
  for cmd in initdb pg_ctl postgres createdb psql; do
    command -v "$cmd" >/dev/null || { echo "Missing PostgreSQL tool: $cmd" >&2; exit 1; }
  done
  pg_ctl --version | grep -q 'PostgreSQL) 17\.' || {
    echo 'The bundled PostgreSQL 17 tools are required.' >&2
    exit 1
  }

  pg_test_dir=$(mktemp -d /tmp/openhands-pg.XXXXXXXX)
  cleanup() {
    if [ -s "$pg_test_dir/data/postmaster.pid" ] &&
       ! pg_ctl -D "$pg_test_dir/data" -m fast -w -t 15 stop; then
      echo "PostgreSQL cleanup failed. Cluster retained at $pg_test_dir" >&2
      return 1
    fi
    rm -rf -- "$pg_test_dir"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS PGPASSWORD
  export PGHOST="$pg_test_dir" PGPORT=55432 PGUSER=openhands_test_owner
  initdb -D "$pg_test_dir/data" --username="$PGUSER" \
    --auth-local=trust --auth-host=reject --no-locale --encoding=UTF8
  if ! pg_ctl -D "$pg_test_dir/data" -l "$pg_test_dir/postgres.log" \
    -o "-k $PGHOST -p $PGPORT -c listen_addresses= -c unix_socket_permissions=0700" \
    -w -t 30 start; then
    cat "$pg_test_dir/postgres.log" >&2
    exit 1
  fi

  createdb --maintenance-db=postgres openhands_test
  export PGDATABASE=openhands_test
  test "$(psql -X -w -v ON_ERROR_STOP=1 -Atqc 'SHOW data_directory')" = "$pg_test_dir/data"
  psql -X -w -v ON_ERROR_STOP=1 -Atqc 'SELECT current_database(), current_user, version();'

  # Run the project's migrations and PostgreSQL test command here.
)
```

## 3. Run the project's integration tests

Check which connection settings the test command actually reads. For a
libpq-compatible PostgreSQL URL, use
`postgresql:///openhands_test?host=$PGHOST&port=$PGPORT&user=$PGUSER` with
the shell variables expanded. For other drivers, use their Unix socket
configuration. Scope any project-specific variables, such as `DATABASE_URL`,
to the test command. Check for project defaults that might override them.
Before migrations or other writes, confirm the project's own connection
targets the verified test database.

If the client requires TCP, use the project's verified isolated test database
or configure the disposable cluster to listen only on loopback with a free
port and a dedicated test login using SCRAM password authentication. Verify
that the TCP connection reaches the disposable cluster before running tests.

Use real PostgreSQL for PostgreSQL-specific coverage. Keep migrations, schema
changes, database creation and cleanup within the verified test environment.

## 4. Report results

Report the PostgreSQL version, test commands, pass/fail/skip counts, and any
database-specific failures or unverified coverage. Report cleanup failures
and the retained directory so the cluster can be stopped before removal.
