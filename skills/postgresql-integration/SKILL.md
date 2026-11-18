---
name: postgresql-integration
description: Use for real PostgreSQL integration tests, database migrations, ORM validation, SQL behavior, transactions, and locking in a host-provisioned OpenHands conversation test database.
---

# PostgreSQL Integration Testing

## Environment and scope

You may be running in an isolated OpenHands Docker conversation container with a separate PostgreSQL 17 server provisioned by the OpenHands host.

- Expected credentials file: `/tmp/openhands-postgres.env`
- Typical host and port: `172.17.0.1:55432` (deployment-specific; not universal)
- Expected dedicated database and role prefix: `oh_`

The host manages the external PostgreSQL server, database provisioning, credentials, and final cleanup. Do **not** try to manage that server using Docker, Compose, the host Docker socket, systemd, or administrator credentials. This does not prohibit working on Docker-related project files.

## 1. Locate credentials

Check for `/tmp/openhands-postgres.env`. If present, load it only into the current shell without displaying its contents:

```sh
if [ ! -f /tmp/openhands-postgres.env ]; then
  echo "PostgreSQL test provisioning is required (credentials file missing)" >&2
  exit 1
fi
set -a
. /tmp/openhands-postgres.env
set +a
```

Do not print secrets, enable shell tracing (`set -x`), echo connection URLs containing passwords, commit credentials, or upload the credential file. Treat that file as sensitive shell code: only source it when supplied by the trusted host provisioning process.

If provisioning is absent, report it and stop; never invent credentials or attempt administrator access.

## 2. Verify the target before any changes

1. Require nonempty `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, and `PGPASSWORD`.
2. Require database and role names to follow the provisioned `oh_` convention; reject `postgres`, `template0`, `template1`, and any known production or shared database.
3. Confirm the endpoint, database, and role match the **trusted host-provisioned configuration**. Do not treat the name prefix or credentials-file contents alone as proof of isolation. The expected network endpoint can vary by deployment.
4. Check connectivity and authenticate with the provided settings, e.g. `psql -X -w -v ON_ERROR_STOP=1 -Atqc 'SELECT current_database(), current_user, current_setting(''server_version'');'` after verification.
5. Stop if the target cannot be independently established as the conversation's isolated test database.

Do not run migrations, schema changes, cleanup, or tests that mutate data until verification succeeds.

## 3. Inspect the project

Identify the actual PostgreSQL driver, existing test configuration and command, migrations, environment variable mapping, and whether the suite creates/drops databases or needs superuser rights or extensions. Map the verified provisioned connection to the project's test settings without overwriting production configuration.

Do not silently replace required PostgreSQL coverage with SQLite or mocks.

## 4. Run integration tests

Use existing project test commands and actual PostgreSQL, covering applicable ORM behavior, migrations, constraints, transactions, concurrency, locking, and PostgreSQL-specific SQL.

Changes to tables and rows **inside the verified conversation database** may be appropriate for tests. Do not create or delete databases, alter roles, escalate privileges, access another conversation's database, or touch shared PostgreSQL infrastructure. Stop and report if the test suite needs privileges the provisioned account does not have.

## 5. Report results

Report the PostgreSQL version, verified database name (never its password), commands executed, pass/fail/skip counts, database-specific failures, and anything blocked or unverified. Never claim PostgreSQL tests passed when they were skipped or could not connect.

The host provisioning process owns final database deletion. Never delete a PostgreSQL volume or the shared server.
