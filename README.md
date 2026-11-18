# OpenHands Agent Image

`ghcr.io/skulldorom/openhands-agent:latest` extends the official
`ghcr.io/openhands/agent-server:latest-python` image with runtime Git identity
configuration and PostgreSQL 17 server and client tools. The published image
targets Linux AMD64 and runs Agent Server as the upstream `openhands` user.

## Git identity

Set these variables in the **conversation container's** runtime environment.

| Variable | Purpose |
| --- | --- |
| `GIT_USER_NAME` | Default author and committer name |
| `GIT_USER_EMAIL` | Default author and committer email |
| `GIT_AUTHOR_NAME` | Override the author name |
| `GIT_AUTHOR_EMAIL` | Override the author email |
| `GIT_COMMITTER_NAME` | Override the committer name |
| `GIT_COMMITTER_EMAIL` | Override the committer email |

For example, set `GIT_USER_NAME=Example Developer` and
`GIT_USER_EMAIL=developer@example.invalid` in your container configuration.
Each field is independent. Explicit Git author or committer variables take
precedence, even when set to an empty string. An omitted field with no default
resolves through normal Git configuration. Git identity is passed in the process
environment, so `git config user.name` continues to show configured Git values.
Use `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` to see the
effective identity. Recreate the conversation container to apply changed
environment variables. Starting the same Docker container again reuses its
original environment. Verify that your OpenHands host forwards the variables
to the conversation container when using Docker-based conversations.

## Git authentication

Configure Git authentication separately from commit attribution. Forward an
SSH agent socket and set `SSH_AUTH_SOCK` inside the container, or mount
restricted SSH credentials and `known_hosts` at runtime. For HTTPS, use your
runtime Git credential helper or OpenHands' runtime authentication integration.
Make mounts readable by the container's `openhands` user. Keep credentials out
of Git remote URLs, Docker builds and the repository.

## PostgreSQL 17

`psql`, `pg_dump`, `pg_restore`, `initdb`, `pg_ctl` and `postgres` are available on
`PATH`. Pass a connection string or regular PostgreSQL client settings at runtime
to use an existing database. For local development, initialize a writable data
directory with `initdb -D <data-dir>` and start it explicitly with
`pg_ctl -D <data-dir> -l <log-file> start`. Configure authentication before
exposing any listener. Mount storage for data that must outlive the container.
Starting Agent Server leaves PostgreSQL stopped.

## Builds and updates

| Trigger | What happens |
| --- | --- |
| Push to `main` | Build and validate the current upstream |
| Daily at 05:23 UTC | Build when upstream or tracked image/validation inputs differ from the published image |
| Manual dispatch | Build and validate the current upstream. Dispatch on `main` to publish after validation |
| Pull request to `main` | Build and validate locally on the GitHub runner |

Each build resolves the upstream tag to an immutable digest and checks its
startup contract. The workflow tests Agent Server startup and shutdown, Git
identity and a real PostgreSQL cluster. It reports inherited vulnerabilities,
blocks new or worsened HIGH/CRITICAL findings and added secret detections, and
checks for supported live credentials across the candidate. Scanner coverage
depends on the tools' detection rules and supported verification endpoints.
Raw secret findings stay off logs and published artifacts.

The publisher uses the repository's `GITHUB_TOKEN`. Give this repository Actions
write access to the GHCR package and make the package public so the daily check
can read `latest` anonymously. Successful production runs publish a unique
`build-<source-sha>-<run-id>-<attempt>` rollback tag with BuildKit provenance,
then move `latest` to the same OCI digest. Production runs are serialized and
recheck both upstream and `main` before updating `latest`.

Use `ghcr.io/skulldorom/openhands-agent:latest` to follow successful builds.
To roll back a deployment, select a prior `build-...` tag from the package
or use its `ghcr.io/skulldorom/openhands-agent@sha256:...` digest, then recreate
the conversation container. The workflow never reuses rollback tags. Automatic
publication updates GHCR, while pulling a new image and recreating containers
remain deployment actions.

## Troubleshooting

Open the failed **OpenHands image** run in GitHub Actions and inspect the
failing step. An upstream startup-contract or Debian compatibility error
requires updating the wrapper or the package install for the new upstream
image. A stale-source or upstream error can be retried with a fresh dispatch on
`main`. A GHCR error warrants checking package visibility and this repository's
Actions access. Failed build, smoke test and scan steps leave the previous
`latest` available.

To run the Git checks without starting Agent Server, use
`bash tests/test-git-identity.sh`. To build locally, resolve upstream with
`skopeo inspect --raw docker://ghcr.io/openhands/agent-server:latest-python`,
hash that manifest with `sha256sum`, and pass
`--build-arg UPSTREAM_IMAGE=ghcr.io/openhands/agent-server@sha256:<digest>`
to `docker build`. Run `tests/test-agent-startup.sh` and
`tests/test-postgresql.sh` with your local image tag.
