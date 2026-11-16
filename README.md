# OpenHands Agent Image

[![CI](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/workflows/ci.yml/badge.svg)](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Skulldorom/OpenHands-Agent-Image)](https://github.com/Skulldorom/OpenHands-Agent-Image/releases/latest)

Public `linux/amd64` OpenHands Agent Server with configurable Git attribution and PostgreSQL 17 server/client tools. [GHCR package](https://github.com/users/Skulldorom/packages/container/package/openhands-agent).

## Architecture and installation

```sh
docker pull ghcr.io/skulldorom/openhands-agent:latest
```

Official `ghcr.io/openhands/agent-server:latest-python`, resolved to an immutable digest, plus PostgreSQL from Debian's signed official repositories. No database cluster, daemon, supervisor, extra port, credential or personal identity is added. Browser tooling, upstream user, working directory, mounts and `/workspace` behavior remain inherited. The wrapper executes the inspected original `tini -- /usr/local/bin/openhands-agent-server`, preserving arguments, signals and exit status.

**Approved Agent Server version: exactly 1.62.0.** Use an independently compatible Agent Canvas host. No official blanket cross-version compatibility guarantee was established. CI verifies registry entrypoint, command, user, working directory, build source version, API startup and signals. Unknown versions or contracts fail closed. Approving another version requires a deliberate `compatibility.json` change, wrapper review and host staging tests; API smoke tests alone do not establish every Canvas feature's compatibility.

Sources: [inspected Dockerfile](https://github.com/OpenHands/software-agent-sdk/blob/1d4c0249668c86d4327af51af1659330f8f0dbfc/openhands-agent-server/openhands/agent_server/docker/Dockerfile), [Docker runtime](https://github.com/OpenHands/software-agent-sdk/blob/1d4c0249668c86d4327af51af1659330f8f0dbfc/openhands-agent-server/openhands/agent_server/docker_runtime/registry.py#L630-L775), [official SDK documentation](https://docs.openhands.dev/sdk), [local deployment documentation](https://docs.openhands.dev/openhands/usage/run-openhands/local-setup).

## Runtime Git identity

```sh
docker run --rm \
  -e GIT_USER_NAME="Example Developer" \
  -e GIT_USER_EMAIL="developer@example.com" \
  ghcr.io/skulldorom/openhands-agent:latest \
  --exec git var GIT_AUTHOR_IDENT
```

Use `GIT_COMMITTER_IDENT` to inspect the committer. Normal commits use both identities. Both variables are optional together; neither preserves upstream defaults, one fails with exit 64. Control characters/newlines, angle brackets, whitespace-only names, malformed email shape and values over 256 characters are rejected. Spaces and Unicode names are supported. Git safely quotes configuration values.

Initialization creates a mode-0600 temporary system-scope config under private container `/tmp`, includes inherited system configuration, then exports `GIT_CONFIG_SYSTEM`. It never writes `$HOME`, repositories, image layers or persistence mounts. Do not share `/tmp` across conversations. Readonly containers need private writable `/tmp`. The file remains for the container lifetime and disappears with its filesystem.

Precedence, lowest to highest: inherited system configuration; runtime system identity; global (`~/.gitconfig`, XDG); repository-local/worktree; command configuration (`git -c`, `GIT_CONFIG_COUNT`); explicit `GIT_AUTHOR_*`/`GIT_COMMITTER_*` identity overrides. Existing local/global identities intentionally win. `GIT_CONFIG_NOSYSTEM=1` or stripping `GIT_CONFIG_SYSTEM` opts out. Attribution is **not GitHub authentication**; use the normal secret manager for authentication.

### Entrypoint override limitation

This invocation **bypasses initialization** and does not apply `GIT_USER_*`:

```sh
docker run --rm \
  -e GIT_USER_NAME="Example Developer" \
  -e GIT_USER_EMAIL="developer@example.com" \
  --entrypoint git \
  ghcr.io/skulldorom/openhands-agent:latest \
  var GIT_AUTHOR_IDENT
```

Use the first example's `--exec git ...` instead. For normal Agent Server startup omit `--exec` and supply upstream server arguments.

## Agent Canvas integration and forwarding

Host configuration selects the image for **new** conversations:

```env
OH_CONVERSATION_RUNTIME=docker
OH_CONVERSATION_IMAGE=ghcr.io/skulldorom/openhands-agent:latest
```

Prefer a validated digest in production. Existing containers are unchanged.

**Adding `GIT_USER_NAME` and `GIT_USER_EMAIL` to host `.agent-canvas.env` alone is insufficient.** The inspected 1.62.0 runtime constructs explicit `docker run -e NAME` flags from an allowlist that omits these variables. No generic environment-forwarding setting was found. The child image cannot change its parent's Docker invocation.

For this exact source version a separate host application customization is required. In `openhands-agent-server/openhands/agent_server/docker_runtime/registry.py`, `_build_container`, immediately before `for name in forwarded_env_names:`, add:

```python
for name in ("GIT_USER_NAME", "GIT_USER_EMAIL"):
    if name in os.environ:
        env[name] = os.environ[name]
        forwarded_env_names.append(name)
```

Then provide both variables to the **host Agent Server process**, rebuild/redeploy the host application through its supported procedure, and verify a fresh conversation with `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT`. Env-file loading depends on the host launcher. This is a documented source customization, **not an upstream setting**, and must be reviewed against the installed source. Neither this repository nor the updater applies it. Multi-user hosts need a reviewed per-conversation mapping rather than one host-wide identity. Never forward arbitrary host secrets.

## PostgreSQL 17

On `PATH`: `psql`, `pg_dump`, `pg_restore`, `pg_isready`, `initdb`, `pg_ctl`, `postgres`, `createdb`. `/usr/lib/postgresql/17/bin` is included. Automatic service startup and main-cluster creation are disabled. No PostgreSQL port starts with the agent.

External server example; use the actual provisioned user/database and existing network:

```sh
docker run --rm --network YOUR_EXISTING_NETWORK \
  -e PGHOST=openhands-postgres -e PGPORT=5432 \
  -e PGUSER=conversation_user -e PGDATABASE=conversation_database \
  ghcr.io/skulldorom/openhands-agent:latest --exec psql -c 'SELECT version();'
```

Use a protected mounted `PGPASSFILE` or manager secret injection. Never bake passwords into the image. The existing `postgres:17` server, provisioning manager, cleanup tool and volumes remain independent and untouched.

Explicit temporary cluster, under the inherited unprivileged user:

```sh
docker run --rm ghcr.io/skulldorom/openhands-agent:latest --exec bash -euc '
  d=$(mktemp -d /tmp/pg-demo.XXXXXXXX)
  trap '\''pg_ctl -D "$d/data" -m immediate -w -t 15 stop >/dev/null 2>&1 || true; rm -rf -- "$d"'\'' EXIT
  initdb -D "$d/data" --auth-local=trust --auth-host=reject
  pg_ctl -D "$d/data" -l "$d/log" -w -t 30 -o "-k $d -p 55432 -c listen_addresses= -c unix_socket_permissions=0700" start
  PGHOST="$d" PGPORT=55432 psql -d postgres -c "SELECT version();"
'
```

PostgreSQL refuses root: if using `--user 0`, switch to an unprivileged account first. Temporary embedded clusters are **not durable storage**. Durable data requires explicitly managed volumes and backups; prefer the external provisioning manager.

## CI, security gates and publishing

Pushes to `main`, manual dispatch and daily upstream checks use one serialized reusable workflow. SHA-pinned Actions, ShellCheck, shell/Python syntax, Dockerfile checks, real Git commits, PostgreSQL backup/restore, API startup, signals, metadata and Trivy checks gate promotion. Candidate tags are unvalidated staging artifacts: never deploy them.

Build once to a candidate GHCR digest with SBOM/max provenance; pull, test and scan that exact digest; promote the existing OCI index without rebuilding. `GITHUB_TOKEN` supplies package/release authentication; no publishing PAT. GitHub may initially create the package as private: change package visibility to **public** in package settings if needed. Public repository visibility does not guarantee public package visibility.

Tags: immutable full SemVer `1.0.0`, immutable `sha-<full commit>`, moving minor alias `1.0`, moving `latest`. Minor aliases necessarily move to new patches; full SemVer tags never overwrite different contents. GHCR administrators can still override tags externally. Previous releases are not pruned. Inspect retained attestations:

```sh
docker buildx imagetools inspect ghcr.io/skulldorom/openhands-agent:1.0.0
# Compare Digest with image_digest in the release's state.json.
docker pull ghcr.io/skulldorom/openhands-agent@sha256:RELEASE_DIGEST
docker buildx imagetools inspect ghcr.io/skulldorom/openhands-agent:1.0.0 --raw
```

Attestations are not an independent cryptographic publisher signature. Review CI and source revision as well as pinning the digest.

### Inherited vulnerability limitations

This image is **not vulnerability-free**. The approved Agent Server base includes Chromium, libxml2, Docker tools and GitHub CLI with inherited vulnerabilities. Supported signed trixie upgrades remediate available Debian fixes; upstream's inherited Docker bookworm vendor channel is aligned to Docker's supported trixie channel without changing Debian releases. No tools are removed or downgraded to reduce counts. Version-output tests cover vendor tools; they do not certify every Docker operation.

CI scans candidate and exact upstream digest using one frozen Trivy database. Artifacts retain unsuppressed all-severity `trivy.json`, `upstream-trivy.json`, package inventory, official Debian tracker snapshot, scanner version/database hash, `security-assessment.json`/`.md` (grouped package/CVE provenance and versions), and `security-gate.json` (separate decision). Any release attaches scan/assessment evidence and names remaining risks. A gate pass means the configured policy passed, not that remaining vulnerabilities are harmless. See [SECURITY.md](SECURITY.md) and [assessment evidence](security/ASSESSMENT.md).

`CVE-2026-6653` remains a blocker: Debian calls this libxml2 issue minor but confirms trixie is affected. General-purpose agent workloads cannot prove untrusted XML unreachable. Vendor Go-module findings also remain blockers until supported fixed binaries or narrowly reviewed evidence justify a change. No exceptions are currently accepted.

### Versioning

Initial release is `v1.0.0`. Afterwards patch by default. Explicit manual `bump` overrides commit directives. With `auto`, standalone `release:major` wins over `release:minor` in commits since the last release; otherwise patch. Major resets minor/patch; minor resets patch. First release remains 1.0.0. Explicit manual bumps force release planning. A commit tag identifies the first validated build from that commit; scheduled upstream rebuilds from the same commit preserve that tag and receive new immutable version tags. Use version/digest pins to identify a specific upstream rebuild. No PR labels, automated commits or tag-trigger recursion.

### Daily upstream updates

Resolve official manifest/source version and compare against the latest successful release's `state.json`: upstream digest and relevant build-file fingerprint. Skip unchanged inputs. Documentation-only commits do not cause image releases. Dockerfile, scripts, tests, workflows and compatibility changes do. Daily jobs default to patch; unknown versions or failed validation leave `latest` unchanged. Configure GitHub Actions notifications for failure alerts. State records source/image/upstream digests, version, commit and fingerprint.

GitHub release creation and registry tagging cannot be one cross-service atomic transaction. Interrupted promotion needs operator reconciliation; never solve it by overwriting immutable tags.

## Pull-only self-hosted updater and rollback

See [LXC-MIGRATION.md](LXC-MIGRATION.md). Optional scripts/units do not build images, restart agents, remove conversations, touch workspaces or access PostgreSQL volumes. They stage validated configuration for operator-controlled activation and preserve a previous image for rollback. Locking prevents overlapping runs; logs go to the systemd journal. No pruning occurs.

A large image needs room for downloads, extraction, writable layers, and both previous/candidate images. Shared layers may reduce actual use but cannot be assumed. A 25 GB filesystem may be insufficient. Inspect `df -h` and `docker system df`; provision capacity or decline the update. A manifest check does not prove extraction capacity. Never automatically prune volumes to make room.

## Troubleshooting and security

See [SECURITY.md](SECURITY.md). No credentials or identities belong in build args, layers or release metadata. These features need no conversation Docker socket or privileged entrypoint. This repository does not deploy to live infrastructure.

* Missing identity: inspect the actual container environment, `GIT_CONFIG_SYSTEM`, local/global overrides and host forwarding. Use `git config --show-origin --get-regexp '^user\.'`.
* Exit 64: supply both values; remove controls and malformed email formatting.
* PostgreSQL command missing: check PATH/image digest. Root errors require an unprivileged account.
* External connection failure: check network, provisioned credentials and `pg_hba.conf`; no fallback daemon starts.
* Upstream CI failure: retain working digest, inspect contract/version error, stage host testing before approving policy changes.
* Trivy failure: all CRITICAL findings, advertised-fix HIGH/CRITICAL findings, designated high-risk CVEs (including unfixed), any HIGH/CRITICAL finding this image introduces relative to its exact upstream base, and every detected secret block promotion. Unfixed HIGH findings inherited from upstream remain in the complete inventory; they are not automatically declared safe. Inspect the complete JSON report and package inventory. A passing scan is not proof of security. Scanner/database errors fail closed.
* GHCR pull denied: confirm package is public and Actions has package write permission.

Local checks need Docker Engine/Buildx, bash, curl, Python 3 and ShellCheck:

```sh
shellcheck scripts/*.sh tests/*.sh
for f in scripts/*.sh tests/*.sh; do bash -n "$f"; done
docker build -t openhands-agent:test .
scripts/validate-image.sh openhands-agent:test
```
