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

Sources: [inspected Dockerfile](https://github.com/OpenHands/software-agent-sdk/blob/48145f7728cd4f9daf5d2f96785e6c91b7057249/openhands-agent-server/openhands/agent_server/docker/Dockerfile), [Docker runtime](https://github.com/OpenHands/software-agent-sdk/blob/48145f7728cd4f9daf5d2f96785e6c91b7057249/openhands-agent-server/openhands/agent_server/docker_runtime/registry.py#L630-L775), [official SDK documentation](https://docs.openhands.dev/sdk), [local deployment documentation](https://docs.openhands.dev/openhands/usage/run-openhands/local-setup).

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

BuildKit provenance alone is not independent authorization. New builds additionally sign GitHub artifact attestations for the exact image and complete functional evidence; promotion verifies the repository, workflow, source revision and run/attempt before trusting them.

### Inherited vulnerability limitations

This image is **not vulnerability-free**. The approved Agent Server base includes Chromium, libxml2, Docker tools and GitHub CLI with inherited vulnerabilities. Only PostgreSQL 17 and its necessary dependencies are installed from signed Debian trixie repositories. There is no broad distribution upgrade or Docker vendor-channel rewrite. Upstream-provided tools, Python and browser components remain intact. No tools are removed or downgraded to reduce counts. Version-output tests cover vendor tools; they do not certify every Docker operation.

CI scans candidate and exact upstream digest using one frozen Trivy database. Artifacts retain unsuppressed all-severity `trivy.json`, `upstream-trivy.json`, package inventory, official Debian tracker snapshot, scanner version/database hash, `security-assessment.json`/`.md` (grouped package/CVE provenance and versions), and `security-gate.json` (separate decision). Any release attaches scan/assessment evidence and names remaining risks. A gate pass means the configured policy passed, not that remaining vulnerabilities are harmless. See [SECURITY.md](SECURITY.md) and [assessment evidence](security/ASSESSMENT.md).

`CVE-2026-6653` remains a blocker: Debian calls this libxml2 issue minor but confirms trixie is affected. General-purpose agent workloads cannot prove untrusted XML unreachable. Vendor Go-module findings also remain blockers until supported fixed binaries or narrowly reviewed evidence justify a change. No exceptions are currently accepted.

### Release status

`v1.0.0` is **not published** and no tag exists for this package. The last validated candidate was blocked by seven inherited findings, including CRITICAL `libxml2` `CVE-2026-6653`, which has no fixed `trixie` or `trixie-security` package (`trixie-security` still ships `2.12.7+dfsg+really2.9.14-2.1+deb13u1`, older than the installed `+deb13u3`). For that historical candidate, every build-and-test stage passed; only the risk gate failed. Run [43872741918](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/43872741918) also passed functional validation of the refreshed upstream pin, with seven inherited release blockers, zero introduced findings and zero secrets. The simplified no-upgrade image passed independent functional and modification-security validation in [run 43876785488](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/43876785488), with seven inherited release blockers, zero introduced HIGH/CRITICAL findings and zero detected secrets. Strict release eligibility failed and promotion was skipped. Generated blocker evidence: `security-blockers.md` (CI artifact `validation-<run>`); the recorded vendor evidence is `security/vendor-evidence.json` and expires 2026-12-16. Unblocking requires one of:

* an upstream base refresh that ships fixed vendor binaries for the Go-module findings, **and** a supported Debian fix for `libxml2`;
* a CVE- and version-scoped reachability assessment accepted by the owner, implemented as reviewed narrow matching rather than a blanket exception.

Do not publish while these findings persist, and do not pull the package expecting tags: `latest` and `1.0.0` return `MANIFEST_UNKNOWN`.

### Separate validation and release decisions

CI reports three independent decisions:

1. **Functional validation**: build, metadata, real Git author/committer commits, PostgreSQL initialization/query/backup/restore/cleanup, official API readiness, entrypoint and signals. `functional-pass.json` is emitted only after these pass.
2. **Modification security**: candidate and exact upstream scanned against the same frozen database, without CVE ignores. Any introduced HIGH/CRITICAL instance or any detected secret fails this gate. Inherited instances remain visible in the full inventory; passing this gate does not accept inherited risk.
3. **Release eligibility**: the existing stricter policy still blocks all CRITICAL, advertised-fix HIGH/CRITICAL, designated high-risk CVEs and introduced HIGH/CRITICAL instances, plus secrets. `security/policy.json` has `release_approved: false`, enforced again by the publishing script. No publication is permitted before explicit owner approval and all required gates pass.

**Policy proposal — IMPLEMENTED, NOT APPROVED:** the owner could review a fixed candidate/upstream digest pair and its exact inherited package/CVE/version instances, require zero introduced HIGH/CRITICAL and zero secrets, then authorize only named inherited instances with rationale, expiry and mandatory rescanning after upstream changes. All other strict safeguards would remain. No blanket inherited-vulnerability waiver is proposed. Activation requires separate reviewed policy records and protected Environment approval; changing the approval boolean alone does not clear any vulnerability blocker.

Removing Docker CLI, GitHub CLI, Chromium or libxml2 to reduce counts violates the runtime-preservation goal. Independently rebuilding their embedded Go modules is outside this minimal extension. Network restrictions reduce exposure but do not prove vulnerable paths unreachable in arbitrary agent workloads. Supported upstream vendor binary refreshes and a Debian trixie libxml2 fix remain the remediation route. No known supported image-only remedy is established by the recorded vendor evidence.

### Versioning

Initial release is `v1.0.0`. Afterwards patch by default. Explicit manual `bump` overrides commit directives. With `auto`, standalone `release:major` wins over `release:minor` in commits since the last release; otherwise patch. Major resets minor/patch; minor resets patch. First release remains 1.0.0. Manual promotion selects patch/minor/major but never triggers a build or bypasses a blocker or owner approval. A commit tag identifies the first validated build from that commit; scheduled upstream rebuilds from the same commit preserve that tag and receive new immutable version tags. Use version/digest pins to identify a specific upstream rebuild. No PR labels, automated commits or tag-trigger recursion.

### Daily upstream updates

Resolve official manifest/source version and compare against the latest successful release's `state.json`: upstream digest and relevant build-file fingerprint. Skip unchanged inputs. Also reuse a completed, functionally passing but security-blocked assessment when its upstream digest and complete relevant fingerprint match; manual bumps do not override this. Matching evidence causes a clearly BLOCKED run without build or publication. Evidence artifacts are retained for 90 days and searched across the latest 50 completed runs; beyond that retention/search window automated deduplication is not guaranteed. Documentation-only commits do not cause image releases. Only Dockerfile, `.dockerignore`, `scripts/init-git.sh` and a changed exact upstream digest change the image content fingerprint. Policy, tests, release tooling and workflow edits do not change image contents. Daily jobs build candidates only; protected manual promotion defaults to patch; unknown versions or failed validation leave `latest` unchanged. Configure GitHub Actions notifications for failure alerts. State records source/image/upstream digests, version, commit and fingerprint.

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

## Controlled risk-acceptance proposal — not activated

The image remains official Agent Server 1.62.0 plus runtime Git identity and PostgreSQL 17. Functional readiness differs from security approval. Seven inherited findings are proposed in [security/proposed-acceptances.json](security/proposed-acceptances.json): libxml2, GitHub CLI, rootlesskit, Compose and three Buildx findings. **None are approved or active.** Accepted vulnerabilities would remain risks, not fixed or harmless findings.

Proposed expiry: **2026-12-16**. Exact CVE, package version, scanner target/type, upstream digest and candidate digest are pinned. Actual owner/date approval is pending. The owner must approve the justification and workload controls in every record. Changed versions, binaries, digests, expiry and new findings require reassessment. Introduced HIGH/CRITICAL findings and detected secrets always block. Complete unsuppressed inventory and acceptance records accompany releases. See [approval procedure](SECURITY.md#proposed-scoped-inherited-risk-acceptance-inactive).

Active `exceptions` remains empty and `release_approved` remains false. Nothing is published, promoted or deployed by this proposal. Production image digest was not inspected; the upstream baseline must not be assumed identical to the LXC deployment. Existing CI proves Git/PostgreSQL/API/signal functionality for the recorded candidate, not all host behavior. Fresh security scans and explicit approvals remain required before release; retained scans are historical evidence, not today's vulnerability-database result.

## Audited exact-candidate release path

Build validation and publication are separate. CI/daily jobs may upload a candidate but cannot create a GitHub release or update release aliases. `promote.yml` is a manual, `main`-only path with exact `candidate` digest, trusted `evidence_run`, `evidence_attempt` and `bump` inputs. It never builds. Both build inputs and exact current approved upstream must match; actual image changes require full build/integration validation. Compatibility must still be Agent Server 1.62.0.

Promotion downloads the unique validation artifact for the specified trusted main run/attempt, verifies its GitHub archive digest and age (maximum 90 days), requires successful build/test/attestation steps, and verifies signed GitHub provenance for the image and functional evidence. Schema-2 evidence binds source SHA, candidate/upstream digests, version, repository, run/attempt, result and every required test. Missing, altered, incomplete, stale, expired or unavailable evidence fails. It does not trust a local `functional-pass.json` or an unsigned JSON provenance statement.

Fresh complete unsuppressed candidate vulnerability/secret scans and an exact-base scan use one frozen Trivy database. The current policy is evaluated. A same-run immutable artifact seals candidate, policy hash/revision, scan results and functional evidence. A separate `release` Environment job requests owner approval of that exact bundle; it rechecks approval, all hashes, attestations, current main/upstream, security policy and expiry immediately before tagging. Scans expire after 24 hours, including time waiting for approval. Any candidate/policy/revision change requires a new run and approval. Individual CVE acceptance and publication approval are separate requirements.

**Configuration blocker:** read-only GitHub inspection during this audit found **zero Environments**. Create `release` with required reviewer **Skulldorom**, prevent self-review, disable administrator bypass, and allow only a custom **branch** rule named `main`. Do not use a tag rule. A different authorized actor must start a run that Skulldorom approves; self-review is prohibited. Enable Actions artifact attestations and protect main/workflow edits using repository rules and review policy. The workflow checks API-visible Environment settings and actual approval history via API; missing/unsupported settings or inaccessible APIs fail closed. Settings were not changed or end-to-end verified. Repository administrators can change workflows/settings; this mechanism does not defend against an administrator deliberately removing the boundary.

**Historical-candidate blocker:** the seven proposals reference the older `0e8e24ac…` candidate. Its historical schema-1 evidence and BuildKit provenance lack the new signed GitHub evidence contract. It is not automatically grandfathered, backdated or re-attested as a new build. The historical evidence path is proposal review only, not release eligible. A separately reviewed trusted revalidation/provenance migration would be required to release that exact older digest. Do not rewrite exception digests to substitute a newly built image. No existing candidate has been published through the new path in this audit.

Evidence retention: CI validation artifacts are retained 90 days; promotion bundles 7 days. Keep signed attestations and candidate manifests accessible; external archival alone does not bypass trusted-run checks. Missing/expired evidence requires new trusted validation, not fallback to another run/image. `security/historical-evidence.json` pins a trusted historical run/attempt, source, candidate and ZIP hash; proposal review discovers its artifact by exact name within that run instead of a hardcoded artifact ID.

GitHub's documented REST Environment response does not expose the administrator-bypass setting. Disable bypass in repository settings and verify it manually; the script cannot attest that UI setting. It additionally requires a recorded approval by the named owner even after an administrative UI bypass, and rejects runs/reruns started by that owner. Missing actual approval always blocks publication. API-verified controls are required reviewer, self-review prevention and exact main branch rule.

The Environment reviewer must copy the exact `approve <digest> policy:<sha256> run:<id>/<attempt>` comment from `approval-summary.md` into the deployment approval. Generic approval comments, an earlier attempt's approval, changed candidates/policies and owner self-started runs/reruns are rejected. This supplements, rather than replaces, GitHub required reviewers.

Active exception scopes must be unique and consumed exactly once by a blocking inherited finding. Unused or reused active scopes fail closed. `metadata_sha256` binds severity, advertised fix, status, CVSS, references, title, description and scanner data source; changed advisory metadata requires renewed review even when package/version/CVE/digests match. Proposed records remain inactive.
