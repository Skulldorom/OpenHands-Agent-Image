# OpenHands Agent image

Public reusable image: `ghcr.io/skulldorom/openhands-agent`. Based on the official `ghcr.io/openhands/agent-server:latest-python`, with runtime Git identity initialization and local PostgreSQL 17 server/client tools. No personal identity, tokens, database passwords or private keys are embedded. PostgreSQL never starts with the agent.

## Automatic releases

`upstream-update.yml` checks daily at 05:23 UTC. `ci.yml` checks main changes and supports manual dispatch with `auto`, `patch`, `minor` or `major`. Both call `release.yml`, with serialized publication; ordinary eligible updates need no recurring Environment approval or GitHub App.

The planner resolves the exact current upstream digest and approved runtime contract. **Every push or merge to main and every manual dispatch forces a fresh, uncached Docker build**, including documentation-only main commits and unchanged upstream/build inputs. Manual dispatch never bypasses functional or security checks. Each build records the exact source SHA, upstream digest, SBOM and provenance under a unique `candidate-RUN-ATTEMPT` tag. An existing run tag fails closed; no content marker is overwritten.

| Trigger | Build | Publication |
| --- | --- | --- |
| Main push/merge | Always fresh | Only after all gates pass |
| Manual dispatch on main | Always fresh; auto/patch/minor/major | Only after all gates pass |
| Daily schedule | Rebuild for changed upstream or image inputs; otherwise reuse | Only after fresh validation and security checks |
| Pull request | Local build, functional and credential-layer tests | Never production publication |

Scheduled checks ignore documentation when deciding whether to rebuild. Small immutable per-run candidate journals allow retries after failed functional or security validation. Pending publication takes priority over other retained candidates. Journals expire after 90 days; if none is available among the latest 100 repository artifacts, a legacy marker may be reused or a fresh build is required. Retained candidates require signed original build provenance and exact base binding; build completion never counts as functional validation. Reused candidates currently rerun all functional tests and fresh scans, avoiding rebuilds without trusting failed or stale tests. Missing provenance fails closed.

Lifecycle states: `build_failed`, `built`, `functional_failed`, `functional_passed`, `security_failed`, `validated`, `published`. Reports and state are retained as Actions artifacts for 90 days. Failed tests retry on the next scheduled/manual run; failed security policy never suppresses retries or authorizes publication.

Four deterministic fingerprints track image content (Dockerfile, init script, base and architecture), functional tests/compatibility, security policy/scanner settings/acceptances, and publisher/workflows. During scheduled checks, policy/test/publisher changes revalidate without rebuilding. Main pushes and manual dispatch always build. Version/revision image labels retain original build identity when reusing an image; release metadata records current authorization source.

The validation job signs functional evidence and seals complete scans, database hash, package inventory and policy decision. A separate minimally privileged publisher downloads the exact GitHub artifact hash, verifies provenance, reassesses raw scans and checks current main SHA and upstream digest. It never rebuilds. Validation jobs run independently so a newer push cannot discard a pending build. The non-cancelling publisher concurrency group prevents conflicting publishers; freshness and newer-version checks prevent stale `latest` updates.

### Versioning and interrupted publication

A new build does not necessarily mean a new release. Build, validation and publication decisions are separate. After all gates pass, an identical OCI digest reuses the previous approved release unless an explicit patch/minor/major dispatch override or minor/major commit directive requests a release. Fresh validation artifacts are retained and an immutable `reassessment-HASH.zip` is appended; original approval assets and release source provenance remain unchanged. Version/revision labels, package changes and SBOM/provenance manifests can make fresh builds produce different digests even when Dockerfile inputs are unchanged.

Security approval under the active reviewed policy is required for publication. The inherited baseline remains unapproved: a successful build does not authorize `v1.0.0`. Candidate images may exist while publication is blocked. `latest` always identifies the latest approved release (or the approved pending release during finalization); security rejection prevents promotion.

First release is `v1.0.0`; later releases default to patch. Manual minor/major overrides and exact commit directives `release:minor` / `release:major` select increments. Immutable image tags `1.0.0` and `v1.0.0` must resolve to the expected candidate digest and cannot be overwritten with another image.

A draft GitHub Release reserves durable publication intent before registry writes. Reconciliation prepares immutable image references, verifies the Git tag, attaches evidence, rechecks freshness, updates and verifies `latest`, then finalizes GitHub Release metadata. Failures at any boundary retry the same version, including failure after `latest`. A forced build still runs while publication is pending; if its digest differs from the reservation, publication blocks until the scheduled path revalidates and recovers the reserved digest. It never substitutes a fresh image into an existing reservation. Existing conflicting tags fail closed. If upstream changes while a draft is pending, the run blocks for maintainer review rather than discarding the reservation or publishing stale content. Rollback uses a previous release digest; never rebuild an old release. Stale source/upstream checks and version ownership conflicts fail closed when pushes overlap. Production GitHub/GHCR publication and recovery have not been tested end to end; the isolated sandbox integration remains unverified.

## Runtime identity

```env
GIT_USER_NAME=
GIT_USER_EMAIL=
```

Supply both at runtime. Missing, partial, malformed and injection attempts are tested; real commits verify author and committer identities. Existing Git configuration is preserved. Attribution does not authenticate to GitHub.

## Agent Canvas integration and forwarding

The host Agent Server does not automatically forward these two variables to conversation containers. Setting them only on the host is insufficient; the image cannot repair host forwarding. See [LXC-MIGRATION.md](LXC-MIGRATION.md) for the separately reviewed operator procedure. No live host changes are part of this PR.

## PostgreSQL 17

Includes `psql`, `pg_dump`, `pg_restore`, `pg_isready`, `initdb`, `pg_ctl`, and `postgres`. Isolated tests create a temporary local cluster, query it, dump, restore and shut it down. No external PostgreSQL container is required. The old LXC PostgreSQL provisioning manager has already been removed. Temporary clusters are not durable database services.

## GitHub setup and blocked runs

One-time: enable Actions, allow `GITHUB_TOKEN` package writes, link the GHCR package to this repository, make the package public and protect main/workflow/security-policy changes with maintainer review. The publisher additionally needs contents write and attestations read; validation needs OIDC/attestations write. No App credentials, promotion enablement flags or recurring Environment reviewer are required.

Initial reviewed risk records are still required; none are approved by this PR. See [SECURITY.md](SECURITY.md). Inspect failed run summaries and the `validation-RUN-ATTEMPT` artifact (`state.json`, full scans, assessment, blocker report). Do not activate proposed acceptances merely to obtain green CI. Unknown Agent Server versions require explicit compatibility review; only `1.62.0` is approved.

## Tests

Run Python behavioral suites in `tests/test-*.py` (layer and historical-evidence scripts require their documented artifact/image argument), ShellCheck and actionlint. `scripts/validate-image.sh IMAGE@DIGEST` runs real Git, PostgreSQL, Agent Server readiness and signal tests; `tests/test-image-layers.py IMAGE@DIGEST` checks layers. Docker integration runs on GitHub Actions, not the LXC. PR policy CI has no publication permission.
