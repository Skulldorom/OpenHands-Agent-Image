# Security policy

Only the newest successful release on the approved Agent Server version is maintained. Digest/version pins remain available for rollback but never receive fixes in place.

Report vulnerabilities privately through GitHub Security Advisories. If private reporting is unavailable, contact the repository owner without posting exploit details or secrets publicly. Never attach credentials, private keys, personal data or complete environment dumps.

CI gates releases with vulnerability and secret scanning. Complete inventories retain every severity and unfixed finding without scanner suppressions. A separate risk gate blocks all CRITICAL findings, HIGH/CRITICAL findings with advertised fixes (conservatively including module fixes pending supported binary verification), HIGH/CRITICAL findings this image introduces relative to its exact upstream base, and explicitly designated high-risk CVEs regardless of fix availability. Unfixed HIGH findings inherited from upstream remain visible as unresolved risks, not claims of safety or accepted CVE exceptions. There are currently **no accepted exceptions**, VEX not-affected assertions, or ignore entries. The machine-readable policy is `security/policy.json`; its owner and review deadline are enforced. A new exception must identify CVE, exact package/version scope, reason, owner, review deadline and evidence and implement reviewed narrow matching; the matcher supports explicitly approved exact records; active exceptions remain empty. Inspect inherited upstream risks and reports. A passing scan is not proof of security: database coverage, detection limits and later disclosures still require review.

Builds replace the upstream Debian snapshot with signed live trixie, trixie-updates and trixie-security repositories to install PostgreSQL 17 and its necessary dependencies. No broad package upgrade or Docker vendor-channel rewrite is performed; inherited tools remain intact. The approved Agent Server Python version stays unchanged. CI retains the package inventory and complete all-severity JSON report, including unfixed findings. Package-generated snakeoil certificate/key files are removed before their installation RUN completes; CI inspects every saved layer, not only the merged filesystem. An inherited lower-layer key fails this test and cannot be fixed by a later whiteout. Unknown upstream versions/contracts fail closed. BuildKit attaches SBOM/provenance. Actions use SHA pins; review updates manually. Dependabot PR creation is disabled for this direct-main repository.

Git attribution is not authentication. Runtime identity stays in private container-local /tmp; never share that mount between conversations. PostgreSQL never starts automatically; test clusters use private Unix sockets. No runtime Docker socket or privilege escalation is required for these features.

Installing the optional host updater requires explicit operator action and Docker administrator access. Check capacity and preserve previous images. Never prune volumes or delete workspaces to make room. No infrastructure deployment is performed by this repository.


## Initial release remediation investigation

The first candidate scan reported 112 HIGH vulnerability instances, no CRITICAL instances, and one package-generated snakeoil private key. PostgreSQL contributed 102 instances across `libpq5`, `postgresql-17`, and `postgresql-client-17` at `17.11-0+deb13u1`; Debian provides `17.12-0+deb13u1`. The PostgreSQL server/client are our additions. The upstream Dockerfile does not explicitly install PostgreSQL; the CI inventory records the inherited libpq presence separately where applicable. Six inherited `linux-libc-dev` findings at `6.12.116-1` have a Debian fix at `6.12.117-1`. The frozen upstream November 10 Debian snapshot prevented access to these fixes.

The following inherited Go dependencies remain in the latest packages examined from the upstream-configured vendor repositories. Module fixes exist, but that does **not** mean fixed vendor binaries exist. Retaining these tools preserves upstream functionality; removing them or replacing their dependencies without rebuilding and compatibility validation is not a safe remedy.

| CVE | Severity | Binary / owning package | Installed module | Fixed module | Ownership |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-78661 | HIGH | `/usr/bin/gh`, GitHub CLI `gh` 2.104.0 | `golang.org/x/net` v0.61.0 | v0.62.0 | Inherited; GitHub CLI vendor |
| CVE-2026-78661 | HIGH | `/usr/bin/rootlesskit`, Docker `docker-ce-rootless-extras` 29.9.3 | `golang.org/x/net` v0.60.0 | v0.62.0 | Inherited; Docker/RootlessKit vendors |
| CVE-2026-78661 | HIGH | Docker Compose, `docker-compose-plugin` 5.7.1 | `golang.org/x/net` v0.60.0 | v0.62.0 | Inherited; Docker Compose vendor |
| CVE-2026-17106 | HIGH | Docker Buildx, `docker-buildx-plugin` 0.39.0 | `github.com/moby/go-archive` v0.2.0 | v0.3.0 | Inherited; Docker Buildx/Moby vendors |

Vendor package metadata and downloaded package SHA-256 hashes were checked, and embedded Go module build information was inspected without executing those binaries. CI scans the actual built candidate; its retained JSON and package inventory are authoritative for that candidate. These findings remain release blockers unless the actual candidate report proves remediation. No exceptions or custom rebuilds have been introduced. See [the focused assessment](security/ASSESSMENT.md) for current evidence, CVE-2026-6653 exposure and the separate inventory/gate policy.

## Proposed scoped inherited-risk acceptance (inactive)

`security/proposed-acceptances.json` contains seven **proposed, not approved** records copied from validated run 43876785488. They are not loaded by the release policy. Approving owner/date remain pending. Proposed expiry: **2026-12-16**, inclusive by the runner's calendar date. The only authorized acceptance owner is `Skulldorom`. Repository review and protected write access establish authorization; a JSON name is not a cryptographic signature.

Matching requires exact CVE, package/module, installed version, full scanner target, result class/type, upstream digest and candidate digest. The same version and binary scope must exist in the exact upstream scan. All fields are mandatory; wildcards, malformed records, expired and future-dated approvals fail closed. Changed versions, targets or digests require fresh review. New HIGH/CRITICAL findings and all secrets always block. Original reasons, severity and complete inventory stay visible, including approved records in generated markdown/JSON. Acceptance is not remediation or proof of harmlessness.

The proposed justification is preserving official Agent Server functionality while accepting time-limited inherited risk without introduced HIGH/CRITICAL findings. Proposed controls restrict workloads and untrusted XML/HTML/archive/image inputs, isolate networks and credentials, and prohibit privileged access or a Docker socket. These controls may be unsuitable for arbitrary agent workloads; the owner must assess that trade-off. XML/HTML findings can cause denial of service; archive/Docker findings can have file-write or code-execution impact. No reachability exclusion is asserted.

Activation requires a separate reviewed change after owner approval of the **exact records**, actual approval dates, expiry and controls. Copy only approved records into `security/policy.json`'s `exceptions`; keep `release_approved` false until independent release authorization. Merging this proposal grants no approval. Before publishing, refresh complete unsuppressed scans for the exact candidate/base and reassess with the approved policy. Promotion requires a matching policy hash, exact functional-pass evidence, no introduced risks/secrets, and checks expiry again. Changed images need new records, not blind digest substitution. Policy-only changes no longer change image-content fingerprints; the audited manual promotion route supports signed schema-2 candidates but does not grandfather the historical schema-1 candidate.

At expiry, remove or deliberately renew records after reviewing current advisories and supported upstream fixes. Never silently extend dates. New upstream digests require reassessment and approval. Releases attach full scans, scanner identity/database hash, assessment, functional evidence, package inventory, Debian tracker and active policy. Versioning and digest-promotion safeguards remain unchanged.

Proposal-review CI only reassesses retained evidence with hypothetical in-memory approval. It has no package/release write permissions and performs no build. Missing or expired evidence fails validation. Its hypothetical PASS report is **not release approval**.

## Audit findings and release trust boundary

1. **Approval invalidated candidate digests.** The planner fingerprinted policy/tests/workflows, then rebuilt with a new revision label. Fingerprints now cover only actual Docker build inputs; upstream digest is compared separately. Manual exact-digest promotion performs fresh scans without rebuilding. Release version is metadata; image labels retain the original build identity.
2. **JSON approval was not authorization.** Repository fields remain fail-closed policy intent, not proof of who approved. The only publisher runs behind the protected `release` GitHub Environment and checks the actual owner approval and settings. Build CI has no release write permission or promotion call. The publish job alone receives contents/package write permissions for promotion (build jobs still need package write to upload candidates). PR jobs remain read-only.
3. **Functional evidence was too weak.** Schema 2 binds candidate, source, upstream, version, run/attempt and all completed required tests. Download checks trusted main workflow execution, archive integrity/retention and successful test steps. Signed GitHub image and evidence attestations must verify exact signer/source/run. Local JSON or historical JSON cannot authorize publishing.
4. **Exception ambiguity and metadata drift.** Exact scope is retained and active records must be unique, used once, and metadata-bound. Full inventories remain unsuppressed. Any CVE metadata change requires review; no newly introduced HIGH/CRITICAL or secret is accepted.
5. **Hardcoded artifact identity.** Discovery now uses explicit trusted run/attempt and exact artifact name, then checks source, candidate and GitHub archive SHA256. Proposal-only historical review additionally pins the historical ZIP hash. Missing/expired evidence fails; there is no alternate-candidate fallback.
6. **Controls were proposals, not deployment evidence.** See enforceability table below. No LXC/runtime configuration was inspected or changed.

### Required GitHub configuration and residual trust

`release` Environment must require user `Skulldorom`, prevent self-review, disable admin bypass and restrict deployments to custom branch `main` only. The workflow validates API-visible settings and recorded owner approval; administrator bypass needs manual configuration as explained below. The reviewer approves the run's exact candidate and policy bundle, not just a repository boolean. Changing main, candidate, policy or run attempt invalidates the context. Maximum scan age is 24 hours at promotion. CVE records still need separately reviewed approval dates, owner and expiry. Do not grant approvals through this PR.

Read-only audit found no Environments configured. Configuration, token access to approval/settings APIs, GitHub attestations generation/verification, Docker integration and publication have not been exercised end-to-end. Missing settings are a blocker, not a fallback. Protect main and workflow modifications; an administrator with authority to replace workflows/settings remains inside the trust boundary. No claim of completed infrastructure enforcement is made.

### Deployment control enforceability

| Proposed control | What can enforce it | Verified active here? / residual risk |
| --- | --- | --- |
| Restrict untrusted XML/HTML/archive/image inputs | Application input policy and operator workload discipline | No. General-purpose agents can fetch arbitrary inputs; do not assert reachability exclusion. |
| No Docker socket | Host container creation/mount policy | No production evidence. Image does not mount a socket; host can still supply one. Inherited Docker clients remain available. |
| No privileged containers | Host Docker runtime security options | No production evidence. Agent Server entrypoint cannot constrain host privileges. Upstream sudo/runtime tools remain inherited. |
| Network isolation | Host Docker networks/firewall and egress policy | No production evidence. Image alone cannot enforce it; external DB access needs deliberate routing. |
| Credential minimization | Host secret forwarding, mounts and scoped service credentials | No production evidence. Runtime identity is attribution, not authentication. Agent workloads may access forwarded credentials. |
| Ephemeral local PostgreSQL | Default no-cluster/no-daemon image behavior plus explicit test cleanup | Covered by existing integration tests; caller volumes/mounts can override durability assumptions. |

The first five controls are recommendations requiring independently verified deployment configuration, not facts established by the public image. The proposed acceptances must be rejected if their required controls cannot be made effective for intended workloads. Accepted vulnerabilities remain exploitable risks; scanner silence and successful tests do not establish safety. No production changes were made.

GitHub's documented REST Environment response does not expose the administrator-bypass setting. Disable bypass in repository settings and verify it manually; the script cannot attest that UI setting. It additionally requires a recorded approval by the named owner even after an administrative UI bypass, and rejects runs/reruns started by that owner. Missing actual approval always blocks publication. API-verified controls are required reviewer, self-review prevention and exact main branch rule.

The Environment reviewer must copy the exact `approve <digest> policy:<sha256> run:<id>/<attempt>` comment from `approval-summary.md` into the deployment approval. Generic approval comments, an earlier attempt's approval, changed candidates/policies and owner self-started runs/reruns are rejected. This supplements, rather than replaces, GitHub required reviewers.

Active exception scopes must be unique and consumed exactly once by a blocking inherited finding. Unused or reused active scopes fail closed. `metadata_sha256` binds severity, advertised fix, status, CVSS, references, title, description and scanner data source; changed advisory metadata requires renewed review even when package/version/CVE/digests match. Proposed records remain inactive.
