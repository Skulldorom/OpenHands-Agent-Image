# Security and release policy

## Official upstream baseline

This image extends `ghcr.io/openhands/agent-server`. The official exact upstream digest is our security baseline. We report all inherited vulnerabilities without pretending they are fixed, unreachable or harmless. Unchanged inherited HIGH/CRITICAL vulnerabilities do not automatically prevent release, whether or not a fix is advertised. There are no ordinary inherited-risk exception records, approval renewals or per-CVE expiry matches.

The audit stays enabled. A passing customization comparison is not a claim that the image is vulnerability-free or universally safe. Operators still need to assess whether official OpenHands is suitable for their workloads. Compatible upstream updates are monitored daily and bring upstream security improvements automatically. New Agent Server versions require explicit runtime-contract compatibility review; currently only 1.62.0 is approved.

## Mandatory release gates

Publication requires all of the following:

- Complete unsuppressed UNKNOWN through CRITICAL scans of the exact candidate and exact upstream base with Trivy 0.69.3 and one frozen database. No ignore-unfixed or directory/severity suppression.
- No HIGH/CRITICAL vulnerability added by our image relative to that base. Comparison binds CVE, package, installed version, affected target, result class/type and severity. A CVE in one upstream binary never authorizes the same CVE in a custom-added binary.
- No materially worsened inherited vulnerability. Increased severity blocks. Any changed version that remains vulnerable to the same CVE in the same target is conservatively treated as potential worsening, even at lower severity; we do not guess version ordering across Debian, Go and other ecosystems. Remediate the changed vulnerable component; if vulnerability disappears, it is reported removed. Same-version severity reductions remain visible as improvements.
- No detected credential or secret material, including upstream layers, until classification resolves the detection. Full saved-layer inspection catches material hidden by later deletion/whiteouts. The existing PEM payload classification excludes only format constants without key material, with adversarial tests; it does not ignore caches or directories. One exact upstream Copilot installation-token-shaped fingerprint is classified non-live using authenticated immutable-layer age evidence plus GitHub’s one-hour installation-token lifetime. Its authenticity is unknown; it is not described as a fake placeholder. The classification is logged and attached, and never exempts other matches in that file. All other keys/tokens remain blocking; see the credential investigation.
- No match against an explicitly reviewed emergency block, at any severity.
- Passing Git identity, PostgreSQL initialization/query/backup/restore, Agent Server readiness/API/entrypoint/signals and metadata/compatibility tests.
- Verified original signed build provenance, exact source/base/image binding, signed same-run functional evidence, sealed artifact hashes, fresh scans (24-hour limit), current policy fingerprints and current main/upstream identity. Missing, failed, incomplete, stale, suppressed or unverifiable evidence blocks publication.

Functional build success never authorizes publication on its own. Main pushes and manual dispatch always build a fresh candidate; scheduled checks reuse only provenance-verified candidates when image inputs are unchanged. Every selected candidate gets fresh complete validation and security assessment. The security policy change itself therefore requires a fresh assessment. PRs never publish production images.

## Emergency denylist

`security/policy.json` has schema 2 and a small `emergency_blocks` list, initially empty. Each record requires an exact `cve`, a meaningful `reason`, `reviewed_by`, `reviewed_at` (ISO date, not future-dated) and an HTTPS `evidence_url` linking the review/advisory. Reviewed policy changes add/remove emergency blocks; automation does not create them from severity counts. Duplicate/malformed records and obsolete acceptance fields fail closed. A matching vulnerability cannot be waived by inheritance or ordinary exception records.

The five former `high_risk_cves` entries were reviewed for migration:

| Former CVE | Recorded rationale | Migration decision |
| --- | --- | --- |
| CVE-2026-6653 | General XML exposure; unreachability not proven | Report inherited risk; no documented emergency prohibition |
| CVE-2026-78661 | Network tools affected; vendor binary still vulnerable | Report inherited risk; no documented emergency prohibition |
| CVE-2026-17106 | Potential archive/build-input exposure | Report inherited risk; no documented emergency prohibition |
| CVE-2026-41567 | Embedded Docker code; unreachability not proven | Report inherited risk; no documented emergency prohibition |
| CVE-2026-42306 | Embedded Docker code; unreachability not proven | Report inherited risk; no documented emergency prohibition |

Those rationales describe potential upstream exposure and absent remediation, rather than a separately documented emergency/incident prohibition. They are retired as automatic inherited blockers under the owner’s requested baseline policy. Their findings stay in complete reports. This is not an exploitability or safety finding; future documented evidence can justify explicit emergency blocks.

## Reporting and upstream changes

CI summaries and release notes distinguish **Custom image security: PASS/FAIL** from **Inherited upstream security: reported, not automatically blocked**. The separate release gate can still fail an emergency block when the customization comparison passes.

Every report includes both image digests, upstream/candidate severity totals, inherited-unchanged/introduced/removed/materially-worsened counts, introduced HIGH/CRITICAL findings, emergency matches and detected secrets. Complete raw Trivy reports, scanner identity, frozen database/hash, comparison, policy, source/build/test evidence and baseline descriptor are attached to immutable release evidence. A new reassessment appends its own content-addressed archive and never overwrites the original approval or release source.

The previous approved release’s original approval archive is checked against its immutable SHA-256 commitment to identify the previous official upstream digest. That previous digest is rescanned with the same scanner/database as both current images. New upstream findings are highlighted independently of custom additions; they do not become custom blockers solely because they appeared upstream. Database disclosures common to both upstream versions are not mislabeled image regressions. The first release explicitly reports that a previous approved baseline is unavailable, rather than claiming zero new upstream risks. Missing baseline evidence or scan failures block; a concurrent baseline change requires reassessment.

Initial release remains v1.0.0, later releases default to patch, explicit version bumps remain available, and byte-identical images reuse the existing release unless explicitly bumped. Immutable tags, latest ownership, pending-publication recovery and rollback remain enforced. A pending reserved digest must be recovered before a different candidate publishes; superseded pending upstream/content requires maintainer review. Production GitHub/GHCR publication and recovery remain untested end to end.

## Historical assessments

[HIGH/CRITICAL inventory](security/HIGH-CRITICAL.md), [priority assessment](security/PRIORITY-ASSESSMENT.md), the inactive `security/proposed-acceptances.json`, [credential investigation](security/CREDENTIAL-LAYER-INVESTIGATION.md) and [Compose verification](security/COMPOSE-VERIFICATION.md) retain historical evidence. Old blanket-block decisions and acceptance proposals are historical, have no active publication role, and are superseded by schema 2. The recorded comparison had 530 inherited HIGH/CRITICAL instances, zero introduced HIGH/CRITICAL and zero detected secrets; CI reassesses authenticated scans and also collects fresh audit evidence. Historical scans never substitute for fresh production evidence.

Report security issues privately to the repository maintainer. Do not put credentials or customer data in public issues.

## Operator-only exposure verification

Run these **separately on the Docker host**, not inside a conversation runtime.
They are read-only; do not send raw container environment values, config files,
logs or credential contents to a public issue. Set `CID` to one actual conversation
container, not the OpenHands control-plane container. Repeat for each runtime
profile; absence of exposure in one container does not establish host policy.

```bash
CID='<conversation-container-id>'
docker inspect "$CID" | jq '.[0] | {
  Id, Image,
  runtime: (.HostConfig | {Privileged, CapAdd, CapDrop, SecurityOpt,
    ReadonlyRootfs, NetworkMode, PidMode, IpcMode, Devices}),
  mounts: [.Mounts[] | {Type, Source, Destination, RW, Propagation}],
  environment_names: [.Config.Env[]? | split("=")[0]],
  ports: .NetworkSettings.Ports,
  networks: (.NetworkSettings.Networks | keys)
}'
docker exec "$CID" sh -c '
  id
  grep -E "^(Cap|NoNewPrivs|Seccomp)" /proc/1/status
  cat /proc/1/mountinfo
  for p in /var/run/docker.sock /run/docker.sock; do
    if test -S "$p"; then stat -c "%a %u:%g %n" "$p"; fi
  done
  for v in DOCKER_HOST DOCKER_CONTEXT; do
    if printenv "$v" >/dev/null; then printf "%s is set; inspect privately\n" "$v"; fi
  done
  cat /proc/net/route
'
docker network ls
docker info --format '{{json .SecurityOptions}}'
# Host firewall inspection; privilege may be necessary, no rules are changed.
sudo nft list ruleset
sudo iptables -S DOCKER-USER
```

Inspect custom socket mounts, TCP daemon exposure and Docker contexts privately;
a missing default socket alone does not exclude daemon access. For each network
from the inspect output, run `docker network inspect '<network>'` and check
`Internal`, gateway and connected peers. Routes alone do not prove unrestricted
or restricted egress: inspect the host firewall, Proxmox firewall, proxy and
provider policy, including IPv6. Do not probe a daemon or external host without
permission. Review the actual container-creation configuration for forbidden
mounts, privileged profiles and capability escalation; observation alone does
not enforce policy.

Mounts, UID/capabilities, read-only rootfs and filesystem permissions determine
filesystem exposure. Review secret *names* and privately review their injection,
rotation and scope; do not print values. General-purpose shell/file/browser tools
can process untrusted XML, HTML and archives. No host setting proves these
parsers unreachable unless workload/tool restrictions are also enforced and
reviewed. Record the runtime image digest and profile with each decision.

Recommended controls pending review: no host Docker socket or daemon credentials,
no privileged execution or host namespaces, no sensitive host mounts, drop
unneeded capabilities, enforce seccomp/AppArmor, least-privilege ephemeral
credentials, restrict egress and isolate untrusted workloads. These are proposed
controls, not observations about the live LXC. Inherited risk remains the operator’s responsibility; it is reported without requiring per-CVE approval.

## Isolated publication integration prerequisites

`tests/hosted-publication.py --self-test` performs offline safety checks only.
The real harness requires an existing, empty, non-fork repository named
`OWNER/publication-integration-NAME`, with an initial commit and description
containing `[publication-integration-only]`. It uses a unique package under
`ghcr.io/OWNER/publication-integration-NAME-UUID` and only an
`integration-latest-UUID` alias. A non-deployable, zero-layer OCI fixture exercises
the real publisher; it is **not** security authorization for a deployable image.

Use only the sandbox repository's scoped `GITHUB_TOKEN`, with job-level
`contents: write` and `packages: write`. No PAT or repository secret is required.
Copy the five files listed in [the minimal setup](security/PUBLICATION-TEST-SETUP.md)
to that dedicated repository's `main`; no production workflow is needed. The
sandbox Environment can be unprotected and empty, and GitHub creates it when
referenced if it does not exist, subject to account policy. Source-repository
runs are excluded by repository/input guards; test packages link to the sandbox.
No production `latest` tag is used. Actual hosted publication remains unverified
until that sandbox is created and the harness passes there.

The harness interrupts after assets persist, retries twice, checks unchanged
asset IDs/bytes and original release body, appends a distinct reassessment,
checks immutable tags and the test alias, and rejects an older version after a
new reservation. Cleanup is opt-in after success and deletes only recorded IDs
whose identity still matches; failures retain the ledger and evidence. Never
point it at the production repository/package, even for cleanup.
