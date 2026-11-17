# Security and release policy

Current work: [credential-layer investigation](security/CREDENTIAL-LAYER-INVESTIGATION.md), [complete grouped HIGH/CRITICAL inventory](security/HIGH-CRITICAL.md), [prioritized reachability assessment](security/PRIORITY-ASSESSMENT.md), and [isolated publication test setup](security/PUBLICATION-TEST-SETUP.md). The Node-cache marker was a false positive; real PEM payloads and tokens remain blocking. Hosted publication is still unverified and the fresh security assessment still blocks 530 instances. The Compose 5.7.1 binary evidence is explicitly superseded by release 5.7.2; remediation remains undetermined because current binary integrity verification has not passed.

## Mandatory gates

Scan exact upstream and candidate with Trivy 0.69.3 and one frozen database. Preserve complete unsuppressed UNKNOWN through CRITICAL results; no severity suppression or ignore-unfixed exclusions. Publication requires successful real functional tests, signed build/test provenance, exact candidate/base/source binding, sealed same-run artifacts, current policy fingerprints and scans no older than 24 hours. Missing, inconsistent, expired or failed evidence blocks.

Always block secrets (including upstream), introduced HIGH/CRITICAL findings, unsupported runtime contracts and explicitly unacceptable CVEs in `high_risk_cves`. Inherited HIGH/CRITICAL findings require reviewed individual acceptance even without an advertised fix. Lower severity findings remain visible; explicitly unacceptable CVEs block at any severity. A policy designation cannot be overridden by an acceptance.

## Equivalent inherited-risk acceptance

`security/policy.json` contains active `exceptions` and allowed approvers. They are empty. Seven records in `security/proposed-acceptances.json` remain proposed, not authorized. Approval must come from the responsible maintainer through reviewed policy changes, never from automation. No recurring per-candidate approval is required after acceptable policy is established.

Each acceptance binds exact CVE, package/module, installed version, binary/filesystem target, result class/type, official upstream origin, advisory metadata hash, justification, exposure assumptions, compensating controls, responsible approver, approval date and expiry. OS scope `os` represents the scanned Debian root filesystem, not a mutable image reference. The metadata fingerprint covers severity, fixed version, status, CVSS, references, title, description and advisory source.

Equivalent risk can survive upstream digest changes only after rescanning both exact images and demonstrating the same inherited finding, version, target, metadata and exposure assumptions. Changed advisory evidence, severity, available fix, target, installed version or assumptions requires reassessment. Duplicate, unused, unapproved, expired or mismatched active records fail closed. Accepted findings retain all original reasons and appear in complete reports and release notes. Acceptance does not mean safe or fixed.

## Initial unresolved review

Historical evidence run `43876785488` identifies seven proposed instances, all still unapproved:

| CVE | Package/version | Target |
| --- | --- | --- |
| CVE-2026-6653 | libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Debian root filesystem |
| CVE-2026-78661 | golang.org/x/net v0.61.0 | usr/bin/gh |
| CVE-2026-78661 | golang.org/x/net v0.60.0 | usr/bin/rootlesskit |
| CVE-2026-41567 | github.com/docker/docker v28.5.2+incompatible | usr/libexec/docker/cli-plugins/docker-buildx |
| CVE-2026-42306 | github.com/docker/docker v28.5.2+incompatible | usr/libexec/docker/cli-plugins/docker-buildx |
| CVE-2026-17106 | github.com/moby/go-archive v0.2.0 | usr/libexec/docker/cli-plugins/docker-buildx |
| CVE-2026-78661 | golang.org/x/net v0.60.0 | usr/libexec/docker/cli-plugins/docker-compose |

These CVEs remain explicitly unacceptable. They need supported remediation or a separately reviewed policy decision changing that designation, with current evidence and justified exact acceptance. Reassessment of the authenticated historical scans under this stricter policy reports **530 blocking finding instances**, zero introduced HIGH/CRITICAL findings and zero detected secrets. All 530 inherited instances require remediation or individual review, not just the seven proposals. The CI artifact retains their complete package/version/target/advisory inventory. Historical reports are not a current vulnerability inventory. `v1.0.0` is not authorized by this PR.

Controls such as trusted workloads, network isolation, credential minimization, no Docker socket and no privileged containers depend on host/operator enforcement. This public image cannot enforce them. No deployment configuration or exploitability exclusion is claimed. Report security issues privately to the repository maintainer; do not include credentials or customer data in public issues.

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
controls, not observations about the live LXC. All remaining inherited HIGH
findings are insufficiently assessed for acceptance until their exact current
package/version/target and reachable functions have been reviewed. No additional
risk acceptance is activated by this remediation.

## Isolated publication integration prerequisites

`tests/hosted-publication.py --self-test` performs offline safety checks only.
The real harness requires an existing, empty, non-fork repository named
`OWNER/publication-integration-NAME`, with an initial commit and description
containing `[publication-integration-only]`. It uses a unique package under
`ghcr.io/OWNER/publication-integration-NAME-UUID` and only an
`integration-latest-UUID` alias. A non-deployable, zero-layer OCI fixture exercises
the real publisher; it is **not** security authorization for a deployable image.

Configure `PUBLICATION_INTEGRATION_TOKEN` in the protected
`publication-integration` environment with repository contents and GHCR package
read/write permissions; optional cleanup also needs package-version deletion.
The currently available token reports `read:org, read:user, repo, workflow`, not
package scopes, and no isolated repository was found. Real publication therefore
remains unverified. The dispatch-only workflow intentionally runs on `main` only;
before merge a maintainer may execute the harness from the audited PR checkout
on a separate Docker-enabled runner with the same isolation requirements. Do
not grant the PR production release credentials or change its trigger to obtain
this test.

The harness interrupts after assets persist, retries twice, checks unchanged
asset IDs/bytes and original release body, appends a distinct reassessment,
checks immutable tags and the test alias, and rejects an older version after a
new reservation. Cleanup is opt-in after success and deletes only recorded IDs
whose identity still matches; failures retain the ledger and evidence. Never
point it at the production repository/package, even for cleanup.

## Fresh exact-candidate audit — 2026-11-17

Run: https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44052745185
at code `da349ebdc51c8d666feb6eb5869b001be4e55243`.
Candidate `sha256:0e8e24ac5258ae9d709886fc3298cb1f028b25146e4c01389056c1fa762e81a0`;
actual upstream `sha256:e74009d51a352c3e9e8db30a788b15683de060c0b2f9e71e0b9d19576034c995`.
Both were rescanned unsuppressed with the same frozen database.
Artifact `14314048804`, digest
`sha256:d4dbfae5025927a2a48445b80b5415739b9c01edba73974f662cc8cb8de34fed`,
retains raw reports, scanner/database identity, Debian tracker and complete
per-package/target assessment.

Current inventory: **2,512 finding instances, 1,040 distinct CVEs**:
1 CRITICAL, 529 HIGH, 794 MEDIUM, 1,152 LOW, 36 UNKNOWN.
2,461 inherited instances; 51 added-package instances, none HIGH/CRITICAL.
Zero introduced HIGH/CRITICAL; zero Trivy-detected secrets. There are 21 instances
with an advertised fix; module fixes are not proof of an available supported
binary. All 530 HIGH/CRITICAL instances block. This supersedes historical counts,
not the original approval evidence. The scan workflow succeeded in collecting
evidence; the **security gate did not pass**.

Separately, run
https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44052745007
passed policy/regressions and Docker functional checks (Git identity, PostgreSQL
17 initialization/query/backup/restore, Agent Server API/readiness/signals), but
**failed** image-layer inspection: a credential-like pattern was found in layer 7
at `tmp/node-compile-cache/v24.22.2-x64-964aae3f-0/0c92995d`.
This has not been classified as a real credential or a false positive. No matched
value is disclosed here. Trivy detecting zero secrets does not clear this separate
finding. Keep the layer check blocking; privately inspect the exact matched bytes
and provenance before deciding whether upstream remediation or a narrowly
justified detector correction is appropriate. Do not merely delete the file in a
later layer: earlier bytes remain recoverable. Merge readiness is blocked by this
unresolved check; release eligibility is independently blocked by the security
baseline. The isolated hosted publisher remains unverified for the prerequisites
above. No production release or live LXC change occurred.
