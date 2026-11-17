# Security and release policy

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
