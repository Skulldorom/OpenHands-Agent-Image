# Security policy

Only the newest successful release on the approved Agent Server version is maintained. Digest/version pins remain available for rollback but never receive fixes in place.

Report vulnerabilities privately through GitHub Security Advisories. If private reporting is unavailable, contact the repository owner without posting exploit details or secrets publicly. Never attach credentials, private keys, personal data or complete environment dumps.

CI gates releases with vulnerability and secret scanning. Complete inventories retain every severity and unfixed finding without scanner suppressions. A separate risk gate blocks all CRITICAL findings, HIGH/CRITICAL findings with advertised fixes (conservatively including module fixes pending supported binary verification), HIGH/CRITICAL findings this image introduces relative to its exact upstream base, and explicitly designated high-risk CVEs regardless of fix availability. Unfixed HIGH findings inherited from upstream remain visible as unresolved risks, not claims of safety or accepted CVE exceptions. There are currently **no accepted exceptions**, VEX not-affected assertions, or ignore entries. The machine-readable policy is `security/policy.json`; its owner and review deadline are enforced. A new exception must identify CVE, exact package/version scope, reason, owner, review deadline and evidence and implement reviewed narrow matching; the current gate rejects all exception entries. Inspect inherited upstream risks and reports. A passing scan is not proof of security: database coverage, detection limits and later disclosures still require review.

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
