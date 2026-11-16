# Focused release-readiness assessment

Assessment date: 2026-11-16. Owner: Skulldorom/OpenHands-Agent-Image maintainers. Review by: 2026-12-16. No accepted exceptions. No live deployment authorization is implied.

## Evidence and provenance

The previous candidate `sha256:34200963b09a575bff0e8258f3728408abd3ebbf77d38e9a8fab24b30a8edc0c`, based on upstream `sha256:163c9d8b0d9ec48d4936d10ce9f109fc380a7a417d83a83c4ba4fe9a4a8efdcb`, reported 529 HIGH and one CRITICAL instance, four with module fixes advertised and 526 without fixes. These were HIGH/CRITICAL-only counts, not a complete all-severity inventory. PostgreSQL 17.12 and linux-libc-dev 6.12.117 resolved the previously available Debian fixes; no remaining PostgreSQL findings were reported.

Current CI produces unsuppressed all-severity scans of the candidate and **that build's exact upstream digest**, using the same Trivy version and frozen vulnerability database. The artifact contains a package/CVE comparison with installed/upstream/fixed versions, vendor statuses, descriptions, CVSS and references. Findings present upstream are inherited; findings absent upstream in an already-present package are distinguished from added packages/components. This classification concerns observed package/CVE presence, not an assertion that an upgraded package caused a vulnerability. Raw reports preserve layer ownership and full package/source metadata. Module and Debian fixes must not be conflated with released, compatible vendor binaries.

All Debian findings are joined to the official tracker by **source package**, not binary name. The full tracker snapshot and scanner database hash are retained. No `ignore-unfixed`, `.trivyignore`, VEX suppression, severity suppression or ignored secret is used. Release notes and attached evidence retain remaining risk, even if a future gate passes. Scanner or advisory retrieval errors fail CI.

## CVE-2026-6653: keep blocked

Official tracker: https://security-tracker.debian.org/tracker/CVE-2026-6653

Debian source/binary: `libxml2`. Installed trixie version: `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. Debian reverted the source to 2.9.14; the apparent 2.12.7 prefix does **not** prove it fixed. Trixie and trixie-security remain open/vulnerable. Trixie is marked `<no-dsa> (Minor issue)`. Forky/sid are resolved; Debian records first fixed unstable package `2.14.5+dfsg-0.1`, referencing upstream fix `463bbeeca1805b5c4828f50d0fefc4eebaf620df` (2.11.0). These other Debian releases are **not** permissible package sources for this image.

Debian describes a use-after-free in `xmlParseInternalSubset`, reached through crafted XML/internal subset/entity handling. Trivy's NVD-derived 9.8 critical score conflicts with Debian's minor assessment and Red Hat's 5.9 availability-impact vector. Neither disagreement nor lack of a DSA establishes non-exploitability. The general-purpose agent executes user tools and processes untrusted repositories/documents; browser libraries and XML consumers may load system libxml2. CI records package reverse dependencies and Chromium linkage. Python wheels can also bundle separate libxml2 builds; system-library remediation does not automatically cover them. An authenticated Agent Server API smoke test cannot prove no reachable XML parser path. There is no demonstrated direct unauthenticated Agent Server XML endpoint, but absence of that endpoint does not eliminate workload-level exposure.

No supported trixie fix was available at assessment. Do not mix releases, swap the shared library manually, or claim not affected based on version prefix. Keep blocked pending a supported fix or a CVE-specific, version-scoped reachability assessment accepted by the owner. No VEX assertion is warranted with the current evidence.

## Measured CI result (run 43860189443)

The gate ran on candidate `ghcr.io/skulldorom/openhands-agent@sha256:0cf30566615316d28fc88ad29d1cd7d07eb711e2949cdc3241c6e976352df4a5` (Debian 13.7) and its exact upstream build. Unsuppressed all-severity inventory: 1 CRITICAL, 529 HIGH, 797 MEDIUM, 1152 LOW, 38 UNKNOWN = 2517 findings; 28 advertise a fix, 2489 do not. Origins: 2466 inherited from upstream, 51 in added packages (locale/l10n and libxslt only; none HIGH or CRITICAL). 24 lower-severity rows advertise fixes in Node/Go components outside this repository's remediation scope and were already present upstream. Zero secrets. Removed upstream pairs (libxml2, linux-libc-dev, PostgreSQL) confirm the applied remediation where Debian has a fix.

The gate blocked with 7 vulnerability instances, and promotion plus `v1.0.0` creation were skipped:

| Package | CVE | Severity | Installed | Fixed | Binary |
| --- | --- | --- | --- | --- | --- |
| libxml2 | CVE-2026-6653 | CRITICAL | 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | none | OS package |
| golang.org/x/net | CVE-2026-78661 | HIGH | v0.61.0 | 0.62.0 | usr/bin/gh |
| golang.org/x/net | CVE-2026-78661 | HIGH | v0.60.0 | 0.62.0 | usr/bin/rootlesskit |
| golang.org/x/net | CVE-2026-78661 | HIGH | v0.60.0 | 0.62.0 | docker-compose plugin |
| github.com/moby/go-archive | CVE-2026-17106 | HIGH | v0.2.0 | 0.3.0 | docker-buildx plugin |
| github.com/docker/docker | CVE-2026-41567 | HIGH | v28.5.2 | none | docker-buildx plugin |
| github.com/docker/docker | CVE-2026-42306 | HIGH | v28.5.2 | none | docker-buildx plugin |

Consequently `v1.0.0` is **not published**, `latest` remains untouched and the package has no tags. Remediation requires an upstream base refresh that ships fixed vendor binaries or a supported trixie libxml2 fix; neither exists at assessment time.

## Supported vendor binaries

Official latest release tags and their go.mod were checked on 2026-11-16:

| Tool / supported release | CVE | Embedded module | Advertised fix | Decision |
| --- | --- | --- | --- | --- |
| [GitHub CLI 2.104.0](https://github.com/cli/cli/releases/tag/v2.104.0) | CVE-2026-78661 | golang.org/x/net v0.61.0 | v0.62.0 | Keep blocked; latest released tool still affected |
| [RootlessKit 3.3.0](https://github.com/rootless-containers/rootlesskit/releases/tag/v3.3.0), Docker rootless extras 29.9.3 | CVE-2026-78661 | golang.org/x/net v0.60.0 | v0.62.0 | Keep blocked; no supported fixed bundle demonstrated |
| [Compose 5.7.1](https://github.com/docker/compose/releases/tag/v5.7.1) | CVE-2026-78661 | golang.org/x/net v0.60.0 | v0.62.0 | Keep blocked; latest released tool still affected |
| [Buildx 0.39.0](https://github.com/docker/buildx/releases/tag/v0.39.0) | CVE-2026-17106 | github.com/moby/go-archive v0.2.0 | v0.3.0 | Keep blocked; latest released tool still affected |
| Buildx 0.39.0 | CVE-2026-41567, CVE-2026-42306 | github.com/docker/docker v28.5.2+incompatible | none advertised | Explicit blockers; daemon-side paths, no daemon shipped, still not cleared without reviewed evidence |

Both docker/docker CVEs describe daemon operations (archive upload into a container, docker cp mount setup) fixed in Engine 29.5.1. This image starts no daemon; rootless extras is 29.9.3. That argues against reachability but does not by itself justify clearing an embedded vulnerable module, so both remain designated blockers pending a reviewed CVE-scoped decision.

Buildx already uses x/net v0.62.0; Compose already uses go-archive v0.3.3. Replacing those tools would not fix the other tool's module. Vendor source evidence: `https://raw.githubusercontent.com/<repository>/<release>/go.mod` at the above tags. Earlier downloaded vendor packages' embedded module metadata agrees with these manifests; CI scans the actual candidate binaries. A dependency manifest is supporting evidence, not a substitute for scanning the binary.

On 2026-11-16 the published release artifacts for those four tags were also downloaded and inspected read-only, without executing them, to test the assumption that a newer vendor release fixes each blocker. Embedded Go module build information:

| Downloaded artifact | Embedded module | Fixed module satisfied? |
| --- | --- | --- |
| `gh_2.104.0_linux_amd64/bin/gh` (GitHub CLI, latest release) | `golang.org/x/net` v0.61.0 | No; still v0.61.0 |
| `rootlesskit` v3.3.0 (RootlessKit, latest release) | `golang.org/x/net` v0.60.0 | No; still v0.60.0 |
| `docker-compose-linux-x86_64` v5.7.1 (Compose, latest release) | `golang.org/x/net` v0.60.0, `github.com/moby/go-archive` v0.3.3 | x/net not fixed; go-archive clean |
| `buildx-v0.39.0.linux-amd64` (Buildx, latest release) | `github.com/moby/go-archive` v0.2.0, `github.com/docker/docker` v28.5.2+incompatible, `golang.org/x/net` v0.62.0 | go-archive and docker not fixed; x/net clean |

Every blocker is confirmed still present in the newest released vendor artifact of the affected tool, so no supported drop-in upgrade exists. This inspection cannot by itself prove exploitability or non-exploitability; it only establishes that upgrading the installed vendor packages would not change these findings. `CVE-2026-6653` remains unaffected by this check because it is an OS package with no supported trixie fix.

The upstream trixie image configured Docker's **bookworm** vendor channel. Docker officially supports [Debian trixie](https://docs.docker.com/engine/install/debian/). This repository aligns only that vendor suite to trixie using the inherited signing key and signed APT metadata; no Debian release mixing, key replacement, custom build or downgrade. Both vendor suites currently offer Buildx 0.39.0, Compose 5.7.1 and Docker/rootless extras 29.9.3. Channel alignment is correctness/support remediation, not a claim to fix the embedded Go CVEs. CI verifies tool startup/version commands and Agent Server 1.62.0; no host Docker daemon or Docker-in-Docker is required or started. Full Docker engine workload compatibility is not established by version checks alone.

HTTP/network parser flaws can affect tools processing remote data; archive flaws can affect untrusted build contexts. Merely not starting a Docker daemon does not prove client/plugin code unreachable. No custom source rebuild, latest-branch binary, removal of functionality, or unsupported module replacement is accepted.

## Inventory versus gate

`security/policy.json` specifies owner, review date and designated CVEs. Every CRITICAL finding blocks pending review; all HIGH/CRITICAL findings with advertised fixes block conservatively, including module-only fixes until supported binaries are verified. Designated high-risk findings block even without fixes. Any HIGH/CRITICAL finding that this image introduces — a new finding in an inherited package or a finding in a package this Dockerfile adds — blocks regardless of fix availability, because it has no upstream baseline to defer to. All secrets block at every severity. Unfixed HIGH findings inherited from the upstream image and outside those categories remain explicitly unresolved inventory risks, not CVE exceptions or a declaration of safety. This does not grant a future exemption to CVE-2026-6653 or any newly reported CRITICAL finding.

No exceptions are accepted. The evaluator rejects nonempty exception lists until a separately reviewed narrow mechanism is implemented. Any future exception must have exact CVE/package/version scope, reason, owner, review date and evidence. No blanket unfixed or vendor-wide exemption is allowed. The initial release remains blocked while the above designated findings persist.

The release publisher rechecks that the successful assessment identifies the exact tested candidate and upstream digests. It promotes the existing attested index without rebuilding. A failed scan, test, policy review or risk gate leaves `latest` unchanged and prevents `v1.0.0` creation.

_This assessment was prepared by an AI agent (OpenHands) on behalf of the repository owner._
