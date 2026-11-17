# Release risk assessment — 2026-11-17

> Historical assessment. Blanket inherited-risk blocking and approval proposals below are superseded by the current [upstream-baseline policy](../SECURITY.md). Findings remain evidence, not current release decisions.


No acceptance is activated. Initial production release remains blocked. This document supersedes the release-readiness conclusions in the older `ASSESSMENT.md`; the older assessment is retained for its historical evidence, not as a current authorization or supported-version claim.

## Exact evidence and limits

Fresh, unsuppressed inventory and compiled-binary inspection: [Actions run 44082258745](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44082258745), artifact `14327198572`. Candidate `sha256:0e8e24ac5258ae9d709886fc3298cb1f028b25146e4c01389056c1fa762e81a0`; its actual upstream `sha256:e74009d51a352c3e9e8db30a788b15683de060c0b2f9e71e0b9d19576034c995`. Both Trivy scans use the same frozen database, with no suppressions. The retained scanner database and Debian tracker are part of the artifact. `HIGH-CRITICAL.json` binds its grouping to the raw assessment's SHA-256; `.md` contains the complete 252-CVE table. `REACHABILITY-EVIDENCE.json` records binary hashes, scan hashes, exact advisory scopes and observed symbol/package/module levels.

There are 530 HIGH/CRITICAL instances: one CRITICAL and 529 HIGH, 252 distinct CVEs, 27 source components/modules. All are inherited in this exact candidate; none introduced by the repository's added packages. Four HIGH instances advertise module fixes. The seven earlier proposed records do not cover the other 523 instances and their old metadata fingerprints are not approval of a fresh assessment. Active policy has zero exceptions and still blocks all 530.

The PR's Docker integration also builds a **different**, explicitly pinned upstream digest (`6a0fe474...` in Dockerfile). Layer investigation and functional tests for that local build do not convert the retained candidate's scan into security approval for a different image. Release eligibility must always be assessed against the exact tested and scanned publication candidate. No current image was published for this work.

## Prioritized components

| Component | Instances | Distinct CVEs in component | Assessment and supported remediation |
| --- | ---: | ---: | --- |
| Chromium | 346 | 173 | Browser functionality is present and enabled by general agent workloads. No unreachability assertion; remote pages and documents are potentially attacker controlled. No fixed trixie versions advertised in this inventory. A browser-disable setting in one smoke test does not restrict future agents. Keep blocked pending fixed supported upstream packages or separate enforced workload restrictions and per-CVE review. |
| krb5 | 56 | 14 | Multiple binaries/libraries repeat CVEs; package presence is not 56 distinct flaws. Kerberos paths depend on authentication mechanisms and service use. Not proven unreachable. |
| util-linux | 36 | 4 | Privileged mount/helpers and local execution paths require per-CVE capability/setuid analysis. Do not infer safety from the conversation user alone. |
| linux headers | 18 | 18 | Findings are in `linux-libc-dev`, not an image-supplied running kernel. Header-only negative runtime evidence is collected separately. Host-kernel vulnerability status remains unknown and must be checked independently; these records are not evidence of an exploitable container kernel. |
| systemd | 9 | 1 | Agent entrypoint is not systemd, but that alone does not establish absence of affected library/function use. |
| libxml2 | 8 | 8 | See below. Affected XML consumers remain plausible. No supported trixie fix advertised in the recorded tracker. Do not mix Debian releases or replace the shared library ad hoc. |
| gnupg2 | 7 | 1 | Agent Git/signature workflows may invoke GnuPG. Untrusted key/message paths need individual analysis. |
| curl | 6 | 2 | Agents retrieve remote resources; keep potentially reachable. |
| git | 6 | 3 | Untrusted repository handling is a core workload; keep potentially reachable. |
| expat | 4 | 4 | XML consumers require actual caller/input analysis; no unreachability established. |
| ncurses | 4 | 1 | Terminal/local paths; no runtime denial-of-service claim cleared. |
| perl | 4 | 1 | Interpreter can execute agent tools; no call-path restriction enforced. |
| sqlite3 | 3 | 3 | Database/parser inputs may be workload controlled. |
| libx11 | 3 | 1 | Chromium/X11 consumer paths need targeted analysis. |
| golang.org/x/net | 3 | 1 | Specific HTML parser flaw, not generic socket/HTTP networking. Two binary-negative candidates below; GitHub CLI has affected functions. |
| cups, tiff, libxi, wget | 2 each | 2 each | Printing, image parsing, X11 and retrieval paths; distinct CVE rows retained. No absence or fix claim based solely on package presence. |
| Docker module in Buildx | 2 | 2 | Daemon-specific symbols absent in exact Buildx binary inspection; scoped review candidate below. No statement about any external daemon. |
| acl, libsndfile, libxrender, libxtst, sudo, xdg-utils | 1 each | 1 each | Local privileges and media/desktop consumers require CVE-specific review. Keep blocked; no broad unfixed waiver. |
| go-archive in Buildx | 1 | 1 | Archive extraction flaw; binary advisory lacks symbol scope, so module-only scan does not prove unreachability. Keep blocked. |

The full per-CVE grouping preserves versions, affected packages, targets, tracker statuses, advertised fixes and metadata fingerprints. The unresolved rows above are deliberately not represented as completed exploitability reviews. Completing those reviews requires consumer/call-path and enforced-deployment evidence; the inventory alone cannot supply it.

## libxml2: eight separate findings

Installed: `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. The `really2.9.14` portion matters; the leading 2.12.7 does not establish the upstream fix.

| CVE | Affected functionality | Reachability conclusion |
| --- | --- | --- |
| CVE-2026-6653 | Internal subset/entity parser use-after-free | Potentially reachable through XML documents; CRITICAL remains an explicit blocker. Debian's minor/no-DSA classification does not mean fixed. |
| CVE-2026-74860 | Python libxml2 SAX attribute declaration callback double-free | Needs proof of binding absence and no other affected callback consumer before an unreachability claim. No blanket libxml2 acceptance. |
| CVE-2026-86138 | `xmlDictAddQString` integer/heap overflow | XML parser consumers may invoke it; unresolved. |
| CVE-2026-86139 | `xmlURIEscapeStr` integer overflow | URI escaping consumer/input analysis missing. |
| CVE-2026-86140 | `xmlSnprintfElements` stack overflow | DTD/content-model consumer analysis missing. |
| CVE-2026-86142 | `xmlXPtrEval` XPointer length saturation | XPointer execution needs targeted caller analysis. |
| CVE-2026-86143 | Write-callback integer overflow | Serializer/output consumer analysis missing. |
| CVE-2026-86144 | Parse-option propagation | Potential SSRF/disclosure/DoS; network restrictions reduce consequences but do not establish absence. |

[Debian's current CVE-2026-6653 tracker](https://security-tracker.debian.org/tracker/CVE-2026-6653) still lists trixie vulnerable; forky/sid fixes are not supported trixie package sources. Core XML findings cannot reasonably be accepted for arbitrary untrusted agent workloads based on the evidence here. XML/DTD/network restrictions would have to be enforced, not just requested in an agent prompt.

## Go: compiled evidence rather than module-name assumptions

`govulncheck v1.1.4 -mode=binary -json` inspected the four copied binaries without executing them. Each report records symbol scan level, Go `go1.27.4`, advisory data and actual binary hash. Positive HTML parser hits in `gh`, plus other package/symbol hits in Compose and Buildx, establish that the inspection recovered compiled symbols rather than only module build metadata. Binary analysis cannot recover a precise dynamic call graph and does not assess arbitrary subsequently downloaded executables.

[CVE-2026-78661 / GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860) affects `golang.org/x/net/html` parsing before 0.62.0. The vulnerable functionality coalesces adjacent text nodes with quadratic allocation/copy cost. Using `x/net` for other protocols is not itself this vulnerability.

| Binary / module | Binary observation | Decision |
| --- | --- | --- |
| `gh` 2.104.0, x/net 0.61.0 | Module, HTML package and affected `Parse`, `ParseWithOptions`, `ParseFragment`, `ParseFragmentWithOptions` functions present | Potentially reachable. Remote/Markdown content can be untrusted. Keep blocked; release v2.104.0 is still current and has no fixed module. |
| RootlessKit 3.3.0, x/net 0.60.0 | Module-only finding; no affected HTML package/symbol hit in symbol-level scan | Evidence supports a narrowly bounded not-linked review for this exact binary, not an assertion that all RootlessKit/networking risks are absent. |
| Compose 5.7.1, x/net 0.60.0 | Module-only finding; no affected HTML package/symbol hit, while unrelated compression functions are detected | Same narrow review opportunity. The official 5.7.2 binary is now verified and still embeds x/net 0.60.0; it supplies no fix for this finding. The negative reachability evidence here remains scoped to the exact installed 5.7.1 binary, not automatically to a replacement. |
| Buildx 0.39.0, Docker module 28.5.2 | GO-2026-5617 (`Daemon.openContainerFS`) and GO-2026-5746 (`Daemon.containerExtractToDir`) are module-only, no affected daemon package/symbol hit | Supports absence of these specific daemon paths in this executable. It says nothing about a host/remote Docker daemon or the agent's permissions. |
| Buildx 0.39.0, go-archive 0.2.0 | GO-2026-6253 module finding; advisory has no affected import/symbol list | Unreachability is not established. The [vendor advisory](https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h) covers extraction routines that can write outside the destination. Keep blocked; fixed module 0.3.0 exists, latest Buildx vendor release still embeds 0.2.0. |

The Compose vendor verification blocker is **resolved**. The old command omitted `--location`: GitHub returned HTTP 302 and zero bytes, rather than an invalid Compose binary. [Hosted run 44096333206](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44096333206) reproduced that behavior and then verified both the binary and separate official checksum asset after one HTTPS redirect. The existing expected binary checksum was correct and unchanged. See [the full transport, pin, size and regression evidence](COMPOSE-VERIFICATION.md).

Latest supported vendor releases were rechecked on 2026-11-17: GitHub CLI 2.104.0, RootlessKit 3.3.0, Buildx 0.39.0 and Compose **5.7.2**. Verified Compose module build information reports `github.com/docker/compose/v5 v5.7.2`, `golang.org/x/net v0.60.0` and `github.com/moby/go-archive v0.3.3`. Thus upgrading to this official Compose release would not fix CVE-2026-78661. `vendor-evidence.json` now records the inspected 5.7.2 binary/hash and current source evidence. A later, unverified vendor release still makes the evaluator return undetermined; the fail-closed regression remains.

The candidate's installed Compose version is unchanged. Successful vendor verification and successful audit evidence collection do **not** waive the 530 inherited HIGH/CRITICAL instances. All seven proposed acceptances remain inactive and all explicit high-risk designations remain blocking.

Engine 29.5.1 is the vendor fix for the two daemon CVEs. Upgrading an external daemon to a supported fixed version is a separate host task; replacing a client module or observing no daemon inside this image cannot verify the host. Do not infer socket mounts, daemon version or privileges from this CI runner.

## Narrow, inactive review proposals

All seven CVEs remain explicitly unacceptable under active `high_risk_cves`; even an approved exception cannot override that designation. Any change would require a separate owner-reviewed policy decision. Only these four of the seven original instances currently have evidence supporting a reasonable short review period. **No approval is granted and security/proposed-acceptances.json is not activated.** Review and expire by **2026-11-24**, or immediately when the binary, candidate, module metadata, advisory scope or workload changes; re-scan on each change.

| Exact candidate scope | CVE / module version / target | Binary SHA-256 |
| --- | --- | --- |
| `0e8e24ac...` above | CVE-2026-78661 / x/net v0.60.0 / `usr/bin/rootlesskit` | `2303f00cd210f3824b4509741758b8de07bde4e5b768250c56d3edc38f7b967b` |
| Same exact candidate | CVE-2026-78661 / x/net v0.60.0 / `usr/libexec/docker/cli-plugins/docker-compose` | `af426722a8af5de812fcee30cc1c39f0639f5f723cbadefb25e5d4db054064cf` |
| Same exact candidate | CVE-2026-41567 / docker v28.5.2+incompatible / `usr/libexec/docker/cli-plugins/docker-buildx` | `54318328408fc650ba619992a0f49a2f712975e1110c805d1b225fdbac3126a2` |
| Same exact candidate | CVE-2026-42306 / same module/version/target | Same exact Buildx SHA-256 |

Justification is **absence of advisory-scoped compiled functionality in the inspected binary**, not lack of fixes, inheritance or trusted-input promises. These are documentary proposals only. The current acceptance schema binds version/target/advisory metadata; it does not independently enforce the extra binary SHA scope written here. Do not translate these proposals into an active policy record without reviewing that binding limitation. A genuine not-affected determination may be more appropriate than accepting exploitable risk, but also requires owner review and exact-artifact evidence.

The other original proposals (libxml2 CRITICAL, GitHub CLI HTML parser, Buildx archive extraction) are not supported by negative reachability evidence. Environmental restrictions alone are not a defensible general-purpose agent release policy. Even accepting the four scoped candidates would leave **526 blocking instances**. Header-only findings may support further per-CVE reviews after file-ownership evidence, but do not make the real host kernel safe.

## Host checks: read only

Use the existing read-only `docker inspect` commands in `SECURITY.md` to inspect actual conversation-container mounts, configured user, capabilities, privileged mode, security options, devices and Docker environment. Do not print full environment values, which may contain credentials.

For a chosen conversation container:

```sh
CID='<actual conversation container ID>'
docker inspect "$CID" --format '{{json .Mounts}}'
docker inspect "$CID" --format '{{json .HostConfig.Privileged}} {{json .HostConfig.CapAdd}} {{json .HostConfig.SecurityOpt}}'
docker inspect "$CID" --format '{{json .Config.User}}'
docker version --format '{{json .Server.Version}}'
uname -r
```

These commands read the selected host's state; nothing in this work ran them on the live LXC. Review mounts and any configured remote Docker endpoint locally. No host verification is assumed complete.

## Independent readiness decisions

- Merge readiness requires final-SHA functional/regression/layer CI and the requested hosted publication test evidence. Missing sandbox infrastructure means that external publication/recovery requirement is still unverified.
- Production `v1.0.0` remains blocked by the security policy, independent of merge readiness. No production tag, release, merge, main branch change or live LXC modification was performed.
