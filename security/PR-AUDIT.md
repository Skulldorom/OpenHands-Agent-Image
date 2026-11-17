# PR audit: official-upstream baseline policy

The PR was reviewed against main `d6b187dc7ded5b5c18a3e8722858f6d738541cd5`, including release triggers, permissions, planner decisions, original/same-run provenance, exact-digest scanning, immutable evidence/recovery, version ownership, runtime contracts and credential checks.

## Implemented behavior

Unchanged official-upstream HIGH/CRITICAL findings are reported without per-CVE approvals. Added HIGH/CRITICAL findings, material worsening, reviewed emergency matches, unclassified credentials and invalid/incomplete evidence block. The emergency list is empty; SECURITY.md documents retirement of the five old blanket inherited CVE designations. Main pushes/manual dispatch always build, scheduled runs retain change detection, and PRs never publish production images. Original release evidence and partial-publication ownership remain protected.

Authenticated historical comparison and fresh exact-candidate audit both pass the vulnerability policy: 530 inherited HIGH/CRITICAL instances, zero introduced HIGH/CRITICAL, zero materially worsened findings and zero Trivy secret detections. That does not authorize publication when independent layer inspection fails.

## Blocking credential-layer inventory

Complete inspection of the official upstream and custom candidate reports six affected file locations:

| Location | Detection | Current decision |
| --- | --- | --- |
| `openhands/.code-server/lib/vscode/node_modules/@github/copilot-sdk-linux-x64/prebuilds/linux-x64/runtime.node` | Additional `ghs_`-shaped fingerprint `ef7109fc09d9fcc273762ba88bbea5d82fdebd1431b5ecea18ce3d91a959026d` | Unclassified; exemption rejected by automatic approval review |
| `openhands/.code-server/lib/vscode/node_modules/ssh2/lib/protocol/constants.js` | Private-key marker with payload-shaped data | Unclassified |
| `openhands/.code-server/node_modules/httpolyglot/test/fixtures/server.key` | Private-key-shaped test-fixture material | Unclassified; location alone does not establish authorization |
| `usr/bin/gh` | OAuth-token-shaped bytes | Unclassified |
| `usr/lib/x86_64-linux-gnu/libgnutls.so.30.40.3` | Several private-key markers with payload-shaped data | Unclassified |
| Codex executable under `acp-node/lib/node_modules/@agentclientprotocol/codex-acp/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex` | Fine-grained-PAT-shaped bytes | Unclassified |

These are detector findings, not a claim of confirmed usable credentials. Raw matches were not logged. In particular, the recorded SHA-256 for a PEM match hashes its header marker, not its entire key material: it must never be used to exempt all keys with that header. Any future classification must establish exact material/source context and appropriate authorization. There is no directory, binary, cache or size exclusion.

Two previously recorded exact non-live installation-token-shaped fingerprints remain documented in CREDENTIAL-LAYER-INVESTIGATION.md. No additional exemption was applied. The third proposed classification was rejected by automatic approval review because exact owner authorization was required; it remains blocking.

## Validation and release verdict

The Python regression suite, ShellCheck, actionlint, Docker build and Git/PostgreSQL/API/signal functional tests pass. Full credential-layer inspection fails and preserves complete inventories. Independent read-only vendor/reachability diagnostics continue after a credential failure so evidence collection does not hide other checks; the failed gate and job remain failed.

**BLOCKED.** The vulnerability policy no longer requires individual inherited-risk approval, but v1.0.0 and latest promotion remain ineligible while these credential findings are unclassified. Production GitHub/GHCR publication/recovery has not been tested end to end. Only Agent Server 1.62.0 is currently compatibility-approved. No merge, main modification, production publication or live LXC change was performed.
