# PR #1 audit — upstream-relative credential gate

The owner explicitly accepted the risk of the five unchanged, unclassified official-upstream token-shaped findings on 18 November 2026. This is a baseline-risk decision, not proof of harmlessness. There are no per-token approvals or expiry exceptions.

The [complete accepted inventory](credential-baseline.json) commits all 19 findings from the exact authenticated upstream scan: 14 individually verified public test keys and five unknown token-shaped findings. [The investigation](CREDENTIAL-LAYER-INVESTIGATION.md) retains the locations, hashes, source evidence and limitations. Raw values/private-key payloads are never included.

## Gate behavior

- Every regular file and historical layer in both exact images is scanned. Layer hashes, RootFS completeness/prefix and full finding identities are verified.
- The five unchanged inherited unknowns remain transparently unclassified and can pass the credential gate under the reviewed baseline.
- Any introduced/changed custom finding, missing inherited evidence, changed upstream image digest or changed upstream finding inventory blocks. Baseline changes require review; automation cannot silently adopt them.
- Confirmed dangerous credentials and exposed private-key/credential-file material always block, including inherited findings. The denylist only blocks and never authorizes risk.
- All 14 public key classifications retain complete payload, type, file and layer scope. Moving/copying a key into a new layer is not exempted.
- The publisher rederives the complete comparison and gate from sealed evidence; missing, stale, count-inconsistent or altered evidence fails closed.

The vulnerability policy remains unchanged: inherited HIGH/CRITICAL findings stay visible; introduced HIGH/CRITICAL, material worsening and emergency matches block. Main/manual fresh builds, scheduled change detection, compatibility/provenance, immutable releases and interrupted-publication recovery are unchanged.

## Validation and limits

152 Python regressions passed locally, including actual archive/scanner tests and publisher acceptance/rejection tests. Hosted lint, Docker integration and fresh security audits are rerun on the final source; see PR #1 for the final run URLs and results. A replay of the verified prior hosted inventory passes the revised gate with five accepted inherited unknowns and zero introduced findings.

Keep PR #1 draft. No merge, main change, production image publication or live LXC change was performed. Production GitHub/GHCR publication/recovery remains untested end to end; only Agent Server 1.62.0 is compatibility-approved. Actual publication requires every fresh production release gate, independently of a merge-readiness verdict.
