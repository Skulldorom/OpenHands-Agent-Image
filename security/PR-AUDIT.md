# PR #1 audit — credential policy follow-up

The official OpenHands vulnerability baseline remains unchanged. Inherited HIGH/CRITICAL findings remain visible without individual approvals. Introduced HIGH/CRITICAL findings, material worsening, emergency blocks, unclassified credentials and invalid evidence remain blocking. Main/manual fresh builds, scheduled change detection, signed provenance, immutable versioning and interrupted-publication recovery remain in place.

## Credential result

The [complete six-location investigation](CREDENTIAL-LAYER-INVESTIGATION.md) and [policy](credential-policy.json) replace the previous token-fingerprint exemptions. SSH2, httpolyglot and GnuTLS contain 14 individually verified public cryptographic test private keys. Full material hashes, types, lengths, immutable source citations and purpose establish their classification. No file, binary or directory is skipped.

Five token-shaped matches remain unclassified: three Copilot runtime matches (including the two previously exempted), one GitHub CLI OAuth-shaped match and one bundled Codex PAT-shaped match. Their binary location, upstream inheritance and apparent age alone do not prove safety. Reproducible source/compiler-boundary evidence or reliable proof of authentic token type and expiration is still required. No matched value or sensitive context is included in evidence.

The scanner compares exact upstream/candidate saved-layer inventories, verifies layer hashes and completeness against Docker RootFS inventories, and preserves historical-layer inspection. The publisher checks report freshness, source-bound policy hash, full classifications and recomputed comparison. Public fixtures can pass; unknown/live secrets remain blocking regardless of inheritance.

## Validation scope

144 local Python regressions passed, including actual scanner/archive tests and publisher gates. Python/shell syntax and diff checks passed. Hosted policy/lint, Docker Git identity, PostgreSQL 17, Agent API/signals and exact retained-candidate security audit are rerun on the final source. See PR #1 for final hosted run URLs and results; local results do not substitute for hosted Docker validation.

The full PR diff against main includes vulnerability reporting, release orchestration, provenance, CI and tests. The current credential changes preserve the vulnerability policy and publication conditions. Existing unsuppressed inventories remain historical evidence; current releases require fresh assessment.

## Verdict

**BLOCKED** while five token-shaped matches remain unclassified. Keep draft; v1.0.0 and latest promotion are ineligible overall. Production publication/recovery remains untested end to end. Only Agent Server 1.62.0 is compatibility-approved. No merge, main modification, production publication or live LXC change was performed.
