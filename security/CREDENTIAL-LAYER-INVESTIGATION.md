# Credential-layer investigation, 17 November 2026

This investigation supersedes the earlier two token-hash exemptions. Neither exemption remains in the scanner. No credential-looking bytes, private-key payloads or surrounding binary strings are included in the report.

## Immutable evidence

Official upstream index: `ghcr.io/openhands/agent-server@sha256:6a0fe47417e1d1227592f693880b0292ebdd4f59fbfe517c8b8685e7c455abe3`.
AMD64 manifest: `sha256:e407fb4c55837564f491d86f1717a3344f3798abf91ffeda5cb927f85e44f6e0`.
Retained exact candidate: `ghcr.io/skulldorom/openhands-agent@sha256:0e8e24ac5258ae9d709886fc3298cb1f028b25146e4c01389056c1fa762e81a0`.

[Prior dual-image inventory](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44156424807/artifacts/14362950394) reports the same findings, file identities, matching fingerprints and immutable saved-layer members in upstream and candidate. The current code independently scans both images and verifies the upstream RootFS prefix, every saved layer SHA-256, and completeness against both Docker RootFS inventories. Local investigation downloaded the four affected upstream layers, verified compressed manifest hashes and uncompressed diff IDs, and inspected their files. Hosted integration supplies the fresh candidate inventory; the historical audit inspects the exact retained remote candidate.

## Six locations

| Location | Rule and evidence | Classification |
| --- | --- | --- |
| Copilot SDK `runtime.node` | `github_token`; match SHA-256 `ef7109fc09d9fcc273762ba88bbea5d82fdebd1431b5ecea18ce3d91a959026d`, length 51; containing file SHA-256 `188dcdf268b019fc37bddadeeccf773eccbd547a37c0febc604c648f1027596a` | **Unclassified, blocking.** Binary data alone does not prove a harmless constant or establish the actual token type/lifetime. |
| ssh2 `lib/protocol/constants.js` | `private_key`; whole file SHA-256 `a3894fdd8e294109b55f06fbda69e467741f15a250801b744b6b0487bbf32529` matches immutable public source | **Public Ed25519 capability-test private key**, not an empty PEM marker. Source signs/verifies a fixed test message to detect API support. Exact complete payload classification only. |
| httpolyglot `test/fixtures/server.key` | `private_key`; whole file SHA-256 `6bf80cc4376ae97a69b2eb95fd3e17df4614bea2fe224e5e707806ed9bf0f2c8` matches immutable public test source | **Public test private key.** Its private material is recoverable but publicly distributed for test TLS. No file/path exemption. |
| `/usr/bin/gh` | `github_token`, family `gho_`; match SHA-256 `902a57265300171f27289680dac688d3c2354f0893c50f89ec0522e0e123c3fe`, length 52; file SHA-256 `fca7ac8a8386e3ad65c9a96a96cbf272d1dcc4f76de174dae91d54e50729e240` | **Unclassified, blocking.** Need reproducible compiler/string-boundary or public-source evidence proving the complete match is not credential material. No authentication attempts were made. |
| GnuTLS `libgnutls.so.30.40.3` | `private_key`; file SHA-256 `4b14edde42e7cbeefd8a6d88d035e096f2e6412a535388bb1d073a1c196e2822` | **12 public cryptographic self-test private keys**, individually matched against public `lib/crypto-selftests-pk.c`. These are real payloads, not harmless header strings. Four EC payloads have no whitespace immediately after the header; the scanner now covers that form too. |
| Bundled Codex executable | `github_pat`; match SHA-256 `7e6b61baefc4f4f225671cf3e64658b91cafa910175b5c6e75c4b2dbf86892e1`, length 72; file SHA-256 `f34a4d2301892ae96c90097786bfe5dc269f187b6f69faf42a7b357b8c081e35` | **Unclassified, blocking.** Need exact source/compiler-boundary evidence. Presence in a public executable is insufficient. |

The two previously exempted Copilot matches, hashes `11116762eb8f44dcdcabd6cc844d36d367f2be80c0788bd61104ef968d874c57` and `e436670abd29f6abc2a834649981d9fbbe33c1bcb4cd70d748100e5a3b844380`, are lengths 43 and 64. They now remain unclassified too: a variable-length substring beginning `ghs_` is insufficient proof of an authentic legacy installation token. All five matches reside in non-writable, non-executable ELF `.rodata` sections; that location alone does not establish harmlessness. Five unique token-shaped matches therefore remain blocking across three of the six named locations plus the other Copilot runtime.

## Small classification policy

`security/credential-policy.json` contains full Base64-payload fingerprints, lengths, PEM types, immutable source URLs and purposes for the 14 verified public private keys. Each key classification also requires its exact immutable upstream layer and verified test-file location. Copying the public key into another file or a new layer remains blocking. It has no token fingerprint exceptions. Changes to material or type fail closed. Whitespace/escaped line endings and adjacent C/JS string literals are normalized; unrelated tokens and additional PEM keys in the same file still scan independently. Encrypted, truncated and unknown private material remains blocking. Known public test private keys must never be reused as production authentication identities.

A separate rule permits only a standalone, exact 40-byte legacy `ghs_` token after its documented one-hour lifetime, using a previously authenticated observation of the exact immutable layer. [Job 134087417504](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44097217505/job/134087417504) recorded layer `1971d2a873adc60b815a2afec78d6befc3ce15025264c1a08ecec191e80a5688` at `2026-11-17T13:54:23.999522Z`; the conservative observation bound is 13:54:24Z. The authenticated log was retrieved again during this investigation. [GitHub documents one-hour installation-token expiration](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app). This rule cannot authorize other token families, current stateless tokens, longer/ambiguous matches, unobserved layers or newly introduced secrets. None of the five current token-shaped matches qualifies.

PEM header/footer constants without material remain harmless by syntax. AWS-shaped slices inside a longer alphanumeric string retain the existing lexical boundary correction. No directory, filename, binary or layer is excluded. No vendor binary or upstream filesystem is rewritten.

## Publication evidence

Schema 2 records both inventories, candidate image ID, exact upstream ref, inspected diff IDs, timestamp, policy hash, full-payload decisions and inherited/non-sensitive/unclassified/introduced/removed groups. Offline scanning does not claim to establish live authentication; suspected live credentials remain unclassified and blocking. The confirmed-credential category is reserved for independently confirmed findings and is not inferred from a pattern match.

The publisher rederives every classification and comparison, rejects missing/old/altered reports and policy changes, requires zero unclassified candidate findings, and binds the official baseline to the sealed Trivy upstream identity. Credential policy and report are sealed with the existing source-bound evidence. Existing vulnerability comparison, fresh-build triggers, release planning, immutability and interrupted-publication recovery remain intact.

No production publication, merge, main change or live LXC operation is authorized or performed. This PR must remain draft while the five token-shaped matches lack conclusive classification evidence.
