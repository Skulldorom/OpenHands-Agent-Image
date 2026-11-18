# Credential-layer investigation, 17 November 2026

This investigation supersedes the earlier two token-hash exemptions. Neither exemption remains in the scanner. No credential-looking bytes, private-key payloads or surrounding binary strings are included in the report.

## Immutable evidence

Official upstream index: `ghcr.io/openhands/agent-server@sha256:6a0fe47417e1d1227592f693880b0292ebdd4f59fbfe517c8b8685e7c455abe3`.
AMD64 manifest: `sha256:e407fb4c55837564f491d86f1717a3344f3798abf91ffeda5cb927f85e44f6e0`.
Legacy retained candidate (historical evidence only): `ghcr.io/skulldorom/openhands-agent@sha256:0e8e24ac5258ae9d709886fc3298cb1f028b25146e4c01389056c1fa762e81a0`.

[Prior dual-image inventory](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44156424807/artifacts/14362950394) reports the same findings, file identities, matching fingerprints and immutable saved-layer members in upstream and candidate. The current code independently scans both images and verifies the upstream RootFS prefix, every saved layer SHA-256, and completeness against both Docker RootFS inventories. Local investigation downloaded the four affected upstream layers, verified compressed manifest hashes and uncompressed diff IDs, and inspected their files. Hosted integration supplies the fresh candidate inventory. The security audit builds the current source, obtains a real immutable manifest digest in a loopback-only runner registry, and validates/scans that exact image against its actual base. The legacy retained candidate uses upstream `sha256:e74009d51a352c3e9e8db30a788b15683de060c0b2f9e71e0b9d19576034c995`, outside the accepted baseline; the earlier description incorrectly associated it with the reviewed base. No risk acceptance was added for that historical image.

## Six locations

| Location | Rule and evidence | Classification |
| --- | --- | --- |
| Copilot SDK `runtime.node` | `github_token`; match SHA-256 `ef7109fc09d9fcc273762ba88bbea5d82fdebd1431b5ecea18ce3d91a959026d`, length 51; containing file SHA-256 `188dcdf268b019fc37bddadeeccf773eccbd547a37c0febc604c648f1027596a` | **Unclassified, accepted upstream risk.** Binary data alone does not prove a harmless constant or establish the actual token type/lifetime. |
| ssh2 `lib/protocol/constants.js` | `private_key`; whole file SHA-256 `a3894fdd8e294109b55f06fbda69e467741f15a250801b744b6b0487bbf32529` matches immutable public source | **Public Ed25519 capability-test private key**, not an empty PEM marker. Source signs/verifies a fixed test message to detect API support. Exact complete payload classification only. |
| httpolyglot `test/fixtures/server.key` | `private_key`; whole file SHA-256 `6bf80cc4376ae97a69b2eb95fd3e17df4614bea2fe224e5e707806ed9bf0f2c8` matches immutable public test source | **Public test private key.** Its private material is recoverable but publicly distributed for test TLS. No file/path exemption. |
| `/usr/bin/gh` | `github_token`, family `gho_`; match SHA-256 `902a57265300171f27289680dac688d3c2354f0893c50f89ec0522e0e123c3fe`, length 52; file SHA-256 `fca7ac8a8386e3ad65c9a96a96cbf272d1dcc4f76de174dae91d54e50729e240` | **Unclassified, accepted upstream risk.** Need reproducible compiler/string-boundary or public-source evidence proving the complete match is not credential material. No authentication attempts were made. |
| GnuTLS `libgnutls.so.30.40.3` | `private_key`; file SHA-256 `4b14edde42e7cbeefd8a6d88d035e096f2e6412a535388bb1d073a1c196e2822` | **12 public cryptographic self-test private keys**, individually matched against public `lib/crypto-selftests-pk.c`. These are real payloads, not harmless header strings. Four EC payloads have no whitespace immediately after the header; the scanner now covers that form too. |
| Bundled Codex executable | `github_pat`; match SHA-256 `7e6b61baefc4f4f225671cf3e64658b91cafa910175b5c6e75c4b2dbf86892e1`, length 72; file SHA-256 `f34a4d2301892ae96c90097786bfe5dc269f187b6f69faf42a7b357b8c081e35` | **Unclassified, accepted upstream risk.** Need exact source/compiler-boundary evidence. Presence in a public executable is insufficient. |

The two older Copilot fingerprints (`11116762eb8f44dcdcabd6cc844d36d367f2be80c0788bd61104ef968d874c57` and `e436670abd29f6abc2a834649981d9fbbe33c1bcb4cd70d748100e5a3b844380`) remain unclassified too. Together with the three token-shaped matches in the table, there are five unchanged inherited unknowns. All are in read-only, non-executable ELF `.rodata`; this does not establish harmlessness. The owner's 18 November 2026 instruction explicitly accepts these unchanged findings as upstream risk without individual classifications. No finding is relabeled safe, fake, non-live or expired.

## Small classification policy

`security/credential-policy.json` contains full Base64-payload fingerprints, lengths, PEM types, immutable source URLs and purposes for the 14 verified public private keys. Each key classification also requires its exact immutable upstream layer and verified test-file location. Copying the public key into another file or a new layer remains blocking. It has no token fingerprint exceptions. Changes to material or type fail closed. Whitespace/escaped line endings and adjacent C/JS string literals are normalized; unrelated tokens and additional PEM keys in the same file still scan independently. Encrypted, truncated and unknown private material remains blocking. Known public test private keys must never be reused as production authentication identities.

The old installation-token expiry rule and immutable-layer timing exceptions have been removed. The new rule compares one accepted official image digest and complete inventory commitment, documented in [credential-baseline.json](credential-baseline.json). Any upstream digest or inventory change requires review; new/changed custom findings and dangerous credentials block regardless of inheritance. The confirmed-dangerous denylist can only add prohibitions and requires reason/evidence.

PEM header/footer constants without material remain harmless by syntax. AWS-shaped slices inside a longer alphanumeric string retain the existing lexical boundary correction. No directory, filename, binary or layer is excluded. No vendor binary or upstream filesystem is rewritten.

## Publication evidence

Schema 3 records both complete inventories, candidate image ID, exact upstream ref, inspected diff IDs, timestamp, policy hash, full-payload decisions, inherited unknowns, introduced/removed groups and the recomputable baseline-risk gate. The publisher verifies counts, identities, layer membership, all public-key classifications, exact baseline commitment, freshness and the sealed comparison/decision. Unknowns retain their unclassified status; accepting unchanged inherited risk is not a safety classification. A confirmed dangerous credential or exposed private-key/credential-file finding still blocks even if the reviewed inventory contains it.

No production publication, merge, main change or live LXC operation is authorized or performed. PR #1 remains draft. Hosted final-source results and merge-readiness are recorded in the PR description; successful CI does not exercise real production publication/recovery.
