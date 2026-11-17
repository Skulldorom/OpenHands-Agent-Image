# Node cache credential detector investigation

Reproduced, without logging any matched bytes or sensitive surrounding bytes, on GitHub-hosted ubuntu-24.04 runners:

- Initial named-rule reproduction: https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44080900917
- Payload and exact-layer confirmation: https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44081851290

The affected file is `tmp/node-compile-cache/v24.22.2-x64-964aae3f-0/0c92995d`, size 96,308 bytes. The exact matching expression was the private-key boundary alternative `-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`, not a GitHub token or AWS access-key expression. It matched one 27-byte format marker at byte offset 45,771. The matching PEM footer begins only 14 bytes after the header ends. There is no PEM payload following the header, with either ordinary whitespace or normalized JSON/JavaScript escaped CR/LF separators. A private key cannot be encoded by this header/footer pair. This is a serialized format-boundary literal, not a leaked PEM credential.

The containing saved archive member is `blobs/sha256/5f89b4767faedc090e725dfe6ef075425511cd04cd7724d8bc325458f75aab21`. That digest is present as filesystem layer 6 in the pinned upstream image `ghcr.io/openhands/agent-server@sha256:6a0fe47417e1d1227592f693880b0292ebdd4f59fbfe517c8b8685e7c455abe3`. Candidate inspection verifies that all 22 upstream filesystem layers are an identical prefix of its 24 layers. The cache originates upstream, not from this Dockerfile's PostgreSQL installation or COPY. Saved archive traversal order varies; the old message's "layer 7" is not a stable Dockerfile instruction index.

## Detector correction

`tests/test-image-layers.py` uses named rules. PEM detection requires evidence of encoded key material after a header: at least 16 Base64 characters, including whitespace-wrapped forms, or the legacy encrypted-key `Proc-Type` header. JSON/JavaScript escaped CR/LF separators are normalized before detection. The deliberately low threshold blocks truncated keys without requiring a footer or successfully parseable DER. GitHub token and AWS access-key rules remain unchanged and are evaluated independently after harmless format literals. No file path or binary-file exemption is added. Existing credential-file and historical-layer/whiteout checks remain active.

The scanner still operates directly on bytes, including NUL-containing and invalid-UTF-8 files. It does not decode with ignored errors or discard binary files. Error messages contain rule/location only, never matched values or surrounding bytes. Original file-size/directory scope is unchanged; this is a targeted fix, not a claim that all possible credential encodings are detected.

Regression tests use synthetic binary format literals and synthetic credential examples: all five GitHub short-token prefixes, fine-grained PATs, AWS access keys, untyped/RSA/EC/OpenSSH/encrypted PEM boundaries with payload, CRLF and escaped separators, unusually short wrapped lines, legacy encrypted headers, truncated keys, and a real token pattern after a harmless marker. Nested-archive tests continue to block credentials recoverable beneath a later whiteout. Assertion messages are checked for absence of matched values.

Final validation scans both the pinned upstream image's saved layers and every saved candidate layer, in addition to Git identity, PostgreSQL initialization/query/backup/restore and Agent Server readiness/API/signal Docker integration. See the PR's final validation run for the result; the investigation runs intentionally retained the failing detector while gathering evidence.
