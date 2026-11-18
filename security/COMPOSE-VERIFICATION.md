# Docker Compose v5.7.2 vendor verification

The previous failure was caused by missing redirect handling, not incorrect official checksums. Without `--location`, the public GitHub release URL returns **HTTP 302, zero redirects followed and zero downloaded bytes**, with a redirect to `release-assets.githubusercontent.com`. With redirect handling, the binary and checksum asset each follow one HTTPS redirect and return HTTP 200.

No credentials are supplied to these public downloads. The helper captures curl diagnostics and URL metadata privately and reports only status, count, size and hostnames; it never logs complete signed redirect URLs, headers or surrounding binary bytes. Ambient curl configuration is disabled.

## Independently pinned official evidence

The pins below were rechecked through Docker's [official GitHub release metadata](https://api.github.com/repos/docker/compose/releases/tags/v5.7.2). They were not changed to fit downloaded data.

| Evidence | Exact value |
| --- | --- |
| Binary name | `docker-compose-linux-x86_64` |
| Official binary size | `34063021` bytes |
| Official binary SHA-256 | `e14235d9c622c5bd57eb8adeed4a0f7308c7f3862e6812dd843f6fe27f1307cc` |
| Separate `.sha256` asset size | `94` bytes |
| Separate checksum asset SHA-256 | `abb9bb05c9726d7b7abf138dde6c3058a64ffc7c05b344700a54dd6e7dc58089` |

The helper verifies the checksum asset's own pinned hash, parses its exact binary filename, requires its declared hash to agree with the independently pinned binary digest, then verifies the binary. It requires an 8–128 MiB plausible binary size, the exact official byte count and ELF magic. Only after all integrity checks succeed does it invoke `go version -m`; it never executes the downloaded Compose binary.

## Bounded transport and regression coverage

`scripts/verify-compose-vendor.py` enforces HTTPS for initial requests and redirects, follows at most five redirects, retries at most three times with a 90-second retry window, uses 10-second connect and 120-second transfer limits, and has a 220-second outer deadline per request. HTTP failures, empty/implausible responses, malformed transport metadata, invalid evidence and checksum disagreement all fail closed. Partial files are removed on transport failure; temporary files are deleted after inspection.

Twelve regressions exercise real curl requests against a local HTTP server (HTTP is enabled only by an internal test argument, never the production CLI). They cover the original zero-byte redirect, following redirects, redirect loops, empty HTTP 200, HTTP errors, transient failures/retries, both matching pins, binary and checksum-asset mismatches, conflicting official evidence, implausible size, refusal of insecure/credential-bearing production URLs, and refusal to inspect modules after failed integrity verification.

The security workflow retains `reachability/vendor-compose-5.7.2-verification.json` with sanitized transport facts, verification state and complete parsed module versions, plus the raw Go build-information text after successful verification. See the PR's final-SHA security run for hosted results. The same workflow preserves the fresh unsuppressed vulnerability inventory; successful vendor verification does not clear the release security gate or update the image's installed Compose version.

## Verified embedded module evidence

[Hosted security run 44096333206](https://github.com/Skulldorom/OpenHands-Agent-Image/actions/runs/44096333206) successfully reproduced the redirect failure, verified both official pins and inspected the binary. Both the audit and Docker/policy integration passed at implementation commit `daa5d87523bdcba50748379cfe7612e73d52b598`; the PR records the final-SHA reruns separately.

| Embedded module | Verified version |
| --- | --- |
| `github.com/docker/compose/v5` | `v5.7.2` |
| `golang.org/x/net` | `v0.60.0` |
| `github.com/moby/go-archive` | `v0.3.3` |

The complete dependency inventory remains in the verification JSON and raw Go module report attached by CI. The current Compose release still embeds the affected x/net version; this is evidence of no supported fix for that Compose finding, not an acceptance. No image package, production release or active security policy was changed.
