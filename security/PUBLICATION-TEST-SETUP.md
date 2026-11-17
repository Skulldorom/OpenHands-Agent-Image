# Hosted publication: unverified until sandbox evidence exists

On 2026-11-17 no accessible `Skulldorom/publication-integration-*` repository was found. No hosted publication test is claimed. Offline recovery/fault-injection tests exercise logic only.

## Exact setup

1. Create a dedicated, non-fork repository such as `Skulldorom/publication-integration-agent-image` with description containing `[publication-integration-only]`. It must have a `main` commit and initially have no releases or `v*` tags.
2. Copy the reviewed PR branch's files to that sandbox's `main` (including `scripts/`, `tests/`, and `.github/workflows/publication-integration.yml`). Enable Actions. Do not install this test on the production branch to gain privileges.
3. Create the sandbox's `publication-integration` Environment if required by account policy. Allow this workflow's `GITHUB_TOKEN` contents read/write and packages read/write. Organization policy must permit GHCR package creation; an existing package would need to grant that sandbox Actions access. The per-run package is uniquely named, so it should be newly created and linked to the sandbox by its source label.
4. Dispatch **Isolated publication integration** in the sandbox, ref `main`, repository `Skulldorom/publication-integration-agent-image`, package_prefix `ghcr.io/skulldorom/publication-integration-agent-image`, cleanup **false**. The workflow uses only its scoped `github.token`; no PAT secret or `/user` lookup is required.
5. Inspect the run and `publication-integration-report.json`. Require `passed: true`, verify the recorded test release/asset IDs and digest/alias, and retain the run URL. The harness injects interruption after persisted assets, retries twice, checks original asset IDs/bytes and appended reassessment evidence, checks stale-owner rejection, and verifies that the package has **no `latest` tag**. Only `integration-latest-UUID` serves as the test promotion alias. Test releases use `v0.0.*` exclusively in the empty, marked sandbox.

The source repository is excluded by the job-level repository-name and input-equality guards. The harness independently refuses unmarked repositories, forks, existing version tags/releases, non-sandbox package names and ordinary `latest` aliases. Production publication gates are unchanged.

Leave cleanup disabled for the evidence run. Optional cleanup needs package-version deletion permission and may be disallowed by GitHub's package administration policy; no broader credential is needed to run and retain the tests. If permissions prevent execution, report the failing API/permission rather than claiming success.

This setup is still required. A successful local self-test is not an external GitHub/GHCR publication result.
