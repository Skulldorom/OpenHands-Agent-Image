# Security policy

Only the newest successful release on the approved Agent Server version is maintained. Digest/version pins remain available for rollback but never receive fixes in place.

Report vulnerabilities privately through GitHub Security Advisories. If private reporting is unavailable, contact the repository owner without posting exploit details or secrets publicly. Never attach credentials, private keys, personal data or complete environment dumps.

CI gates releases with vulnerability and secret scanning. Fixed HIGH/CRITICAL vulnerabilities block promotion; unfixed vulnerabilities are not claimed absent. Inspect inherited upstream risks and reports. Unknown upstream versions/contracts fail closed. BuildKit attaches SBOM/provenance. Actions use SHA pins; review updates manually. Dependabot PR creation is disabled for this direct-main repository.

Git attribution is not authentication. Runtime identity stays in private container-local /tmp; never share that mount between conversations. PostgreSQL never starts automatically; test clusters use private Unix sockets. No runtime Docker socket or privilege escalation is required for these features.

Installing the optional host updater requires explicit operator action and Docker administrator access. Check capacity and preserve previous images. Never prune volumes or delete workspaces to make room. No infrastructure deployment is performed by this repository.
