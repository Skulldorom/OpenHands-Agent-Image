#!/usr/bin/env python3
"""Reassess authenticated historical scans under the current upstream-baseline policy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def verify(archive):
    with zipfile.ZipFile(archive) as evidence:
        load = lambda name: json.loads(evidence.read(name))
        candidate, upstream = load("trivy.json"), load("upstream-trivy.json")
        state, functional = load("state.json"), load("functional-pass.json")
        tracker = load("debian-tracker.json")
        stored = load("security-gate.json")
        manifest = evidence.read("scanner-database.sha256").decode().split()[0]
        assert len(manifest) == 64, "Missing scanner database fingerprint"
    policy = json.loads(Path("security/policy.json").read_text())
    module.validate_policy(policy)
    assert functional["pass"] is True and functional["candidate"] == candidate["ArtifactName"]
    assert state["agent_server_version"] == "1.62.0"
    assert upstream["ArtifactName"] == "ghcr.io/openhands/agent-server@" + state["upstream_digest"]
    current = module.assess(candidate, upstream, policy, tracker, candidate["ArtifactName"], upstream["ArtifactName"])
    assert current["modification_pass"] and not current["secrets"]
    assert not current["introduced_high_critical"] and not current["materially_worsened"]
    assert current["pass"] and not current["blockers"]
    Path("active-policy.json").write_text(json.dumps(current, indent=2) + "\n")
    Path("active-policy.md").write_text(module.markdown(current))
    print(json.dumps({"historical_functional_pass": True, "release_security_pass": current["pass"],
                      "introduced_high_critical": len(current["introduced_high_critical"]),
                      "materially_worsened": len(current["materially_worsened"]),
                      "inherited_unchanged": current["comparison_counts"].get("inherited unchanged", 0),
                      "inherited_high_critical": sum(r["comparison"] == "inherited unchanged" and r["severity"] in {"HIGH", "CRITICAL"} for r in current["findings"]),
                      "secrets": len(current["secrets"]), "candidate": candidate["ArtifactName"], "upstream": upstream["ArtifactName"],
                      "evidence_sha256": hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
                      "note": "Historical evidence reassessment only; cannot authorize a current production release."}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    verify(parser.parse_args().archive)
