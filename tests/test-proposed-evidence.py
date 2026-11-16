#!/usr/bin/env python3
"""Reassess retained real scans; hypothetical approval never changes active policy."""
import argparse
from copy import deepcopy
from datetime import date
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
    proposal = json.loads(Path("security/proposed-acceptances.json").read_text())
    policy = json.loads(Path("security/policy.json").read_text())
    assert policy["exceptions"] == [] and policy["release_approved"] is False
    assert functional["pass"] is True and functional["candidate"] == candidate["ArtifactName"]
    assert state["agent_server_version"] == "1.62.0"
    assert upstream["ArtifactName"] == "ghcr.io/openhands/agent-server@" + state["upstream_digest"]
    current = module.assess(candidate, upstream, policy, tracker, candidate["ArtifactName"], upstream["ArtifactName"])
    assert current["modification_pass"] and not current["secrets"]
    assert len(current["blockers"]) == len(proposal["records"]) == 7
    assert not current["pass"] and not current["accepted_exceptions"]
    assert {(r["cve"], r["package"], r["installed"], r["target"]) for r in current["blockers"]} == {
        (r["cve"], r["package"], r["installed"], r["target"]) for r in stored["blockers"]}
    hypothetical = deepcopy(policy)
    hypothetical["exceptions"] = deepcopy(proposal["records"])
    for record in hypothetical["exceptions"]:
        record.update(status="approved", approved_by="Skulldorom", approval_date=date.today().isoformat())
    approved = module.assess(candidate, upstream, hypothetical, tracker, candidate["ArtifactName"], upstream["ArtifactName"])
    assert approved["pass"] and approved["modification_pass"]
    assert len(approved["accepted_exceptions"]) == 7
    # Every proposed scope must be necessary; removing any leaves a real blocker.
    for i in range(7):
        removed = hypothetical["exceptions"].pop(i)
        assert not module.assess(candidate, upstream, hypothetical, tracker, candidate["ArtifactName"], upstream["ArtifactName"])["pass"]
        hypothetical["exceptions"].insert(i, removed)
    for name, assessment in [("active-policy", current), ("hypothetical-approval", approved)]:
        Path(f"{name}.json").write_text(json.dumps(assessment, indent=2) + "\n")
        Path(f"{name}.md").write_text(module.markdown(assessment))
    print(json.dumps({"functional_pass": True, "introduced_high_critical": len(current["introduced_high_critical"]),
                      "secrets": len(current["secrets"]), "active_policy_blockers": len(current["blockers"]),
                      "hypothetical_acceptances": len(approved["accepted_exceptions"]),
                      "candidate": candidate["ArtifactName"], "upstream": upstream["ArtifactName"],
                      "evidence_sha256": hashlib.sha256(Path(archive).read_bytes()).hexdigest()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    verify(parser.parse_args().archive)
