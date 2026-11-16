#!/usr/bin/env python3
"""Prepare and recheck exact-digest promotion under a protected Environment."""
from datetime import datetime, timezone, timedelta
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

import evidence
import release


def policy_hash():
    return hashlib.sha256(Path("security/policy.json").read_bytes()).hexdigest()


def check_environment(settings):
    assert settings["name"] == "release"
    reviewers = [r for r in settings["protection_rules"] if r["type"] == "required_reviewers"]
    assert len(reviewers) == 1 and reviewers[0]["prevent_self_review"] is True
    assert [(r["type"], r["reviewer"]["login"]) for r in reviewers[0]["reviewers"]] == [("User", "Skulldorom")], "Unexpected release reviewers"
    assert settings.get("can_admins_bypass") is False, "Admin bypass disabled setting must be independently verifiable"
    assert settings["deployment_branch_policy"] == {"protected_branches": False, "custom_branch_policies": True}


def environment_gate():
    check_environment(evidence.api("environments/release"))
    branches = evidence.api("environments/release/deployment-branch-policies")["branch_policies"]
    assert len(branches) == 1 and branches[0]["name"] == "main" and branches[0]["type"] == "branch"


def protected_approval():
    environment_gate()
    run = os.environ["GITHUB_RUN_ID"]
    reviews = evidence.api(f"actions/runs/{run}/approvals")
    selection = json.loads(Path("selection.json").read_text())
    validate_approval(reviews, selection, os.environ["GITHUB_ACTOR"], os.environ["GITHUB_TRIGGERING_ACTOR"])


def approval_token(selection):
    return f"approve {selection['candidate']} policy:{selection['policy_sha256']} run:{selection['run_id']}/{selection['run_attempt']}"


def validate_approval(reviews, selection, actor, triggering_actor):
    assert actor != "Skulldorom" and triggering_actor != "Skulldorom", "Owner cannot approve own run or rerun"
    relevant = [r for r in reviews if any(e["name"] == "release" for e in r["environments"])]
    assert relevant and all(r["state"] == "approved" for r in relevant), "Missing approval or rejected Environment review"
    assert any(r["user"]["login"] == "Skulldorom" and r["comment"].strip() == approval_token(selection)
               for r in relevant), "No exact authorized Environment approval"

def check_selection(state, source_fingerprint, current_fingerprint, upstream):
    assert source_fingerprint == current_fingerprint, "Image content changed: full build and validation required"
    assert upstream == state["upstream_digest"], "Selected upstream is no longer the approved upstream"
    assert state["agent_server_version"] == json.loads(Path("compatibility.json").read_text())["agent_server_version"]


def prepare():
    assert os.environ["GITHUB_REF"] == "refs/heads/main"
    digest = os.environ["CANDIDATE_DIGEST"]
    expected_policy = os.environ.get("EXPECTED_POLICY_SHA256", "")
    assert not expected_policy or expected_policy == policy_hash(), "Dispatched policy changed"
    state = evidence.download(int(os.environ["EVIDENCE_RUN"]), int(os.environ["EVIDENCE_ATTEMPT"]), digest, "trusted")
    upstream, _ = release.registry("openhands/agent-server", "latest-python")
    check_selection(state, release.fingerprint(state["commit"]), release.fingerprint(), upstream)
    assert state["fingerprint"] == release.fingerprint(state["commit"]), "Build-input evidence mismatch"
    # Resolve only after authenticated evidence retrieval. Historical artifacts never authorize promotion.
    for name in evidence.FILES:
        Path(name).write_bytes((Path("trusted") / name).read_bytes())
    environment_gate()
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"upstream={state['upstream_digest']}\n")
    Path("selection.json").write_text(json.dumps({"candidate": digest, "policy_sha256": policy_hash(),
        "source_commit": state["commit"], "policy_commit": os.environ["GITHUB_SHA"],
        "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "evidence_run": int(os.environ["EVIDENCE_RUN"]), "evidence_attempt": int(os.environ["EVIDENCE_ATTEMPT"]),
        "prepared_at": datetime.now(timezone.utc).isoformat()}, indent=2) + "\n")


def validate_fresh_scans(selection, now):
    prepared = datetime.fromisoformat(selection["prepared_at"])
    assert timedelta(0) <= now - prepared <= timedelta(hours=24), "Preparation expired"
    for name in ("trivy.json", "upstream-trivy.json"):
        scan = json.loads(Path(name).read_text())
        created = datetime.fromisoformat(scan["CreatedAt"].replace("Z", "+00:00"))
        assert prepared <= created <= now, "Scan predates promotion or is future-dated"
        assert scan["Trivy"]["Version"] == "0.69.3", "Unapproved scanner"
    assert json.loads(Path("scanner-version.json").read_text())["Version"] == "0.69.3"
    assert re.fullmatch(r"[a-f0-9]{64}\s+\.cache/trivy/db/trivy\.db\s*", Path("scanner-database.sha256").read_text()), "Missing frozen database fingerprint"

def seal():
    selection = json.loads(Path("selection.json").read_text())
    validate_fresh_scans(selection, datetime.now(timezone.utc))
    names = evidence.FILES | {"selection.json", "security-assessment.json", "security-assessment.md", "security-gate.json"}
    selection["files"] = {n: hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in names - {"selection.json"}}
    selection["scanned_at"] = datetime.now(timezone.utc).isoformat()
    Path("selection.json").write_text(json.dumps(selection, indent=2) + "\n")
    Path("approval-summary.md").write_text(f"# Exact-candidate release approval\n\nCandidate `{selection['candidate']}`\n\nPolicy SHA256 `{selection['policy_sha256']}` at `{selection['policy_commit']}`\n\nSource `{selection['source_commit']}`\n\nValidation run {selection['evidence_run']} attempt {selection['evidence_attempt']}\n\nReview full scans and assessment before approving. Approval is not CVE acceptance.\n\nRequired Environment review comment:\n```text\n{approval_token(selection)}\n```\n")


def recheck(selection, now):
    assert selection["candidate"] == os.environ["CANDIDATE_DIGEST"]
    assert selection["policy_sha256"] == policy_hash(), "Policy changed since scanning"
    assert selection["policy_commit"] == os.environ["GITHUB_SHA"]
    assert selection["run_id"] == int(os.environ["GITHUB_RUN_ID"]) and selection["run_attempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"])
    assert timedelta(0) <= now - datetime.fromisoformat(selection["scanned_at"]) <= timedelta(hours=24), "Fresh scans expired; new run and approval required"
    assert set(selection["files"]) == evidence.FILES | {"security-assessment.json", "security-assessment.md"}, "Incomplete sealed evidence"
    for name, digest in selection["files"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, "Evidence changed after approval preparation"
    validate_fresh_scans(selection, now)


def bundle():
    run = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    artifacts = evidence.api(f"actions/runs/{run}/artifacts?per_page=100")["artifacts"]
    selected = [a for a in artifacts if a["name"] == f"promotion-{run}-{attempt}"]
    assert len(selected) == 1 and not selected[0]["expired"]
    raw = subprocess.check_output(["gh", "api", f"repos/{release.REPO}/actions/artifacts/{selected[0]['id']}/zip"])
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == os.environ["BUNDLE_DIGEST"] == selected[0]["digest"]
    allowed = evidence.FILES | {"selection.json", "approval-summary.md", "security-assessment.json", "security-assessment.md", "security-gate.json"}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert set(archive.namelist()) == allowed and len(archive.namelist()) == len(allowed)
        for name in allowed:
            assert archive.getinfo(name).file_size < 200_000_000
            Path(name).write_bytes(archive.read(name))


def reassess(selection, state):
    spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    load = lambda n: json.loads(Path(n).read_text())
    assessment = module.assess(load("trivy.json"), load("upstream-trivy.json"), load("security/policy.json"),
                               load("debian-tracker.json"), release.IMAGE + "@" + selection["candidate"],
                               "ghcr.io/openhands/agent-server@" + state["upstream_digest"])
    assert assessment == load("security-assessment.json"), "Assessment changed at promotion"
    release.validate_publication_evidence(state, assessment, load("functional-pass.json"),
                                         load("security/policy.json"), selection["candidate"])
    return assessment

def dry_run():
    checks = {}
    def check(name, operation):
        try:
            operation()
            checks[name] = {"pass": True}
        except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
            checks[name] = {"pass": False, "error": str(error)}
    check("environment_configuration", environment_gate)
    check("independent_initiator", independent_initiator)
    def authorization():
        policy = json.loads(Path("security/policy.json").read_text())
        assert policy["release_approved"] is True, "Release authorization is false; publication forbidden"
    check("release_authorization", authorization)
    check("signed_provenance_and_functional_evidence", lambda: evidence.download(
        int(os.environ["EVIDENCE_RUN"]), int(os.environ["EVIDENCE_ATTEMPT"]),
        os.environ["CANDIDATE_DIGEST"], "reverified"))
    def selected():
        return json.loads(Path("selection.json").read_text())
    def state():
        return json.loads(Path("state.json").read_text())
    check("fresh_sealed_scans", lambda: recheck(selected(), datetime.now(timezone.utc)))
    check("policy_matching_and_release_authorization", lambda: reassess(selected(), state()))
    check("exact_environment_approval", protected_approval)
    def content():
        chosen = selected()
        assert evidence.api("git/ref/heads/main")["object"]["sha"] == os.environ["GITHUB_SHA"], "Main changed"
        check_selection(state(), release.fingerprint(chosen["source_commit"]), release.fingerprint(),
                        release.registry("openhands/agent-server", "latest-python")[0])
    check("current_content_and_upstream", content)
    report = {"dry_run": True, "publication_attempted": False, "checks": checks,
              "pass": all(item["pass"] for item in checks.values())}
    Path("promotion-dry-run.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1

def independent_initiator():
    actor, trigger = os.environ["GITHUB_ACTOR"], os.environ["GITHUB_TRIGGERING_ACTOR"]
    expected = os.environ.get("TRUSTED_RELEASE_ACTOR", "")
    assert expected and expected != "Skulldorom", "Configure an independently controlled trusted release identity"
    assert actor == trigger == expected, "Untrusted initiator or rerun identity"

def publish():
    assert os.environ["GITHUB_REF"] == "refs/heads/main"
    independent_initiator()
    selection = json.loads(Path("selection.json").read_text())
    recheck(selection, datetime.now(timezone.utc))
    assert evidence.api("git/ref/heads/main")["object"]["sha"] == os.environ["GITHUB_SHA"], "Main changed: renewed assessment and approval required"
    protected_approval()
    state = evidence.download(selection["evidence_run"], selection["evidence_attempt"], selection["candidate"], "reverified")
    assert (Path("reverified") / "functional-pass.json").read_bytes() == Path("functional-pass.json").read_bytes()
    check_selection(state, release.fingerprint(state["commit"]), release.fingerprint(),
                    release.registry("openhands/agent-server", "latest-python")[0])
    reassess(selection, state)
    # Version is release metadata, not an image build input. Do not change source identity.
    previous = subprocess.run(["gh", "api", f"repos/{release.REPO}/releases/latest"], capture_output=True, text=True)
    if previous.returncode:
        assert "404" in previous.stderr, previous.stderr
        state["version"] = "1.0.0"
    else:
        old = json.loads(previous.stdout)["tag_name"]
        assert re.fullmatch(r"v\d+\.\d+\.\d+", old)
        state["version"] = release.next_version(old[1:], os.environ["BUMP"])
    Path("state.json").write_text(json.dumps(state, indent=2) + "\n")
    release.publish(selection["candidate"])


if __name__ == "__main__":
    if sys.argv[1] == "dry-run":
        sys.exit(dry_run())
    {"prepare": prepare, "seal": seal, "publish": publish, "bundle": bundle}[sys.argv[1]]()
