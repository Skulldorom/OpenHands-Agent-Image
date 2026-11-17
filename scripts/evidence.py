#!/usr/bin/env python3
"""Fail-closed GitHub Actions evidence retrieval; ZIP content is never executed."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone, timedelta

REPO = "Skulldorom/OpenHands-Agent-Image"
IMAGE = "ghcr.io/skulldorom/openhands-agent"
TESTS = ["metadata", "git-identity", "postgresql-17", "agent-api-entrypoint-signals", "layer-security"]
FILES = {"state.json", "functional-pass.json", "trivy.json", "upstream-trivy.json", "debian-tracker.json",
         "scanner-version.json", "scanner-database.sha256", "package-inventory.txt", "security-gate.json"}


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", f"repos/{REPO}/{path}"], text=True))


def validate_run(run, attempt):
    assert run["repository"]["full_name"] == REPO
    assert run["head_branch"] == "main" and run["event"] in {"push", "schedule", "workflow_dispatch"}
    assert run["path"] in {".github/workflows/ci.yml", ".github/workflows/upstream-update.yml"}
    assert run["run_attempt"] == attempt and run["status"] == "completed"
    assert re.fullmatch(r"[a-f0-9]{40}", run["head_sha"])
    created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    assert timedelta(0) <= datetime.now(timezone.utc) - created <= timedelta(days=90), "Stale evidence"


def validate_functional(functional, state, run, candidate):
    assert functional == {
        "schema": 2, "pass": True, "candidate": candidate,
        "source_commit": run["head_sha"], "upstream_digest": state["upstream_digest"],
        "agent_server_version": state["agent_server_version"],
        "repository": REPO, "run_id": run["id"], "run_attempt": run["run_attempt"],
        "tests": {test: "passed" for test in TESTS},
    }, "Incomplete or inconsistent functional evidence"
    assert state["commit"] == run["head_sha"]
    policy = json.loads(Path("compatibility.json").read_text())
    assert state["agent_server_version"] in policy.get("approved_agent_server_versions", [policy["agent_server_version"]])
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", state["upstream_digest"])


def verify_signature(subject, run):
    verified = json.loads(subprocess.check_output([
        "gh", "attestation", "verify", subject, "--repo", REPO,
        "--signer-workflow", REPO + "/.github/workflows/release.yml",
        "--source-ref", "refs/heads/main", "--source-digest", run["head_sha"],
        "--signer-digest", run["head_sha"], "--deny-self-hosted-runners", "--format", "json"], text=True))
    validate_signature_run(verified, run)


def verify_build_signature(subject, source):
    assert re.fullmatch(r"[a-f0-9]{40}", source)
    verified = json.loads(subprocess.check_output([
        "gh", "attestation", "verify", subject, "--repo", REPO,
        "--signer-workflow", REPO + "/.github/workflows/release.yml",
        "--source-ref", "refs/heads/main", "--source-digest", source,
        "--signer-digest", source, "--deny-self-hosted-runners", "--format", "json"], text=True))
    assert verified, "Missing trusted build provenance"

def validate_signature_run(verified, run):
    invocation = f"https://github.com/{REPO}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
    assert any(item["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] == invocation
               for item in verified), "Attestation came from another run/attempt"


def validate_archive(artifact, run, raw):
    assert not artifact["expired"] and artifact["workflow_run"]["head_sha"] == run["head_sha"]
    assert artifact["workflow_run"]["id"] == run["id"]
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == artifact["digest"], "Artifact integrity mismatch"
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())), "Duplicate ZIP paths"
        assert FILES <= set(archive.namelist()), "Required evidence files missing"
        assert all(archive.getinfo(n).file_size < 200_000_000 for n in FILES), "Oversized evidence"
        return {n: archive.read(n) for n in FILES}


def download(run_id, attempt, digest, destination, historical=False):
    assert run_id > 0 and attempt > 0 and re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
    run = api(f"actions/runs/{run_id}/attempts/{attempt}")
    validate_run(run, attempt)
    artifacts = api(f"actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    matching = [a for a in artifacts if a["name"] == f"validation-{run_id}-{attempt}"]
    assert len(matching) == 1, "Missing or ambiguous validation artifact"
    artifact = matching[0]
    raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"])
    content = validate_archive(artifact, run, raw)
    state, functional = (json.loads(content[n]) for n in ["state.json", "functional-pass.json"])
    candidate = IMAGE + "@" + digest
    assert functional["candidate"] == candidate and functional["pass"] is True
    if historical:
        # This mode is for proposal review only; its output cannot satisfy schema 2 release evidence.
        reference = json.loads(Path("security/historical-evidence.json").read_text())
        assert reference == {"run_id": run_id, "attempt": attempt, "candidate": candidate,
                             "source_commit": run["head_sha"], "artifact_sha256": artifact["digest"]}
    else:
        validate_functional(functional, state, run, candidate)
        jobs = api(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")["jobs"]
        required = {"Build candidate once with SBOM and provenance", "Git, PostgreSQL 17, Agent Server API, and signals",
                    "Layer security and package inventory", "Attest image build", "Attest functional evidence"}
        assert any(required <= {s["name"] for s in job["steps"] if s["status"] == "completed" and s["conclusion"] == "success"}
                   for job in jobs), "Trusted validation steps incomplete"
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in content.items():
        (destination / name).write_bytes(data)
    (destination / "evidence.zip").write_bytes(raw)
    if not historical:
        verify_signature("oci://" + candidate, run)
        verify_signature(str(destination / "functional-pass.json"), run)
    (destination / "trusted-run.json").write_text(json.dumps(run, indent=2) + "\n")
    return state


def write_functional(digest):
    state = json.loads(Path("state.json").read_text())
    evidence = {"schema": 2, "pass": True, "candidate": IMAGE + "@" + digest,
                "source_commit": os.environ["GITHUB_SHA"], "upstream_digest": state["upstream_digest"],
                "agent_server_version": state["agent_server_version"], "repository": REPO,
                "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                "tests": {test: "passed" for test in TESTS}}
    Path("functional-pass.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    if sys.argv[1] == "record":
        write_functional(sys.argv[2])
    else:
        download(int(os.environ["EVIDENCE_RUN"]), int(os.environ["EVIDENCE_ATTEMPT"]),
                 os.environ["CANDIDATE_DIGEST"], sys.argv[2], historical=sys.argv[1] == "historical")
