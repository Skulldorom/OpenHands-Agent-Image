#!/usr/bin/env python3
"""Verify sealed CI evidence and reconcile a durable release intent."""
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
import urllib.error

import evidence
import release

SEALED_FILES = evidence.FILES | {"security-assessment.json", "security-assessment.md"}

def policy_hash():
    return hashlib.sha256(Path("security/policy.json").read_bytes()).hexdigest()

def check_selection(state, source_fingerprint, current_fingerprint, upstream):
    assert source_fingerprint == current_fingerprint, "Image content changed; rebuild required"
    assert upstream == state["upstream_digest"], "Upstream changed; validation required"
    policy = json.loads(Path("compatibility.json").read_text())
    assert state["agent_server_version"] in policy.get("approved_agent_server_versions", [policy["agent_server_version"]])

def validate_fresh_scans(selection, now):
    prepared = datetime.fromisoformat(selection["prepared_at"])
    assert timedelta(0) <= now - prepared <= timedelta(hours=24), "Security evidence expired"
    for name in ("trivy.json", "upstream-trivy.json"):
        scan = json.loads(Path(name).read_text())
        created = datetime.fromisoformat(scan["CreatedAt"].replace("Z", "+00:00"))
        assert prepared <= created <= now, "Scan predates validation or is future-dated"
        assert scan["Trivy"]["Version"] == "0.69.3", "Unapproved scanner"
    assert json.loads(Path("scanner-version.json").read_text())["Version"] == "0.69.3"
    assert re.fullmatch(r"[a-f0-9]{64}\s+\.cache/trivy/db/trivy\.db\s*", Path("scanner-database.sha256").read_text())

def prepare(digest):
    state = json.loads(Path("state.json").read_text())
    assert state["status"] == "validated"
    selection = {"candidate": digest, "policy_sha256": policy_hash(), "policy_commit": os.environ["GITHUB_SHA"],
                 "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                 "prepared_at": state["validation_started_at"], "scanned_at": datetime.now(timezone.utc).isoformat()}
    validate_fresh_scans(selection, datetime.now(timezone.utc))
    selection["files"] = {n: hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in SEALED_FILES}
    Path("selection.json").write_text(json.dumps(selection, sort_keys=True, indent=2) + "\n")

def recheck(selection, now):
    assert selection["candidate"] == os.environ["CANDIDATE_DIGEST"]
    assert selection["policy_sha256"] == policy_hash(), "Policy changed since assessment"
    assert selection["policy_commit"] == os.environ["GITHUB_SHA"]
    assert selection["run_id"] == int(os.environ["GITHUB_RUN_ID"]) and selection["run_attempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"])
    assert timedelta(0) <= now - datetime.fromisoformat(selection["scanned_at"]) <= timedelta(hours=24)
    assert set(selection["files"]) == SEALED_FILES, "Incomplete evidence seal"
    for name, digest in selection["files"].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, "Evidence changed after assessment"
    validate_fresh_scans(selection, now)

def verify_bundle_digest(raw, recorded, workflow_output):
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    expected = workflow_output if workflow_output.startswith("sha256:") else "sha256:" + workflow_output
    assert actual == recorded == expected, "Validation artifact digest mismatch"

def bundle():
    run, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    artifacts = evidence.api(f"actions/runs/{run}/artifacts?per_page=100")["artifacts"]
    selected = [a for a in artifacts if a["name"] == f"validation-{run}-{attempt}"]
    assert len(selected) == 1 and not selected[0]["expired"]
    raw = subprocess.check_output(["gh", "api", f"repos/{release.REPO}/actions/artifacts/{selected[0]['id']}/zip"])
    verify_bundle_digest(raw, selected[0]["digest"], os.environ["BUNDLE_DIGEST"])
    allowed = SEALED_FILES | {"selection.json"}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist()))
        assert allowed <= set(archive.namelist())
        for name in allowed:
            assert archive.getinfo(name).file_size < 200_000_000
            Path(name).write_bytes(archive.read(name))

def assert_fresh(state):
    assert os.environ["GITHUB_REF"] == "refs/heads/main"
    assert evidence.api("git/ref/heads/main")["object"]["sha"] == state["commit"] == os.environ["GITHUB_SHA"], "Stale source SHA"
    assert release.registry("openhands/agent-server", "latest-python")[0] == state["upstream_digest"], "Stale upstream digest"
    assert state["fingerprints"] == release.fingerprints(state["upstream_digest"]), "Authorization inputs changed"

class GitHubRegistry:
    """Remote side effects; the journal is a draft GitHub Release before tag writes."""
    def records(self):
        return release.release_records()

    def reserve(self, state):
        body = release_notes(state)
        return json.loads(release.gh("api", "--method", "POST", f"repos/{release.REPO}/releases",
            "-f", "tag_name=v" + state["version"], "-f", "target_commitish=" + state.get("release_source_commit", state["commit"]),
            "-f", "name=v" + state["version"], "-f", "body=" + body, "-F", "draft=true"))

    def tag_digest(self, tag):
        try:
            return release.registry("skulldorom/openhands-agent", tag)[0]
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def tag(self, tag, digest):
        subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false", "--tag", release.IMAGE + ":" + tag, release.IMAGE + "@" + digest], check=True)

    def git_tag(self, version, commit):
        tag = "v" + version
        result = subprocess.run(["gh", "api", f"repos/{release.REPO}/git/ref/tags/{tag}"], capture_output=True, text=True)
        if result.returncode == 0:
            obj = json.loads(result.stdout)["object"]
            while obj["type"] == "tag":
                obj = evidence.api("git/tags/" + obj["sha"])["object"]
            assert obj["sha"] == commit, "Immutable Git tag conflict"
        else:
            assert "404" in result.stderr, result.stderr
            release.gh("api", "--method", "POST", f"repos/{release.REPO}/git/refs", "-f", "ref=refs/tags/" + tag, "-f", "sha=" + commit)

    def assets(self, record):
        tag = record["tag_name"]
        # Exact candidate/upstream and full unsuppressed evidence remain inspectable.
        subprocess.run(["gh", "release", "upload", tag, "--clobber", *sorted(SEALED_FILES), "selection.json", "security/policy.json"], check=True)

    def complete(self, record, state):
        release.gh("api", "--method", "PATCH", f"repos/{release.REPO}/releases/{record['id']}",
                   "-F", "draft=false", "-f", "body=" + release_notes(state))

def release_notes(state):
    assessment = json.loads(Path("security-assessment.json").read_text())
    return (f"Validated image: `{release.IMAGE}@{state['image_digest']}`\n"
            f"Upstream: `ghcr.io/openhands/agent-server@{state['upstream_digest']}`\n"
            f"Agent Server: {state['agent_server_version']}. Previous immutable releases remain available for rollback.\n"
            f"Accepted findings (not suppressed): {json.dumps(assessment.get('accepted_exceptions', []))}. "
            "Full inventories, advisory evidence and all four fingerprints are attached.\n\n"
            "_Created by an AI-authored OpenHands workflow on behalf of the repository owner._\n"
            "<!-- release-state:" + json.dumps(state, sort_keys=True) + " -->")

def version_tuple(version):
    assert re.fullmatch(r"\d+\.\d+\.\d+", version)
    return tuple(map(int, version.split(".")))

def reconcile(state, backend, freshness):
    """Idempotent boundaries: intent, immutable image, Git tag, assets, latest, completion.

    A single non-cancelling Actions concurrency group owns this operation. The
    durable intent reserves the version before any registry writes; retries use it.
    """
    records = backend.records()
    matching = [r for r in records if r["tag_name"] == "v" + state["version"]]
    assert len(matching) <= 1
    newer = [r for r in records if version_tuple(r["tag_name"][1:]) > version_tuple(state["version"])]
    assert not newer, "Newer release owns latest"
    freshness(state)
    if matching:
        record = matching[0]
        intent = release.journal_state(record)
        assert intent["image_digest"] == state["image_digest"] and intent["upstream_digest"] == state["upstream_digest"], "Version reserved for another candidate"
        assert intent["fingerprints"]["image"] == state["fingerprints"]["image"]
        # Git tags retain the original intent's source, even if policy-only changes
        # caused a newer source revision to reauthorize the same image.
        original_commit = intent.get("release_source_commit", intent["commit"])
    else:
        record = backend.reserve(state)
        original_commit = state.get("release_source_commit", state["commit"])
    digest = state["image_digest"]
    for tag in (state["version"], "v" + state["version"]):
        existing = backend.tag_digest(tag)
        assert existing in (None, digest), "Immutable image tag conflict: " + tag
        if existing is None:
            backend.tag(tag, digest)
        assert backend.tag_digest(tag) == digest, "Registry tag verification failed"
    backend.git_tag(state["version"], original_commit)
    backend.assets(record)
    freshness(state)
    # Re-read ownership immediately before touching the mutable alias.
    assert not any(version_tuple(r["tag_name"][1:]) > version_tuple(state["version"]) for r in backend.records()), "Newer release owns latest"
    if backend.tag_digest("latest") != digest:
        backend.tag("latest", digest)
    assert backend.tag_digest("latest") == digest, "Latest verification failed"
    state = dict(state, status="published")
    backend.complete(record, state)
    return state

def publish():
    state = json.loads(Path("state.json").read_text())
    selection = json.loads(Path("selection.json").read_text())
    os.environ["CANDIDATE_DIGEST"] = selection["candidate"]
    recheck(selection, datetime.now(timezone.utc))
    assert state["status"] == "validated"
    run = evidence.api(f"actions/runs/{selection['run_id']}/attempts/{selection['run_attempt']}")
    assert run["head_sha"] == state["commit"] and run["head_branch"] == "main"
    evidence.verify_signature("functional-pass.json", run)
    evidence.validate_functional(json.loads(Path("functional-pass.json").read_text()), state, run,
                                 release.IMAGE + "@" + selection["candidate"])
    release.verify_candidate(selection["candidate"])
    spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    load = lambda name: json.loads(Path(name).read_text())
    reassessed = module.assess(load("trivy.json"), load("upstream-trivy.json"), load("security/policy.json"),
                              load("debian-tracker.json"), release.IMAGE + "@" + selection["candidate"],
                              "ghcr.io/openhands/agent-server@" + state["upstream_digest"])
    assert reassessed == load("security-assessment.json"), "Security reassessment differs from sealed decision"
    release.validate_publication_evidence(state, json.loads(Path("security-assessment.json").read_text()),
        json.loads(Path("functional-pass.json").read_text()), json.loads(Path("security/policy.json").read_text()), selection["candidate"])
    release.write_state(reconcile(state, GitHubRegistry(), assert_fresh))

if __name__ == "__main__":
    {"prepare": lambda: prepare(sys.argv[2]), "publish": publish, "bundle": bundle}[sys.argv[1]]()
