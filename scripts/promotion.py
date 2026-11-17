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
import tempfile
import tarfile
import zipfile
import urllib.error

import evidence
import release

SEALED_FILES = evidence.FILES | {"security-assessment.json", "security-assessment.md", "scanner-database.tar.gz", "security/policy.json", "upstream-baseline.json", "previous-upstream-trivy.json", "layer-classifications.json", "security/credential-policy.json"}

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
    baseline = json.loads(Path("upstream-baseline.json").read_text())
    previous = json.loads(Path("previous-upstream-trivy.json").read_text())
    names = ["trivy.json", "upstream-trivy.json"]
    if baseline["upstream"] is not None:
        assert previous is not None and previous["ArtifactName"] == baseline["upstream"], "Unbound previous upstream scan"
        names.append("previous-upstream-trivy.json")
    else:
        assert previous is None, "Unexpected previous upstream scan"
    for name in names:
        scan = json.loads(Path(name).read_text())
        created = datetime.fromisoformat(scan["CreatedAt"].replace("Z", "+00:00"))
        assert prepared <= created <= now, "Scan predates validation or is future-dated"
        assert scan["Trivy"]["Version"] == "0.69.3", "Unapproved scanner"
    assert json.loads(Path("scanner-version.json").read_text())["Version"] == "0.69.3"
    expected = Path("scanner-database.sha256").read_text()
    assert re.fullmatch(r"[a-f0-9]{64}\s+\.cache/trivy/db/trivy\.db\s*", expected)
    with tarfile.open("scanner-database.tar.gz", "r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.name == "db/trivy.db"]
        assert len(matches) == 1 and matches[0].isfile() and matches[0].size < 2_000_000_000
        with archive.extractfile(matches[0]) as database:
            assert hashlib.file_digest(database, "sha256").hexdigest() == expected.split()[0], "Frozen scanner database changed"

def validate_layer_report(digest, now, prepared_at=None):
    report = json.loads(Path("layer-classifications.json").read_text())
    assert set(report) == {"candidate", "layers", "unclassified_detections", "classifications",
                           "unclassified_findings", "schema", "upstream", "comparison", "scanned_at", "policy_sha256", "layer_diff_ids", "image_id"}
    assert report["schema"] == 2
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", report["image_id"])
    assert report["candidate"] == release.IMAGE + "@" + digest, "Layer report candidate mismatch"
    assert type(report["layers"]) is int and report["layers"] > 0
    assert type(report["unclassified_detections"]) is int and report["unclassified_detections"] == 0
    assert report["unclassified_findings"] == []
    assert timedelta(0) <= now - datetime.fromisoformat(report["scanned_at"]) <= timedelta(hours=24), "Layer evidence expired"
    if prepared_at is not None:
        assert datetime.fromisoformat(prepared_at) <= datetime.fromisoformat(report["scanned_at"]), "Layer scan predates validation"
    source = Path(__file__).resolve().parents[1] / "tests/test-image-layers.py"
    spec = importlib.util.spec_from_file_location("credential_layers", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert report["policy_sha256"] == hashlib.sha256(module.POLICY_PATH.read_bytes()).hexdigest(), "Credential policy changed"
    upstream = report["upstream"]
    expected_base = json.loads(Path("upstream-trivy.json").read_text())["ArtifactName"]
    assert upstream["candidate"] == expected_base, "Layer baseline mismatch"
    assert type(upstream["layers"]) is int and 0 < upstream["layers"] <= report["layers"]
    for scan in (upstream, report):
        assert len(scan["layer_diff_ids"]) == scan["layers"]
        assert all(re.fullmatch(r"sha256:[a-f0-9]{64}", d) for d in scan["layer_diff_ids"])
    assert set(upstream["layer_diff_ids"]) <= set(report["layer_diff_ids"])
    assert report["comparison"] == module.compare_findings(upstream, report), "Credential comparison altered"
    assert not report["comparison"]["inherited_unclassified"]
    assert not report["comparison"]["inherited_confirmed_credentials"]
    assert not any(r["status"] != "non-sensitive" for r in report["comparison"]["introduced"])
    for scan in (upstream, report):
        assert isinstance(scan["classifications"], list)
        for record in scan["classifications"]:
            assert module.credential_classification(record, now) == record["decision"], "Unknown credential classification"


def prepare(digest):
    state = json.loads(Path("state.json").read_text())
    assert state["status"] == "validated"
    selection = {"candidate": digest, "policy_sha256": policy_hash(), "policy_commit": os.environ["GITHUB_SHA"],
                 "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                 "prepared_at": state["validation_started_at"], "scanned_at": datetime.now(timezone.utc).isoformat()}
    validate_fresh_scans(selection, datetime.now(timezone.utc))
    validate_layer_report(digest, datetime.now(timezone.utc), selection["prepared_at"])
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
    validate_layer_report(selection["candidate"], now, selection["prepared_at"])

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

def evidence_archive(files=None):
    names = set(files) if files is not None else SEALED_FILES | {"selection.json", "security/policy.json"}
    assert len({Path(n).name for n in names}) == len(names), "Evidence filename collision"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(names):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[name] if files is not None else Path(name).read_bytes())
    return buffer.getvalue()


def evidence_descriptor(raw):
    digest = hashlib.sha256(raw).hexdigest()
    selection = json.loads(Path("selection.json").read_text())
    return {"sha256": digest, "name": "approval-" + digest + ".zip",
            "run_id": selection["run_id"], "run_attempt": selection["run_attempt"]}


def original_evidence(record):
    match = re.search(r"<!-- release-evidence:(.*?) -->", record.get("body", ""), re.S)
    assert match, "Release lacks immutable evidence commitment; manual migration required"
    descriptor = json.loads(match[1])
    assert re.fullmatch(r"[a-f0-9]{64}", descriptor["sha256"])
    assert descriptor["name"] == "approval-" + descriptor["sha256"] + ".zip"
    return descriptor


class GitHubRegistry:
    """Remote side effects; the journal is a draft GitHub Release before tag writes."""
    def __init__(self, repo=None, image=None, latest_alias="latest"):
        self.repo = repo or release.REPO
        self.image = image or release.IMAGE
        self.latest_alias = latest_alias

    def records(self):
        pages = json.loads(release.gh("api", "--paginate", "--slurp", f"repos/{self.repo}/releases?per_page=100"))
        return [r for page in pages for r in page if re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"])]

    def reserve(self, state):
        body = release_notes(state, self.image) + "\n<!-- release-evidence:" + json.dumps(evidence_descriptor(evidence_archive()), sort_keys=True) + " -->"
        return json.loads(release.gh("api", "--method", "POST", f"repos/{self.repo}/releases",
            "-f", "tag_name=v" + state["version"], "-f", "target_commitish=" + state.get("release_source_commit", state["commit"]),
            "-f", "name=v" + state["version"], "-f", "body=" + body, "-F", "draft=true"))

    def tag_digest(self, tag):
        try:
            return release.registry(self.image.removeprefix("ghcr.io/"), tag, authenticated=True)[0]
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def tag(self, tag, digest):
        subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false", "--tag", self.image + ":" + tag, self.image + "@" + digest], check=True)

    def git_tag(self, version, commit):
        tag = "v" + version
        result = subprocess.run(["gh", "api", f"repos/{self.repo}/git/ref/tags/{tag}"], capture_output=True, text=True)
        if result.returncode == 0:
            obj = json.loads(result.stdout)["object"]
            while obj["type"] == "tag":
                obj = json.loads(release.gh("api", f"repos/{self.repo}/git/tags/" + obj["sha"]))["object"]
            assert obj["sha"] == commit, "Immutable Git tag conflict"
        else:
            assert "404" in result.stderr, result.stderr
            release.gh("api", "--method", "POST", f"repos/{self.repo}/git/refs", "-f", "ref=refs/tags/" + tag, "-f", "sha=" + commit)

    def asset_bytes(self, asset):
        return subprocess.check_output(["gh", "api", "-H", "Accept: application/octet-stream",
                                        f"repos/{self.repo}/releases/assets/{asset['id']}"])

    def upload_once(self, record, name, raw):
        assets = json.loads(release.gh("api", "--paginate", "--slurp",
                            f"repos/{self.repo}/releases/{record['id']}/assets?per_page=100"))
        matches = [a for page in assets for a in page if a["name"] == name]
        assert len(matches) <= 1, "Duplicate evidence assets"
        if matches:
            assert self.asset_bytes(matches[0]) == raw, "Immutable evidence asset conflict: " + name
            return
        # GitHub rejects duplicate names. Never delete or clobber on upload failure.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_bytes(raw)
            subprocess.run(["gh", "release", "upload", record["tag_name"], "--repo", self.repo, str(path)], check=True)
        assets = json.loads(release.gh("api", "--paginate", "--slurp",
                            f"repos/{self.repo}/releases/{record['id']}/assets?per_page=100"))
        matches = [a for page in assets for a in page if a["name"] == name]
        assert len(matches) == 1 and self.asset_bytes(matches[0]) == raw, "Evidence upload verification failed"

    def recover_original(self, descriptor):
        run = descriptor["run_id"]
        attempt = descriptor["run_attempt"]
        artifacts = json.loads(release.gh("api", f"repos/{self.repo}/actions/runs/{run}/artifacts?per_page=100"))["artifacts"]
        matches = [a for a in artifacts if a["name"] == f"validation-{run}-{attempt}" and not a["expired"]]
        assert len(matches) == 1, "Original approval artifact unavailable; refusing replacement"
        raw = subprocess.check_output(["gh", "api", f"repos/{self.repo}/actions/artifacts/{matches[0]['id']}/zip"])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            assert len(archive.namelist()) == len(set(archive.namelist()))
            selection = json.loads(archive.read("selection.json"))
            names = set(selection["files"]) | {"selection.json"}
            assert evidence.FILES <= names and names <= SEALED_FILES | {"selection.json"}, "Unknown original approval schema"
            assert all(archive.getinfo(n).file_size < 200_000_000 for n in names)
            restored = evidence_archive({n: archive.read(n) for n in names})
        assert hashlib.sha256(restored).hexdigest() == descriptor["sha256"], "Original approval commitment mismatch"
        return restored

    def upload_original(self, record, descriptor, raw):
        assert hashlib.sha256(raw).hexdigest() == descriptor["sha256"], "Original evidence changed"
        self.upload_once(record, descriptor["name"], raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in sorted(archive.namelist()):
                self.upload_once(record, Path(name).name, archive.read(name))

    def assets(self, record):
        descriptor = original_evidence(record)
        raw = evidence_archive()
        current = hashlib.sha256(raw).hexdigest()
        if current == descriptor["sha256"]:
            self.upload_original(record, descriptor, raw)
            return
        assets = json.loads(release.gh("api", "--paginate", "--slurp",
                            f"repos/{self.repo}/releases/{record['id']}/assets?per_page=100"))
        originals = [a for page in assets for a in page if a["name"] == descriptor["name"]]
        assert len(originals) <= 1
        original = self.asset_bytes(originals[0]) if originals else self.recover_original(descriptor)
        assert hashlib.sha256(original).hexdigest() == descriptor["sha256"], "Original evidence changed"
        self.upload_original(record, descriptor, original)
        self.upload_once(record, "reassessment-" + current + ".zip", raw)

    def complete(self, record, state):
        intent = release.journal_state(record)
        assert intent["image_digest"] == state["image_digest"], "Completion candidate changed"
        original_evidence(record)
        if record["draft"]:
            release.gh("api", "--method", "PATCH", f"repos/{self.repo}/releases/{record['id']}",
                       "-F", "draft=false")

def release_notes(state, image=None):
    assessment = json.loads(Path("security-assessment.json").read_text())
    counts = assessment["comparison_counts"]
    new_upstream = assessment["new_upstream_findings"]
    classifications = json.loads(Path("layer-classifications.json").read_text())["classifications"]
    summary = (f"Custom image security: {'PASS' if assessment['modification_pass'] else 'FAIL'}. "
               "Inherited upstream security: reported, not automatically blocked.\n"
               f"Candidate severity totals: {assessment['severity_counts']}; upstream: {assessment['upstream_severity_counts']}.\n"
               f"Inherited unchanged: {counts.get('inherited unchanged', 0)}; introduced: {counts.get('introduced', 0)}; "
               f"removed: {len(assessment['removed_findings'])}; worsened: {len(assessment['materially_worsened'])}.\n"
               f"Introduced HIGH/CRITICAL: {len(assessment['introduced_high_critical'])}; "
               f"new upstream findings: {len(new_upstream) if new_upstream is not None else 'first approved baseline not established'}; "
               f"emergency-blocked: {len(assessment['emergency_blocked'])}; secret detections: {len(assessment['secrets'])}. "
               f"Classified non-sensitive credential findings: {len(classifications)} (details attached); unclassified layer detections: 0.")
    return (f"Validated custom image: `{image or release.IMAGE}@{state['image_digest']}`\n"
            f"Official upstream: `ghcr.io/openhands/agent-server@{state['upstream_digest']}`\n"
            f"Agent Server: {state['agent_server_version']}. Previous immutable releases remain available for rollback.\n\n"
            + summary + "\n\n"
            "Complete unsuppressed scans, comparison, baseline, policy and build/test evidence are attached. "
            "A passing comparison is not a vulnerability-free or universal safety claim.\n\n"
            "_Created by an AI-authored OpenHands workflow on behalf of the repository owner._\n"
            "<!-- release-state:" + json.dumps(state, sort_keys=True) + " -->")


def approved_baseline(state, backend):
    owner = state.get("previous_approved")
    if owner is None:
        return {"upstream": None, "version": None, "approval_sha256": None}
    records = [r for r in backend.records() if r["tag_name"] == "v" + owner["version"] and not r["draft"]]
    assert len(records) == 1, "Previous approved release unavailable"
    record = records[0]
    intent = release.journal_state(record)
    assert intent["upstream_digest"] == owner["upstream_digest"] and intent["image_digest"] == owner["image_digest"]
    descriptor = original_evidence(record)
    assets = json.loads(release.gh("api", "--paginate", "--slurp", f"repos/{backend.repo}/releases/{record['id']}/assets?per_page=100"))
    matches = [a for page in assets for a in page if a["name"] == descriptor["name"]]
    assert len(matches) <= 1
    raw = backend.asset_bytes(matches[0]) if matches else backend.recover_original(descriptor)
    assert hashlib.sha256(raw).hexdigest() == descriptor["sha256"], "Previous approval commitment mismatch"
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.getinfo("state.json").file_size < 1_000_000
        original = json.loads(archive.read("state.json"))
        assert original["upstream_digest"] == intent["upstream_digest"] and original["image_digest"] == intent["image_digest"]
    return {"upstream": "ghcr.io/openhands/agent-server@" + intent["upstream_digest"],
            "version": intent["version"], "approval_sha256": descriptor["sha256"]}


def baseline():
    state = json.loads(Path("state.json").read_text())
    selection = approved_baseline(state, GitHubRegistry())
    Path("upstream-baseline.json").write_text(json.dumps(selection, sort_keys=True, indent=2) + "\n")
    Path("previous-upstream-trivy.json").write_text("null\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write("previous_upstream=" + (selection["upstream"] or "") + "\n")


def verify_baseline_owner(baseline, records):
    approved = sorted([r for r in records if not r["draft"]], key=lambda r: version_tuple(r["tag_name"][1:]))
    if not approved:
        assert baseline == {"upstream": None, "version": None, "approval_sha256": None}, "Unexpected approved baseline"
        return
    latest = approved[-1]
    intent = release.journal_state(latest)
    assert baseline == {"upstream": "ghcr.io/openhands/agent-server@" + intent["upstream_digest"],
                        "version": intent["version"], "approval_sha256": original_evidence(latest)["sha256"]}, "Approved baseline changed during validation; reassess"

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
        assert intent.get("agent_server_version") == state.get("agent_server_version"), "Runtime metadata conflict"
        assert intent.get("release_source_commit", intent["commit"]) == state.get("release_source_commit", state["commit"]), "Release source conflict"
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
    owners = backend.records()
    assert not any(version_tuple(r["tag_name"][1:]) > version_tuple(state["version"]) for r in owners), "Newer release owns latest"
    alias = getattr(backend, "latest_alias", "latest")
    existing_alias = backend.tag_digest(alias)
    owned_digests = {release.journal_state(r)["image_digest"] for r in owners}
    assert existing_alias is None or existing_alias in owned_digests, "Unowned mutable image alias"
    if existing_alias != digest:
        backend.tag(alias, digest)
    assert backend.tag_digest(alias) == digest, "Latest verification failed"
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
                              "ghcr.io/openhands/agent-server@" + state["upstream_digest"],
                              load("previous-upstream-trivy.json"), load("upstream-baseline.json"))
    assert reassessed == load("security-assessment.json"), "Security reassessment differs from sealed decision"
    release.validate_publication_evidence(state, json.loads(Path("security-assessment.json").read_text()),
        json.loads(Path("functional-pass.json").read_text()), json.loads(Path("security/policy.json").read_text()), selection["candidate"])
    records = release.release_records()
    verify_baseline_owner(load("upstream-baseline.json"), records)
    state = release.select_release(state, records)
    release.write_state(reconcile(state, GitHubRegistry(), assert_fresh))

if __name__ == "__main__":
    {"baseline": baseline, "prepare": lambda: prepare(sys.argv[2]), "publish": publish, "bundle": bundle}[sys.argv[1]]()
