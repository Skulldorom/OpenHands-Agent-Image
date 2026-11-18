#!/usr/bin/env python3
"""Resolve upstream contracts and plan/promote only validated registry artifacts."""
import hashlib
import base64
import importlib.util
import json
import io
import zipfile
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone
import urllib.error
import urllib.request

IMAGE = "ghcr.io/skulldorom/openhands-agent"
REPO = "Skulldorom/OpenHands-Agent-Image"
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])


def request(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=60) as response:
        return response.read(), response.headers


def registry(repo, reference, authenticated=False):
    auth = {}
    if authenticated:
        credential = os.environ["GH_TOKEN"]
        auth["Authorization"] = "Basic " + base64.b64encode(("token:" + credential).encode()).decode()
    token = json.loads(request("https://ghcr.io/token?scope=repository:" + repo + ":pull", auth)[0])["token"]
    headers = {"Authorization": "Bearer " + token, "Accept": ACCEPT}
    raw, meta = request(f"https://ghcr.io/v2/{repo}/manifests/{reference}", headers)
    digest = meta["Docker-Content-Digest"]
    manifest = json.loads(raw)
    if "manifests" in manifest:
        selected = next(x for x in manifest["manifests"] if x.get("platform", {}).get("architecture") == "amd64" and x["platform"].get("os") == "linux")
        manifest = json.loads(request(f"https://ghcr.io/v2/{repo}/manifests/" + selected["digest"], headers)[0])
    config = json.loads(request(f"https://ghcr.io/v2/{repo}/blobs/" + manifest["config"]["digest"], headers)[0])
    return digest, config["config"]


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True).strip()


BUILD_INPUTS = ["Dockerfile", ".dockerignore", "scripts/init-git.sh"]
INPUT_GROUPS = {
    "image": BUILD_INPUTS,
    "functional": ["compatibility.json", "scripts/validate-image.sh", "scripts/evidence.py", "tests/test-git-identity.sh", "tests/test-postgresql.sh", "tests/test-agent-startup.sh", "tests/test-image-layers.py"],
    "security": ["security/policy.json", "security/credential-policy.json", "security/credential-baseline.json", "security/vendor-evidence.json", "scripts/security-assessment.py", "scripts/promotion.py", ".github/workflows/release.yml"],
    "publishing": ["scripts/release.py", "scripts/promotion.py", ".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/upstream-update.yml"],
}
STATES = {"build_failed", "built", "functional_failed", "functional_passed", "security_failed", "validated", "published"}

def fingerprint(revision=None, group="image"):
    h = hashlib.sha256()
    for name in sorted(INPUT_GROUPS[group]):
        data = (subprocess.check_output(["git", "show", revision + ":" + name])
                if revision else Path(name).read_bytes())
        h.update(name.encode() + b"\0" + data + b"\0")
    return h.hexdigest()

def fingerprints(upstream, revision=None):
    result = {group: fingerprint(revision, group) for group in INPUT_GROUPS}
    result["image"] = hashlib.sha256((result["image"] + "\0" + upstream + "\0linux/amd64").encode()).hexdigest()
    return result

def build_required(previous, current, upstream):
    return previous is None or previous["fingerprint"] != current or previous["upstream_digest"] != upstream

def reusable_candidate(state, current, upstream):
    return (state.get("status") in STATES - {"build_failed"} and
            state.get("fingerprint") == current and state.get("upstream_digest") == upstream and
            re.fullmatch(r"sha256:[a-f0-9]{64}", state.get("image_digest", "")) is not None)

def candidate_action(state, identities, upstream, authenticated_functional=False):
    if not state or not reusable_candidate(state, identities["image"], upstream):
        return "build"
    # Build provenance permits image reuse, never authorization or test reuse.
    if not authenticated_functional or state.get("status") in {"built", "functional_failed"}:
        return "validate"
    if state.get("fingerprints", {}).get("functional") != identities["functional"]:
        return "validate"
    return "rescan"

def candidate_key(current, upstream):
    return "content-" + hashlib.sha256((current + "\0" + upstream).encode()).hexdigest()

def retained_marker(current, upstream):
    # Small per-run journals retain failed validations without moving any OCI
    # tag. Expired journals cause a rebuild, never trust in missing provenance.
    prefix = "candidate-state-" + candidate_key(current, upstream) + "-"
    artifacts = json.loads(gh("api", f"repos/{REPO}/actions/artifacts?per_page=100"))["artifacts"]
    for artifact in sorted(artifacts, key=lambda a: a["id"], reverse=True):
        if artifact["expired"] or not artifact["name"].startswith(prefix):
            continue
        raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            assert archive.namelist() == ["state.json"]
            assert archive.getinfo("state.json").file_size < 1_000_000
            state = json.loads(archive.read("state.json"))
        assert reusable_candidate(state, current, upstream), "Invalid retained candidate journal"
        return state["image_digest"]
    # Compatibility with candidates retained before run-specific journals.
    try:
        return registry("skulldorom/openhands-agent", candidate_key(current, upstream))[0]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise

def next_version(previous, bump):
    assert bump in {"patch", "minor", "major"}, "Invalid release increment"
    if previous is None:
        return "1.0.0"
    assert re.fullmatch(r"\d+\.\d+\.\d+", previous), "Invalid previous version"
    major, minor, patch = map(int, previous.split("."))
    return f"{major+1}.0.0" if bump == "major" else f"{major}.{minor+1}.0" if bump == "minor" else f"{major}.{minor}.{patch+1}"

def record_candidate(digest):
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
    state = json.loads(Path("state.json").read_text())
    state.update(image_digest=digest, status="built")
    write_state(state)

def write_state(state):
    Path("state.json").write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")

def record_status(status):
    assert status in STATES
    state = json.loads(Path("state.json").read_text())
    state["status"] = status
    if status == "built":
        state["validation_started_at"] = datetime.now(timezone.utc).isoformat()
    write_state(state)

def release_records():
    pages = json.loads(gh("api", "--paginate", "--slurp", f"repos/{REPO}/releases?per_page=100"))
    return [r for page in pages for r in page if re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"])]

def journal_state(record):
    match = re.search(r"<!-- release-state:(.*?) -->", record.get("body", ""), re.S)
    assert match, "Release has no recoverable publication intent: " + record["tag_name"]
    state = json.loads(match[1])
    assert "v" + state["version"] == record["tag_name"]
    return state

def plan():
    policy = json.loads(Path("compatibility.json").read_text())
    upstream, config = registry("openhands/agent-server", "latest-python")
    assert config.get("Entrypoint") == policy["contract"]["entrypoint"], "Upstream entrypoint changed; review compatibility.json"
    assert config.get("Cmd") in (None, []), "Upstream command changed"
    assert config.get("User") == policy["contract"]["user"] and config.get("WorkingDir") == policy["contract"]["working_directory"], "Upstream user/workdir changed"
    env = dict(x.split("=", 1) for x in config["Env"])
    sha = env["OPENHANDS_BUILD_GIT_SHA"]
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    source = request(f"https://raw.githubusercontent.com/OpenHands/software-agent-sdk/{sha}/openhands-agent-server/pyproject.toml")[0].decode()
    version = re.search(r'^version = "([^"]+)"', source, re.M)[1]
    approved = policy.get("approved_agent_server_versions", [policy["agent_server_version"]])
    assert version in approved, f"Unapproved Agent Server {version}; review compatibility.json and runtime contract tests"
    identities = fingerprints(upstream)
    records = sorted(release_records(), key=lambda r: tuple(map(int, r["tag_name"][1:].split("."))))
    owner_fields = {"version", "commit", "release_source_commit", "upstream_digest", "image_digest", "fingerprints", "fingerprint", "agent_server_version"}
    states = [dict({k: v for k, v in journal_state(r).items() if k in owner_fields},
                   status="built" if r["draft"] else "published") for r in records]
    old = states[-1] if states else None
    pending = [journal_state(r) for r in records if r["draft"]]
    assert len(pending) <= 1, "Multiple interrupted releases require reconciliation"
    same = old if old and old["fingerprints"]["image"] == identities["image"] else None
    bump = os.environ.get("BUMP", "auto")
    explicit_bump = bump != "auto"
    assert bump in {"auto", "patch", "minor", "major"}, "Invalid release increment"
    if bump == "auto":
        messages = subprocess.check_output(["git", "log", old["commit"] + "..HEAD", "--format=%B"], text=True) if old else ""
        explicit_bump = bool(re.search(r"(?m)^release:(minor|major)\s*$", messages))
        bump = "major" if re.search(r"(?m)^release:major\s*$", messages) else "minor" if re.search(r"(?m)^release:minor\s*$", messages) else "patch"
    force_build = (os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" or
                   (os.environ.get("GITHUB_EVENT_NAME") == "push" and
                    os.environ.get("GITHUB_REF") == "refs/heads/main"))
    if pending and not force_build:
        assert pending[0]["fingerprints"]["image"] == identities["image"], "Interrupted release uses superseded content/upstream; review draft before proceeding"
    release_version = pending[0]["version"] if pending else next_version(old["version"] if old else None, bump)
    current = identities["image"]
    # Forced builds never select or depend on a retained candidate.
    candidate = None if force_build else (pending[0]["image_digest"] if pending else
                 retained_marker(current, upstream) or (same["image_digest"] if same else None))
    state = {"version": release_version, "upstream_digest": upstream, "upstream_source": sha,
             "agent_server_version": version, "fingerprint": current, "fingerprints": identities,
             "commit": os.environ["GITHUB_SHA"], "release_source_commit": os.environ["GITHUB_SHA"],
             "bump": bump, "explicit_bump": explicit_bump, "pending_release": pending[0] if pending else None,
             "previous_approved": next((s for s in reversed(states) if s["status"] == "published"), None),
             "status": "built" if candidate else "build_failed"}
    if candidate:
        state["image_digest"] = candidate
    write_state(state)
    if candidate:
        verify_candidate(candidate)
    prior = same or (dict(state, status="built") if candidate else None)
    action = "build" if force_build else candidate_action(prior, identities, upstream)
    # Scheduled reuse always gets fresh functional/layer/security evidence. It
    # must not skip alias repair or an interrupted release merely for equal bytes.
    state["action"] = action
    write_state(state)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in {"build": str(action == "build").lower(), "validate": str(action != "skip").lower(),
                           "action": action,
                           "version": release_version, "upstream": upstream, "blocked": "",
                           "candidate_key": candidate_key(current, upstream), "candidate": candidate or ""}.items():
            output.write(f"{key}={value}\n")

def select_release(state, records=None):
    """Publication intent is selected only after exact-digest validation succeeds."""
    assert state["status"] == "validated", "Candidate is not validated"
    if records is not None:
        ordered = sorted(records, key=lambda r: tuple(map(int, r["tag_name"][1:].split("."))))
        drafts = [journal_state(r) for r in ordered if r["draft"]]
        assert len(drafts) <= 1, "Multiple interrupted releases require reconciliation"
        approved = next((journal_state(r) for r in reversed(ordered) if not r["draft"]), None)
        # Publication owns the lock here. Re-read reservations/version ownership
        # rather than racing with a version calculated before a long build.
        state = dict(state, pending_release=drafts[0] if drafts else None, previous_approved=approved,
                     version=drafts[0]["version"] if drafts else next_version(approved["version"] if approved else None, state["bump"]))
    pending = state.get("pending_release")
    previous = state.get("previous_approved")
    if pending:
        assert pending["image_digest"] == state["image_digest"], "Pending release must be recovered before another candidate can publish; run scheduled reconciliation"
        owner = pending
    elif previous and previous["image_digest"] == state["image_digest"] and not state.get("explicit_bump"):
        owner = previous
    else:
        return state
    # Reassessments append fresh evidence; original release source and approval
    # commitment are never replaced, even on a byte-identical new build.
    return dict(state, version=owner["version"],
                release_source_commit=owner.get("release_source_commit", owner["commit"]))


def assert_candidate_tag_absent():
    tag = "candidate-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    try:
        registry("skulldorom/openhands-agent", tag, authenticated=True)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
        raise
    raise AssertionError("Immutable candidate tag already exists: " + tag)


def verify_candidate(digest, state=None):
    import evidence
    # Verify the original build, not a newly asserted digest label. Trusted workflow
    # identity and original source must match the inspected immutable artifact.
    actual, config = registry("skulldorom/openhands-agent", digest)
    assert actual == digest
    labels = config["Labels"]
    source = labels["org.opencontainers.image.revision"]
    state = state if state is not None else json.loads(Path("state.json").read_text())
    assert labels["org.opencontainers.image.base.digest"] == state["upstream_digest"]
    assert hashlib.sha256((fingerprint(source) + "\0" + state["upstream_digest"] + "\0linux/amd64").encode()).hexdigest() == state["fingerprints"]["image"]
    evidence.verify_build_signature("oci://" + IMAGE + "@" + digest, source)

def validate_publication_evidence(state, assessment, functional, policy, digest):
    assert functional["pass"] is True and functional["candidate"] == IMAGE + "@" + digest, "Missing functional pass for exact candidate"
    assert assessment["policy_sha256"] == hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(), "Assessment policy changed"
    assert assessment["pass"] and assessment["modification_pass"], "Security gate not passed"
    assert not assessment["blockers"] and not assessment["secrets"] and not assessment["introduced_high_critical"]
    assert assessment["candidate"] == IMAGE + "@" + digest
    assert assessment["upstream"] == "ghcr.io/openhands/agent-server@" + state["upstream_digest"]
    spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_policy(policy)
    assert assessment["schema"] == 2 and not assessment["materially_worsened"] and not assessment["emergency_blocked"]

if __name__ == "__main__":
    {"plan": plan, "assert-candidate-tag-absent": assert_candidate_tag_absent,
     "record-candidate": lambda: record_candidate(sys.argv[2]),
     "status": lambda: record_status(sys.argv[2]), "verify-candidate": lambda: verify_candidate(sys.argv[2])}[sys.argv[1]]()
