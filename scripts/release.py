#!/usr/bin/env python3
"""Resolve upstream contracts and plan/promote only validated registry artifacts."""
import hashlib
import importlib.util
import json
import io
import zipfile
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request

IMAGE = "ghcr.io/skulldorom/openhands-agent"
REPO = "Skulldorom/OpenHands-Agent-Image"
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])


def request(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=60) as response:
        return response.read(), response.headers


def registry(repo, reference):
    token = json.loads(request("https://ghcr.io/token?scope=repository:" + repo + ":pull")[0])["token"]
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


def fingerprint(revision=None):
    h = hashlib.sha256()
    for name in BUILD_INPUTS:
        data = (subprocess.check_output(["git", "show", revision + ":" + name])
                if revision else Path(name).read_bytes())
        h.update(name.encode() + b"\0" + data)
    return h.hexdigest()


def build_required(previous, current, upstream):
    return previous is None or previous["fingerprint"] != current or previous["upstream_digest"] != upstream


def reusable_blocker(state, gate, functional, current, upstream):
    return (state["fingerprint"] == current and state["upstream_digest"] == upstream
            and functional["pass"] and functional["candidate"] == gate["candidate"]
            and gate["upstream"] == "ghcr.io/openhands/agent-server@" + upstream
            and not gate["pass"] and bool(gate["blockers"]))

def reusable_candidate(state, current, upstream):
    return (state["fingerprint"] == current and state["upstream_digest"] == upstream
            and re.fullmatch(r"sha256:[a-f0-9]{64}", state.get("image_digest", "")) is not None)

def candidate_key(current, upstream):
    return "content-" + hashlib.sha256((current + "\0" + upstream).encode()).hexdigest()

def retained_marker(current, upstream):
    try:
        digest, _ = registry("skulldorom/openhands-agent", candidate_key(current, upstream))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    return digest

def previous_candidate(current, upstream):
    page = 1
    while True:
        runs = json.loads(gh("api", f"repos/{REPO}/actions/runs?branch=main&status=completed&per_page=100&page={page}"))["workflow_runs"]
        for run in runs:
            if run["path"] not in {".github/workflows/ci.yml", ".github/workflows/upstream-update.yml"}:
                continue
            artifacts = json.loads(gh("api", f"repos/{REPO}/actions/runs/{run['id']}/artifacts?per_page=100"))["artifacts"]
            for artifact in artifacts:
                if artifact["expired"] or artifact["name"] != f"validation-{run['id']}-{run['run_attempt']}":
                    continue
                raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"])
                assert "sha256:" + hashlib.sha256(raw).hexdigest() == artifact["digest"], "Candidate ledger integrity mismatch"
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    assert len(archive.namelist()) == len(set(archive.namelist()))
                    if "state.json" not in archive.namelist():
                        continue
                    state = json.loads(archive.read("state.json"))
                    if "image_digest" not in state and "functional-pass.json" in archive.namelist():
                        state["image_digest"] = json.loads(archive.read("functional-pass.json"))["candidate"].removeprefix(IMAGE + "@")
                    state["fingerprint"] = fingerprint(state["commit"])
                    if reusable_candidate(state, current, upstream):
                        return {"candidate": state["image_digest"], "evidence_run": str(run["id"]),
                                "evidence_attempt": str(run["run_attempt"]), "url": run["html_url"]}
        if len(runs) < 100:
            return None
        page += 1

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
    state["image_digest"] = digest
    Path("state.json").write_text(json.dumps(state, indent=2) + "\n")

def plan():
    policy = json.loads(Path("compatibility.json").read_text())
    upstream, config = registry("openhands/agent-server", "latest-python")
    assert config.get("Entrypoint") == ["tini", "--", "/usr/local/bin/openhands-agent-server"], "Upstream entrypoint changed"
    assert config.get("Cmd") in (None, []), "Upstream command changed"
    assert config.get("User") == "openhands" and config.get("WorkingDir") == "/", "Upstream user/workdir changed"
    env = dict(x.split("=", 1) for x in config["Env"])
    sha = env["OPENHANDS_BUILD_GIT_SHA"]
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    source = request(f"https://raw.githubusercontent.com/OpenHands/software-agent-sdk/{sha}/openhands-agent-server/pyproject.toml")[0].decode()
    version = re.search(r'^version = "([^"]+)"', source, re.M)[1]
    assert version == policy["agent_server_version"], f"Unapproved upstream version: {version}"
    old = None
    result = subprocess.run(["gh", "api", f"repos/{REPO}/releases/latest"], capture_output=True, text=True)
    if result.returncode == 0:
        release = json.loads(result.stdout)
        asset = next(x for x in release["assets"] if x["name"] == "state.json")
        old = json.loads(request(asset["browser_download_url"])[0])
    else:
        # A missing initial release is acceptable; authentication/network errors are not.
        assert "404" in result.stderr, result.stderr
    current = fingerprint()
    changed = build_required(old, current, upstream)
    retained = previous_candidate(current, upstream) if changed else None
    marker = retained_marker(current, upstream) if changed and not retained else None
    blocked = retained["url"] if retained else ("Persistent candidate " + marker + "; evidence expired or unavailable; do not rebuild" if marker else None)
    if retained:
        Path("retained-candidate.json").write_text(json.dumps(retained, indent=2) + "\n")
    bump = os.environ.get("BUMP", "auto")
    messages = ""
    if old:
        messages = subprocess.check_output(["git", "log", old["commit"] + "..HEAD", "--format=%B"], text=True)
    if bump == "auto":
        bump = "major" if re.search(r"(?m)^release:major\s*$", messages) else "minor" if re.search(r"(?m)^release:minor\s*$", messages) else "patch"
    release_version = next_version(old["version"] if old else None, bump)
    state = {"version": release_version, "upstream_digest": upstream, "upstream_source": sha, "agent_server_version": version, "fingerprint": current, "commit": os.environ["GITHUB_SHA"]}
    Path("state.json").write_text(json.dumps(state, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in {"build": str(not blocked and changed).lower(), "version": release_version, "upstream": upstream, "blocked": blocked or "",
                           "candidate_key": candidate_key(current, upstream),
                           "candidate": retained["candidate"] if retained else (marker or ""),
                           "evidence_run": retained["evidence_run"] if retained else "",
                           "evidence_attempt": retained["evidence_attempt"] if retained else ""}.items():
            output.write(f"{key}={value}\n")


def validate_publication_evidence(state, assessment, functional, policy, digest):
    assert policy["release_approved"] is True, "Owner release approval missing"
    assert functional["pass"] is True and functional["candidate"] == IMAGE + "@" + digest, "Missing functional pass for exact candidate"
    assert assessment["policy_sha256"] == hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(), "Assessment policy changed"
    assert assessment["pass"] and assessment["modification_pass"], "Security gate not passed"
    assert not assessment["blockers"] and not assessment["secrets"] and not assessment["introduced_high_critical"]
    assert assessment["candidate"] == IMAGE + "@" + digest, "Assessment is for another candidate"
    assert assessment["upstream"] == "ghcr.io/openhands/agent-server@" + state["upstream_digest"]
    # Recheck expiry at promotion, not only when the scan was assessed.
    spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_exceptions(policy["exceptions"], module.date.today())
    assert module.date.fromisoformat(policy["review_date"]) >= module.date.today(), "Security policy review overdue"
    assert all(r["approved_by"] in policy["acceptance_approvers"] for r in policy["exceptions"]), "Unauthorized acceptance owner"


def publish(digest):
    # All publication entry points require the same exact-bundle approval boundary.
    import promotion
    promotion.independent_initiator()
    promotion.protected_approval()
    import evidence
    state_evidence = json.loads(Path("state.json").read_text())
    run_evidence = json.loads(Path("reverified/trusted-run.json").read_text())
    evidence.verify_signature("oci://" + IMAGE + "@" + digest, run_evidence)
    evidence.verify_signature("functional-pass.json", run_evidence)
    evidence.validate_functional(json.loads(Path("functional-pass.json").read_text()), state_evidence,
                                 json.loads(Path("reverified/trusted-run.json").read_text()), IMAGE + "@" + digest)
    assert json.loads(Path("security/policy.json").read_text())["release_approved"] is True, "Owner release approval missing"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    state = json.loads(Path("state.json").read_text())
    assessment = json.loads(Path("security-assessment.json").read_text())
    validate_publication_evidence(state, assessment, json.loads(Path("functional-pass.json").read_text()),
                                  json.loads(Path("security/policy.json").read_text()), digest)
    state["image_digest"] = digest
    version = state["version"]
    immutable = [version, "sha-" + state["commit"]]
    existing_commit_tag = False
    for tag in immutable:
        result = subprocess.run(["docker", "buildx", "imagetools", "inspect", IMAGE + ":" + tag], capture_output=True, text=True)
        if result.returncode == 0:
            if tag.startswith("sha-") and digest not in result.stdout:
                existing_commit_tag = True
            else:
                assert digest in result.stdout, f"Refusing to overwrite immutable tag {tag}"
        else:
            assert "not found" in result.stderr.lower() or "manifest unknown" in result.stderr.lower(), result.stderr
    tags = [tag for tag in immutable if not (existing_commit_tag and tag.startswith("sha-"))] + [".".join(version.split(".")[:2])]
    for tag in tags:
        subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false", "--tag", IMAGE + ":" + tag, IMAGE + "@" + digest], check=True)
    Path("state.json").write_text(json.dumps(state, indent=2) + "\n")
    notes = f"""Validated linux/amd64 image: `{IMAGE}@{digest}`
Upstream: `ghcr.io/openhands/agent-server@{state['upstream_digest']}`
Upstream source: `{state['upstream_source']}`
Compatibility: Agent Server **{state['agent_server_version']}** only. Host compatibility requires the same approved version; no cross-version guarantee.
Git real-commit, PostgreSQL 17 backup/restore, API readiness, signals and security gates passed in CI.
Security inventory: {assessment['severity_counts']}; advertised fixes: {assessment['with_advertised_fix']}; no advertised fixes: {assessment['without_advertised_fix']}.
Accepted CVE exceptions: {assessment['accepted_exceptions']}. A passing risk gate is not a vulnerability-free image.
The attached security-assessment.md groups all findings and inherited risks by package/CVE; raw candidate/upstream scans are attached.
Full state and build fingerprint are attached in state.json. Previous versions remain available for rollback.

_This release was created by an AI-authored OpenHands workflow on behalf of the repository owner._
"""
    Path("release-notes.txt").write_text(notes)
    subprocess.run(["gh", "release", "create", "v" + version, "--target", state["commit"], "--title", "v" + version, "--notes-file", "release-notes.txt", "state.json", "security-assessment.md", "security-assessment.json", "security-gate.json", "trivy.json", "upstream-trivy.json", "scanner-version.json", "scanner-database.sha256", "functional-pass.json", "package-inventory.txt", "debian-tracker.json", "security/policy.json", "selection.json", "approval-summary.md"], check=True)
    subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false", "--tag", IMAGE + ":latest", IMAGE + "@" + digest], check=True)


if __name__ == "__main__":
    if sys.argv[1] == "plan":
        plan()
    elif sys.argv[1] == "record-candidate":
        record_candidate(sys.argv[2])
    elif sys.argv[1] == "publish":
        import promotion
        promotion.publish()
    else:
        raise SystemExit("Usage: release.py plan | publish DIGEST")
