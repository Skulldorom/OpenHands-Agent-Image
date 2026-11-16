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


def fingerprint():
    files = subprocess.check_output(["git", "ls-files", "Dockerfile", "scripts", "tests", ".github/workflows", ".dockerignore", "compatibility.json", "security/policy.json"], text=True).splitlines()
    h = hashlib.sha256()
    for name in files:
        h.update(name.encode() + b"\0" + Path(name).read_bytes())
    return h.hexdigest()


def reusable_blocker(state, gate, functional, current, upstream):
    return (state["fingerprint"] == current and state["upstream_digest"] == upstream
            and functional["pass"] and functional["candidate"] == gate["candidate"]
            and gate["upstream"] == "ghcr.io/openhands/agent-server@" + upstream
            and not gate["pass"] and bool(gate["blockers"]))

def previous_blocked_attempt(current, upstream):
    runs = json.loads(gh("api", f"repos/{REPO}/actions/runs?branch=main&status=completed&per_page=50"))
    for run in runs["workflow_runs"]:
        if run["name"] not in {"CI", "Daily upstream update"}:
            continue
        artifacts = json.loads(gh("api", f"repos/{REPO}/actions/runs/{run['id']}/artifacts"))
        for artifact in artifacts["artifacts"]:
            if artifact["expired"] or not artifact["name"].startswith("validation-"):
                continue
            raw = subprocess.check_output(["gh", "api", f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"])
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if not {"state.json", "security-gate.json", "functional-pass.json"} <= set(archive.namelist()):
                    continue
                state = json.loads(archive.read("state.json"))
                gate = json.loads(archive.read("security-gate.json"))
                functional = json.loads(archive.read("functional-pass.json"))
                if reusable_blocker(state, gate, functional, current, upstream):
                    return run["html_url"]
    return None

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
    changed = not old or old["fingerprint"] != current or old["upstream_digest"] != upstream
    blocked = previous_blocked_attempt(current, upstream) if changed else None
    bump = os.environ.get("BUMP", "auto")
    messages = ""
    if old:
        messages = subprocess.check_output(["git", "log", old["commit"] + "..HEAD", "--format=%B"], text=True)
    if bump == "auto":
        bump = "major" if re.search(r"(?m)^release:major\s*$", messages) else "minor" if re.search(r"(?m)^release:minor\s*$", messages) else "patch"
    if not old:
        release_version = "1.0.0"
    else:
        major, minor, patch = map(int, old["version"].split("."))
        release_version = f"{major+1}.0.0" if bump == "major" else f"{major}.{minor+1}.0" if bump == "minor" else f"{major}.{minor}.{patch+1}"
    state = {"version": release_version, "upstream_digest": upstream, "upstream_source": sha, "agent_server_version": version, "fingerprint": current, "commit": os.environ["GITHUB_SHA"]}
    Path("state.json").write_text(json.dumps(state, indent=2) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in {"build": str(not blocked and (changed or os.environ.get("BUMP", "auto") != "auto")).lower(), "version": release_version, "upstream": upstream, "blocked": blocked or ""}.items():
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
    subprocess.run(["gh", "release", "create", "v" + version, "--target", state["commit"], "--title", "v" + version, "--notes-file", "release-notes.txt", "state.json", "security-assessment.md", "security-assessment.json", "security-gate.json", "trivy.json", "upstream-trivy.json", "scanner-version.json", "scanner-database.sha256", "functional-pass.json", "package-inventory.txt", "debian-tracker.json", "security/policy.json"], check=True)
    subprocess.run(["docker", "buildx", "imagetools", "create", "--prefer-index=false", "--tag", IMAGE + ":latest", IMAGE + "@" + digest], check=True)


if __name__ == "__main__":
    if sys.argv[1] == "plan":
        plan()
    elif sys.argv[1] == "publish":
        publish(sys.argv[2])
    else:
        raise SystemExit("Usage: release.py plan | publish DIGEST")
