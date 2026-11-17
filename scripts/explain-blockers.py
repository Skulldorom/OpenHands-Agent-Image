#!/usr/bin/env python3
"""Explain every release blocker and prove whether supported remediation exists.

Reads the gate decision and the recorded vendor evidence. Exits non-zero when a
blocker has no remediation verdict, or when remediation exists but was not
applied, so a blocked gate can never be dismissed as unfixable by assertion.
"""
import argparse
import json
import re
from datetime import date
from pathlib import Path
import sys


def normalize(version):
    return tuple(int(part) for part in re.findall(r"\d+", version.split("+")[0])[:3])


def fixed_release_available(installed, fixed, artifact_version):
    """True when the recorded newest vendor artifact already ships the fix."""
    if not fixed:
        return False
    return normalize(artifact_version) >= normalize(fixed)


def debian_verdict(blocker):
    release = blocker.get("vendor_trixie") or {}
    versions = release.get("repositories") or {}
    if blocker["fixed"]:
        return False, f"Debian advertises fixed version {blocker['fixed']} in this target"
    if not release:
        return None, "no Debian tracker entry for this source package and CVE"
    unresolved = [suite for suite in ("trixie", "trixie-security")
                  if suite in versions and versions[suite] == blocker["installed"]]
    if not unresolved:
        return None, f"tracker release data does not show the installed version as unresolved: {versions}"
    return True, f"no supported Debian fix; {' and '.join(unresolved)} still at {blocker['installed']}"


def vendor_verdict(blocker, evidence):
    artifact = evidence["artifacts"].get(blocker["target"])
    if not artifact:
        return None, "no recorded inspection of the newest release artifact that ships this binary"
    latest = artifact.get("latest_release", artifact["release"])
    if latest != artifact["release"]:
        return None, (f"newest vendor release {latest} has no verified binary inspection; "
                      f"last inspected artifact {artifact['release']} is superseded")
    module = blocker["package"]
    shipped = artifact["modules"].get(module)
    if shipped is None:
        return None, f"recorded artifact {artifact['release']} does not embed {module}"
    if blocker["severity"] not in {"HIGH", "CRITICAL"}:
        return None, "only HIGH/CRITICAL module findings are assessed here"
    if fixed_release_available(blocker["installed"], blocker["fixed"], shipped):
        return False, (f"newest release {artifact['release']} ships {module} {shipped}, "
                       f"which satisfies the advertised fix {blocker['fixed']}")
    if not blocker["fixed"]:
        return True, (f"newest release {artifact['release']} still ships {module} {shipped}; "
                      "no fixed release advertised")
    return True, (f"newest release {artifact['release']} still ships {module} {shipped}; "
                  f"advertised fix {blocker['fixed']} has no supported binary")


def explain(gate, evidence):
    artifacts = {artifact["target"]: artifact for artifact in evidence["artifacts"]}
    stale = date.today() > date.fromisoformat(evidence["review_by"])
    verdicts = []
    for blocker in gate["blockers"]:
        if blocker["package"].startswith("github.com/") or blocker["package"].startswith("golang.org/"):
            remediable, reason = vendor_verdict(blocker, {"artifacts": artifacts})
        else:
            remediable, reason = debian_verdict(blocker)
        if stale:
            verdicts.append({"blocker": blocker, "state": "undetermined",
                             "reason": "vendor inspection evidence expired on " + evidence["review_by"]
                                       + "; re-inspect the newest release artifact"})
        elif remediable is None:
            verdicts.append({"blocker": blocker, "state": "undetermined", "reason": reason})
        elif remediable:
            verdicts.append({"blocker": blocker, "state": "no-supported-remediation", "reason": reason})
        else:
            verdicts.append({"blocker": blocker, "state": "remediation-available", "reason": reason})
    return verdicts


def binary(blocker):
    target = blocker["target"]
    return "OS package" if target.startswith("ghcr.io/") else target


def summary(verdicts):
    lines = ["| Package | CVE | Severity | Origin | Binary | Verdict | Evidence |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for verdict in verdicts:
        blocker = verdict["blocker"]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in [
            blocker["package"], blocker["cve"], blocker["severity"], blocker["origin"],
            binary(blocker), verdict["state"], verdict["reason"]]))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", default="security-gate.json")
    parser.add_argument("--evidence", default="security/vendor-evidence.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    if not Path(args.gate).exists():
        print(f"No gate decision at {args.gate}; no blockers to explain.")
        return 0
    gate = json.loads(Path(args.gate).read_text())
    evidence = json.loads(Path(args.evidence).read_text())
    if gate["pass"]:
        print("Gate passed; no blockers to explain.")
        return 0
    verdicts = explain(gate, evidence)
    introduced = [v for v in verdicts if v["blocker"]["origin"] != "inherited finding"]
    undetermined = [v for v in verdicts if v["state"] == "undetermined"]
    remediable = [v for v in verdicts if v["state"] == "remediation-available"]
    table = summary(verdicts)
    print(table)
    print()
    print(f"Blockers: {len(verdicts)}; inherited: {len(verdicts) - len(introduced)}; "
          f"introduced by this image: {len(introduced)}; "
          f"no supported remediation: {len(verdicts) - len(undetermined) - len(remediable)}; "
          f"remediation available: {len(remediable)}; undetermined: {len(undetermined)}")
    if introduced:
        print("BLOCKED: this image introduced findings that have no upstream baseline; fix the Dockerfile change.")
    if remediable:
        print("BLOCKED: a supported fixed artifact exists; apply it instead of recording an exception.")
    if undetermined:
        print("BLOCKED: at least one blocker has no recorded remediation verdict; inspect vendor artifacts first.")
    if args.summary:
        Path("security-blockers.md").write_text(
            "# Release blockers\n\n"
            f"Candidate: `{gate['candidate']}`\n\nUpstream: `{gate['upstream']}`\n\n"
            f"{table}\n\nNo blocker is waived. A blocked gate never promotes `latest` or creates a release.\n")
    return 0 if not (introduced or remediable or undetermined) else 1


if __name__ == "__main__":
    sys.exit(main())
