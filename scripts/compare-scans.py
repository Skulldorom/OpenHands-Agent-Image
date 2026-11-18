"""Report upstream findings and block image additions without printing secret evidence."""

import json
from pathlib import Path
import sys


def vulnerabilities(report):
    findings = {}
    for result in report.get("Results", []):
        kind = result.get("Class")
        target = "" if kind == "os-pkgs" else result.get("Target")
        for entry in result.get("Vulnerabilities", []):
            key = (kind, result.get("Type"), target, entry["VulnerabilityID"],
                   entry["PkgName"], entry["InstalledVersion"])
            findings[key] = entry["Severity"]
    return findings


def secrets(report):
    return {
        (result["Target"], item["RuleID"], item.get("StartLine"), item.get("Match"),
         item.get("Layer", {}).get("DiffID"))
        for result in report.get("Results", [])
        for item in result.get("Secrets", [])
    }


def diff_ids(report):
    return report["Metadata"]["DiffIDs"]


def main(directory):
    source, upstream, candidate = (
        json.loads((directory / f"{name}.json").read_text())
        for name in ("source", "upstream", "candidate")
    )
    base, extended = diff_ids(upstream), diff_ids(candidate)
    if not base or len(extended) <= len(base) or extended[:len(base)] != base:
        sys.exit("Candidate layers do not extend the resolved upstream image")

    baseline = vulnerabilities(upstream)
    current = vulnerabilities(candidate)
    levels = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    new = {key: value for key, value in current.items()
           if key not in baseline or levels.index(value) > levels.index(baseline[key])}
    for severity in levels:
        inherited = sorted({key[3] for key, value in current.items()
                            if value == severity and key not in new})
        introduced = sorted({key[3] for key, value in new.items() if value == severity})
        print(f"- {severity} inherited: {', '.join(inherited) or 'none'}")
        print(f"- {severity} added or worsened: {', '.join(introduced) or 'none'}")

    inherited_secrets = {item for item in secrets(upstream) if item[-1] in base}
    candidate_secrets = secrets(candidate)
    added_secrets = candidate_secrets - inherited_secrets
    print(f"- Source secret detections: {len(secrets(source))}")
    print(f"- Upstream secret detections: {len(secrets(upstream))}")
    print(f"- Candidate secret detections outside matched upstream layers: {len(added_secrets)}")
    if secrets(source) or added_secrets or {"HIGH", "CRITICAL"}.intersection(new.values()):
        sys.exit("Image validation blocked by added vulnerabilities or secret detections")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
