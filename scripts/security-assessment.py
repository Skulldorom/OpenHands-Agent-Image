#!/usr/bin/env python3
"""Compare unsuppressed scans and write a separate fail-closed release decision."""
import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import sys


def findings(report):
    for result in report.get("Results", []):
        packages = {p["Name"]: p for p in result.get("Packages", [])}
        for vulnerability in result.get("Vulnerabilities", []):
            yield result, packages.get(vulnerability["PkgName"], {}), vulnerability


def key(vulnerability):
    return vulnerability["PkgName"], vulnerability["VulnerabilityID"]


def assess(candidate, upstream, policy, tracker, expected_candidate, expected_upstream):
    assert candidate["ArtifactName"] == expected_candidate, "Candidate digest mismatch"
    assert upstream["ArtifactName"] == expected_upstream, "Upstream digest mismatch"
    assert candidate.get("Results") and upstream.get("Results"), "Empty scan"
    assert candidate["Metadata"]["OS"]["Family"] == "debian"
    assert candidate["Metadata"]["OS"]["Name"].startswith("13"), "Unreviewed Debian release"
    assert policy["block_all_critical"] is True
    assert date.fromisoformat(policy["review_date"]) >= date.today(), "Security policy review overdue"
    # Exceptions require a separate code review of matching semantics before activation.
    assert policy["exceptions"] == [], "No exception mechanism approved; fail closed"
    old = defaultdict(list)
    for result, package, vulnerability in findings(upstream):
        old[(result.get("Class"), result.get("Type"), *key(vulnerability))].append(vulnerability)
    upstream_packages = {
        (result.get("Class"), result.get("Type"), package["Name"])
        for result in upstream["Results"] for package in result.get("Packages", [])
    }
    rows = []
    for result, package, vulnerability in findings(candidate):
        identity = (result.get("Class"), result.get("Type"), *key(vulnerability))
        inherited = old.get(identity, [])
        source = package.get("SrcName", vulnerability["PkgName"])
        vendor = tracker.get(source, {}).get(vulnerability["VulnerabilityID"], {})
        release = vendor.get("releases", {}).get("trixie", {})
        severity = vulnerability["Severity"]
        origin = "inherited finding" if inherited else (
            "new finding in inherited package" if (result.get("Class"), result.get("Type"), vulnerability["PkgName"]) in upstream_packages
            else "added package/component")
        reasons = []
        if severity == "CRITICAL":
            reasons.append("critical exposure not accepted")
        if severity in {"HIGH", "CRITICAL"}:
            if origin != "inherited finding":
                # Risk this image introduces has no upstream baseline to defer to.
                reasons.append("introduced by this image; upstream baseline lacks this finding")
            if vulnerability.get("FixedVersion"):
                reasons.append("fixed version advertised; supported package/binary remediation must be verified")
            if vulnerability["VulnerabilityID"] in policy["high_risk_cves"]:
                reasons.append(policy["high_risk_cves"][vulnerability["VulnerabilityID"]])
        rows.append({
            "package": vulnerability["PkgName"], "source_package": source,
            "cve": vulnerability["VulnerabilityID"], "severity": severity,
            "installed": vulnerability["InstalledVersion"], "fixed": vulnerability.get("FixedVersion", ""),
            "status": vulnerability.get("Status", "unknown"), "target": result["Target"],
            "origin": origin, "upstream_installed": sorted({v["InstalledVersion"] for v in inherited}),
            "vendor_trixie": release, "vendor_scope": vendor.get("scope", "unknown"),
            "title": vulnerability.get("Title", ""), "description": vulnerability.get("Description", ""),
            "references": vulnerability.get("References", []), "cvss": vulnerability.get("CVSS", {}),
            "blocking_reasons": reasons,
            "exposure": "Potentially reachable in arbitrary agent workloads; no negative reachability or exploitability claim.",
        })
    secrets = [dict(target=result["Target"], rule=secret.get("RuleID"), title=secret.get("Title"))
               for result in candidate["Results"] for secret in result.get("Secrets", [])]
    blockers = [row for row in rows if row["blocking_reasons"]]
    removed = sorted({key(v) for _, _, v in findings(upstream)} - {key(v) for _, _, v in findings(candidate)})
    return {"candidate": expected_candidate, "upstream": expected_upstream,
            "policy_owner": policy["owner"], "policy_review_date": policy["review_date"],
            "severity_counts": dict(Counter(row["severity"] for row in rows)),
            "with_advertised_fix": sum(bool(row["fixed"]) for row in rows),
            "without_advertised_fix": sum(not row["fixed"] for row in rows),
            "origin_counts": dict(Counter(row["origin"] for row in rows)),
            "removed_package_cves": removed, "findings": rows, "secrets": secrets,
            "blockers": blockers, "accepted_exceptions": [], "pass": not blockers and not secrets}


def markdown(assessment):
    lines = ["# Candidate security assessment", "", f"Candidate: `{assessment['candidate']}`",
             f"Upstream: `{assessment['upstream']}`", "",
             f"Release gate: **{'PASS' if assessment['pass'] else 'BLOCKED'}**; secrets: {len(assessment['secrets'])}.",
             f"All-severity inventory: {assessment['severity_counts']}.",
             f"Advertised fix: {assessment['with_advertised_fix']}; no advertised fix: {assessment['without_advertised_fix']}.",
             f"Origins: {assessment['origin_counts']}.",
             "Accepted exceptions: none. Unfixed does not mean safe. Module fixes do not guarantee supported binary fixes.", "",
             "## Findings grouped by package and CVE", "",
             "Package | CVE | Severity | Installed | Advertised fix | Debian trixie | Origin | Gate",
             "--- | --- | --- | --- | --- | --- | --- | ---"]
    for row in sorted(assessment["findings"], key=lambda r: (r["package"], r["cve"], r["target"])):
        values = [row["package"], row["cve"], row["severity"], row["installed"], row["fixed"] or "none",
                  json.dumps(row["vendor_trixie"], sort_keys=True), row["origin"],
                  "; ".join(row["blocking_reasons"]) or "inventory; no supported fix advertised"]
        lines.append(" | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in values))
    lines += ["", "## Removed upstream package/CVE pairs", "", *[f"- {p}: {c}" for p, c in assessment["removed_package_cves"]],
              "", "Reports are generated by an AI-authored OpenHands workflow on behalf of the repository owner."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    for name in ["candidate", "upstream", "policy", "tracker", "candidate-ref", "upstream-ref"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    load = lambda name: json.loads(Path(name).read_text())
    assessment = assess(load(args.candidate), load(args.upstream), load(args.policy), load(args.tracker),
                        args.candidate_ref, args.upstream_ref)
    Path("security-assessment.json").write_text(json.dumps(assessment, indent=2) + "\n")
    Path("security-assessment.md").write_text(markdown(assessment))
    Path("security-gate.json").write_text(json.dumps({k: assessment[k] for k in
        ["candidate", "upstream", "pass", "blockers", "secrets", "accepted_exceptions"]}, indent=2) + "\n")
    print(f"Security gate: {'PASS' if assessment['pass'] else 'BLOCKED'}, {len(assessment['blockers'])} vulnerability instances, {len(assessment['secrets'])} secrets")
    return 0 if assessment["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
