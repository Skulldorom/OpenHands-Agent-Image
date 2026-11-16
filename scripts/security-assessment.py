#!/usr/bin/env python3
"""Compare unsuppressed scans and write a separate fail-closed release decision."""
import argparse
import hashlib
from collections import Counter, defaultdict
from datetime import date
import json
import re
from pathlib import Path
import sys


def findings(report):
    for result in report.get("Results", []):
        packages = {p["Name"]: p for p in result.get("Packages", [])}
        for vulnerability in result.get("Vulnerabilities", []):
            yield result, packages.get(vulnerability["PkgName"], {}), vulnerability


def key(vulnerability):
    return vulnerability["PkgName"], vulnerability["VulnerabilityID"]

def scope(result):
    # OS results embed the scanned image reference, which differs per artifact;
    # language results must stay per-binary so a finding new in one binary is not
    # masked by the same package/CVE in a different inherited binary.
    return "os" if result.get("Class") == "os-pkgs" else result["Target"]

def identity(result, vulnerability):
    return scope(result), result.get("Class"), result.get("Type"), *key(vulnerability)

def metadata_hash(vulnerability):
    fields = {k: vulnerability.get(k) for k in ("Severity", "FixedVersion", "Status", "CVSS", "References", "Title", "Description", "SeveritySource", "DataSource")}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def validate_exceptions(records, today):
    seen = set()
    scopes = set()
    required = {"id", "cve", "package", "installed", "target", "result_class", "result_type",
                "upstream_digest", "candidate_digest", "justification", "compensating_controls",
                "approved_by", "approval_date", "expires", "status", "metadata_sha256"}
    for record in records:
        assert set(record) == required, "Invalid acceptance schema"
        assert all(isinstance(record[k], str) and record[k].strip() for k in required), "Empty acceptance field"
        assert not any("*" in record[k] for k in required), "Wildcards are forbidden"
        assert record["status"] == "approved", "Acceptance not explicitly approved"
        assert record["id"] not in seen, "Duplicate acceptance ID"
        seen.add(record["id"])
        exact = tuple(record[k] for k in ("cve", "package", "installed", "target", "result_class", "result_type", "upstream_digest", "candidate_digest"))
        assert exact not in scopes, "Duplicate acceptance scope"
        scopes.add(exact)
        assert re.fullmatch(r"[a-f0-9]{64}", record["metadata_sha256"]), "Invalid metadata fingerprint"
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", record["cve"]), "Invalid CVE"
        for field in ("upstream_digest", "candidate_digest"):
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", record[field]), "Invalid acceptance digest"
        assert date.fromisoformat(record["approval_date"]) <= today <= date.fromisoformat(record["expires"]), "Acceptance expired or not yet valid"


def accepted_record(row, result, records, candidate_ref, upstream_ref):
    # A CVE in another version or binary is never evidence of inheritance.
    if row["origin"] != "inherited finding" or row["installed"] not in row["upstream_installed"]:
        return None
    for record in records:
        if (record["cve"] == row["cve"] and record["package"] == row["package"]
                and record["metadata_sha256"] == row["metadata_sha256"]
                and record["installed"] == row["installed"] and record["target"] == row["target"]
                and record["result_class"] == result.get("Class") and record["result_type"] == result.get("Type")
                and candidate_ref == "ghcr.io/skulldorom/openhands-agent@" + record["candidate_digest"]
                and upstream_ref == "ghcr.io/openhands/agent-server@" + record["upstream_digest"]):
            return record
    return None


def validate_scan(report, expected):
    assert report["ArtifactName"] == expected, "Scan artifact mismatch"
    assert report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image", "Unsupported scan schema"
    assert report["Metadata"]["OS"]["Family"] == "debian" and report["Metadata"]["OS"]["Name"].startswith("13"), "Unsupported OS"
    assert isinstance(report.get("Results"), list) and report["Results"], "Empty scan"
    assert any(r.get("Class") == "os-pkgs" and r.get("Type") == "debian" and r.get("Packages") for r in report["Results"]), "Missing OS inventory"
    for result in report["Results"]:
        assert isinstance(result.get("Target"), str) and result["Target"]
        assert not result.get("Misconfigurations") and not result.get("MisconfSummary"), "Unexpected scan format"
        assert not result.get("SuppressedFindings"), "Suppressed scanner findings forbidden"
        for vulnerability in result.get("Vulnerabilities", []):
            for field in ("PkgName", "VulnerabilityID", "InstalledVersion", "Severity"):
                assert isinstance(vulnerability.get(field), str) and vulnerability[field], "Malformed vulnerability"
            assert vulnerability["Severity"] in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, "Unsupported severity"
        assert isinstance(result.get("Secrets", []), list), "Malformed secrets inventory"


def assess(candidate, upstream, policy, tracker, expected_candidate, expected_upstream):
    validate_scan(candidate, expected_candidate)
    validate_scan(upstream, expected_upstream)
    assert candidate["ArtifactName"] == expected_candidate, "Candidate digest mismatch"
    assert upstream["ArtifactName"] == expected_upstream, "Upstream digest mismatch"
    assert candidate.get("Results") and upstream.get("Results"), "Empty scan"
    assert candidate["Metadata"]["OS"]["Family"] == "debian"
    assert candidate["Metadata"]["OS"]["Name"].startswith("13"), "Unreviewed Debian release"
    assert policy["block_all_critical"] is True
    assert date.fromisoformat(policy["review_date"]) >= date.today(), "Security policy review overdue"
    validate_exceptions(policy["exceptions"], date.today())
    assert all(record["approved_by"] in policy["acceptance_approvers"] for record in policy["exceptions"]), "Unauthorized acceptance owner"
    old = defaultdict(list)
    for result, package, vulnerability in findings(upstream):
        old[identity(result, vulnerability)].append(vulnerability)
    upstream_packages = {
        (scope(result), result.get("Class"), result.get("Type"), package["Name"])
        for result in upstream["Results"] for package in result.get("Packages", [])
    }
    rows = []
    accepted = []
    consumed = set()
    for result, package, vulnerability in findings(candidate):
        inherited = [v for v in old.get(identity(result, vulnerability), [])
                     if v["InstalledVersion"] == vulnerability["InstalledVersion"]]
        source = package.get("SrcName", vulnerability["PkgName"])
        vendor = tracker.get(source, {}).get(vulnerability["VulnerabilityID"], {})
        release = vendor.get("releases", {}).get("trixie", {})
        severity = vulnerability["Severity"]
        origin = "inherited finding" if inherited else (
            "new finding in inherited package" if (scope(result), result.get("Class"), result.get("Type"), vulnerability["PkgName"]) in upstream_packages
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
        row = {
            "package": vulnerability["PkgName"], "source_package": source,
            "metadata_sha256": metadata_hash(vulnerability),
            "cve": vulnerability["VulnerabilityID"], "severity": severity,
            "installed": vulnerability["InstalledVersion"], "fixed": vulnerability.get("FixedVersion", ""),
            "status": vulnerability.get("Status", "unknown"), "target": result["Target"],
            "origin": origin, "upstream_installed": sorted({v["InstalledVersion"] for v in inherited}),
            "vendor_trixie": release, "vendor_scope": vendor.get("scope", "unknown"),
            "title": vulnerability.get("Title", ""), "description": vulnerability.get("Description", ""),
            "references": vulnerability.get("References", []), "cvss": vulnerability.get("CVSS", {}),
            "blocking_reasons": reasons,
            "exposure": "Potentially reachable in arbitrary agent workloads; no negative reachability or exploitability claim.",
        }
        record = accepted_record(row, result, policy["exceptions"], expected_candidate, expected_upstream)
        row["accepted_exception"] = record["id"] if record and reasons else None
        if row["accepted_exception"]:
            assert record["id"] not in consumed, "Acceptance reused for multiple findings"
            consumed.add(record["id"])
            accepted.append(record)
        rows.append(row)
    assert consumed == {r["id"] for r in policy["exceptions"]}, "Renewed risk acceptance required: candidate, upstream, finding metadata or exact scope changed"
    secrets = [dict(target=result["Target"], rule=secret.get("RuleID"), title=secret.get("Title"))
               for result in candidate["Results"] for secret in result.get("Secrets", [])]
    blockers = [row for row in rows if row["blocking_reasons"] and not row["accepted_exception"]]
    removed = sorted({key(v) for _, _, v in findings(upstream)} - {key(v) for _, _, v in findings(candidate)})
    introduced = [row for row in rows if row["severity"] in {"HIGH", "CRITICAL"}
                  and row["origin"] != "inherited finding"]
    return {"modification_pass": not introduced and not secrets, "introduced_high_critical": introduced,
            "candidate": expected_candidate, "upstream": expected_upstream,
            "policy_sha256": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
            "policy_owner": policy["owner"], "policy_review_date": policy["review_date"],
            "severity_counts": dict(Counter(row["severity"] for row in rows)),
            "with_advertised_fix": sum(bool(row["fixed"]) for row in rows),
            "without_advertised_fix": sum(not row["fixed"] for row in rows),
            "origin_counts": dict(Counter(row["origin"] for row in rows)),
            "removed_package_cves": removed, "findings": rows, "secrets": secrets,
            "blockers": blockers, "accepted_exceptions": accepted, "pass": not blockers and not secrets and not introduced}


def markdown(assessment):
    lines = ["# Candidate security assessment", "", f"Candidate: `{assessment['candidate']}`",
             f"Upstream: `{assessment['upstream']}`", "",
             f"Release gate: **{'PASS' if assessment['pass'] else 'BLOCKED'}**; secrets: {len(assessment['secrets'])}.",
             f"All-severity inventory: {assessment['severity_counts']}.",
             f"Advertised fix: {assessment['with_advertised_fix']}; no advertised fix: {assessment['without_advertised_fix']}.",
             f"Origins: {assessment['origin_counts']}.",
             f"Accepted exceptions: {len(assessment['accepted_exceptions'])}. Accepted does not mean fixed or harmless.",
             "Unfixed does not mean safe. Module fixes do not guarantee supported binary fixes.", "",
             "## Findings grouped by package and CVE", "",
             "Package | Target | CVE | Severity | Installed | Advertised fix | Debian trixie | Origin | Gate",
             "--- | --- | --- | --- | --- | --- | --- | --- | ---"]
    for row in sorted(assessment["findings"], key=lambda r: (r["package"], r["cve"], r["target"])):
        values = [row["package"], row["target"], row["cve"], row["severity"], row["installed"], row["fixed"] or "none",
                  json.dumps(row["vendor_trixie"], sort_keys=True), row["origin"],
                  ("ACCEPTED " + row["accepted_exception"] + ": " if row["accepted_exception"] else "")
                  + ("; ".join(row["blocking_reasons"]) or "inventory; no supported fix advertised")]
        lines.append(" | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in values))
    lines += ["", "## Exact approved risk records", "",
              "```json", json.dumps(assessment["accepted_exceptions"], indent=2), "```", ""]
    lines += ["", "## Removed upstream package/CVE pairs", "", *[f"- {p}: {c}" for p, c in assessment["removed_package_cves"]],
              "", "Reports are generated by an AI-authored OpenHands workflow on behalf of the repository owner."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    for name in ["candidate", "upstream", "policy", "tracker", "candidate-ref", "upstream-ref"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    load = lambda name: json.loads(Path(name).read_text())
    assessment = assess(load(args.candidate), load(args.upstream), load(args.policy), load(args.tracker),
                        args.candidate_ref, args.upstream_ref)
    Path("security-assessment.json").write_text(json.dumps(assessment, indent=2) + "\n")
    Path("security-assessment.md").write_text(markdown(assessment))
    Path("security-gate.json").write_text(json.dumps({k: assessment[k] for k in
        ["candidate", "upstream", "pass", "blockers", "secrets", "accepted_exceptions"]}, indent=2) + "\n")
    print(f"Security gate: {'PASS' if assessment['pass'] else 'BLOCKED'}, {len(assessment['blockers'])} vulnerability instances, {len(assessment['secrets'])} secrets")
    return 0 if args.report_only or assessment["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
