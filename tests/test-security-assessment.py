#!/usr/bin/env python3
"""Exercise real policy evaluation without scanner or network mocks."""
from copy import deepcopy
from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("assessment", "scripts/security-assessment.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(Path("security/policy.json").read_text())
        self.base = {"ArtifactName": "base@sha256:abc", "Metadata": {"OS": {"Family": "debian", "Name": "13.7"}},
                     "Results": [{"Target": "debian", "Class": "os-pkgs", "Type": "debian",
                                  "Packages": [{"Name": "libxml2"}], "Vulnerabilities": []}]}
        self.candidate = deepcopy(self.base)
        self.candidate["ArtifactName"] = "candidate@sha256:def"

    def run_assessment(self):
        return module.assess(self.candidate, self.base, self.policy, {},
                             "candidate@sha256:def", "base@sha256:abc")

    def vulnerability(self, severity="HIGH", cve="CVE-2026-0001", fixed=""):
        return {"PkgName": "libxml2", "VulnerabilityID": cve, "Severity": severity,
                "InstalledVersion": "1.0", "FixedVersion": fixed}

    def test_fixed_inherited_high_blocks_and_unfixed_is_retained(self):
        vulnerabilities = [self.vulnerability(fixed="2.0"), self.vulnerability(cve="CVE-2026-0002")]
        self.base["Results"][0]["Vulnerabilities"] = deepcopy(vulnerabilities)
        self.candidate["Results"][0]["Vulnerabilities"] = deepcopy(vulnerabilities)
        result = self.run_assessment()
        self.assertFalse(result["pass"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual([row["cve"] for row in result["blockers"]], ["CVE-2026-0001"])
        self.assertTrue(result["modification_pass"])

    def test_unfixed_inherited_high_is_inventory_only(self):
        vulnerability = self.vulnerability()
        self.base["Results"][0]["Vulnerabilities"] = [deepcopy(vulnerability)]
        self.candidate["Results"][0]["Vulnerabilities"] = [deepcopy(vulnerability)]
        result = self.run_assessment()
        self.assertEqual(result["origin_counts"], {"inherited finding": 1})
        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["pass"])
        self.assertTrue(result["modification_pass"])

    def test_introduced_high_blocks_without_upstream_baseline(self):
        self.candidate["Results"][0]["Vulnerabilities"] = [self.vulnerability(cve="CVE-2026-0009")]
        result = self.run_assessment()
        self.assertEqual(result["findings"][0]["origin"], "new finding in inherited package")
        self.assertFalse(result["modification_pass"])
        self.assertFalse(result["pass"])

    def test_added_package_high_blocks(self):
        self.candidate["Results"].append({"Target": "pg", "Class": "lang-pkgs", "Type": "gobinary",
                                         "Packages": [{"Name": "example/mod"}],
                                         "Vulnerabilities": [{"PkgName": "example/mod", "VulnerabilityID": "CVE-2026-0010",
                                                              "Severity": "HIGH", "InstalledVersion": "v1"}]})
        result = self.run_assessment()
        self.assertEqual(result["findings"][0]["origin"], "added package/component")
        self.assertFalse(result["pass"])

    def test_critical_and_designated_unfixed_block(self):
        for v in [self.vulnerability("CRITICAL"), self.vulnerability(cve="CVE-2026-41567")]:
            self.candidate["Results"][0]["Vulnerabilities"] = [v]
            self.assertFalse(self.run_assessment()["pass"])

    def test_secret_blocks_any_severity(self):
        self.candidate["Results"][0]["Secrets"] = [{"RuleID": "test", "Severity": "LOW"}]
        self.assertFalse(self.run_assessment()["pass"])

    def test_origin_and_removed_pairs(self):
        self.base["Results"][0]["Vulnerabilities"] = [self.vulnerability(), self.vulnerability(cve="CVE-2026-0003")]
        self.candidate["Results"][0]["Vulnerabilities"] = [self.vulnerability()]
        result = self.run_assessment()
        self.assertEqual(result["findings"][0]["origin"], "inherited finding")
        self.assertEqual(result["removed_package_cves"], [("libxml2", "CVE-2026-0003")])

    def test_same_cve_in_another_binary_is_not_inherited(self):
        upstream_result = {"Target": "usr/bin/gh", "Class": "lang-pkgs", "Type": "gobinary",
                           "Packages": [{"Name": "golang.org/x/net"}],
                           "Vulnerabilities": [{"PkgName": "golang.org/x/net", "VulnerabilityID": "CVE-2026-78661",
                                                "Severity": "HIGH", "InstalledVersion": "v0.61.0"}]}
        added_result = {"Target": "usr/bin/newtool", "Class": "lang-pkgs", "Type": "gobinary",
                        "Packages": [{"Name": "golang.org/x/net"}],
                        "Vulnerabilities": [{"PkgName": "golang.org/x/net", "VulnerabilityID": "CVE-2026-78661",
                                             "Severity": "HIGH", "InstalledVersion": "v0.60.0"}]}
        self.base["Results"].append(upstream_result)
        self.candidate["Results"] += [deepcopy(upstream_result), added_result]
        result = self.run_assessment()
        origins = {row["target"]: row["origin"] for row in result["findings"]}
        self.assertEqual(origins["usr/bin/gh"], "inherited finding")
        self.assertEqual(origins["usr/bin/newtool"], "added package/component")
        self.assertFalse(result["pass"])

    def test_identity_and_unapproved_exceptions_fail_closed(self):
        self.candidate["ArtifactName"] = "wrong"
        with self.assertRaises(AssertionError):
            self.run_assessment()
        self.candidate["ArtifactName"] = "candidate@sha256:def"
        self.policy["exceptions"] = [{}]
        with self.assertRaises(AssertionError):
            self.run_assessment()


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.record = deepcopy(json.loads(Path("security/proposed-acceptances.json").read_text())["records"][1])
        self.record.update(status="approved", approved_by="Test owner", approval_date=date.today().isoformat(),
                           expires=(date.today() + timedelta(days=1)).isoformat())
        self.policy = json.loads(Path("security/policy.json").read_text())
        self.policy["exceptions"] = [self.record]
        self.policy["acceptance_approvers"] = ["Test owner"]
        self.policy["review_date"] = self.record["expires"]
        self.candidate_ref = "ghcr.io/skulldorom/openhands-agent@" + self.record["candidate_digest"]
        self.upstream_ref = "ghcr.io/openhands/agent-server@" + self.record["upstream_digest"]
        result = {"Target": self.record["target"], "Class": self.record["result_class"], "Type": self.record["result_type"],
                  "Packages": [{"Name": self.record["package"]}],
                  "Vulnerabilities": [{"PkgName": self.record["package"], "InstalledVersion": self.record["installed"],
                                       "VulnerabilityID": self.record["cve"], "Severity": "HIGH", "FixedVersion": "fixed"}]}
        self.candidate = {"ArtifactName": self.candidate_ref, "Metadata": {"OS": {"Family": "debian", "Name": "13.7"}}, "Results": [result]}
        self.upstream = deepcopy(self.candidate)
        self.upstream["ArtifactName"] = self.upstream_ref

    def assess(self):
        return module.assess(self.candidate, self.upstream, self.policy, {}, self.candidate_ref, self.upstream_ref)

    def test_exact_acceptance_keeps_inventory_and_original_reasons(self):
        result = self.assess()
        self.assertTrue(result["pass"])
        self.assertTrue(result["findings"][0]["blocking_reasons"])
        self.assertEqual(result["accepted_exceptions"], [self.record])
        self.assertIn(self.record["id"], module.markdown(result))

    def test_each_scope_change_blocks(self):
        for field, value in {"cve": "CVE-2026-99999", "package": "other/module", "installed": "v99",
                             "target": "usr/bin/other", "upstream_digest": "sha256:" + "a" * 64,
                             "candidate_digest": "sha256:" + "b" * 64, "result_class": "other", "result_type": "other"}.items():
            with self.subTest(field=field):
                previous = self.record[field]
                self.record[field] = value
                self.assertFalse(self.assess()["pass"])
                self.record[field] = previous

    def test_expired_future_unapproved_malformed_and_wildcards_fail_closed(self):
        for field, value in {"expires": (date.today() - timedelta(days=1)).isoformat(),
                             "approval_date": (date.today() + timedelta(days=1)).isoformat(),
                             "status": "proposed", "target": "*", "approved_by": "Unauthorized owner", "upstream_digest": "invalid"}.items():
            with self.subTest(field=field):
                previous = self.record[field]
                self.record[field] = value
                with self.assertRaises((AssertionError, ValueError)):
                    self.assess()
                self.record[field] = previous

    def test_changed_upstream_version_cannot_be_inherited(self):
        self.upstream["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "different"
        result = self.assess()
        self.assertFalse(result["pass"])
        self.assertFalse(result["modification_pass"])
        self.assertEqual(result["accepted_exceptions"], [])

    def test_secrets_and_unmatched_introduced_findings_always_block(self):
        self.candidate["Results"][0]["Secrets"] = [{"RuleID": "secret"}]
        self.assertFalse(self.assess()["pass"])
        del self.candidate["Results"][0]["Secrets"]
        for severity in ("HIGH", "CRITICAL"):
            v = deepcopy(self.candidate["Results"][0]["Vulnerabilities"][0])
            v.update(VulnerabilityID="CVE-2026-99999", Severity=severity)
            self.candidate["Results"][0]["Vulnerabilities"].append(v)
            self.assertFalse(self.assess()["pass"])
            self.candidate["Results"][0]["Vulnerabilities"].pop()

    def test_unapproved_inherited_finding_blocks(self):
        self.policy["exceptions"] = []
        self.assertFalse(self.assess()["pass"])

    def test_proposed_records_are_inactive_and_rejected(self):
        policy = json.loads(Path("security/policy.json").read_text())
        self.assertEqual(policy["exceptions"], [])
        self.assertFalse(policy["release_approved"])
        proposed = json.loads(Path("security/proposed-acceptances.json").read_text())["records"]
        self.assertEqual(len(proposed), 7)
        with self.assertRaises(AssertionError):
            module.validate_exceptions(proposed, date.today())

if __name__ == "__main__":
    unittest.main()
