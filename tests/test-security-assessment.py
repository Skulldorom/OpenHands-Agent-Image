#!/usr/bin/env python3
"""Exercise real policy evaluation without scanner or network mocks."""
from copy import deepcopy
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

    def test_fixed_high_blocks_and_unfixed_is_retained(self):
        self.candidate["Results"][0]["Vulnerabilities"] = [self.vulnerability(fixed="2.0"), self.vulnerability(cve="CVE-2026-0002")]
        result = self.run_assessment()
        self.assertFalse(result["pass"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(len(result["blockers"]), 1)

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

    def test_identity_and_unapproved_exceptions_fail_closed(self):
        self.candidate["ArtifactName"] = "wrong"
        with self.assertRaises(AssertionError):
            self.run_assessment()
        self.candidate["ArtifactName"] = "candidate@sha256:def"
        self.policy["exceptions"] = [{}]
        with self.assertRaises(AssertionError):
            self.run_assessment()


if __name__ == "__main__":
    unittest.main()
