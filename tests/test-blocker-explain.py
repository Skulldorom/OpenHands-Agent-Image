#!/usr/bin/env python3
"""Verify remediation verdicts fail closed without scanner or network access."""
from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("blockers", "scripts/explain-blockers.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def blocker(**overrides):
    row = {"package": "golang.org/x/net", "cve": "CVE-2026-78661", "severity": "HIGH",
           "origin": "inherited finding", "target": "usr/bin/gh", "installed": "v0.60.0",
           "fixed": "v0.62.0", "vendor_trixie": {}}
    row.update(overrides)
    return row


def evidence(shipped="v0.61.0", review_by=None):
    return {"review_by": review_by or (date.today() + timedelta(days=30)).isoformat(),
            "artifacts": [{"package": "gh", "target": "usr/bin/gh", "release": "v2.104.0",
                           "modules": {"golang.org/x/net": shipped}}]}


class VerdictTests(unittest.TestCase):
    def test_unfixed_newest_artifact_is_not_remediable(self):
        verdicts = module.explain({"blockers": [blocker()]}, evidence())
        self.assertEqual(verdicts[0]["state"], "no-supported-remediation")

    def test_newest_artifact_shipping_fix_requires_remediation(self):
        verdicts = module.explain({"blockers": [blocker()]}, evidence(shipped="v0.62.0"))
        self.assertEqual(verdicts[0]["state"], "remediation-available")

    def test_expired_evidence_is_undetermined(self):
        expired = (date.today() - timedelta(days=1)).isoformat()
        verdicts = module.explain({"blockers": [blocker()]}, evidence(review_by=expired))
        self.assertEqual(verdicts[0]["state"], "undetermined")

    def test_missing_artifact_is_undetermined(self):
        record = evidence()
        record["artifacts"][0]["target"] = "usr/bin/other"
        verdicts = module.explain({"blockers": [blocker()]}, record)
        self.assertEqual(verdicts[0]["state"], "undetermined")

    def test_debian_blocker_with_advertised_fix_requires_remediation(self):
        row = blocker(package="libxml2", target="ghcr.io/base@sha256:abc", fixed="2.12.7+dfsg-1")
        verdicts = module.explain({"blockers": [row]}, evidence())
        self.assertEqual(verdicts[0]["state"], "remediation-available")

    def test_debian_blocker_without_tracker_entry_is_undetermined(self):
        row = blocker(package="libxml2", target="ghcr.io/base@sha256:abc", fixed="")
        verdicts = module.explain({"blockers": [row]}, evidence())
        self.assertEqual(verdicts[0]["state"], "undetermined")

    def test_introduced_blocker_still_blocks(self):
        verdicts = module.explain({"blockers": [blocker(origin="added package/component")]}, evidence())
        self.assertEqual(verdicts[0]["state"], "no-supported-remediation")
        self.assertNotEqual(verdicts[0]["blocker"]["origin"], "inherited finding")

    def test_newer_unverified_release_cannot_inherit_old_binary_verdict(self):
        record = evidence(shipped="v0.62.0")
        record['artifacts'][0]['latest_release'] = 'v2.105.0'
        verdict = module.explain({'blockers': [blocker()]}, record)[0]
        self.assertEqual(verdict['state'], 'undetermined')
        self.assertIn('no verified binary inspection', verdict['reason'])

    def test_recorded_evidence_matches_published_versions(self):
        record = json.loads(Path("security/vendor-evidence.json").read_text())
        targets = {artifact["target"] for artifact in record["artifacts"]}
        self.assertIn("usr/bin/gh", targets)
        self.assertGreaterEqual(date.fromisoformat(record["review_by"]), date.today(),
                                "Vendor evidence expired; re-inspect newest release artifacts")
        for artifact in record["artifacts"]:
            self.assertTrue(artifact["modules"], artifact["target"])
            self.assertTrue(artifact["url"].endswith(artifact["release"]), artifact["target"])


if __name__ == "__main__":
    unittest.main()
