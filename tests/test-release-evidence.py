#!/usr/bin/env python3
"""Verify exact retained evidence decisions without network mocks."""
import importlib.util
import hashlib
from datetime import date, timedelta
import json
from copy import deepcopy
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("release", "scripts/release.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.state = {"fingerprint": "inputs", "upstream_digest": "base"}
        self.gate = {"candidate": "image@candidate", "upstream": "ghcr.io/openhands/agent-server@base", "pass": False, "blockers": [{}]}
        self.functional = {"pass": True, "candidate": "image@candidate"}

    def reusable(self, current="inputs", upstream="base"):
        return module.reusable_blocker(self.state, self.gate, self.functional, current, upstream)

    def test_exact_blocker_reused(self):
        self.assertTrue(self.reusable())

    def test_changed_inputs_and_upstream_not_reused(self):
        self.assertFalse(self.reusable(current="new"))
        self.assertFalse(self.reusable(upstream="new"))

    def test_functional_failure_or_wrong_candidate_not_reused(self):
        self.functional["pass"] = False
        self.assertFalse(self.reusable())
        self.functional.update({"pass": True, "candidate": "wrong"})
        self.assertFalse(self.reusable())

    def test_passed_or_empty_blocker_not_reused(self):
        self.gate["pass"] = True
        self.assertFalse(self.reusable())
        self.gate.update({"pass": False, "blockers": []})
        self.assertFalse(self.reusable())

class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.digest = "sha256:" + "a" * 64
        self.policy = json.loads(Path("security/policy.json").read_text())
        self.policy["release_approved"] = True
        self.state = {"upstream_digest": "sha256:" + "b" * 64}
        self.functional = {"pass": True, "candidate": module.IMAGE + "@" + self.digest}
        self.assessment = {"policy_sha256": hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest(),
                           "pass": True, "modification_pass": True, "blockers": [], "secrets": [], "introduced_high_critical": [],
                           "candidate": self.functional["candidate"], "upstream": "ghcr.io/openhands/agent-server@" + self.state["upstream_digest"]}

    def validate(self):
        module.validate_publication_evidence(self.state, self.assessment, self.functional, self.policy, self.digest)

    def test_exact_evidence_passes(self):
        self.validate()

    def test_failure_missing_and_mismatched_assessment_blocks(self):
        for field, value in {"pass": False, "modification_pass": False, "blockers": [{}], "secrets": [{}],
                             "introduced_high_critical": [{}], "candidate": "wrong", "upstream": "wrong", "policy_sha256": "wrong"}.items():
            with self.subTest(field=field):
                old = deepcopy(self.assessment)
                self.assessment[field] = value
                with self.assertRaises(AssertionError):
                    self.validate()
                self.assessment = old
        del self.assessment["policy_sha256"]
        with self.assertRaises(KeyError):
            self.validate()

    def test_expired_acceptance_rechecked_at_promotion(self):
        record = deepcopy(json.loads(Path("security/proposed-acceptances.json").read_text())["records"][0])
        record.update(status="approved", approved_by="Skulldorom",
                      approval_date=(date.today() - timedelta(days=2)).isoformat(),
                      expires=(date.today() - timedelta(days=1)).isoformat())
        self.policy["exceptions"] = [record]
        self.assessment["policy_sha256"] = hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest()
        with self.assertRaises(AssertionError):
            self.validate()

    def test_functional_and_owner_approval_required(self):
        self.functional["pass"] = False
        with self.assertRaises(AssertionError):
            self.validate()
        self.functional["pass"] = True
        self.policy["release_approved"] = False
        with self.assertRaises(AssertionError):
            self.validate()

if __name__ == "__main__":
    unittest.main()
