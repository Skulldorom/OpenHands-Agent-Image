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

class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.digest = "sha256:" + "a" * 64
        self.policy = json.loads(Path("security/policy.json").read_text())
        self.state = {"upstream_digest": "sha256:" + "b" * 64}
        self.functional = {"pass": True, "candidate": module.IMAGE + "@" + self.digest}
        self.assessment = {"policy_sha256": hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest(),
                           "schema": 2, "materially_worsened": [], "emergency_blocked": [],
                           "pass": True, "modification_pass": True, "blockers": [], "secrets": [], "introduced_high_critical": [],
                           "candidate": self.functional["candidate"], "upstream": "ghcr.io/openhands/agent-server@" + self.state["upstream_digest"]}

    def validate(self):
        module.validate_publication_evidence(self.state, self.assessment, self.functional, self.policy, self.digest)

    def test_exact_evidence_passes(self):
        self.validate()

    def test_failure_missing_and_mismatched_assessment_blocks(self):
        for field, value in {"pass": False, "modification_pass": False, "blockers": [{}], "secrets": [{}],
                             "introduced_high_critical": [{}], "materially_worsened": [{}], "emergency_blocked": [{}], "schema": 1, "candidate": "wrong", "upstream": "wrong", "policy_sha256": "wrong"}.items():
            with self.subTest(field=field):
                old = deepcopy(self.assessment)
                self.assessment[field] = value
                with self.assertRaises(AssertionError):
                    self.validate()
                self.assessment = old
        del self.assessment["policy_sha256"]
        with self.assertRaises(KeyError):
            self.validate()

    def test_obsolete_policy_fields_rejected_at_promotion(self):
        self.policy['exceptions'] = []
        self.assessment['policy_sha256'] = hashlib.sha256(json.dumps(self.policy, sort_keys=True).encode()).hexdigest()
        with self.assertRaises(AssertionError):
            self.validate()

    def test_functional_pass_required(self):
        self.functional["pass"] = False
        with self.assertRaises(AssertionError):
            self.validate()

if __name__ == "__main__":
    unittest.main()
