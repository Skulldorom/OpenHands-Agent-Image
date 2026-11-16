#!/usr/bin/env python3
"""Verify exact retained evidence decisions without network mocks."""
import importlib.util
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

if __name__ == "__main__":
    unittest.main()
