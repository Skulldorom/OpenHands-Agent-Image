#!/usr/bin/env python3
"""Exercise real Git tree fingerprints without builds or network."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("release", "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PlanningTests(unittest.TestCase):
    def test_policy_authorization_and_code_are_not_image_inputs(self):
        root = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                subprocess.run(["git", "init", "-q"], check=True)
                for name in release.BUILD_INPUTS + ["security/policy.json", "scripts/release.py", "tests/test.py", "compatibility.json"]:
                    path = Path(name)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("original")
                subprocess.run(["git", "add", "."], check=True)
                subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
                initial = release.fingerprint()
                previous = {"fingerprint": initial, "upstream_digest": "base"}
                self.assertEqual(initial, release.fingerprint("HEAD"))
                for name in ["security/policy.json", "scripts/release.py", "tests/test.py", "compatibility.json"]:
                    Path(name).write_text("changed")
                    self.assertEqual(initial, release.fingerprint())
                    self.assertFalse(release.build_required(previous, release.fingerprint(), "base"))
                for name in release.BUILD_INPUTS:
                    Path(name).write_text("changed")
                    self.assertTrue(release.build_required(previous, release.fingerprint(), "base"))
                    Path(name).write_text("original")
                self.assertTrue(release.build_required(previous, initial, "new-base"))
                self.assertTrue(release.build_required(None, initial, "base"))
            finally:
                os.chdir(root)

    def test_existing_candidate_requires_same_content_and_upstream(self):
        import sys
        sys.path.insert(0, "scripts")
        import promotion
        state = {"upstream_digest": "base", "agent_server_version": "1.62.0"}
        promotion.check_selection(state, "same", "same", "base")
        for source, current, base in [("old", "changed", "base"), ("same", "same", "changed")]:
            with self.assertRaises(AssertionError):
                promotion.check_selection(state, source, current, base)
        with self.assertRaises(AssertionError):
            promotion.check_selection(dict(state, agent_server_version="unknown"), "same", "same", "base")


if __name__ == "__main__":
    unittest.main()
