#!/usr/bin/env python3
"""Real filesystem fingerprints and explicit lifecycle decisions."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, "scripts")
import release

class PlanningTests(unittest.TestCase):
    def test_independent_deterministic_fingerprints(self):
        root = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                for group in release.INPUT_GROUPS.values():
                    for name in group:
                        path = Path(name)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("original")
                initial = release.fingerprints("base")
                self.assertEqual(initial, release.fingerprints("base"))
                Path("README.md").write_text("docs only")
                self.assertEqual(initial, release.fingerprints("base"))
                for group, names in release.INPUT_GROUPS.items():
                    for name in names:
                        Path(name).write_text("changed")
                        actual = release.fingerprints("base")
                        self.assertNotEqual(initial[group], actual[group])
                        for other in set(initial) - {group}:
                            if name in release.INPUT_GROUPS[other]:
                                self.assertNotEqual(initial[other], actual[other])
                            else:
                                self.assertEqual(initial[other], actual[other])
                        Path(name).write_text("original")
                changed = release.fingerprints("changed-base")
                self.assertNotEqual(initial["image"], changed["image"])
                for group in set(initial) - {"image"}:
                    self.assertEqual(initial[group], changed[group])
            finally:
                os.chdir(root)

    def test_each_lifecycle_state_and_failed_tests_retry(self):
        identities = {g: g for g in release.INPUT_GROUPS}
        state = {"fingerprint": "image", "fingerprints": identities, "upstream_digest": "base", "image_digest": "sha256:" + "a"*64}
        for status in release.STATES:
            candidate = dict(state, status=status)
            expected = "build" if status == "build_failed" else "validate"
            self.assertEqual(release.candidate_action(candidate, identities, "base"), expected)
            authenticated = "build" if status == "build_failed" else "validate" if status in {"built", "functional_failed"} else "rescan"
            self.assertEqual(release.candidate_action(candidate, identities, "base", True), authenticated)
        for changed in (dict(identities, image="new"),):
            self.assertEqual(release.candidate_action(dict(state, status="validated"), changed, "base", True), "build")
        self.assertEqual(release.candidate_action(dict(state, status="validated"), identities, "new-base", True), "build")
        for group in ("functional", "security", "publishing"):
            changed = dict(identities, **{group: "changed"})
            self.assertEqual(release.candidate_action(dict(state, status="validated"), changed, "base", True), "validate" if group == "functional" else "rescan")

    def test_versioning(self):
        self.assertEqual(release.next_version(None, "patch"), "1.0.0")
        for bump, expected in [("patch", "1.2.4"), ("minor", "1.3.0"), ("major", "2.0.0")]:
            self.assertEqual(release.next_version("1.2.3", bump), expected)
        with self.assertRaises(AssertionError):
            release.next_version("1.2.3", "unknown")

if __name__ == "__main__":
    unittest.main()
