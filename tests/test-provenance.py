#!/usr/bin/env python3
"""Adversarial evidence and approval tests; real parser/validation code paths."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import io
import zipfile
import os
import sys
import unittest

sys.path.insert(0, "scripts")
import evidence
import promotion


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.run = {"repository": {"full_name": evidence.REPO}, "head_branch": "main", "event": "push",
                    "path": ".github/workflows/ci.yml", "run_attempt": 1, "status": "completed",
                    "head_sha": "a" * 40, "created_at": datetime.now(timezone.utc).isoformat(), "id": 123}
        self.state = {"upstream_digest": "sha256:" + "b" * 64, "agent_server_version": "1.62.0", "commit": "a" * 40}
        self.candidate = evidence.IMAGE + "@sha256:" + "c" * 64
        self.functional = {"schema": 2, "pass": True, "candidate": self.candidate,
                           "source_commit": "a" * 40, "upstream_digest": self.state["upstream_digest"],
                           "agent_server_version": "1.62.0", "repository": evidence.REPO, "run_id": 123,
                           "run_attempt": 1, "tests": {test: "passed" for test in evidence.TESTS}}

    def test_valid_run_and_complete_functional_evidence(self):
        evidence.validate_run(self.run, 1)
        evidence.validate_functional(self.functional, self.state, self.run, self.candidate)

    def test_wrong_run_source_repository_branch_event_or_attempt(self):
        for key, value in {"repository": {"full_name": "attacker/repo"}, "head_branch": "feature", "event": "pull_request",
                           "path": ".github/workflows/other.yml", "run_attempt": 2, "status": "in_progress",
                           "head_sha": "tag", "created_at": (datetime.now(timezone.utc)-timedelta(days=91)).isoformat()}.items():
            run = dict(self.run, **{key: value})
            with self.subTest(key=key), self.assertRaises(AssertionError):
                evidence.validate_run(run, 1)

    def test_missing_altered_incomplete_or_legacy_evidence(self):
        for key in self.functional:
            changed = deepcopy(self.functional)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(AssertionError):
                evidence.validate_functional(changed, self.state, self.run, self.candidate)
        for key, value in {"candidate": "other", "source_commit": "b"*40, "upstream_digest": "other", "pass": False,
                           "run_id": 999, "run_attempt": 2, "tests": {"git-identity": "passed"}, "schema": 1}.items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                evidence.validate_functional(dict(self.functional, **{key: value}), self.state, self.run, self.candidate)

    def test_verified_signature_requires_exact_run_and_attempt(self):
        def result(invocation):
            return [{"verificationResult": {"statement": {"predicate": {"runDetails": {"metadata": {"invocationId": invocation}}}}}}]
        invocation = f"https://github.com/{evidence.REPO}/actions/runs/123/attempts/1"
        evidence.validate_signature_run(result(invocation), self.run)
        for wrong in [invocation.replace("123", "456"), invocation.replace("attempts/1", "attempts/2"), "untrusted"]:
            with self.assertRaises(AssertionError):
                evidence.validate_signature_run(result(wrong), self.run)
        with self.assertRaises(AssertionError):
            evidence.validate_signature_run([], self.run)
        with self.assertRaises(KeyError):
            evidence.validate_signature_run([{}], self.run)

    def test_archive_missing_expired_wrong_origin_or_tampered(self):
        def archive(names):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as output:
                for name in names:
                    output.writestr(name, "{}")
            return stream.getvalue()
        raw = archive(evidence.FILES)
        artifact = {"expired": False, "workflow_run": {"head_sha": self.run["head_sha"], "id": self.run["id"]},
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        self.assertEqual(set(evidence.validate_archive(artifact, self.run, raw)), evidence.FILES)
        for key, value in {"expired": True, "workflow_run": {"head_sha": "b"*40, "id": 123}, "digest": "wrong"}.items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                evidence.validate_archive(dict(artifact, **{key: value}), self.run, raw)
        for names in [evidence.FILES - {"functional-pass.json"}, list(evidence.FILES) + ["functional-pass.json"]]:
            altered = archive(names)
            with self.assertRaises(AssertionError):
                evidence.validate_archive(dict(artifact, digest="sha256:"+hashlib.sha256(altered).hexdigest()), self.run, altered)

    def test_environment_requires_owner_nonself_no_bypass_main(self):
        setting = {"name": "release", "can_admins_bypass": False,
                   "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                   "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                                         "reviewers": [{"type": "User", "reviewer": {"login": "Skulldorom"}}]}]}
        promotion.check_environment(setting)
        for key, value in {"protection_rules": [], "can_admins_bypass": True, "deployment_branch_policy": None}.items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                promotion.check_environment(dict(setting, **{key: value}))
        changed = deepcopy(setting)
        changed["protection_rules"][0]["prevent_self_review"] = False
        with self.assertRaises(AssertionError):
            promotion.check_environment(changed)
        changed["protection_rules"][0]["prevent_self_review"] = True
        changed["protection_rules"][0]["reviewers"][0]["reviewer"]["login"] = "attacker"
        with self.assertRaises(AssertionError):
            promotion.check_environment(changed)

    def test_approval_binds_candidate_policy_run_attempt_and_owner(self):
        selection = {"candidate": "sha256:exact", "policy_sha256": "policy", "run_id": 123, "run_attempt": 1}
        review = {"state": "approved", "user": {"login": "Skulldorom"}, "environments": [{"name": "release"}],
                  "comment": promotion.approval_token(selection)}
        promotion.validate_approval([review], selection, "operator", "operator")
        for actor, trigger in [("Skulldorom", "operator"), ("operator", "Skulldorom")]:
            with self.assertRaises(AssertionError):
                promotion.validate_approval([review], selection, actor, trigger)
        for key, value in {"state": "rejected", "user": {"login": "attacker"}, "comment": "approved", "environments": [{"name": "other"}]}.items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                promotion.validate_approval([dict(review, **{key: value})], selection, "operator", "operator")
        for key, value in {"candidate": "other", "policy_sha256": "new", "run_id": 456, "run_attempt": 2}.items():
            with self.subTest(key=key), self.assertRaises(AssertionError):
                promotion.validate_approval([review], dict(selection, **{key: value}), "operator", "operator")

    def test_policy_and_candidate_changes_expired_scans_or_rerun_require_new_approval(self):
        old = dict(os.environ)
        try:
            os.environ.update(CANDIDATE_DIGEST="candidate", GITHUB_SHA="source", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
            selection = {"candidate": "candidate", "policy_sha256": promotion.policy_hash(), "policy_commit": "source",
                         "run_id": 123, "run_attempt": 1, "scanned_at": datetime.now(timezone.utc).isoformat(), "files": {}}
            with self.assertRaises(AssertionError):
                promotion.recheck(selection, datetime.now(timezone.utc))
            for key, value in {"candidate": "other", "policy_sha256": "other", "policy_commit": "other", "run_id": 456,
                               "run_attempt": 2, "scanned_at": (datetime.now(timezone.utc)-timedelta(hours=25)).isoformat(),
                               "files": {"security/policy.json": "altered"}}.items():
                with self.subTest(key=key), self.assertRaises(AssertionError):
                    promotion.recheck(dict(selection, **{key: value}), datetime.now(timezone.utc))
        finally:
            os.environ.clear()
            os.environ.update(old)


if __name__ == "__main__":
    unittest.main()
