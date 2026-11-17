#!/usr/bin/env python3
"""Fault-inject every external publication boundary around the real reconciler.

The in-memory backend substitutes only unavailable GitHub/GHCR side effects;
version ownership, conflict checks, ordering and retry logic execute unchanged.
"""
from copy import deepcopy
import json
import sys
import unittest

sys.path.insert(0, "scripts")
import promotion

class Backend:
    def __init__(self, fail=None):
        self.releases, self.tags, self.git, self.uploaded = [], {}, {}, set()
        self.fail, self.events = fail, []

    def boundary(self, event):
        self.events.append(event)
        if self.fail == event:
            self.fail = None
            raise ConnectionError(event)

    def records(self):
        return deepcopy(self.releases)

    def reserve(self, state):
        self.boundary("before_intent")
        record = {"id": len(self.releases)+1, "tag_name": "v"+state["version"], "draft": True,
                  "body": "<!-- release-state:"+json.dumps(state)+" -->"}
        self.releases.append(record)
        self.boundary("after_intent")
        return deepcopy(record)

    def tag_digest(self, tag):
        return self.tags.get(tag)

    def tag(self, tag, digest):
        self.boundary("before_"+tag)
        self.tags[tag] = digest
        self.boundary("after_"+tag)

    def git_tag(self, version, commit):
        self.boundary("before_git")
        assert self.git.get(version, commit) == commit
        self.git[version] = commit
        self.boundary("after_git")

    def assets(self, record):
        self.boundary("before_assets")
        self.uploaded.add(record["id"])
        self.boundary("after_assets")

    def complete(self, record, state):
        self.boundary("before_complete")
        self.releases[record["id"]-1].update(draft=False, body="<!-- release-state:"+json.dumps(state)+" -->")
        self.boundary("after_complete")

class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.state = {"version": "1.0.0", "commit": "a"*40, "image_digest": "sha256:"+"b"*64,
                      "upstream_digest": "sha256:"+"c"*64, "fingerprints": {"image": "content"}, "status": "validated"}

    def test_successful_release_is_idempotent(self):
        backend = Backend()
        for _ in range(3):
            final = promotion.reconcile(self.state, backend, lambda s: None)
        self.assertEqual(final["status"], "published")
        self.assertEqual(len(backend.releases), 1)
        self.assertFalse(backend.releases[0]["draft"])
        self.assertEqual(backend.tags, {tag: self.state["image_digest"] for tag in ("1.0.0", "v1.0.0", "latest")})
        self.assertLess(backend.events.index("after_assets"), backend.events.index("before_latest"))

    def test_interruption_before_and_after_every_boundary(self):
        for action in ("intent", "1.0.0", "v1.0.0", "git", "assets", "latest", "complete"):
            for side in ("before", "after"):
                with self.subTest(boundary=side+"_"+action):
                    backend = Backend(side+"_"+action)
                    with self.assertRaises(ConnectionError):
                        promotion.reconcile(self.state, backend, lambda s: None)
                    promotion.reconcile(self.state, backend, lambda s: None)
                    self.assertEqual(len(backend.releases), 1)
                    self.assertEqual(backend.releases[0]["tag_name"], "v1.0.0")
                    self.assertFalse(backend.releases[0]["draft"])
                    self.assertEqual(backend.tags["latest"], self.state["image_digest"])

    def test_immutable_conflicts_fail_closed(self):
        for tag in ("1.0.0", "v1.0.0"):
            backend = Backend()
            backend.tags[tag] = "different"
            with self.assertRaises(AssertionError):
                promotion.reconcile(self.state, backend, lambda s: None)
            self.assertNotIn("latest", backend.tags)

    def test_concurrent_reservation_for_other_candidate_blocks(self):
        backend = Backend("after_intent")
        with self.assertRaises(ConnectionError):
            promotion.reconcile(self.state, backend, lambda s: None)
        with self.assertRaises(AssertionError):
            promotion.reconcile(dict(self.state, image_digest="other"), backend, lambda s: None)
        self.assertNotIn("latest", backend.tags)

    def test_original_source_and_runtime_conflicts_are_rejected(self):
        for field, value in (("release_source_commit", "d" * 40), ("agent_server_version", "unknown")):
            backend = Backend("after_intent")
            with self.assertRaises(ConnectionError):
                promotion.reconcile(self.state, backend, lambda s: None)
            with self.assertRaises(AssertionError):
                promotion.reconcile(dict(self.state, **{field: value}), backend, lambda s: None)
            self.assertNotIn("latest", backend.tags)

    def test_newer_release_blocks_stale_latest(self):
        backend = Backend()
        backend.releases = [{"tag_name": "v1.0.1"}]
        with self.assertRaises(AssertionError):
            promotion.reconcile(self.state, backend, lambda s: None)
        self.assertEqual(backend.tags, {})

    def test_unowned_latest_cannot_be_replaced(self):
        backend = Backend()
        backend.tags["latest"] = "unknown"
        with self.assertRaisesRegex(AssertionError, "Unowned"):
            promotion.reconcile(self.state, backend, lambda s: None)
        self.assertEqual(backend.tags["latest"], "unknown")

    def test_freshness_rechecked_before_latest(self):
        backend = Backend()
        calls = []
        def freshness(state):
            calls.append(state)
            if len(calls) == 2:
                raise AssertionError("source/upstream changed")
        with self.assertRaises(AssertionError):
            promotion.reconcile(self.state, backend, freshness)
        self.assertNotIn("latest", backend.tags)
        self.assertTrue(backend.releases[0]["draft"])

if __name__ == "__main__":
    unittest.main()
