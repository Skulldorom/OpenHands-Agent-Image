#!/usr/bin/env python3
"""Exercise real archive/asset code; substitute unavailable GitHub HTTP transport only."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import promotion


class ImmutableAssetsTests(unittest.TestCase):
    def setUp(self):
        self.previous = os.getcwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        for name in promotion.SEALED_FILES | {'selection.json', 'security/policy.json'}:
            path = Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}')
        Path('selection.json').write_text(json.dumps({'run_id': 1, 'run_attempt': 1}))
        self.raw = promotion.evidence_archive()
        self.descriptor = promotion.evidence_descriptor(self.raw)
        self.record = {'id': 3, 'tag_name': 'v1.0.0', 'draft': True,
                       'body': '<!-- release-evidence:' + json.dumps(self.descriptor) + ' -->\n<!-- release-state:' + json.dumps({'version': '1.0.0', 'image_digest': 'original'}) + ' -->'}
        self.backend = promotion.GitHubRegistry()
        self.remote = {}
        self.requests = []

    def tearDown(self):
        os.chdir(self.previous)
        self.directory.cleanup()

    def api(self, *args):
        self.requests.append(args)
        if '--method' in args:
            return '{}'
        return json.dumps([[{'id': name, 'name': name} for name in self.remote]])

    def upload(self, args, **kwargs):
        self.assertNotIn('--clobber', args)
        path = Path(args[-1])
        self.assertNotIn(path.name, self.remote)
        self.remote[path.name] = path.read_bytes()

    def transport(self):
        return (patch.object(promotion.release, 'gh', side_effect=self.api),
                patch.object(promotion.subprocess, 'run', side_effect=self.upload),
                patch.object(self.backend, 'asset_bytes', side_effect=lambda a: self.remote[a['name']]))

    def test_repeated_upload_preserves_exact_original(self):
        a, b, c = self.transport()
        with a, b, c:
            for _ in range(3):
                self.backend.assets(self.record)
        self.assertEqual(self.remote[self.descriptor['name']], self.raw)
        self.assertEqual(self.remote['state.json'], b'{}')

    def test_reassessment_keeps_original_and_is_content_addressed(self):
        a, b, c = self.transport()
        with a, b, c:
            self.backend.assets(self.record)
            Path('trivy.json').write_text('{"fresh":true}')
            newer = promotion.evidence_archive()
            for _ in range(3):
                self.backend.assets(self.record)
        self.assertEqual(self.remote[self.descriptor['name']], self.raw)
        self.assertEqual(self.remote['reassessment-' + hashlib.sha256(newer).hexdigest() + '.zip'], newer)
        self.assertEqual(len(self.remote), len(promotion.SEALED_FILES) + 3)

    def test_conflicting_original_rejected_without_overwrite(self):
        self.remote[self.descriptor['name']] = b'conflict'
        a, b, c = self.transport()
        with a, b, c, self.assertRaisesRegex(AssertionError, 'conflict'):
            self.backend.assets(self.record)
        self.assertEqual(self.remote[self.descriptor['name']], b'conflict')

    def test_interruption_after_upload_resumes_without_duplicate(self):
        def interrupt(args, **kwargs):
            self.upload(args, **kwargs)
            raise ConnectionError('upload response lost')
        a, b, c = self.transport()
        with a, c:
            with patch.object(promotion.subprocess, 'run', side_effect=interrupt), self.assertRaises(ConnectionError):
                self.backend.assets(self.record)
            with b:
                self.backend.assets(self.record)
        self.assertEqual(len(self.remote), len(promotion.SEALED_FILES) + 2)

    def test_missing_original_restored_before_reassessment(self):
        Path('selection.json').write_text(json.dumps({'run_id': 2, 'run_attempt': 1}))
        a, b, c = self.transport()
        with a, b, c, patch.object(self.backend, 'recover_original', return_value=self.raw):
            self.backend.assets(self.record)
        self.assertEqual(self.remote[self.descriptor['name']], self.raw)
        self.assertEqual(len(self.remote), len(promotion.SEALED_FILES) + 3)

    def test_missing_original_never_replaced_by_new_run(self):
        Path('selection.json').write_text(json.dumps({'run_id': 2, 'run_attempt': 1}))
        a, b, c = self.transport()
        with a, b, c, patch.object(self.backend, 'recover_original', side_effect=AssertionError('unavailable')):
            with self.assertRaisesRegex(AssertionError, 'unavailable'):
                self.backend.assets(self.record)
        self.assertFalse(self.remote)

    def test_complete_preserves_original_journal_and_approval(self):
        with patch.object(promotion.release, 'gh', side_effect=self.api):
            self.backend.complete(self.record, {'commit': 'changed', 'image_digest': 'original'})
            self.backend.complete(dict(self.record, draft=False), {'commit': 'changed', 'image_digest': 'original'})
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn('body=', ' '.join(self.requests[0]))

    def test_initial_upstream_baseline_is_explicitly_unavailable(self):
        self.assertEqual(promotion.approved_baseline({}, self.backend), {'upstream': None, 'version': None, 'approval_sha256': None})
        promotion.verify_baseline_owner({'upstream': None, 'version': None, 'approval_sha256': None}, [])

    def test_baseline_requires_committed_original_approval(self):
        owner = {'version': '1.0.0', 'image_digest': 'sha256:' + 'a'*64, 'upstream_digest': 'sha256:' + 'b'*64}
        Path('state.json').write_text(json.dumps(owner))
        original = promotion.evidence_archive()
        descriptor = promotion.evidence_descriptor(original)
        record = {'id': 1, 'tag_name': 'v1.0.0', 'draft': False,
                  'body': '<!-- release-state:' + json.dumps(owner) + ' -->\n<!-- release-evidence:' + json.dumps(descriptor) + ' -->'}
        with patch.object(self.backend, 'records', return_value=[record]), patch.object(promotion.release, 'gh', return_value='[[]]'), patch.object(self.backend, 'recover_original', return_value=original):
            baseline = promotion.approved_baseline({'previous_approved': owner}, self.backend)
            self.assertEqual(baseline['upstream'], 'ghcr.io/openhands/agent-server@' + owner['upstream_digest'])
            promotion.verify_baseline_owner(baseline, [record])
            with patch.object(self.backend, 'recover_original', return_value=b'tampered'), self.assertRaisesRegex(AssertionError, 'commitment mismatch'):
                promotion.approved_baseline({'previous_approved': owner}, self.backend)
            for field in ('version', 'upstream', 'approval_sha256'):
                with self.assertRaisesRegex(AssertionError, 'baseline changed'):
                    promotion.verify_baseline_owner(dict(baseline, **{field: 'different'}), [record])
            with self.assertRaises(AssertionError):
                promotion.verify_baseline_owner({'upstream': None, 'version': None, 'approval_sha256': None}, [record])

    def test_prior_evidence_schema_recovery_keeps_original_bytes(self):
        names = promotion.SEALED_FILES - {'upstream-baseline.json', 'previous-upstream-trivy.json'}
        files = {n: Path(n).read_bytes() for n in names}
        files['selection.json'] = json.dumps({'files': {n: hashlib.sha256(files[n]).hexdigest() for n in names}}).encode()
        original = promotion.evidence_archive(files)
        descriptor = {'sha256': hashlib.sha256(original).hexdigest(), 'run_id': 1, 'run_attempt': 1}
        artifacts = {'artifacts': [{'id': 4, 'name': 'validation-1-1', 'expired': False}]}
        with patch.object(promotion.release, 'gh', return_value=json.dumps(artifacts)), patch.object(promotion.subprocess, 'check_output', return_value=original):
            self.assertEqual(self.backend.recover_original(descriptor), original)

    def test_archive_retains_exact_policy_scans_and_state(self):
        with zipfile.ZipFile(io.BytesIO(self.raw)) as archive:
            self.assertIn('security/policy.json', archive.namelist())
            self.assertIn('scanner-database.sha256', archive.namelist())
            self.assertIn('upstream-trivy.json', archive.namelist())
            self.assertIn('state.json', archive.namelist())
        self.assertEqual(self.raw, promotion.evidence_archive())


if __name__ == '__main__':
    unittest.main()
