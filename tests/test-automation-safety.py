#!/usr/bin/env python3
"""Release orchestration invariants through real validators and local files."""
from datetime import datetime, timezone, timedelta
import os
import json
from pathlib import Path
import sys
import tempfile
import hashlib
import unittest
from unittest.mock import patch
import urllib.error
import io
import zipfile
import tarfile

sys.path.insert(0, 'scripts')
import promotion
import evidence
import release


class SafetyTests(unittest.TestCase):

    def test_candidate_reuse_includes_auth_only_and_functional_failures(self):
        state = {'status': 'functional_failed', 'fingerprint': 'content', 'upstream_digest': 'base', 'image_digest': 'sha256:' + 'a'*64}
        self.assertTrue(release.reusable_candidate(state, 'content', 'base'))
        self.assertFalse(release.reusable_candidate(state, 'changed', 'base'))
        self.assertFalse(release.reusable_candidate(state, 'content', 'new-base'))
        self.assertFalse(release.reusable_candidate(dict(state, image_digest='latest'), 'content', 'base'))

    def test_immutable_candidate_tag_preflight_blocks_existing_tag(self):
        with patch.dict(os.environ, GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='2'):
            with patch.object(release, 'registry', return_value=('different-content', {})) as registry:
                with self.assertRaisesRegex(AssertionError, 'already exists'):
                    release.assert_candidate_tag_absent()
                self.assertEqual(registry.call_args.args[1], 'candidate-42-2')
            for code in (404, 403, 500):
                error = urllib.error.HTTPError('https://ghcr.io', code, 'error', {}, None)
                with patch.object(release, 'registry', side_effect=error):
                    if code == 404:
                        release.assert_candidate_tag_absent()
                    else:
                        with self.assertRaises(urllib.error.HTTPError):
                            release.assert_candidate_tag_absent()

    def test_failed_validation_candidate_journal_can_be_retried(self):
        state = dict(status='built', fingerprint='content', upstream_digest='base', image_digest='sha256:' + 'a'*64)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('state.json', json.dumps(state))
        artifact = dict(id=1, expired=False, name='candidate-state-' + release.candidate_key('content', 'base') + '-42-1')
        with patch.object(release, 'gh', return_value=json.dumps({'artifacts': [artifact]})), patch.object(release.subprocess, 'check_output', return_value=buffer.getvalue()):
            self.assertEqual(release.retained_marker('content', 'base'), state['image_digest'])
            self.assertEqual(release.candidate_action(state, {'image': 'content'}, 'base'), 'validate')

    def test_release_increment_is_validated_and_patch_default(self):
        self.assertEqual(release.next_version('1.2.3', 'patch'), '1.2.4')
        self.assertEqual(release.next_version('1.2.3', 'minor'), '1.3.0')
        self.assertEqual(release.next_version('1.2.3', 'major'), '2.0.0')
        self.assertEqual(release.next_version(None, 'minor'), '1.0.0')
        with self.assertRaises(AssertionError):
            release.next_version('1.2.3', 'typo')


    def test_seal_recheck_requires_complete_hash_manifest(self):
        old = dict(os.environ)
        try:
            os.environ.update(CANDIDATE_DIGEST='candidate', GITHUB_SHA='source', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
            selection = {'candidate': 'candidate', 'policy_sha256': promotion.policy_hash(), 'policy_commit': 'source',
                         'run_id': 123, 'run_attempt': 1, 'scanned_at': datetime.now(timezone.utc).isoformat(), 'files': {}}
            with self.assertRaises(AssertionError):
                promotion.recheck(selection, datetime.now(timezone.utc))
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_complete_manifest_passes_and_tampering_fails(self):
        old = dict(os.environ)
        root = Path.cwd()
        policy_hash = promotion.policy_hash()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                Path('security').mkdir()
                Path('security/policy.json').write_bytes((root / 'security/policy.json').read_bytes())
                names = promotion.SEALED_FILES
                for name in names:
                    if name != "security/policy.json":
                        Path(name).write_text('evidence')
                stamp = datetime.now(timezone.utc).isoformat()
                for name in ('trivy.json', 'upstream-trivy.json'):
                    Path(name).write_text(json.dumps({'CreatedAt': stamp, 'Trivy': {'Version': '0.69.3'}}))
                Path('scanner-version.json').write_text('{"Version":"0.69.3"}')
                database = b'frozen test database'
                Path('scanner-database.sha256').write_text(hashlib.sha256(database).hexdigest() + '  .cache/trivy/db/trivy.db\n')
                with tarfile.open('scanner-database.tar.gz', 'w:gz') as archive:
                    member = tarfile.TarInfo('db/trivy.db')
                    member.size = len(database)
                    archive.addfile(member, io.BytesIO(database))
                Path('upstream-baseline.json').write_text(json.dumps({'upstream': None, 'version': None, 'approval_sha256': None}))
                Path('previous-upstream-trivy.json').write_text('null')
                os.environ.update(CANDIDATE_DIGEST='candidate', GITHUB_SHA='source', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
                selection = {'candidate': 'candidate', 'policy_sha256': policy_hash, 'policy_commit': 'source',
                             'run_id': 123, 'run_attempt': 1, 'prepared_at': stamp, 'scanned_at': datetime.now(timezone.utc).isoformat(),
                             'files': {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in names}}
                promotion.recheck(selection, datetime.now(timezone.utc))
                late = dict(selection, prepared_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat())
                with self.assertRaises(AssertionError):
                    promotion.validate_fresh_scans(late, datetime.now(timezone.utc))
                original_manifest = Path('scanner-database.sha256').read_text()
                Path('scanner-database.sha256').write_text('a'*64 + '  .cache/trivy/db/trivy.db\n')
                with self.assertRaisesRegex(AssertionError, 'database changed'):
                    promotion.validate_fresh_scans(selection, datetime.now(timezone.utc))
                Path('scanner-database.sha256').write_text(original_manifest)
                Path('upstream-baseline.json').write_text(json.dumps({'upstream': 'previous@sha256:' + 'b'*64}))
                with self.assertRaisesRegex(AssertionError, 'Unbound'):
                    promotion.validate_fresh_scans(selection, datetime.now(timezone.utc))
                Path('upstream-baseline.json').write_text(json.dumps({'upstream': None}))
                Path('trivy.json').write_text('altered')
                with self.assertRaises(AssertionError):
                    promotion.recheck(selection, datetime.now(timezone.utc))
        finally:
            os.chdir(root)
            os.environ.clear()
            os.environ.update(old)


if __name__ == '__main__':
    unittest.main()
