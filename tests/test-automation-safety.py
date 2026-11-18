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


def layer_report():
    module = promotion.credential_module()
    scan_path = Path('upstream-trivy.json')
    scan = json.loads(scan_path.read_text()) if scan_path.exists() else {}
    scan['ArtifactName'] = 'ghcr.io/openhands/agent-server@sha256:'+'a'*64
    scan_path.write_text(json.dumps(scan))
    empty = dict(candidate='ghcr.io/openhands/agent-server@sha256:'+'a'*64, layers=1,
                 unclassified_detections=0, classifications=[], unclassified_findings=[], layer_diff_ids=['sha256:'+'a'*64])
    report = dict(empty, candidate=release.IMAGE+'@candidate', schema=3, upstream=empty, image_id='sha256:'+'b'*64,
                  scanned_at=datetime.now(timezone.utc).isoformat(),
                  policy_sha256=hashlib.sha256(module.POLICY_PATH.read_bytes()).hexdigest())
    refresh_report(report, accept=True)
    return report


def refresh_report(report, accept=False):
    module = promotion.credential_module()
    policy = json.loads(module.POLICY_PATH.read_text())
    if accept:
        policy['accepted_upstream'].update(upstream=report['upstream']['candidate'],
            inventory_sha256=module.inventory_fingerprint(report['upstream']),
            finding_count=len(module.flatten(report['upstream'])))
        module.POLICY_PATH.write_text(json.dumps(policy))
    report['comparison'] = module.compare_findings(report['upstream'], report)
    report['gate'] = module.credential_gate(report['upstream'], report)
    report['policy_sha256'] = hashlib.sha256(module.POLICY_PATH.read_bytes()).hexdigest()


class SafetyTests(unittest.TestCase):
    def setUp(self):
        module = promotion.credential_module()
        original = module.POLICY_PATH.read_bytes()
        self.policy_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.policy_directory.cleanup)
        module.POLICY_PATH = Path(self.policy_directory.name)/'credential-policy.json'
        module.POLICY_PATH.write_bytes(original)
        self.module_patch = patch.object(promotion, 'credential_module', return_value=module)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)


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

    def test_layer_classification_report_cannot_authorize_unknown_detections(self):
        root = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                report = layer_report()
                for field, value in [('candidate', 'different'), ('layers', 0), ('unclassified_detections', 1),
                        ('comparison', {}), ('policy_sha256', 'altered'), ('schema', 1),
                        ('scanned_at', (datetime.now(timezone.utc)-timedelta(days=2)).isoformat())]:
                    Path('layer-classifications.json').write_text(json.dumps(dict(report, **{field: value})))
                    with self.assertRaises(AssertionError):
                        promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
                Path('layer-classifications.json').write_text(json.dumps(report))
                promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
        finally:
            os.chdir(root)

    def test_publisher_accepts_public_material_and_rejects_unknown_or_altered_evidence(self):
        root = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                report = layer_report()
                policy = json.loads((root/'security/credential-policy.json').read_text())
                fixture = policy['public_private_keys'][0]
                row = dict(credential_rule='private_key', match_sha256='b'*64, match_length=200,
                           diff_id=fixture['diff_id'], file_offset=0, token_family=None, standalone=True,
                           file=fixture['file'], archive_member='blobs/sha256/'+fixture['diff_id'].split(':')[1],
                           **{k: fixture[k] for k in ('kind', 'payload_sha256', 'payload_length')})
                row['decision'] = dict(classification='public-cryptographic-test-material', **fixture)
                report['layer_diff_ids'] = report['upstream']['layer_diff_ids'] = [fixture['diff_id']]
                report['classifications'] = [row]
                report['upstream']['classifications'] = [row]
                spec = __import__('importlib.util', fromlist=['']).spec_from_file_location('layers_gate', root/'tests/test-image-layers.py')
                module = __import__('importlib.util', fromlist=['']).module_from_spec(spec)
                spec.loader.exec_module(module)
                refresh_report(report, accept=True)
                Path('layer-classifications.json').write_text(json.dumps(report))
                promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
                for inherited in (True, False):
                    blocked = json.loads(json.dumps(report))
                    unknown = dict(row, credential_rule='github_token', match_sha256='c'*64, token_family='ghp_')
                    unknown.pop('decision')
                    finding = dict(file=unknown['file'], archive_member=unknown['archive_member'], rule='github_token', patterns=[unknown])
                    blocked['unclassified_findings'] = [finding]
                    blocked['unclassified_detections'] = 1
                    if inherited:
                        blocked['upstream']['unclassified_findings'] = [finding]
                        blocked['upstream']['unclassified_detections'] = 1
                    refresh_report(blocked)
                    Path('layer-classifications.json').write_text(json.dumps(blocked))
                    with self.assertRaises(AssertionError):
                        promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
                altered = json.loads(json.dumps(report))
                altered['classifications'][0]['decision']['purpose'] = 'changed'
                # Preserve the altered decision so the actual validator must reject it.
                Path('layer-classifications.json').write_text(json.dumps(altered))
                with self.assertRaises(AssertionError):
                    promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
                Path('layer-classifications.json').unlink()
                with self.assertRaises(FileNotFoundError):
                    promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
        finally:
            os.chdir(root)

    def test_publisher_allows_reviewed_unknown_and_blocks_live_introduced_and_forged_gate(self):
        root = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                report = layer_report()
                row = dict(credential_rule='github_token', match_sha256='c'*64, match_length=40,
                           diff_id='sha256:'+'a'*64, file_offset=0, token_family='ghp_', standalone=True,
                           file='usr/bin/vendor', archive_member='blobs/sha256/'+'a'*64)
                finding = dict(file=row['file'], archive_member=row['archive_member'], rule='github_token', patterns=[row])
                for scan in (report, report['upstream']):
                    scan['unclassified_findings'] = [finding]
                    scan['unclassified_detections'] = 1
                refresh_report(report, accept=True)
                Path('layer-classifications.json').write_text(json.dumps(report))
                promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
                self.assertEqual(report['gate']['accepted_inherited_unclassified'], 1)
                for mutation in ('introduced', 'changed-upstream', 'forged-gate', 'confirmed-live'):
                    changed = json.loads(json.dumps(report))
                    if mutation == 'introduced':
                        changed['unclassified_findings'].append(dict(finding, patterns=[dict(row, match_sha256='d'*64)]))
                        changed['unclassified_detections'] = 2
                        refresh_report(changed)
                    elif mutation == 'changed-upstream':
                        for scan in (changed, changed['upstream']):
                            scan['unclassified_findings'][0]['patterns'][0]['match_sha256'] = 'e'*64
                        refresh_report(changed)
                    elif mutation == 'confirmed-live':
                        module = promotion.credential_module()
                        policy = json.loads(module.POLICY_PATH.read_text())
                        policy['confirmed_dangerous'] = [dict(finding_sha256=module.finding_fingerprint(row),
                            reason='Confirmed live token', evidence='https://github.com/example/security')]
                        module.POLICY_PATH.write_text(json.dumps(policy))
                        refresh_report(changed)
                    else:
                        changed['gate']['accepted_inherited_unclassified'] = 0
                    Path('layer-classifications.json').write_text(json.dumps(changed))
                    with self.assertRaises(AssertionError):
                        promotion.validate_layer_report('candidate', datetime.now(timezone.utc))
        finally:
            os.chdir(root)

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
                Path('layer-classifications.json').write_text(json.dumps(layer_report()))
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
