#!/usr/bin/env python3
"""Run the real planner against local Git content; replace external transports only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import release
import evidence

class PlannerExecutionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        for name in set(sum(release.INPUT_GROUPS.values(), [])):
            path = Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        subprocess.run(['git', 'init', '-q'], check=True)
        subprocess.run(['git', 'add', '.'], check=True)
        subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        self.env = patch.dict(os.environ, GITHUB_SHA=self.commit, GITHUB_OUTPUT=str(Path.cwd() / 'output'), BUMP='auto', GITHUB_EVENT_NAME='schedule', GITHUB_REF='refs/heads/main', SECURITY_REASSESS='false')
        self.env.start()
        self.base, self.digest = 'sha256:' + 'a'*64, 'sha256:' + 'b'*64
        self.identities = release.fingerprints(self.base)
        self.old = dict(version='1.0.0', commit=self.commit, upstream_digest=self.base, image_digest=self.digest,
                        fingerprints=self.identities, fingerprint=self.identities['image'], agent_server_version='1.62.0')
        contract = json.loads(Path('compatibility.json').read_text())['contract']
        self.config = dict(Entrypoint=contract['entrypoint'], Cmd=[], User=contract['user'], WorkingDir=contract['working_directory'], Env=['OPENHANDS_BUILD_GIT_SHA=' + self.commit])
        self.marker = None
        self.records = []

    def tearDown(self):
        self.env.stop()
        os.chdir(self.root)
        self.directory.cleanup()

    def registry(self, repo, reference):
        if repo == 'openhands/agent-server':
            return self.base, self.config
        if reference.startswith('content-'):
            return self.marker, {}
        if reference == 'latest':
            return self.digest, {}
        return self.digest, {'Labels': {'org.opencontainers.image.revision': self.commit, 'org.opencontainers.image.base.digest': self.base}}

    def run_plan(self):
        # Only network APIs/signature transport are substituted; planner, Git
        # fingerprinting, candidate verification and output files remain real.
        with patch.object(release, 'registry', side_effect=self.registry), patch.object(release, 'request', return_value=(b'version = "1.62.0"', {})), patch.object(release, 'release_records', return_value=self.records), patch.object(release, 'retained_marker', return_value=self.marker), patch.object(evidence, 'verify_build_signature') as signature:
            release.plan()
            return json.loads(Path('state.json').read_text()), signature.call_count

    def published(self, draft=False):
        self.records = [{'tag_name': 'v1.0.0', 'draft': draft, 'body': '<!-- release-state:' + json.dumps(self.old) + ' -->'}]

    def test_first_build_and_failed_build_retry(self):
        for _ in range(2):
            state, signatures = self.run_plan()
            self.assertEqual(state['action'], 'build')
            self.assertEqual(signatures, 0)
            self.assertEqual(state['version'], '1.0.0')

    def test_retained_candidate_retries_functional_validation_without_build(self):
        self.marker = self.digest
        state, signatures = self.run_plan()
        self.assertEqual(state['action'], 'validate')
        self.assertEqual(signatures, 1)

    def test_schedule_unchanged_and_docs_only_reuses_with_fresh_validation(self):
        self.published()
        for docs in ('', 'documentation only'):
            Path('README.md').write_text(docs)
            state, signatures = self.run_plan()
            self.assertEqual(state['action'], 'validate')
            self.assertEqual(state['image_digest'], self.digest)
            self.assertEqual(signatures, 1)

    def test_main_push_and_manual_always_build_even_docs_only(self):
        self.published()
        self.marker = self.digest
        for event in ('push', 'workflow_dispatch'):
            os.environ['GITHUB_EVENT_NAME'] = event
            for docs in ('', 'documentation only'):
                Path('README.md').write_text(docs)
                state, signatures = self.run_plan()
                self.assertEqual(state['action'], 'build')
                self.assertNotIn('image_digest', state)
                self.assertEqual(signatures, 0)
                outputs = dict(line.split('=', 1) for line in Path('output').read_text().splitlines())
                self.assertEqual((outputs['build'], outputs['validate']), ('true', 'true'))
                self.assertEqual(state['commit'], self.commit)
                self.assertEqual(state['upstream_digest'], self.base)

    def test_schedule_changed_upstream_builds(self):
        self.published()
        self.base = 'sha256:' + 'c'*64
        state, _ = self.run_plan()
        self.assertEqual(state['action'], 'build')

    def test_minor_major_and_commit_directive_remain_explicit(self):
        self.published()
        for bump, expected in [('patch', '1.0.1'), ('minor', '1.1.0'), ('major', '2.0.0')]:
            os.environ.update(BUMP=bump, GITHUB_EVENT_NAME='workflow_dispatch')
            state, _ = self.run_plan()
            self.assertEqual(state['version'], expected)
            self.assertTrue(state['explicit_bump'])
            self.assertEqual(state['action'], 'build')
        os.environ['BUMP'] = 'auto'
        subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-qm', 'release:minor'], check=True)
        state, _ = self.run_plan()
        self.assertTrue(state['explicit_bump'])
        self.assertEqual(state['version'], '1.1.0')

    def test_interrupted_publication_reuses_reserved_version(self):
        self.published(draft=True)
        state, _ = self.run_plan()
        self.assertEqual(state['action'], 'validate')
        self.assertEqual(state['version'], '1.0.0')

    def test_forced_build_runs_before_superseded_pending_release_blocks_publication(self):
        self.published(draft=True)
        self.base = 'sha256:' + 'c'*64
        for event in ('push', 'workflow_dispatch'):
            os.environ['GITHUB_EVENT_NAME'] = event
            state, _ = self.run_plan()
            self.assertEqual(state['action'], 'build')
        os.environ['GITHUB_EVENT_NAME'] = 'schedule'
        with self.assertRaisesRegex(AssertionError, 'superseded'):
            self.run_plan()

    def test_policy_and_functional_changes_revalidate_same_image(self):
        self.published()
        for name in ('security/policy.json', 'scripts/validate-image.sh'):
            path = Path(name)
            path.write_text(path.read_text() + '\n')
            state, _ = self.run_plan()
            self.assertEqual(state['action'], 'validate')
            self.assertEqual(state['image_digest'], self.digest)

    def test_content_change_builds_new_patch(self):
        self.published()
        Path('Dockerfile').write_text(Path('Dockerfile').read_text() + '\n')
        state, _ = self.run_plan()
        self.assertEqual(state['action'], 'build')
        self.assertEqual(state['version'], '1.0.1')

    def test_invalid_original_provenance_blocks_reuse(self):
        self.published()
        self.old['image_digest'] = 'sha256:' + 'c'*64
        self.published()
        with self.assertRaises(AssertionError):
            self.run_plan()

if __name__ == '__main__':
    unittest.main()
