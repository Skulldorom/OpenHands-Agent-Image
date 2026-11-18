#!/usr/bin/env python3
"""Validate workflow schema and security wiring, not publication."""
from pathlib import Path
import re
import subprocess
import unittest
import yaml
import os
import json
import tempfile
from types import SimpleNamespace


class WorkflowPolicyTests(unittest.TestCase):
    def test_yaml_actions_pinned_and_pull_requests_read_only(self):
        for path in Path('.github/workflows').glob('*.yml'):
            workflow = yaml.safe_load(path.read_text())
            self.assertIsInstance(workflow['jobs'], dict)
            for job in workflow['jobs'].values():
                for step in job.get('steps', []):
                    script = step.get('run', '')
                    subprocess.run(['bash', '-n'], input=script, text=True, check=True)
                    for source in re.findall(r"python3 - <<'PY'\n(.*?)\nPY", script, re.S):
                        compile(source, str(path), 'exec')
            for job in workflow['jobs'].values():
                for step in job.get('steps', []):
                    if 'uses' in step:
                        self.assertRegex(step['uses'], r'^[\w/-]+@[a-f0-9]{40}$')
            if path.name == 'policy-review.yml':
                self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
                for job in workflow['jobs'].values():
                    self.assertNotIn('environment', job)

    def test_sandbox_publication_uses_only_repository_token_and_isolated_targets(self):
        workflow = yaml.safe_load(Path('.github/workflows/publication-integration.yml').read_text())
        job = workflow['jobs']['integration']
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(job['permissions'], {'contents': 'write', 'packages': 'write'})
        self.assertIn("startsWith(github.event.repository.name, 'publication-integration-')", job['if'])
        self.assertIn('inputs.repository == github.repository', job['if'])
        live = next(step for step in job['steps'] if step.get('name') == 'Real isolated GitHub and GHCR integration')
        self.assertEqual(live['env']['GH_TOKEN'], '${{ github.token }}')
        self.assertEqual(live['env']['REGISTRY_USER'], '${{ github.repository_owner }}')
        self.assertNotIn('secrets.', str(workflow))
        self.assertNotIn('gh api user ', live['run'])

    def test_real_workflow_conditions_for_trigger_build_and_failed_security(self):
        workflow = yaml.safe_load(Path('.github/workflows/release.yml').read_text())
        def enabled(condition, **context):
            expression = condition.replace('&&', ' and ').replace('||', ' or ')
            return eval(expression, {'__builtins__': {}}, context)
        build = next(s for s in workflow['jobs']['validate']['steps'] if s.get('id') == 'build')
        for event in ('push', 'workflow_dispatch', 'schedule', 'pull_request'):
            github = SimpleNamespace(ref='refs/pull/1/merge' if event == 'pull_request' else 'refs/heads/main', event_name=event)
            runnable = enabled(workflow['jobs']['validate']['if'], github=github)
            self.assertEqual(runnable, event != 'pull_request')
            for plan_build in ('true', 'false'):
                steps = SimpleNamespace(plan=SimpleNamespace(outputs=SimpleNamespace(build=plan_build)))
                self.assertEqual(enabled(build['if'], steps=steps), plan_build == 'true')
            for result, eligible, expected in [('failure', 'false', False), ('failure', 'true', False), ('success', 'false', False), ('success', 'true', True)]:
                needs = SimpleNamespace(validate=SimpleNamespace(result=result, outputs=SimpleNamespace(eligible=eligible)))
                self.assertEqual(enabled(workflow['jobs']['publish']['if'], needs=needs), expected)
        pr = yaml.safe_load(Path('.github/workflows/policy-review.yml').read_text())
        integration = pr['jobs']['integration']
        self.assertEqual(integration['permissions'], {'contents': 'read'})
        self.assertTrue(any('docker build --tag local-pr-validation' in s.get('run', '') for s in integration['steps']))
        self.assertFalse(any('push: true' in str(s) or 'promotion.py publish' in s.get('run', '') for s in integration['steps']))

    def test_actual_historical_workflow_script_propagates_reassessment_failure(self):
        workflow = yaml.safe_load(Path('.github/workflows/policy-review.yml').read_text())
        step = next(s for s in workflow['jobs']['policy']['steps'] if s.get('name', '').startswith('Reassess retained'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fakebin = root / 'bin'
            fakebin.mkdir()
            for name, body in {'jq': '#!/bin/sh\necho 1\n', 'python3': '#!/bin/sh\ncase "$1" in tests/*) exit 23;; *) exit 0;; esac\n'}.items():
                path = fakebin / name
                path.write_text(body)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin)+':'+os.environ['PATH'], GITHUB_STEP_SUMMARY=str(root/'summary'))
            result = subprocess.run(['bash', '-e', '-c', step['run']], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)
            self.assertFalse((root/'summary').exists())

    def test_actual_security_audit_gate_blocks_rejected_assessment(self):
        workflow = yaml.safe_load(Path('.github/workflows/security-audit.yml').read_text())
        step = next(s for s in workflow['jobs']['scan']['steps'] if s.get('name') == 'Require exact-upstream custom security policy')
        self.assertFalse(step.get('continue-on-error', False))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'security-assessment.json'
            for accepted in (False, True):
                path.write_text(json.dumps({'pass': accepted}))
                result = subprocess.run(['bash', '-e', '-c', step['run']], cwd=directory, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, accepted)


    def test_actual_dual_layer_command_propagates_scanner_failure(self):
        workflow = yaml.safe_load(Path('.github/workflows/policy-review.yml').read_text())
        step = next(s for s in workflow['jobs']['integration']['steps'] if s.get('name') == 'Inspect layers for credentials')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fakebin = root / 'bin'
            fakebin.mkdir()
            (root/'Dockerfile').write_text('ARG UPSTREAM_IMAGE=upstream-fixture\n')
            commands = {
                'docker': '#!/bin/sh\nexit 0\n',
                'python3': '#!/bin/sh\nif [ "$1" = tests/test-image-layers.py ]; then echo "$2 $3" >> "$CALLS"; if [ "$CANDIDATE_FAIL" != 0 ]; then exit "$CANDIDATE_FAIL"; else exit "$UPSTREAM_FAIL"; fi; fi\nexit 0\n',
            }
            for name, body in commands.items():
                path = fakebin/name
                path.write_text(body)
                path.chmod(0o755)
            for upstream, candidate in [(0,0), (23,0), (0,29), (23,29)]:
                calls = root/'calls'
                calls.write_text('')
                env = dict(os.environ, PATH=str(fakebin)+':'+os.environ['PATH'], CALLS=str(calls),
                           UPSTREAM_FAIL=str(upstream), CANDIDATE_FAIL=str(candidate))
                result = subprocess.run(['bash', '-e', '-c', step['run']], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, upstream == candidate == 0)
                self.assertEqual(calls.read_text().splitlines(), ['local-pr-validation upstream-fixture'])

    def test_audit_candidate_helper_uses_only_loopback_and_verifies_source_and_digest(self):
        helper = Path('scripts/prepare-security-candidate.sh').resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fakebin = root/'bin'
            fakebin.mkdir()
            (root/'Dockerfile').write_text('ARG UPSTREAM_IMAGE=ghcr.io/openhands/agent-server@sha256:'+'b'*64+'\n')
            (fakebin/'git').write_text('#!/bin/sh\nif [ "$1" = rev-parse ]; then printf "%s\\n" "$EXPECTED_SOURCE"; fi\n')
            (fakebin/'curl').write_text('#!/bin/sh\nexit 0\n')
            (fakebin/'docker').write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['CALLS'],'a') as log: log.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='inspect': print(os.environ['DOCKER_METADATA'])
''')
            for path in fakebin.iterdir(): path.chmod(0o755)
            valid = dict(RepoDigests=['127.0.0.1:5000/openhands-pr-security@sha256:'+'c'*64],
                         Id='sha256:'+'d'*64, Config=dict(Labels={
                             'org.opencontainers.image.revision':'a'*40,
                             'org.opencontainers.image.base.digest':'sha256:'+'b'*64}))
            for source, metadata, success in [('a'*40, valid, True), ('e'*40, valid, False),
                ('a'*40, dict(valid, RepoDigests=['ghcr.io/production/image@sha256:'+'c'*64]), False)]:
                calls=root/'calls'
                calls.write_text('')
                env=dict(os.environ, PATH=str(fakebin)+':'+os.environ['PATH'], EXPECTED_SOURCE='a'*40,
                         CALLS=str(calls), DOCKER_METADATA=json.dumps([metadata]))
                result=subprocess.run(['bash',str(helper),source],cwd=root,env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode==0,success,result.stderr)
                recorded=[json.loads(line) for line in calls.read_text().splitlines()]
                pushes=[cmd for cmd in recorded if cmd[0]=='push']
                self.assertTrue(all(cmd[1]=='127.0.0.1:5000/openhands-pr-security:'+'a'*40 for cmd in pushes))
                if success:
                    self.assertEqual(len(pushes),1)
                    identity=json.loads((root/'candidate-image-identity.json').read_text())
                    self.assertEqual(identity['source_commit'],'a'*40)
                    self.assertEqual(identity['candidate'],valid['RepoDigests'][0])
                    self.assertEqual((root/'candidate-ref.txt').read_text().strip(),identity['candidate'])
                    registry=[cmd for cmd in recorded if cmd[0]=='run'][0]
                    self.assertIn('127.0.0.1:5000:5000',registry)
                if source!='a'*40:self.assertEqual(recorded,[])

    def test_automatic_publisher_is_gated_and_never_rebuilds(self):
        workflow = yaml.safe_load(Path('.github/workflows/release.yml').read_text())
        publisher = workflow['jobs']['publish']
        self.assertEqual(publisher['needs'], 'validate')
        self.assertIn("needs.validate.result == 'success'", publisher['if'])
        self.assertIn("needs.validate.outputs.eligible == 'true'", publisher['if'])
        self.assertNotIn('environment', publisher)
        self.assertEqual(publisher['permissions']['contents'], 'write')
        for step in publisher['steps']:
            self.assertNotIn('docker/build-push-action', step.get('uses', ''))
            self.assertNotIn('docker build', step.get('run', ''))
        self.assertNotIn('concurrency', workflow)
        self.assertNotIn('concurrency', workflow['jobs']['validate'])
        self.assertEqual(publisher['concurrency'], {'group': 'ghcr-main-release', 'cancel-in-progress': False})
        self.assertFalse(Path('.github/workflows/promote.yml').exists())
        self.assertFalse(Path('.github/workflows/promotion-proposal.yml').exists())
        self.assertEqual(workflow['jobs']['validate']['permissions']['contents'], 'read')

if __name__ == '__main__':
    unittest.main()
