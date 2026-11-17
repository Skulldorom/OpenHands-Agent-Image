#!/usr/bin/env python3
"""Validate workflow schema and security wiring, not publication."""
from pathlib import Path
import re
import subprocess
import unittest
import yaml


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
        self.assertEqual(workflow['concurrency'], {'group': 'ghcr-main-release', 'cancel-in-progress': False})
        self.assertFalse(Path('.github/workflows/promote.yml').exists())
        self.assertFalse(Path('.github/workflows/promotion-proposal.yml').exists())
        self.assertEqual(workflow['jobs']['validate']['permissions']['contents'], 'read')

if __name__ == '__main__':
    unittest.main()
