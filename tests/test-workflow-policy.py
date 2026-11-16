#!/usr/bin/env python3
"""Validate workflow schema and security wiring, not publication."""
from pathlib import Path
import unittest
import yaml


class WorkflowPolicyTests(unittest.TestCase):
    def test_yaml_actions_pinned_and_pull_requests_read_only(self):
        for path in Path('.github/workflows').glob('*.yml'):
            workflow = yaml.safe_load(path.read_text())
            self.assertIsInstance(workflow['jobs'], dict)
            for job in workflow['jobs'].values():
                for step in job.get('steps', []):
                    if 'uses' in step:
                        self.assertRegex(step['uses'], r'^[\w/-]+@[a-f0-9]{40}$')
            if path.name == 'policy-review.yml':
                self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})
                for job in workflow['jobs'].values():
                    self.assertNotIn('environment', job)

    def test_policy_only_promotion_no_build_and_environment_required(self):
        workflow = yaml.safe_load(Path('.github/workflows/promote.yml').read_text())
        self.assertEqual(workflow['jobs']['publish']['environment']['name'], 'release')
        self.assertEqual(workflow['jobs']['publish']['needs'], 'assess')
        self.assertNotIn('write', workflow['jobs']['assess']['permissions'].values())
        self.assertEqual(workflow['jobs']['publish']['permissions']['packages'], 'write')
        for job in workflow['jobs'].values():
            for step in job['steps']:
                self.assertNotIn('docker/build-push-action', step.get('uses', ''))
                self.assertNotIn('docker build', step.get('run', ''))
        build = Path('.github/workflows/release.yml').read_text()
        self.assertNotIn('release.py publish', build)
        self.assertNotIn('promotion.py publish', build)
        self.assertIn('Attest functional evidence', build)
        self.assertIn('Attest image build', build)
        promotion = Path('.github/workflows/promote.yml').read_text()
        self.assertIn('Freeze scanner database', promotion)
        self.assertIn('--scanners vuln,secret', promotion)
        self.assertIn('--ignorefile /dev/null', promotion)
        self.assertIn('sha256sum --check scanner-database.sha256', promotion)
        self.assertIn('promotion.py publish', promotion)


if __name__ == '__main__':
    unittest.main()
