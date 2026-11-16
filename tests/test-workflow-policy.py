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


    def workflow(self, name):
        return yaml.safe_load(Path(f'.github/workflows/{name}.yml').read_text())

    def events(self, workflow):
        # PyYAML resolves the Actions key `on` as a YAML 1.1 boolean.
        return workflow.get('on', workflow.get(True))

    def test_pr_never_builds_or_publishes(self):
        workflow = self.workflow('policy-review')
        self.assertEqual(set(self.events(workflow)), {'pull_request'})
        for job in workflow['jobs'].values():
            self.assertNotIn('uses', job)
            self.assertNotIn('write', job.get('permissions', {}).values())
            steps = str(job['steps'])
            self.assertIn('python3 tests/test-workflow-policy.py', steps)
            self.assertIn('python3 tests/test-automation-safety.py', steps)
            for forbidden in ('docker/', 'docker build', 'docker push', 'promotion.py publish',
                              'gh workflow run', 'create-github-app-token', 'release.py plan'):
                self.assertNotIn(forbidden, steps)
        for name in ('ci', 'release', 'upstream-update', 'promote', 'promotion-proposal'):
            self.assertNotIn('pull_request', self.events(self.workflow(name)))
            self.assertNotIn('pull_request_target', self.events(self.workflow(name)))

    def test_dry_run_default_read_only_and_failure_diagnostics(self):
        workflow = self.workflow('promote')
        setting = self.events(workflow)['workflow_dispatch']['inputs']['dry_run']
        self.assertEqual(setting['type'], 'boolean')
        self.assertIs(setting['default'], True)
        assess = workflow['jobs']['assess']
        self.assertEqual(workflow['env']['TRUSTED_RELEASE_ACTOR'], '${{ vars.TRUSTED_RELEASE_ACTOR }}')
        self.assertNotIn('environment', assess)
        self.assertNotIn('write', assess['permissions'].values())
        self.assertNotIn('docker/login-action', str(assess))
        steps = assess['steps']
        commands = [s.get('run', '') for s in steps]
        prepare = commands.index('python3 scripts/promotion.py prepare')
        seal = next(i for i, c in enumerate(commands) if 'promotion.py seal' in c)
        dry = next(s for s in steps if s.get('run') == 'python3 scripts/promotion.py dry-run')
        self.assertLess(prepare, seal)
        self.assertLess(seal, steps.index(dry))
        self.assertNotIn('release_approved', commands[seal])
        self.assertEqual(dry['if'], 'always() && inputs.dry_run')
        self.assertNotIn('continue-on-error', dry)
        diagnostics = next(s for s in steps if s.get('name') == 'Preserve all assessment diagnostics')
        self.assertEqual(diagnostics['if'], 'always()')
        for name in ('promotion-dry-run.json', 'selection.json', 'trusted/', 'debian-tracker.json', 'security-assessment.json'):
            self.assertIn(name, diagnostics['with']['path'])
        bundle = next(s for s in steps if s.get('id') == 'bundle')
        self.assertEqual(bundle['if'], "always() && steps.seal.outcome == 'success'")
        self.assertNotIn('promotion-dry-run.json', bundle['with']['path'])
        publish = workflow['jobs']['publish']
        for condition in ('!inputs.dry_run', "needs.assess.result == 'success'", "needs.assess.outputs.bundle_digest != ''"):
            self.assertIn(condition, publish['if'])
        gate = next(s for s in steps if s.get('name') == 'Require release policy authorization')
        self.assertEqual(gate['if'], '${{ !inputs.dry_run }}')
        self.assertIn('release_approved', gate['run'])

    def test_automation_opt_in_trusted_app_and_duplicate_suppression(self):
        workflow = self.workflow('promotion-proposal')
        self.assertEqual(self.events(workflow)['workflow_run'], {
            'workflows': ['CI', 'Daily upstream update'], 'types': ['completed'], 'branches': ['main']})
        self.assertNotIn('write', workflow['permissions'].values())
        job = workflow['jobs']['propose']
        self.assertNotIn('environment', job)
        self.assertIn("vars.PROMOTION_AUTOMATION_ENABLED == 'true'", job['if'])
        self.assertIn('head_repository.full_name == github.repository', job['if'])
        self.assertIn("head_branch == 'main'", job['if'])
        steps = job['steps']
        self.assertEqual(steps[0]['with']['ref'], 'refs/heads/main')
        self.assertIs(steps[0]['with']['persist-credentials'], False)
        candidate = next(s for s in steps if s.get('id') == 'candidate')
        self.assertIn('evidence.download(run, attempt, digest,', candidate['run'])
        self.assertIn('release.fingerprint(state[', candidate['run'])
        self.assertIn("r['display_title'] == title", candidate['run'])
        self.assertIn('--paginate', candidate['run'])
        self.assertIn("'retained-candidate.json' in archive.namelist()", candidate['run'])
        self.assertIn("os.environ['PUBLICATION_ENABLED'] == 'true' and policy['release_approved'] is True", candidate['run'])
        self.assertIn('hashlib.sha256', candidate['run'])
        self.assertIn('dry-run {str(dry_run).lower()}', candidate['run'])
        app = next(s for s in steps if s.get('id') == 'app')
        self.assertLess(steps.index(candidate), steps.index(app))
        self.assertEqual(app['with']['permission-actions'], 'write')
        self.assertEqual(app['if'], "steps.candidate.outputs.candidate != ''")
        dispatch = next(s for s in steps if 'gh workflow run' in s.get('run', ''))
        self.assertEqual(dispatch['env']['GH_TOKEN'], '${{ steps.app.outputs.token }}')
        for required in ('= Bot', '!= Skulldorom', '-f dry_run="$DRY_RUN"', '--ref main'):
            self.assertIn(required, dispatch['run'])
        self.assertIn('test "${APP_SLUG}[bot]" = "$TRUSTED_RELEASE_ACTOR"', dispatch['run'])
        self.assertIn('-f policy_sha256="$POLICY_SHA256"', dispatch['run'])
        self.assertNotIn('promotion.py publish', str(steps))
        self.assertNotIn('docker build', str(steps))

    def test_polling_preserves_content_gate_and_blocked_retry_suppression(self):
        workflow = self.workflow('upstream-update')
        self.assertIn('schedule', self.events(workflow))
        self.assertEqual(workflow['jobs']['release']['uses'], './.github/workflows/release.yml')
        steps = self.workflow('release')['jobs']['build-test-publish']['steps']
        self.assertEqual(next(s for s in steps if s.get('id') == 'plan')['run'], 'python3 scripts/release.py plan')
        self.assertEqual(next(s for s in steps if s.get('id') == 'build')['if'], "steps.plan.outputs.build == 'true'")
        skip = next(s for s in steps if s.get('name') == 'Skip unchanged image')
        self.assertEqual(skip['env']['BLOCKED'], '${{ steps.plan.outputs.blocked }}')
        self.assertIn('no rebuild or release', skip['run'])
        build = next(s for s in steps if s.get('id') == 'build')
        self.assertIn('steps.plan.outputs.candidate_key', build['with']['tags'])
        record = next(s for s in steps if s.get('name') == 'Record built candidate before validation')
        self.assertLess(steps.index(build), steps.index(record))
        self.assertIn('record-candidate', record['run'])
        archive = next(s for s in steps if s.get('name') == 'Preserve validation evidence')
        self.assertIn('retained-candidate.json', archive['with']['path'])

if __name__ == '__main__':
    unittest.main()
