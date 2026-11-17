#!/usr/bin/env python3
"""Behavioral exact-upstream security regression tests; no scanner/network mocks."""
from copy import deepcopy
from datetime import date
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('assessment', 'scripts/security-assessment.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(Path('security/policy.json').read_text())
        self.base_ref = 'ghcr.io/openhands/agent-server@sha256:' + 'a'*64
        self.candidate_ref = 'ghcr.io/skulldorom/openhands-agent@sha256:' + 'b'*64
        self.base = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'ArtifactName': self.base_ref,
                     'Trivy': {'Version': '0.69.3'}, 'Metadata': {'OS': {'Family': 'debian', 'Name': '13.7'}},
                     'Results': [{'Target': 'debian', 'Class': 'os-pkgs', 'Type': 'debian',
                                  'Packages': [{'Name': 'libxml2'}], 'Vulnerabilities': []}]}
        self.candidate = deepcopy(self.base)
        self.candidate['ArtifactName'] = self.candidate_ref

    def vulnerability(self, severity='HIGH', cve='CVE-2026-0001', fixed=''):
        return {'PkgName': 'libxml2', 'VulnerabilityID': cve, 'Severity': severity, 'InstalledVersion': '1.0', 'FixedVersion': fixed}

    def inherit(self, severity='HIGH', fixed=''):
        v = self.vulnerability(severity, fixed=fixed)
        for report in (self.base, self.candidate):
            report['Results'][0]['Vulnerabilities'] = [deepcopy(v)]

    def run_assessment(self, previous=None, baseline=None):
        return module.assess(self.candidate, self.base, self.policy, {}, self.candidate_ref, self.base_ref, previous, baseline)

    def test_unchanged_inherited_high_passes_with_complete_inventory(self):
        self.inherit()
        r = self.run_assessment()
        self.assertTrue(r['pass'])
        self.assertEqual(r['comparison_counts'], {'inherited unchanged': 1})
        self.assertEqual(len(r['findings']), 1)
        self.assertEqual(r['blockers'], [])

    def test_unchanged_inherited_critical_passes(self):
        self.inherit('CRITICAL')
        self.assertTrue(self.run_assessment()['pass'])

    def test_advertised_fix_or_no_fix_does_not_change_inheritance_gate(self):
        for fix in ('', '2.0'):
            self.inherit(fixed=fix)
            self.assertTrue(self.run_assessment()['pass'])

    def test_old_five_blanket_cves_are_not_implicit_emergency_blocks(self):
        for cve in ('CVE-2026-6653', 'CVE-2026-78661', 'CVE-2026-17106', 'CVE-2026-41567', 'CVE-2026-42306'):
            self.inherit('CRITICAL')
            for report in (self.base, self.candidate):
                report['Results'][0]['Vulnerabilities'][0]['VulnerabilityID'] = cve
            self.assertTrue(self.run_assessment()['pass'])
        self.assertEqual(self.policy['emergency_blocks'], [])

    def test_introduced_high_blocks(self):
        self.candidate['Results'][0]['Vulnerabilities'] = [self.vulnerability()]
        r = self.run_assessment()
        self.assertFalse(r['pass'])
        self.assertFalse(r['modification_pass'])
        self.assertEqual(len(r['introduced_high_critical']), 1)

    def test_introduced_critical_blocks(self):
        self.candidate['Results'][0]['Vulnerabilities'] = [self.vulnerability('CRITICAL')]
        self.assertFalse(self.run_assessment()['pass'])

    def test_added_os_package_serious_vulnerability_blocks(self):
        self.candidate['Results'][0]['Packages'].append({'Name': 'custom-postgresql'})
        self.candidate['Results'][0]['Vulnerabilities'] = [dict(self.vulnerability(), PkgName='custom-postgresql')]
        r = self.run_assessment()
        self.assertEqual(r['findings'][0]['origin'], 'added package/component')
        self.assertFalse(r['pass'])

    def test_added_binary_cannot_borrow_cve_from_inherited_binary(self):
        for version in ('1.0', '2.0'):
            self.setUp()
            result = {'Target': 'usr/bin/gh', 'Class': 'lang-pkgs', 'Type': 'gobinary',
                      'Packages': [{'Name': 'libxml2'}], 'Vulnerabilities': [self.vulnerability()]}
            self.base['Results'].append(deepcopy(result))
            self.candidate['Results'] += [deepcopy(result), dict(deepcopy(result), Target='usr/bin/added')]
            self.candidate['Results'][-1]['Vulnerabilities'][0]['InstalledVersion'] = version
            r = self.run_assessment()
            self.assertFalse(r['pass'])
            self.assertEqual(r['findings'][-1]['comparison'], 'introduced')
            self.assertEqual(len(r['introduced_high_critical']), 1)

    def test_vulnerable_package_version_change_is_conservative_worsening(self):
        for version in ('2.0', '0.9', '1:1.0-2'):
            self.inherit()
            self.candidate['Results'][0]['Vulnerabilities'][0]['InstalledVersion'] = version
            r = self.run_assessment()
            self.assertFalse(r['pass'])
            self.assertEqual(len(r['materially_worsened']), 1)

    def test_same_version_increased_severity_blocks(self):
        for before, after in [('HIGH', 'CRITICAL'), ('LOW', 'MEDIUM'), ('MEDIUM', 'HIGH')]:
            self.inherit(before)
            self.candidate['Results'][0]['Vulnerabilities'][0]['Severity'] = after
            r = self.run_assessment()
            self.assertFalse(r['pass'])
            self.assertEqual(r['findings'][0]['comparison'], 'materially worsened')

    def test_lower_severity_same_version_remains_visible_without_block(self):
        self.inherit('CRITICAL')
        self.candidate['Results'][0]['Vulnerabilities'][0]['Severity'] = 'HIGH'
        r = self.run_assessment()
        self.assertTrue(r['pass'])
        self.assertEqual(r['findings'][0]['comparison'], 'improved')

    def test_introduced_lower_severity_is_reported(self):
        for severity in ('UNKNOWN', 'LOW', 'MEDIUM'):
            self.candidate['Results'][0]['Vulnerabilities'] = [self.vulnerability(severity)]
            r = self.run_assessment()
            self.assertTrue(r['pass'])
            self.assertEqual(r['comparison_counts']['introduced'], 1)

    def test_removed_findings_keep_target_version_and_severity(self):
        self.base['Results'][0]['Vulnerabilities'] = [self.vulnerability()]
        r = self.run_assessment()
        self.assertEqual(len(r['removed_findings']), 1)
        self.assertEqual(r['removed_findings'][0]['target'], 'os')
        self.assertEqual(r['removed_findings'][0]['installed'], '1.0')
        self.assertEqual(r['removed_package_cves'], [('libxml2', 'CVE-2026-0001')])

    def test_new_upstream_vulnerability_highlighted_but_inherited_passes(self):
        previous = deepcopy(self.base)
        self.inherit('CRITICAL')
        baseline = {'upstream': self.base_ref, 'version': '1.0.0', 'approval_sha256': 'c'*64}
        r = self.run_assessment(previous, baseline)
        self.assertTrue(r['pass'])
        self.assertEqual(len(r['new_upstream_findings']), 1)
        self.assertIn('CVE-2026-0001', module.markdown(r))
        self.assertIn('new upstream findings since previous approved upstream', module.markdown(r))

    def test_first_baseline_reports_unknown_not_zero(self):
        self.inherit()
        r = self.run_assessment()
        self.assertIsNone(r['new_upstream_findings'])
        self.assertIn('baseline not established', module.markdown(r))

    def test_previous_scan_missing_or_wrong_digest_blocks(self):
        baseline = {'upstream': self.base_ref}
        with self.assertRaises(AssertionError):
            self.run_assessment(None, baseline)
        previous = dict(self.base, ArtifactName='wrong')
        with self.assertRaises(AssertionError):
            self.run_assessment(previous, baseline)
        with self.assertRaises(AssertionError):
            self.run_assessment(self.base, None)

    def test_emergency_block_rejects_unchanged_inheritance_at_any_severity(self):
        self.policy['emergency_blocks'] = [{'cve': 'CVE-2026-0001', 'reason': 'Reviewed unacceptable exposure for this deployment',
            'reviewed_by': 'Skulldorom', 'reviewed_at': date.today().isoformat(), 'evidence_url': 'https://example.invalid/review/1'}]
        for severity in ('LOW', 'HIGH', 'CRITICAL'):
            self.inherit(severity)
            r = self.run_assessment()
            self.assertFalse(r['pass'])
            self.assertTrue(r['modification_pass'])
            self.assertEqual(len(r['emergency_blocked']), 1)

    def test_unreviewed_or_duplicate_emergency_records_fail_closed(self):
        self.policy['emergency_blocks'] = [{'cve': 'CVE-2026-0001'}]
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_secret_candidate_blocks_without_leaking_match(self):
        self.candidate['Results'][0]['Secrets'] = [{'RuleID': 'private-key', 'Match': 'sensitive-value'}]
        r = self.run_assessment()
        self.assertFalse(r['pass'])
        self.assertFalse(r['modification_pass'])
        self.assertNotIn('sensitive-value', json.dumps(r))

    def test_inherited_layer_secret_blocks(self):
        self.base['Results'][0]['Secrets'] = [{'RuleID': 'private-key'}]
        self.assertFalse(self.run_assessment()['pass'])

    def test_wrong_artifact_schema_or_empty_scan_fail_closed(self):
        for field, value in {'ArtifactName': 'wrong', 'SchemaVersion': 999, 'ArtifactType': 'filesystem', 'Results': [], 'Trivy': {}}.items():
            saved = deepcopy(self.candidate)
            self.candidate[field] = value
            with self.assertRaises((AssertionError, KeyError)):
                self.run_assessment()
            self.candidate = saved

    def test_scanner_mismatch_and_error_fail_closed(self):
        self.base['Trivy']['Version'] = 'old'
        with self.assertRaises(AssertionError):
            self.run_assessment()
        self.base['Trivy']['Version'] = '0.69.3'
        self.candidate['Errors'] = ['scan failed']
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_suppressed_or_malformed_lists_fail_closed(self):
        for field, value in [('SuppressedFindings', [{}]), ('Vulnerabilities', {}), ('Secrets', None), ('Packages', None)]:
            saved = deepcopy(self.candidate)
            self.candidate['Results'][0][field] = value
            with self.assertRaises(AssertionError):
                self.run_assessment()
            self.candidate = saved

    def test_missing_os_inventory_or_scope_blocks(self):
        self.candidate['Results'][0]['Packages'] = []
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_invalid_severity_or_duplicate_findings_fail(self):
        self.candidate['Results'][0]['Vulnerabilities'] = [self.vulnerability('unsupported')]
        with self.assertRaises(AssertionError):
            self.run_assessment()
        self.candidate['Results'][0]['Vulnerabilities'] = [self.vulnerability()]*2
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_old_acceptance_policy_cannot_reenable_exceptions(self):
        self.policy['exceptions'] = [{}]
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_cannot_disable_introduced_high_gate_in_policy(self):
        self.policy['block_severities'] = ['CRITICAL']
        with self.assertRaises(AssertionError):
            self.run_assessment()

    def test_summary_distinguishes_custom_pass_from_upstream_risk(self):
        self.inherit('CRITICAL')
        summary = module.markdown(self.run_assessment())
        self.assertIn('Custom image security: **PASS**', summary)
        self.assertIn('reported, not automatically blocked', summary)
        self.assertIn('not a vulnerability-free', summary)


if __name__ == '__main__':
    unittest.main()
