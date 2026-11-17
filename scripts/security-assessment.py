#!/usr/bin/env python3
"""Compare complete exact-digest scans against official OpenHands, fail closed."""
import argparse
import hashlib
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import re
import sys

SEVERITIES = {name: i for i, name in enumerate(('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))}
SCANNER_VERSION = '0.69.3'


def findings(report):
    for result in report['Results']:
        packages = {p['Name']: p for p in result.get('Packages', [])}
        for vulnerability in result.get('Vulnerabilities', []):
            yield result, packages.get(vulnerability['PkgName'], {}), vulnerability


def key(vulnerability):
    return vulnerability['PkgName'], vulnerability['VulnerabilityID']


def scope(result):
    # Trivy's OS Target contains the image ref; language targets identify binaries.
    return 'os' if result.get('Class') == 'os-pkgs' else result['Target']


def identity(result, vulnerability):
    return scope(result), result.get('Class'), result.get('Type'), *key(vulnerability)


def exact_identity(result, vulnerability):
    return (*identity(result, vulnerability), vulnerability['InstalledVersion'], vulnerability['Severity'])


def metadata_hash(vulnerability):
    fields = {k: vulnerability.get(k) for k in ('Severity', 'FixedVersion', 'Status', 'CVSS', 'References', 'Title', 'Description', 'SeveritySource', 'DataSource')}
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def validate_policy(policy):
    assert set(policy) == {'schema', 'owner', 'baseline', 'scanner_version', 'block_severities', 'emergency_blocks'}, 'Invalid/obsolete policy schema'
    assert policy['schema'] == 2 and policy['baseline'] == 'ghcr.io/openhands/agent-server'
    assert policy['scanner_version'] == SCANNER_VERSION
    assert policy['block_severities'] == ['HIGH', 'CRITICAL'], 'Introduced serious risk must block'
    assert isinstance(policy['owner'], str) and policy['owner'].strip()
    assert isinstance(policy['emergency_blocks'], list)
    seen = set()
    for record in policy['emergency_blocks']:
        assert set(record) == {'cve', 'reason', 'reviewed_by', 'reviewed_at', 'evidence_url'}, 'Emergency block requires explicit review evidence'
        assert all(isinstance(v, str) and v.strip() for v in record.values())
        assert re.fullmatch(r'CVE-\d{4}-\d{4,}', record['cve']) and record['cve'] not in seen
        assert date.fromisoformat(record['reviewed_at']) <= date.today()
        assert record['evidence_url'].startswith('https://') and len(record['reason']) >= 20
        seen.add(record['cve'])


def validate_scan(report, expected):
    assert re.fullmatch(r'.+@sha256:[a-f0-9]{64}', expected), 'Exact image digest required'
    assert report['ArtifactName'] == expected, 'Scan artifact mismatch'
    assert report.get('SchemaVersion') == 2 and report.get('ArtifactType') == 'container_image', 'Unsupported scan schema'
    assert report['Metadata']['OS']['Family'] == 'debian' and report['Metadata']['OS']['Name'].startswith('13'), 'Unsupported OS'
    assert report['Trivy']['Version'] == SCANNER_VERSION, 'Missing/unapproved scanner identity'
    assert not report.get('Errors') and not report.get('Error'), 'Scanner errors present'
    assert isinstance(report.get('Results'), list) and report['Results'], 'Empty scan'
    assert any(r.get('Class') == 'os-pkgs' and r.get('Type') == 'debian' and r.get('Packages') for r in report['Results']), 'Missing OS inventory'
    seen = set()
    for result in report['Results']:
        assert isinstance(result.get('Target'), str) and result['Target']
        assert not result.get('Misconfigurations') and not result.get('MisconfSummary'), 'Unexpected scan format'
        assert not result.get('SuppressedFindings'), 'Suppressed findings forbidden'
        for field in ('Packages', 'Vulnerabilities', 'Secrets'):
            assert isinstance(result.get(field, []), list), 'Malformed scan inventory: ' + field
        for package in result.get('Packages', []):
            assert isinstance(package.get('Name'), str) and package['Name']
        for vulnerability in result.get('Vulnerabilities', []):
            assert result.get('Class') in {'os-pkgs', 'lang-pkgs'} and result.get('Type'), 'Unscoped vulnerability'
            for field in ('PkgName', 'VulnerabilityID', 'InstalledVersion', 'Severity'):
                assert isinstance(vulnerability.get(field), str) and vulnerability[field], 'Malformed vulnerability'
            assert vulnerability['Severity'] in SEVERITIES, 'Unsupported severity'
            # Duplicate identities would otherwise hide an additional affected target.
            exact = exact_identity(result, vulnerability)
            assert exact not in seen, 'Ambiguous duplicate vulnerability'
            seen.add(exact)
        for secret in result.get('Secrets', []):
            assert isinstance(secret, dict) and secret.get('RuleID'), 'Malformed secret finding'


def assess(candidate, upstream, policy, tracker, expected_candidate, expected_upstream, previous_upstream=None, baseline=None):
    validate_policy(policy)
    validate_scan(candidate, expected_candidate)
    validate_scan(upstream, expected_upstream)
    old = defaultdict(list)
    for result, _, vulnerability in findings(upstream):
        old[identity(result, vulnerability)].append(vulnerability)
    upstream_packages = {(scope(r), r.get('Class'), r.get('Type'), p['Name'])
                         for r in upstream['Results'] for p in r.get('Packages', [])}
    emergency = {r['cve']: r for r in policy['emergency_blocks']}
    rows = []
    for result, package, vulnerability in findings(candidate):
        alternatives = old.get(identity(result, vulnerability), [])
        same_version = [v for v in alternatives if v['InstalledVersion'] == vulnerability['InstalledVersion']]
        severity = vulnerability['Severity']
        if any(v['Severity'] == severity for v in same_version):
            comparison = 'inherited unchanged'
        elif same_version and SEVERITIES[severity] <= max(SEVERITIES[v['Severity']] for v in same_version):
            comparison = 'improved'
        elif alternatives:
            comparison = 'materially worsened'
        else:
            comparison = 'introduced'
        origin = 'inherited finding' if comparison in {'inherited unchanged', 'improved'} else (
            'new finding in inherited package' if (scope(result), result.get('Class'), result.get('Type'), vulnerability['PkgName']) in upstream_packages else 'added package/component')
        reasons = []
        if comparison == 'introduced' and severity in policy['block_severities']:
            reasons.append('HIGH/CRITICAL introduced by custom image relative to exact upstream')
        if comparison == 'materially worsened':
            reasons.append('customization changed a vulnerable version or increased inherited severity; potential worsening requires remediation')
        if vulnerability['VulnerabilityID'] in emergency:
            reasons.append('reviewed emergency block: ' + emergency[vulnerability['VulnerabilityID']]['reason'])
        source = package.get('SrcName', vulnerability['PkgName'])
        vendor = tracker.get(source, {}).get(vulnerability['VulnerabilityID'], {})
        rows.append({'package': vulnerability['PkgName'], 'source_package': source, 'metadata_sha256': metadata_hash(vulnerability),
                     'cve': vulnerability['VulnerabilityID'], 'severity': severity, 'installed': vulnerability['InstalledVersion'],
                     'fixed': vulnerability.get('FixedVersion', ''), 'status': vulnerability.get('Status', 'unknown'),
                     'target': result['Target'], 'comparison_target': scope(result), 'result_class': result.get('Class'), 'result_type': result.get('Type'),
                     'comparison': comparison, 'origin': origin, 'upstream_installed': sorted({v['InstalledVersion'] for v in alternatives}),
                     'vendor_trixie': vendor.get('releases', {}).get('trixie', {}), 'vendor_scope': vendor.get('scope', 'unknown'),
                     'title': vulnerability.get('Title', ''), 'description': vulnerability.get('Description', ''),
                     'references': vulnerability.get('References', []), 'cvss': vulnerability.get('CVSS', {}),
                     'blocking_reasons': reasons, 'exposure': 'Potentially reachable in arbitrary agent workloads; inherited does not mean harmless.'})
    candidate_exact = {exact_identity(r, v) for r, _, v in findings(candidate)}
    removed = [{'target': scope(r), 'result_class': r.get('Class'), 'result_type': r.get('Type'),
                'package': v['PkgName'], 'cve': v['VulnerabilityID'], 'installed': v['InstalledVersion'], 'severity': v['Severity']}
               for r, _, v in findings(upstream) if exact_identity(r, v) not in candidate_exact]
    secrets = [dict(image=report['ArtifactName'], target=result['Target'], rule=secret['RuleID'], title=secret.get('Title'))
               for report in (candidate, upstream) for result in report['Results'] for secret in result.get('Secrets', [])]
    introduced = [r for r in rows if r['comparison'] == 'introduced' and r['severity'] in policy['block_severities']]
    worsened = [r for r in rows if r['comparison'] == 'materially worsened']
    new_upstream = None
    if baseline is not None and baseline.get('upstream') is not None:
        assert previous_upstream is not None, 'Previous approved upstream scan missing'
        validate_scan(previous_upstream, baseline['upstream'])
        previous = {exact_identity(r, v) for r, _, v in findings(previous_upstream)}
        new_upstream = [{'target': scope(r), 'package': v['PkgName'], 'cve': v['VulnerabilityID'], 'installed': v['InstalledVersion'], 'severity': v['Severity']}
                        for r, _, v in findings(upstream) if exact_identity(r, v) not in previous]
    else:
        assert previous_upstream is None, 'Unbound previous upstream scan'
    blockers = [r for r in rows if r['blocking_reasons']]
    return {'schema': 2, 'modification_pass': not introduced and not worsened and not secrets,
            'introduced_high_critical': introduced, 'materially_worsened': worsened,
            'candidate': expected_candidate, 'upstream': expected_upstream,
            'policy_sha256': hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(), 'policy_owner': policy['owner'],
            'severity_counts': dict(Counter(r['severity'] for r in rows)),
            'upstream_severity_counts': dict(Counter(v['Severity'] for _, _, v in findings(upstream))),
            'with_advertised_fix': sum(bool(r['fixed']) for r in rows), 'without_advertised_fix': sum(not r['fixed'] for r in rows),
            'origin_counts': dict(Counter(r['origin'] for r in rows)), 'comparison_counts': dict(Counter(r['comparison'] for r in rows)),
            'removed_findings': removed, 'removed_package_cves': sorted({(r['package'], r['cve']) for r in removed}),
            'new_upstream_findings': new_upstream, 'previous_baseline': baseline,
            'emergency_blocked': [r for r in rows if r['cve'] in emergency],
            'findings': rows, 'secrets': secrets, 'blockers': blockers, 'pass': not blockers and not secrets}


def concise(assessment):
    counts = assessment['comparison_counts']
    new = assessment['new_upstream_findings']
    return [f"Custom image security: **{'PASS' if assessment['modification_pass'] else 'FAIL'}**",
            'Inherited upstream security: **reported, not automatically blocked**. Inherited does not mean fixed or harmless.',
            f"Release security gate: **{'PASS' if assessment['pass'] else 'BLOCKED'}**; emergency-blocked: {len(assessment['emergency_blocked'])}; secret detections: {len(assessment['secrets'])}.",
            f"Candidate totals by severity: {assessment['severity_counts']}; upstream: {assessment['upstream_severity_counts']}.",
            f"Inherited unchanged: {counts.get('inherited unchanged', 0)}; introduced (all severities): {counts.get('introduced', 0)}; removed: {len(assessment['removed_findings'])}; materially worsened: {len(assessment['materially_worsened'])}.",
            f"Introduced HIGH/CRITICAL: {len(assessment['introduced_high_critical'])}; new upstream findings since previous approved upstream (rescanned with same database): {len(new) if new is not None else 'unavailable — first approved baseline not established'}."]


def markdown(assessment):
    lines = ['# Candidate security comparison', '', f"Candidate: `{assessment['candidate']}`", f"Upstream: `{assessment['upstream']}`", '', *concise(assessment), '',
             'Changed vulnerable versions are conservatively treated as potential worsening; version strings are never compared lexically. A passing custom comparison is not a vulnerability-free or universal safety claim.', '',
             '| Package | Target | CVE | Severity | Installed | Advertised fix | Comparison | Gate |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in sorted(assessment['findings'], key=lambda r: (r['package'], r['cve'], r['target'])):
        values = [row['package'], row['target'], row['cve'], row['severity'], row['installed'], row['fixed'] or 'none', row['comparison'], '; '.join(row['blocking_reasons']) or 'reported']
        lines.append('| ' + ' | '.join(str(v).replace('|', '\\|').replace('\n', ' ') for v in values) + ' |')
    for title, records in [('New upstream findings since previous approved baseline', assessment['new_upstream_findings']), ('Removed upstream findings', assessment['removed_findings']), ('Emergency-blocked findings', assessment['emergency_blocked'])]:
        lines += ['', '## ' + title, '', '```json', json.dumps(records, indent=2), '```']
    lines += ['', 'Complete raw reports remain attached. No scanner finding is suppressed.']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    for name in ('candidate', 'upstream', 'policy', 'tracker', 'candidate-ref', 'upstream-ref'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--previous-upstream')
    parser.add_argument('--baseline')
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args()
    load = lambda name: json.loads(Path(name).read_text())
    baseline = load(args.baseline) if args.baseline else None
    previous = load(args.previous_upstream) if args.previous_upstream else None
    assessment = assess(load(args.candidate), load(args.upstream), load(args.policy), load(args.tracker), args.candidate_ref, args.upstream_ref, previous, baseline)
    Path('security-assessment.json').write_text(json.dumps(assessment, indent=2) + '\n')
    Path('security-assessment.md').write_text(markdown(assessment))
    Path('security-gate.json').write_text(json.dumps({k: assessment[k] for k in ('candidate', 'upstream', 'pass', 'blockers', 'secrets', 'emergency_blocked')}, indent=2) + '\n')
    print('\n'.join(concise(assessment)))
    return 0 if args.report_only or assessment['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
