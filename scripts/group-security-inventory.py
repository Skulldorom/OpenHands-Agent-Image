#!/usr/bin/env python3
"""Group the unsuppressed assessment without making reachability/waiver claims."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


def group(assessment):
    rows = [row for row in assessment['findings'] if row['severity'] in {'HIGH', 'CRITICAL'}]
    groups = defaultdict(list)
    for row in rows:
        groups[row['cve']].append(row)
    result = []
    for cve, instances in sorted(groups.items()):
        components = defaultdict(list)
        for row in instances:
            components[row['source_package'] or row['package']].append(row)
        result.append({'cve': cve, 'severity': 'CRITICAL' if any(r['severity'] == 'CRITICAL' for r in instances) else 'HIGH',
                       'instances': len(instances), 'components': [
                           {'name': name, 'instances': len(items),
                            'packages': sorted({r['package'] for r in items}),
                            'versions': sorted({r['installed'] for r in items}),
                            'targets': sorted({r['target'] for r in items}),
                            'advertised_fixes': sorted({r['fixed'] for r in items if r['fixed']}),
                            'vendor_trixie': [json.loads(v) for v in sorted({json.dumps(r.get('vendor_trixie'), sort_keys=True) for r in items})],
                            'metadata_sha256': sorted({r['metadata_sha256'] for r in items}),
                            'reachability': 'not established; requires component/CVE-specific evidence',
                            'decision': 'blocking; no acceptance activated'}
                           for name, items in sorted(components.items())]})
    return {'candidate': assessment['candidate'], 'upstream': assessment['upstream'],
            'instance_count': len(rows), 'distinct_cves': len(groups),
            'component_counts': dict(sorted(Counter(r['source_package'] or r['package'] for r in rows).items())),
            'findings': result}


def markdown(report):
    lines = ['# HIGH/CRITICAL inventory grouped by CVE', '',
             f"Candidate: `{report['candidate']}`", '', f"Upstream: `{report['upstream']}`", '',
             f"{report['instance_count']} instances; {report['distinct_cves']} distinct CVEs. Counts preserve every binary/package occurrence.", '',
             'Advertised fixes are scanner module/package versions, not proof of a supported fixed vendor binary. '
             'No entry is asserted unreachable or accepted by this grouping. See PRIORITY-ASSESSMENT.md for focused evidence.', '',
             '| CVE | Severity | Components (instances) | Total | Advertised fixes |',
             '| --- | --- | --- | ---: | --- |']
    for row in report['findings']:
        lines.append('| ' + ' | '.join([row['cve'], row['severity'],
                     '; '.join(f"{c['name']} ({c['instances']})" for c in row['components']), str(row['instances']),
                     '; '.join(f"{c['name']}: {', '.join(c['advertised_fixes'])}" for c in row['components'] if c['advertised_fixes']) or 'none advertised']) + ' |')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assessment')
    parser.add_argument('--prefix', default='high-critical-inventory')
    args = parser.parse_args()
    raw = Path(args.assessment).read_bytes()
    report = group(json.loads(raw))
    report['assessment_sha256'] = hashlib.sha256(raw).hexdigest()
    Path(args.prefix + '.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    Path(args.prefix + '.md').write_text(markdown(report))
    print(f"Grouped {report['instance_count']} HIGH/CRITICAL instances into {report['distinct_cves']} CVEs; no waivers")


if __name__ == '__main__':
    main()
