#!/usr/bin/env python3
"""Every scan instance survives grouping; module fixes confer no waiver."""
import importlib.util
import unittest

spec = importlib.util.spec_from_file_location('inventory', 'scripts/group-security-inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_repeated_cves_across_binaries_and_source_packages(self):
        row = {'cve': 'CVE-2026-10000', 'severity': 'HIGH', 'package': 'module', 'source_package': '',
               'installed': '1', 'fixed': '2', 'target': 'bin/a', 'metadata_sha256': 'a' * 64}
        report = inventory.group({'candidate': 'exact-candidate', 'upstream': 'exact-base', 'findings': [
            row, dict(row, target='bin/b'), dict(row, package='other', source_package='source', severity='CRITICAL'),
            dict(row, severity='LOW')]})
        self.assertEqual((report['instance_count'], report['distinct_cves']), (3, 1))
        cve = report['findings'][0]
        self.assertEqual(cve['severity'], 'CRITICAL')
        self.assertEqual(sum(c['instances'] for c in cve['components']), 3)
        self.assertEqual(cve['components'][0]['targets'], ['bin/a', 'bin/b'])
        for component in cve['components']:
            self.assertEqual(component['advertised_fixes'], ['2'])
            self.assertIn('no acceptance activated', component['decision'])
            self.assertIn('not established', component['reachability'])
        self.assertIn('3 instances; 1 distinct CVEs', inventory.markdown(report))


if __name__ == '__main__':
    unittest.main()
