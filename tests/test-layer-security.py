#!/usr/bin/env python3
"""Real nested archives exercise historical-layer credential detection."""
import importlib.util
import io
import tarfile
import subprocess
import unittest
import struct
import json
from contextlib import redirect_stdout
from datetime import timedelta
from unittest.mock import patch
import hashlib
from pathlib import Path

spec = importlib.util.spec_from_file_location('layers', 'tests/test-image-layers.py')
layers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layers)


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return output.getvalue()


class LayerTests(unittest.TestCase):
    def test_saved_layer_hash_is_verified_before_using_age_evidence(self):
        payload = archive({'app/file': b'normal'})
        with self.assertRaisesRegex(AssertionError, 'Saved layer digest mismatch'):
            layers.check_layers(io.BytesIO(archive({'blobs/sha256/'+'a'*64: payload})))
        digest = hashlib.sha256(payload).hexdigest()
        inspected = []
        self.assertEqual(layers.check_layers(io.BytesIO(archive({'blobs/sha256/'+digest: payload})), inspected=inspected), 1)
        self.assertEqual(inspected, ['sha256:'+digest])

    def test_image_scan_retains_every_historical_detection_and_docker_failures(self):
        payload = archive({'tmp/token': b'ghp_'+b'A'*36})
        saved = archive({'blobs/sha256/'+hashlib.sha256(payload).hexdigest(): payload})
        from types import SimpleNamespace
        for code in (0, 9):
            process = SimpleNamespace(stdout=io.BytesIO(saved), wait=lambda timeout: code, poll=lambda: code)
            with patch.object(layers.subprocess, 'Popen', return_value=process), redirect_stdout(io.StringIO()):
                if code:
                    with self.assertRaisesRegex(AssertionError, 'docker save failed'):
                        layers.scan_image('immutable-fixture')
                else:
                    report = layers.scan_image('immutable-fixture')
                    self.assertEqual(report['unclassified_detections'], 1)
                    self.assertEqual(report['unclassified_findings'][0]['patterns'][0]['credential_rule'], 'github_token')

    def test_accepted_complete_inventory_is_not_an_individual_token_waiver(self):
        original = json.loads(Path('security/credential-baseline.json').read_text())
        policy = json.loads(layers.POLICY_PATH.read_text())
        identities = sorted(json.dumps(tuple(row[k] for k in layers.IDENTITY_FIELDS), separators=(',', ':')) for row in original['findings'])
        digest = hashlib.sha256(json.dumps(identities, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(digest, policy['accepted_upstream']['inventory_sha256'])
        self.assertEqual(len(original['findings']), 19)
        self.assertEqual(len(policy['public_private_keys']), 14)

    def test_normal_files(self):
        self.assertEqual(layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({'app/source.py': b'print(1)'})}))), 1)

    def test_historical_credentials_remain_blocking_after_whiteout(self):
        for name, raw in [('home/openhands/.git-credentials', b'https://user:secret@example.invalid'),
                          ('tmp/key', b'-----BEGIN PRIVATE KEY-----\n' + b'M' * 64),
                          ('tmp/token', b'ghp_' + b'a' * 36),
                          ('etc/ssl/private/ssl-cert-snakeoil.key', b'key')]:
            with self.subTest(name=name), self.assertRaises(AssertionError):
                layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({name: raw}),
                                                       'new/layer.tar': archive({'tmp/.wh.token': b''})})))

    def test_binary_format_literals_are_not_keys(self):
        for raw in [
            b"\x00\xff-----BEGIN PRIVATE KEY-----\x01\x20-----END PRIVATE KEY-----\x00",
            b"\x00-----BEGIN RSA PRIVATE KEY-----' + value + '-----END RSA PRIVATE KEY-----\xff",
            b"\x00-----BEGIN PRIVATE KEY-----\\n' + data\x00",
        ]:
            with self.subTest(size=len(raw)):
                self.assertEqual(layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({
                    'tmp/node-compile-cache/fixture': raw})}))), 1)

    def test_private_material_and_tokens_in_binary_files_still_block(self):
        examples = [b'gh' + kind + b'_' + b'A1' * 18 for kind in [b'p', b'o', b'u', b's', b'r']]
        examples += [b'github_pat_' + b'A1_' * 20, b'AKIA' + b'A1' * 8]
        for kind in [b'', b'RSA ', b'EC ', b'OPENSSH ', b'ENCRYPTED ']:
            header = b'-----BEGIN ' + kind + b'PRIVATE KEY-----'
            footer = b'-----END ' + kind + b'PRIVATE KEY-----'
            for separator in [b'\n', b'\r\n', b'\\n', b'\\r\\n']:
                # Synthetic example key material; deliberately not a usable secret.
                examples.append(header + separator + b'MII' + b'A' * 61 + separator + footer)
            examples.append(header + b'\n' + b'M' * 16)  # truncated keys block too
            examples.append(header + b'\n' + b'M\n' * 16)  # short wrapped lines
            examples.append(header + b'\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\n' + b'M' * 64)
        for value in examples:
            for prefix in ['tmp/', 'home/user/', 'root/', 'run/']:
                with self.subTest(prefix=prefix, length=len(value)):
                    with self.assertRaises(AssertionError) as caught:
                        layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({
                            prefix + 'binary': b'\x00\xff' + value + b'\x00\x80'})})))
                    self.assertNotIn(value.decode('ascii'), str(caught.exception))

    def test_generated_valid_private_key_is_blocked_in_binary(self):
        # Ephemeral test-only key stays in memory; never logged or uploaded.
        value = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'EC',
                                         '-pkeyopt', 'ec_paramgen_curve:prime256v1'], stderr=subprocess.DEVNULL)
        with self.assertRaisesRegex(AssertionError, 'rule=private_key') as caught:
            layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({'tmp/cache': b'\x00' + value + b'\xff'})})))
        self.assertNotIn(value.decode('ascii'), str(caught.exception))

    def test_large_files_outside_home_and_chunk_boundaries_are_scanned(self):
        token = b'ghp_' + b'Z'*36
        for name in ('usr/lib/binary', 'opt/app/data', 'var/cache/file', 'etc/application.conf'):
            for offset in (1024*1024-8, 2*1024*1024):
                raw = b'x'*offset + b'\x00' + token
                with self.subTest(name=name, offset=offset), self.assertRaisesRegex(AssertionError, 'rule=github_token') as caught:
                    layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({name: raw})})))
                self.assertNotIn(token.decode(), str(caught.exception))

    def test_streaming_pem_keeps_arbitrary_whitespace_and_wrapped_material(self):
        header = b'-----BEGIN PRIVATE KEY-----'
        for payload in (b' '*20000 + b'A'*16, (b' '*2000+b'A')*16, b'\\n' + b'A'*64):
            self.assertEqual(layers.scan_file(io.BytesIO(header+payload), chunk_size=11), 'private_key')

    def test_root_credential_file_and_long_whitespace_prefix_block(self):
        for name in ('.env', '.git-credentials', '.aws/credentials'):
            raw = b' '*(1024*1024+1) + b'password=value'
            with self.assertRaisesRegex(AssertionError, 'credential_file'):
                layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({name: raw})})))

    def test_executable_sections_remain_subject_to_credential_scanning(self):
        table = 2*1024*1024
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', header, 40, table)
        struct.pack_into('<HH', header, 58, 64, 1)
        payload = bytes(header) + b'\x00'*64 + b'AKIA' + b'A1'*8
        payload += b'\x00'*(table-len(payload))
        payload += struct.pack('<IIQQQQIIQQ', 0, 1, 6, 0, 64, table-64, 0, 0, 0, 0)
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(AssertionError, 'rule=aws_access_key'):
            layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({'usr/bin/node': payload})})))
        record = json.loads(output.getvalue())
        self.assertEqual(record['credential_rule'], 'aws_access_key')
        self.assertEqual(record['file_offset'], 128)

    def test_aws_id_substrings_are_classified_but_standalone_ids_block(self):
        identifier = b'AKIA' + b'A2'*8
        for raw in (b'ABC'+identifier+b'XYZ', identifier+b'X', b'X'+identifier):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertIsNone(layers.scan_file(io.BytesIO(raw)))
            self.assertIn('substring_of_longer_alphanumeric_sequence', output.getvalue())
            self.assertNotIn(identifier.decode(), output.getvalue())
        for raw in (identifier, b'key='+identifier, b'\x00'+identifier+b'\x00', b'"'+identifier+b'"'):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(layers.scan_file(io.BytesIO(raw), chunk_size=11), 'aws_access_key')

    def test_stateless_github_installation_tokens_remain_blocking(self):
        # GitHub's 2026 ghs_APPID_JWT format; synthetic, never usable.
        value = b'ghs_1234567_' + b'eyJ'*40 + b'.' + b'A_'*80 + b'.' + b'B-'*40
        with redirect_stdout(io.StringIO()):
            self.assertEqual(layers.scan_file(io.BytesIO(value), chunk_size=17), 'github_installation')

    def test_token_age_does_not_create_per_token_classifications(self):
        value = b'ghs_' + b'Q2'*18
        records = []
        with redirect_stdout(io.StringIO()):
            self.assertEqual(layers.scan_file(io.BytesIO(value), classified=records), 'github_token')
        self.assertEqual(records, [])

    def test_public_private_key_uses_complete_material_and_continues_scanning(self):
        value = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'EC',
                                         '-pkeyopt', 'ec_paramgen_curve:prime256v1'], stderr=subprocess.DEVNULL)
        match = layers.CREDENTIAL.search(value)
        material, _ = layers.pem_material(value, match)
        policy = {'public_private_keys': [dict(material, diff_id='sha256:'+'a'*64, file='test/source', source='https://example.invalid/public-fixture',
                   purpose='Synthetic public-fixture classification test')], 'confirmed_dangerous': []}
        for suffix, expected in [(b'', None), (b'\x00ghp_'+b'A'*36, 'github_token'),
                                 (b'\n-----BEGIN PRIVATE KEY-----\n'+b'B'*64, 'private_key')]:
            records = []
            with redirect_stdout(io.StringIO()):
                self.assertEqual(layers.scan_file(io.BytesIO(value+suffix), policy=policy, classified=records, diff_id='sha256:'+'a'*64, file_name='test/source'), expected)
            self.assertEqual(len(records), 1)
        altered = value.replace(value.splitlines()[1], b'A'*len(value.splitlines()[1]))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(layers.scan_file(io.BytesIO(altered), policy=policy, diff_id='sha256:'+'a'*64, file_name='test/source'), 'private_key')

    def test_public_key_copied_into_a_new_layer_or_file_remains_blocking(self):
        value = b'-----BEGIN PRIVATE KEY-----\n'+b'A'*64+b'\n-----END PRIVATE KEY-----'
        material, _ = layers.pem_material(value, layers.CREDENTIAL.search(value))
        fixture = dict(material, file='test/fixture', diff_id='sha256:'+'a'*64,
                       source='https://example.invalid/public', purpose='synthetic public test fixture')
        policy = dict(public_private_keys=[fixture], confirmed_dangerous=[])
        for file, diff_id, expected in [('test/fixture', fixture['diff_id'], None),
                                       ('etc/service.key', fixture['diff_id'], 'private_key'),
                                       ('test/fixture', 'sha256:'+'b'*64, 'private_key')]:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(layers.scan_file(io.BytesIO(value), policy=policy,
                                 diff_id=diff_id, file_name=file), expected)

    def test_full_payload_fingerprints_distinguish_multiple_keys(self):
        raw = b'-----BEGIN PRIVATE KEY-----\n'+b'A'*64+b'\n-----END PRIVATE KEY-----\n'
        raw += raw.replace(b'A'*64, b'B'*64)
        detected = []
        with redirect_stdout(io.StringIO()):
            self.assertEqual(layers.scan_file(io.BytesIO(raw), detected=detected), 'private_key')
        self.assertEqual(len(detected), 2)
        self.assertNotEqual(detected[0]['payload_sha256'], detected[1]['payload_sha256'])

    def test_exact_comparison_distinguishes_path_layer_and_material(self):
        row = dict(file='app/file', archive_member='blobs/sha256/aaa', credential_rule='github_token', match_sha256='b'*64)
        def report(rows):
            return dict(classifications=[], unclassified_findings=[dict(file=r['file'], archive_member=r['archive_member'],
                        rule=r['credential_rule'], patterns=[r]) for r in rows])
        before = report([row])
        after = report([row, dict(row, archive_member='blobs/sha256/new'), dict(row, match_sha256='c'*64)])
        comparison = layers.compare_findings(before, after)
        self.assertEqual(len(comparison['inherited_unclassified']), 1)
        self.assertEqual(len(comparison['introduced']), 2)
        self.assertEqual(layers.compare_findings(after, before)['removed'], comparison['introduced'])

    def test_complete_inventory_still_fails_and_reports_all_affected_files(self):
        files = {'opt/first': b'ghp_' + b'A2'*18, 'usr/lib/second': b'github_pat_' + b'B_'*30}
        with redirect_stdout(io.StringIO()), self.assertRaises(layers.CredentialFindings) as caught:
            layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive(files)})))
        self.assertEqual({r['file'] for r in caught.exception.findings}, set(files))
        self.assertIn('rule=github_token', str(caught.exception))
        self.assertIn('rule=github_pat', str(caught.exception))

    def test_all_matches_checked_after_harmless_literal(self):
        raw = b'\x00-----BEGIN PRIVATE KEY-----\x00' + b'ghp_' + b'Z' * 36
        with self.assertRaisesRegex(AssertionError, 'rule=github_token'):
            layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({'tmp/cache': raw})})))


class BaselineGateTests(unittest.TestCase):
    def scan(self, layer_files):
        payloads = [archive(files) for files in layer_files]
        saved = archive({'blobs/sha256/'+hashlib.sha256(p).hexdigest(): p for p in payloads})
        classified, inspected = [], []
        with redirect_stdout(io.StringIO()):
            try:
                count = layers.check_layers(io.BytesIO(saved), classified, inspected=inspected)
                unknown = []
            except layers.CredentialFindings as error:
                count, unknown = error.layers, error.findings
        return dict(candidate='ghcr.io/openhands/agent-server@sha256:'+'a'*64, layers=count,
                    layer_diff_ids=inspected, classifications=classified, unclassified_findings=unknown,
                    unclassified_detections=sum(max(1,len(r['patterns'])) for r in unknown))

    def policy(self, upstream):
        return dict(schema=2, public_private_keys=[], confirmed_dangerous=[], accepted_upstream=dict(
            upstream=upstream['candidate'], inventory_sha256=layers.inventory_fingerprint(upstream),
            finding_count=len(layers.flatten(upstream)), decision='accept-unchanged-unclassified-upstream-risk',
            evidence='https://github.com/example/review'))

    def test_unchanged_inherited_unknown_is_visible_and_passes(self):
        scan = self.scan([{'usr/bin/vendor': b'\x00ghp_'+b'A'*36}])
        gate = layers.credential_gate(scan, scan, policy=self.policy(scan))
        self.assertTrue(gate['pass'])
        self.assertEqual(gate['accepted_inherited_unclassified'], 1)
        self.assertEqual(scan['unclassified_detections'], 1)
        self.assertEqual(len(layers.compare_findings(scan, scan)['inherited_unclassified']), 1)

    def test_introduced_and_changed_custom_credentials_block(self):
        base_files = {'usr/bin/vendor': b'ghp_'+b'A'*36}
        before = self.scan([base_files])
        for filename, value in [('tmp/token', b'ghp_'+b'B'*36), ('usr/bin/vendor', b'ghp_'+b'C'*36)]:
            candidate = self.scan([base_files, {filename:value}])
            gate = layers.credential_gate(before, candidate, policy=self.policy(before))
            self.assertFalse(gate['pass'])
            self.assertTrue(any('customization' in r for r in gate['blockers']))

    def test_new_changed_removed_or_relocated_upstream_findings_require_review(self):
        before = self.scan([{'usr/bin/vendor': b'ghp_'+b'A'*36}])
        for files in [{'usr/bin/vendor': b'ghp_'+b'B'*36},
                      {'usr/bin/vendor': b'ghp_'+b'A'*36, 'tmp/other': b'gho_'+b'C'*36},
                      {'usr/bin/vendor': b'normal'}, {'new/path': b'ghp_'+b'A'*36}]:
            changed = self.scan([files])
            gate = layers.credential_gate(changed, changed, policy=self.policy(before))
            self.assertFalse(gate['pass'])
            self.assertTrue(gate['baseline_changed'])
        changed = dict(before, candidate='ghcr.io/openhands/agent-server@sha256:'+'b'*64)
        self.assertTrue(layers.credential_gate(changed, changed, policy=self.policy(before))['baseline_changed'])

    def test_confirmed_live_inherited_credential_overrides_baseline_acceptance(self):
        scan = self.scan([{'usr/bin/vendor': b'ghp_'+b'A'*36}])
        policy = self.policy(scan)
        policy['confirmed_dangerous'] = [dict(finding_sha256=layers.finding_fingerprint(layers.flatten(scan)[0]),
            reason='Confirmed live credential', evidence='https://github.com/example/security-review')]
        gate = layers.credential_gate(scan, scan, policy=policy)
        self.assertFalse(gate['pass'])
        self.assertEqual(len(layers.compare_findings(scan, scan, policy)['inherited_confirmed_credentials']), 1)

    def test_inherited_exposed_keys_and_credential_files_always_block(self):
        for files in [{'tmp/key': b'-----BEGIN PRIVATE KEY-----\n'+b'M'*64},
                      {'root/.git-credentials': b'https://user:password@example.invalid'},
                      {'etc/ssl/private/ssl-cert-snakeoil.key': b'key'}]:
            scan = self.scan([files])
            gate = layers.credential_gate(scan, scan, policy=self.policy(scan))
            self.assertFalse(gate['pass'])
            self.assertTrue(gate['dangerous_findings'])

    def test_invalid_inventory_evidence_fails_closed(self):
        scan = self.scan([{'usr/bin/vendor': b'ghp_'+b'A'*36}])
        for field, value in [('unclassified_detections', 0), ('layer_diff_ids', []), ('unclassified_findings', [])]:
            broken = dict(scan, **{field:value})
            with self.assertRaises(AssertionError):
                layers.credential_gate(scan, broken, policy=self.policy(scan))
        broken = json.loads(json.dumps(scan))
        broken['unclassified_findings'][0]['patterns'][0]['diff_id'] = 'sha256:'+'b'*64
        with self.assertRaises(AssertionError):
            layers.credential_gate(scan, broken, policy=self.policy(scan))


if __name__ == '__main__':
    unittest.main()
