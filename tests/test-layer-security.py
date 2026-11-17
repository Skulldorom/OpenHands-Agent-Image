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

    def test_elf_diagnostics_work_on_streams_and_do_not_exempt_code_sections(self):
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
        self.assertTrue(record['elf_scope']['executable_section'])
        self.assertEqual(record['file_offset'], 128)

    def test_all_matches_checked_after_harmless_literal(self):
        raw = b'\x00-----BEGIN PRIVATE KEY-----\x00' + b'ghp_' + b'Z' * 36
        with self.assertRaisesRegex(AssertionError, 'rule=github_token'):
            layers.check_layers(io.BytesIO(archive({'old/layer.tar': archive({'tmp/cache': raw})})))


if __name__ == '__main__':
    unittest.main()
