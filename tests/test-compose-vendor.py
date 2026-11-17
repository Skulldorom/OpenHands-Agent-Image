#!/usr/bin/env python3
"""Real curl requests against a local redirect/error server, plus integrity failures."""
from contextlib import redirect_stdout
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vendor', 'scripts/verify-compose-vendor.py')
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)
BINARY = b'\x7fELF' + b'example-binary' * 32
DIGEST = hashlib.sha256(BINARY).hexdigest()
CHECKSUM = (DIGEST + '  ' + vendor.ARTIFACT + '\n').encode()


class Handler(BaseHTTPRequestHandler):
    attempts = 0

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path in {'/redirect', '/loop'}:
            self.send_response(302)
            self.send_header('Location', '/binary' if self.path == '/redirect' else '/loop')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/flaky':
            Handler.attempts += 1
            if Handler.attempts <= 2:
                self.send_error(503)
                return
        if self.path not in {'/binary', '/empty', '/flaky'}:
            self.send_error(404)
            return
        raw = b'' if self.path == '/empty' else BINARY
        self.send_response(200)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class VendorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = 'http://127.0.0.1:' + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fetch(self, route, **kwargs):
        return vendor.fetch(self.url + route, self.root / 'download', minimum=1, maximum=4096,
                            allow_http=True, **kwargs)

    def test_reproduces_no_location_zero_byte_redirect_then_follows(self):
        probe = vendor.fetch(self.url + '/redirect', self.root / 'probe', minimum=0, maximum=4096,
                             follow=False, allow_http=True)
        self.assertEqual((probe['status'], probe['redirects'], probe['size']), (302, 0, 0))
        result = self.fetch('/redirect')
        self.assertEqual((result['status'], result['redirects'], result['size']), (200, 1, len(BINARY)))
        self.assertEqual((self.root / 'download').read_bytes(), BINARY)

    def test_empty_200_response_rejected_and_removed(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'size'):
            self.fetch('/empty')
        self.assertFalse((self.root / 'download').exists())

    def test_http_error_rejected_and_partial_file_removed(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'curl exit'):
            self.fetch('/missing')
        self.assertFalse((self.root / 'download').exists())

    def test_redirect_loop_is_bounded(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'curl exit 47'):
            self.fetch('/loop')

    def test_transient_failure_retries_then_succeeds(self):
        Handler.attempts = 0
        self.assertEqual(self.fetch('/flaky')['size'], len(BINARY))
        self.assertEqual(Handler.attempts, 3)

    def verify(self, binary=BINARY, checksum=CHECKSUM, **kwargs):
        (self.root / 'binary').write_bytes(binary)
        (self.root / 'checksum').write_bytes(checksum)
        return vendor.verify_pair(self.root / 'binary', self.root / 'checksum', expected=DIGEST,
                                  checksum_digest=hashlib.sha256(CHECKSUM).hexdigest(),
                                  minimum=32, maximum=4096, **kwargs)

    def test_both_pinned_official_evidence_and_binary_match(self):
        self.assertEqual(self.verify(), DIGEST)

    def test_binary_checksum_mismatch_rejected(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'checksum mismatch'):
            self.verify(binary=BINARY[:-1] + b'!')

    def test_modified_checksum_asset_rejected(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'checksum mismatch'):
            self.verify(checksum=CHECKSUM.replace(DIGEST.encode(), b'0' * 64))

    def test_disagreement_between_independent_official_pins_rejected(self):
        binary = self.root / 'binary'
        checksum = self.root / 'checksum'
        binary.write_bytes(BINARY)
        checksum.write_bytes(CHECKSUM)
        with self.assertRaisesRegex(vendor.VerificationError, 'disagrees'):
            vendor.verify_pair(binary, checksum, expected='0' * 64,
                               checksum_digest=hashlib.sha256(CHECKSUM).hexdigest(), minimum=32, maximum=4096)

    def test_implausible_size_rejected_before_module_inspection(self):
        with self.assertRaisesRegex(vendor.VerificationError, 'size'):
            self.verify(binary=b'\x7fELF')

    def test_production_transport_refuses_http_and_url_credentials(self):
        for url in [self.url, 'https://user:password@example.invalid/asset']:
            with self.subTest(url=url), self.assertRaises(vendor.VerificationError):
                vendor.fetch(url, self.root / 'download', minimum=1, maximum=4096)

    def test_integrity_failure_never_executes_go_inspection(self):
        previous = Path.cwd()
        os.chdir(self.root)
        try:
            with patch.object(vendor, 'fetch', return_value={'status': 200}), \
                 patch.object(vendor, 'verify_pair', side_effect=vendor.VerificationError('checksum mismatch')), \
                 patch.object(vendor, 'inspect_modules') as inspect, redirect_stdout(io.StringIO()):
                with self.assertRaises(vendor.VerificationError):
                    vendor.main()
                inspect.assert_not_called()
            report = __import__('json').loads((self.root / 'reachability/vendor-compose-5.7.2-verification.json').read_text())
            self.assertFalse(report['verified'])
            self.assertNotIn('modules', report)
        finally:
            os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
