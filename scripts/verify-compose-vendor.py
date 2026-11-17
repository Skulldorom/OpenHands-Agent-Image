#!/usr/bin/env python3
"""Download official Compose evidence with bounded HTTPS redirects; verify before inspection."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

ARTIFACT = 'docker-compose-linux-x86_64'
URL = 'https://github.com/docker/compose/releases/download/v5.7.2/' + ARTIFACT
# Independently recorded from Docker's official GitHub release asset metadata.
EXPECTED_SHA256 = 'e14235d9c622c5bd57eb8adeed4a0f7308c7f3862e6812dd843f6fe27f1307cc'
CHECKSUM_ASSET_SHA256 = 'abb9bb05c9726d7b7abf138dde6c3058a64ffc7c05b344700a54dd6e7dc58089'
EXPECTED_SIZE = 34063021


class VerificationError(RuntimeError):
    pass


def fetch(url, destination, *, minimum, maximum, follow=True, allow_http=False):
    """No authentication, verbose logs or raw redirect URLs. Partial files never survive failure."""
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.scheme not in ({'http', 'https'} if allow_http else {'https'}):
        raise VerificationError('Invalid download URL')
    destination = Path(destination)
    destination.unlink(missing_ok=True)
    protocols = '=http,https' if allow_http else '=https'
    args = ['curl', '--fail', '--silent', '--show-error', '--proto', protocols,
            '--proto-redir', protocols, '--max-redirs', '5', '--retry', '3', '--retry-delay', '1',
            '--retry-max-time', '90', '--connect-timeout', '10', '--max-time', '120',
            '--max-filesize', str(maximum), '--output', str(destination), '--write-out', '%{json}']
    if follow:
        args.append('--location')
    try:
        # Capture all curl output: signed redirect paths/query strings never enter logs/artifacts.
        result = subprocess.run([*args, url], capture_output=True, text=True, timeout=220)
        if result.returncode:
            raise VerificationError(f'Download failed (curl exit {result.returncode})')
        metadata = json.loads(result.stdout)
        status = int(metadata['http_code'])
        if (follow and status != 200) or (not follow and not 200 <= status < 400):
            raise VerificationError(f'Unexpected HTTP status {status}')
        size = destination.stat().st_size
        if not minimum <= size <= maximum:
            raise VerificationError('Downloaded size outside required bounds')
        return {'status': status, 'redirects': int(metadata['num_redirects']), 'size': size,
                'effective_host': urlsplit(metadata['url_effective']).hostname,
                'redirect_host': urlsplit(metadata.get('redirect_url') or '').hostname}
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        destination.unlink(missing_ok=True)
        raise VerificationError('Download failed or returned invalid transport metadata') from None
    except VerificationError:
        destination.unlink(missing_ok=True)
        raise


def verify_file(path, expected, *, minimum, maximum):
    raw = Path(path).read_bytes()
    if not minimum <= len(raw) <= maximum:
        raise VerificationError('Downloaded size outside required bounds')
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise VerificationError('Official artifact checksum mismatch')
    return actual


def verify_pair(binary, checksum, *, expected=EXPECTED_SHA256,
                checksum_digest=CHECKSUM_ASSET_SHA256, minimum=8 * 1024 * 1024,
                maximum=128 * 1024 * 1024, artifact=ARTIFACT):
    verify_file(checksum, checksum_digest, minimum=64, maximum=4096)
    text = Path(checksum).read_text(encoding='ascii').strip()
    match = re.fullmatch(r'([a-f0-9]{64})\s+\*?' + re.escape(artifact), text)
    if not match or match[1] != expected:
        raise VerificationError('Official checksum asset disagrees with pinned release metadata')
    actual = verify_file(binary, expected, minimum=minimum, maximum=maximum)
    if Path(binary).read_bytes()[:4] != b'\x7fELF':
        raise VerificationError('Verified artifact is not an ELF binary')
    return actual


def inspect_modules(binary, output):
    # Called only after both independently pinned official checksums and size checks succeed.
    result = subprocess.run(['go', 'version', '-m', str(binary)], capture_output=True, text=True, check=True)
    Path(output).write_text(result.stdout)
    modules = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] in {'dep', 'mod'}:
            modules[fields[1]] = fields[2]
    if not modules:
        raise VerificationError('Verified binary has no readable Go module build information')
    return modules


def main():
    output = Path('reachability')
    output.mkdir(exist_ok=True)
    report = {'release': 'v5.7.2', 'verified': False, 'expected_sha256': EXPECTED_SHA256,
              'checksum_asset_sha256': CHECKSUM_ASSET_SHA256,
              'evidence': 'Docker official GitHub release metadata and separately downloaded checksum asset'}
    try:
        with tempfile.TemporaryDirectory(prefix='compose-vendor-') as directory:
            root = Path(directory)
            report['without_location'] = fetch(URL, root / 'probe', minimum=0, maximum=128 * 1024 * 1024, follow=False)
            report['checksum_transport'] = fetch(URL + '.sha256', root / 'official.sha256', minimum=64, maximum=4096)
            report['binary_transport'] = fetch(URL, root / ARTIFACT, minimum=8 * 1024 * 1024, maximum=128 * 1024 * 1024)
            report['download_sha256'] = verify_pair(root / ARTIFACT, root / 'official.sha256')
            if (root / ARTIFACT).stat().st_size != EXPECTED_SIZE:
                raise VerificationError('Artifact size disagrees with official release metadata')
            report['integrity_verified'] = True
            report['modules'] = inspect_modules(root / ARTIFACT, output / 'vendor-compose-5.7.2.modules.txt')
            report['verified'] = True
    except Exception as error:
        # Known errors contain only categories; do not expose subprocess stdout/stderr or signed URLs.
        report['error'] = str(error) if isinstance(error, VerificationError) else type(error).__name__
        raise VerificationError(report['error']) from None
    finally:
        (output / 'vendor-compose-5.7.2-verification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
