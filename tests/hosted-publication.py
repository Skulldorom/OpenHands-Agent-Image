#!/usr/bin/env python3
"""Real GitHubRegistry/GHCR integration, never production authorization.

Requires GitHubRegistry(repo=..., image=..., latest_alias=...) retaining those
attributes and routing ALL side effects to them; reconcile must honor the alias.
A dedicated non-fork repository must contain an existing commit, no releases or
v* tags, and [publication-integration-only] in its description. GH_TOKEN needs
contents/packages read+write and, for --cleanup only, package-version deletion.
Private GHCR reads must be supported by the backend. No gh auth setup is used.
"""
import argparse
import base64
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def targets(repo, image, alias):
    require(bool(re.fullmatch(r'[A-Za-z0-9-]+/publication-integration-[A-Za-z0-9-]+', repo)),
            'Repository must be OWNER/publication-integration-NAME; production is forbidden')
    owner = repo.split('/')[0].lower()
    require(bool(re.fullmatch(r'ghcr\.io/' + re.escape(owner) + r'/publication-integration-[a-z0-9-]+', image)),
            'Package must use the same owner and publication-integration- prefix; production is forbidden')
    require(bool(re.fullmatch(r'integration-latest-[a-f0-9]{32}', alias)), 'Only unique integration-latest-UUID aliases allowed')


def api(path, method='GET'):
    return json.loads(subprocess.check_output(['gh', 'api', '--method', method, path], text=True) or 'null')


def pages(path):
    return [item for page in json.loads(subprocess.check_output(
        ['gh', 'api', '--paginate', '--slurp', path], text=True)) for item in page]


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def seed(image, tag, repo, username):
    """Push a non-deployable zero-layer, unknown-platform OCI artifact."""
    package = image.removeprefix('ghcr.io/')
    basic = base64.b64encode((username + ':' + os.environ['GH_TOKEN']).encode()).decode()
    url = 'https://ghcr.io/token?' + urllib.parse.urlencode({
        'service': 'ghcr.io', 'scope': f'repository:{package}:pull,push'})
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Authorization': 'Basic ' + basic}), timeout=60) as response:
        token = json.load(response)['token']

    def request(url, method, raw, media):
        require(url.startswith('https://ghcr.io/'), 'Refusing non-GHCR upload location')
        req = urllib.request.Request(url, data=raw, method=method, headers={
            'Authorization': 'Bearer ' + token, 'Content-Type': media})
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.headers

    config = json.dumps({'architecture': 'unknown', 'os': 'unknown', 'config': {'Labels': {
        'org.opencontainers.image.source': 'https://github.com/' + repo,
        'org.opencontainers.image.description':
            'Non-deployable integration fixture created by OpenHands AI on behalf of the repository owner'}},
        'rootfs': {'type': 'layers', 'diff_ids': []}}, sort_keys=True).encode()
    base = f'https://ghcr.io/v2/{package}'
    headers = request(base + '/blobs/uploads/', 'POST', b'', 'application/octet-stream')
    location = urllib.parse.urljoin(base + '/', headers['Location'])
    location += ('&' if '?' in location else '?') + urllib.parse.urlencode({'digest': digest(config)})
    request(location, 'PUT', config, 'application/octet-stream')
    raw = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': digest(config),
                   'size': len(config)}, 'layers': []}, sort_keys=True).encode()
    request(base + '/manifests/' + tag, 'PUT', raw, 'application/vnd.oci.image.manifest.v1+json')
    return digest(raw)


def snapshot(repo, record):
    current = api(f"repos/{repo}/releases/{record['id']}")
    assets = {}
    for asset in pages(f"repos/{repo}/releases/{record['id']}/assets?per_page=100"):
        raw = subprocess.check_output(['gh', 'api', '-H', 'Accept: application/octet-stream',
                                      f"repos/{repo}/releases/assets/{asset['id']}"])
        require(asset['name'] not in assets, 'Duplicate asset name')
        assets[asset['name']] = {'id': asset['id'], 'digest': digest(raw)}
        if asset['name'].endswith('.zip'):
            require(hashlib.sha256(raw).hexdigest() in asset['name'], 'Evidence ZIP is not content-addressed')
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                require(len(archive.namelist()) == len(set(archive.namelist())), 'Duplicate evidence ZIP paths')
                require('selection.json' in archive.namelist(), 'Fixture evidence missing from ZIP')
    return current, assets


def run(args):
    require(args.execute, 'Live publication requires --execute; use --self-test offline')
    require(not sys.flags.optimize, 'Assertions must remain enabled')
    require(bool(os.environ.get('GH_TOKEN')), 'Set GH_TOKEN externally; no gh auth setup is performed')
    identity = uuid.uuid4().hex
    repo, image, alias = args.repository, args.package_prefix + '-' + identity, 'integration-latest-' + identity
    targets(repo, image, alias)
    sys.path.insert(0, str(ROOT / 'scripts'))
    import promotion
    require({'repo', 'image', 'latest_alias'} <= set(inspect.signature(promotion.GitHubRegistry).parameters),
            'Backend prerequisite: GitHubRegistry(repo=..., image=..., latest_alias=...)')
    backend = promotion.GitHubRegistry(repo=repo, image=image, latest_alias=alias)
    require((backend.repo, backend.image, backend.latest_alias) == (repo, image, alias), 'Backend ignored isolation config')
    metadata = api('repos/' + repo)
    require(metadata['full_name'].lower() == repo.lower() and not metadata['fork'], 'Unexpected repository identity or fork')
    require('[publication-integration-only]' in (metadata.get('description') or ''), 'Missing isolated repository marker')
    require(not pages(f'repos/{repo}/releases?per_page=100'), 'Isolated repository must have no releases')
    require(not any(t['name'].startswith('v') for t in pages(f'repos/{repo}/tags?per_page=100')), 'Existing version tags refused')
    commit = api(f"repos/{repo}/commits/" + urllib.parse.quote(metadata['default_branch'], safe=''))['sha']
    require(bool(re.fullmatch(r'[a-f0-9]{40}', commit)), 'Missing isolated repository commit')
    user = os.environ.get('REGISTRY_USER') or api('user')['login']
    owner, package = image.removeprefix('ghcr.io/').split('/', 1)
    kind = 'orgs' if api('users/' + owner)['type'] == 'Organization' else 'users'
    package_api = f'{kind}/{owner}/packages/container/{package}'
    ledger = {'repository': repo, 'image': image, 'alias': alias, 'releases': [], 'git_tags': [],
              'package_versions': [], 'passed': False, 'cleanup_requested': args.cleanup}
    report = Path(args.report).resolve()

    def save():
        report.write_text(json.dumps(ledger, indent=2, sort_keys=True) + '\n')

    def collect():
        for item in pages(package_api + '/versions?per_page=100'):
            require(item['name'] == ledger['digest'], 'Unexpected package version; refusing cleanup')
            if item['id'] not in ledger['package_versions']:
                ledger['package_versions'].append(item['id'])
        save()

    real_reserve, real_git_tag = backend.reserve, backend.git_tag

    def reserve(state):
        record = real_reserve(state)
        ledger['releases'].append(record['id'])
        save()
        return record

    def git_tag(version, sha):
        real_git_tag(version, sha)
        entry = {'ref': 'v' + version, 'sha': sha}
        if entry not in ledger['git_tags']:
            ledger['git_tags'].append(entry)
        save()

    backend.reserve, backend.git_tag = reserve, git_tag
    original = Path.cwd()
    save()
    try:
        ledger['digest'] = seed(image, 'fixture-' + identity, repo, user)
        save()
        collect()
        with tempfile.TemporaryDirectory(prefix='hosted-publication-') as directory:
            os.chdir(directory)
            Path('security-assessment.json').write_text(json.dumps({'integration_fixture': True, 'authorization': 'none',
                'comparison_counts': {}, 'new_upstream_findings': None, 'modification_pass': True,
                'severity_counts': {}, 'upstream_severity_counts': {}, 'removed_findings': [],
                'materially_worsened': [], 'introduced_high_critical': [], 'emergency_blocked': [], 'secrets': []}))
            for name in promotion.SEALED_FILES - {'security-assessment.json'}:
                path = Path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({'fixture': identity, 'deployable': False}))
            Path('layer-classifications.json').write_text(json.dumps({'classifications': [], 'integration_fixture': True}))
            Path('selection.json').write_text(json.dumps({'run_id': 1, 'run_attempt': 1, 'fixture': identity}))
            state = {'version': '0.0.1', 'commit': commit, 'release_source_commit': commit,
                     'image_digest': ledger['digest'], 'upstream_digest': ledger['digest'],
                     'agent_server_version': 'integration-only', 'fingerprints': {'image': identity}, 'status': 'validated'}
            calls = []

            def freshness(current):
                require(current['commit'] == commit and current['image_digest'] == ledger['digest'], 'Fixture identity changed')
                calls.append(True)

            real_assets = backend.assets
            def interrupted_assets(*values, **kwargs):
                real_assets(*values, **kwargs)
                raise ConnectionError('injected interruption after persisted assets')
            backend.assets = interrupted_assets
            try:
                promotion.reconcile(state, backend, freshness)
            except ConnectionError as error:
                require(str(error) == 'injected interruption after persisted assets', 'Unexpected network failure')
            else:
                raise RuntimeError('Interruption not exercised')
            finally:
                backend.assets = real_assets
            records = backend.records()
            require(len(records) == 1 and records[0]['draft'], 'Expected one durable draft journal')
            record = records[0]
            journal, assets = snapshot(repo, record)
            require(any(n.endswith('.zip') for n in assets), 'No immutable ZIP evidence persisted')
            require(backend.tag_digest(alias) is None, 'Latest alias moved before evidence completion')
            for _ in range(2):
                require(promotion.reconcile(state, backend, freshness)['status'] == 'published', 'Retry failed')
            current, unchanged = snapshot(repo, record)
            require(not current['draft'] and current['body'] == journal['body'] and unchanged == assets,
                    'Retry replaced original journal/assets')
            require(backend.tag_digest(alias) == ledger['digest'], 'Isolated alias missing')
            Path('layer-classifications.json').write_text(json.dumps({'classifications': [], 'integration_fixture': True}))
            Path('selection.json').write_text(json.dumps({'run_id': 2, 'run_attempt': 1, 'fixture': identity}))
            promotion.reconcile(dict(state, fingerprints={'image': identity, 'security': 'reassessment'}),
                                backend, freshness)
            current, appended = snapshot(repo, record)
            require(current['body'] == journal['body'], 'Reassessment rewrote journal')
            require(all(appended.get(n) == value for n, value in assets.items()) and len(appended) > len(assets),
                    'Reassessment did not preserve and append immutable evidence')
            backend.reserve(dict(state, version='0.0.2'))
            count = len(calls)
            try:
                promotion.reconcile(state, backend, freshness)
            except AssertionError as error:
                require('Newer release owns latest' in str(error), 'Wrong stale rejection')
            else:
                raise RuntimeError('Stale version accepted')
            require(len(calls) == count and backend.tag_digest(alias) == ledger['digest'], 'Stale attempt performed publication')
            require(backend.tag_digest('latest') is None, 'Production-style latest was written')
            ledger['passed'] = True
    finally:
        os.chdir(original)
        save()
        # Failures retain evidence. Never delete a repository, package, or discovered release.
        if args.cleanup and ledger['passed']:
            collect()
            for release_id in ledger['releases']:
                record = api(f'repos/{repo}/releases/{release_id}')
                require(identity in record.get('body', ''), 'Release identity changed; refusing cleanup')
                api(f'repos/{repo}/releases/{release_id}', 'DELETE')
            for tag in ledger['git_tags']:
                current = api(f"repos/{repo}/git/ref/tags/{tag['ref']}")
                require(current['object']['sha'] == tag['sha'], 'Tag changed; refusing cleanup')
                api(f"repos/{repo}/git/refs/tags/{tag['ref']}", 'DELETE')
            for version_id in ledger['package_versions']:
                require(api(package_api + f'/versions/{version_id}')['name'] == ledger['digest'], 'Version identity changed')
                api(package_api + f'/versions/{version_id}', 'DELETE')
            ledger['cleaned'] = True
            save()
    print(json.dumps(ledger, indent=2, sort_keys=True))


class SafetyTests(unittest.TestCase):
    def test_isolated(self):
        targets('Example/publication-integration-sandbox', 'ghcr.io/example/publication-integration-fixture',
                'integration-latest-' + 'a' * 32)

    def test_unsafe(self):
        valid = ['Example/publication-integration-sandbox', 'ghcr.io/example/publication-integration-fixture',
                 'integration-latest-' + 'a' * 32]
        for index, bad in ((0, 'Skulldorom/OpenHands-Agent-Image'), (0, 'Example/production'),
                           (0, '../publication-integration-x'), (1, 'ghcr.io/skulldorom/openhands-agent'),
                           (1, 'ghcr.io/other/publication-integration-x'),
                           (1, 'ghcr.io/example/publication-integration-x:latest'), (2, 'latest'),
                           (2, 'integration-latest-fixed')):
            values = valid.copy()
            values[index] = bad
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                targets(*values)

    def test_missing_targets(self):
        for values in (('', '', ''), ('Example/publication-integration-x', '', 'integration-latest-' + 'a' * 32)):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                targets(*values)

    def test_opt_in_before_network(self):
        with self.assertRaisesRegex(RuntimeError, 'requires --execute'):
            run(argparse.Namespace(execute=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--repository', default='')
    parser.add_argument('--package-prefix', default='')
    parser.add_argument('--cleanup', action='store_true', help='Delete recorded IDs after success only; failures retain evidence')
    parser.add_argument('--report', default='publication-integration-report.json')
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    else:
        run(args)


if __name__ == '__main__':
    main()
