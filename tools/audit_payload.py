#!/usr/bin/env python3
"""Audit the complete public candidate and exact extracted Debian payload."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = 'ae20080ca2e4cfc6d0fcd399ea09c7068c88c15e'
KEY_PATTERN = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
TOKEN_PATTERN = re.compile(rb'(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk-proj-[A-Za-z0-9_-]{30,})')
PRIVATE_PATTERN = re.compile(
    rb'(?:/[U]sers/[^\s/]+|/[h]ome/[^\s/]+|git\.[a-z]+fam\.com|'
    rb'https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)|'
    rb'[.]hermes/|SectorC[Z]1|192[.]168[.]1[.]|'
    rb'agent[_-]session[_-]id|codex[_-]session[_-]id|'
    rb'bba79f625bcb13f4b58c034a9ba51ab2c90a945[0])')
FORBIDDEN = {'.pcap', '.pcapng', '.cap', '.p12', '.pfx'}
PRIVATE_PARTS = {'.git', '.hermes', '.serena', '.cobro', 'graphify-out', '.venv',
                 '.pytest_cache', '__pycache__', 'build', 'plans', 'node_modules'}
NAMES = {f'{v}-g3{k}-{p}' for v in ('dv', 'ov', 'ev') for k in ('b', 'c') for p in ('aaa', 'emsign')}
KEYS = {f'{name}/ca.key' for name in NAMES}
PACKAGE = 'dist/gainsec-gitm_0.2.1-1_arm64.deb'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def check_public_data(path, data, *, allow_profile_key):
    assert not TOKEN_PATTERN.search(data), f'Unexpected credential pattern: {path}'
    assert not PRIVATE_PATTERN.search(data), f'Unexpected private development data: {path}'
    assert allow_profile_key or not KEY_PATTERN.search(data), f'Unapproved private key: {path}'


def scan(paths, base, profile_root, pins):
    files = 0
    allowed = set()
    for path in sorted(set(paths)):
        assert not path.is_symlink(), f'Unexpected symlink: {path.relative_to(base)}'
        if not path.is_file():
            continue
        relative_path = path.relative_to(base)
        assert not (set(relative_path.parts) & PRIVATE_PARTS), f'Private/cache path: {relative_path}'
        assert path.suffix.lower() not in FORBIDDEN | {'.pyc', '.pyo'}, f'Capture/export/cache artifact: {relative_path}'
        data = path.read_bytes()
        relative_profile = str(path.relative_to(profile_root)) if path.is_relative_to(profile_root) else None
        allow_key = relative_profile in KEYS
        check_public_data(relative_path, data, allow_profile_key=allow_key)
        if relative_profile is not None and relative_profile != 'provenance.json':
            assert digest(path) == pins['sha256'][relative_profile], f'Profile byte drift: {relative_path}'
            assert git_blob(data) == pins['git_blobs'][relative_profile], f'Profile Git blob drift: {relative_path}'
        if KEY_PATTERN.search(data):
            assert allow_key, f'Unapproved private key: {relative_path}'
            allowed.add(relative_profile)
        if path.suffix.lower() in {'.key', '.crt', '.pem'}:
            assert relative_profile in pins['sha256'], f'Unapproved CA material: {relative_path}'
        files += 1
    assert allowed == KEYS, f'Expected exactly twelve documented profile keys: {sorted(allowed)}'
    return {'files_scanned': files, 'exact_public_profile_keys_allowlisted': sorted(allowed)}


def payload_map():
    fixed = {
        'DEBIAN/control': 'packaging/debian/control',
        'DEBIAN/postinst': 'packaging/debian/postinst',
        'DEBIAN/prerm': 'packaging/debian/prerm',
        'DEBIAN/postrm': 'packaging/debian/postrm',
        'usr/bin/gitm': 'packaging/wrappers/gitm',
        'usr/share/GITM/bin/gitm': 'packaging/wrappers/gitm-applaunch',
        'usr/libexec/gainsec-gitm-helper': 'packaging/wrappers/gainsec-gitm-helper',
        'usr/share/APPLaunch/applications/gitm.desktop': 'packaging/gitm.desktop',
        'usr/share/APPLaunch/share/images/gitm.png': 'assets/gitm.png',
        'lib/systemd/system/gainsec-gitm-helper.socket': 'packaging/systemd/gainsec-gitm-helper.socket',
        'lib/systemd/system/gainsec-gitm-helper.service': 'packaging/systemd/gainsec-gitm-helper.service',
        'usr/share/doc/gainsec-gitm/README.md': 'README.md',
        'usr/share/doc/gainsec-gitm/README.CardputerZero.md': 'docs/CARDPUTERZERO.md',
        'usr/share/GITM/app-builder.json': 'app-builder.json',
        'usr/share/doc/gainsec-gitm/LICENSE': 'LICENSE',
        'usr/share/doc/gainsec-gitm/copyright': 'LICENSE',
    }
    for folder in ('assets', 'screenshots', 'profiles/emudhra'):
        for path in (ROOT/folder).rglob('*'):
            if path.is_file():
                fixed['usr/share/GITM/' + str(path.relative_to(ROOT))] = str(path.relative_to(ROOT))
    for path in (ROOT/'src/gitm').rglob('*.py'):
        fixed['usr/share/GITM/gitm/' + str(path.relative_to(ROOT/'src/gitm'))] = str(path.relative_to(ROOT))
    return fixed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('extracted', type=Path)
    parser.add_argument('--validated-source', type=Path, help='Optional read-only checkout for independent source-byte proof')
    args = parser.parse_args()
    package = args.extracted.resolve()
    pins = json.loads((ROOT/'profiles/emudhra/provenance.json').read_text())
    assert pins['validated_source_commit'] == SOURCE_COMMIT
    assert pins['repository'] == 'https://github.com/GainSec/GITM-CardputorZero'
    assert {p.name for p in (ROOT/'profiles/emudhra').iterdir() if p.is_dir()} == NAMES
    source_names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    source_paths = [ROOT/name for name in source_names if name and name != PACKAGE]
    report = {'source': scan(source_paths, ROOT, ROOT/'profiles/emudhra', pins),
              'payload': scan(package.rglob('*'), package, package/'usr/share/GITM/profiles/emudhra', pins),
              'validated_source_commit': SOURCE_COMMIT}
    if args.validated_source:
        compared = 0
        for path in sorted((ROOT/'profiles/emudhra').rglob('*')):
            if path.is_file() and path.parent.name in NAMES:
                relative = str(path.relative_to(ROOT))
                original = subprocess.check_output(['git','show',f'{SOURCE_COMMIT}:{relative}'], cwd=args.validated_source)
                assert path.read_bytes() == original, f'Validated source drift: {relative}'
                compared += 1
        assert compared == 54
        report['independent_source_profile_files_verified'] = compared
    mapping = payload_map()
    actual = {str(p.relative_to(package)) for p in package.rglob('*') if p.is_file()}
    assert actual == set(mapping), f'Unexpected or missing payload: {actual ^ set(mapping)}'
    for destination, source in mapping.items():
        assert (package/destination).read_bytes() == (ROOT/source).read_bytes(), f'Payload byte drift: {destination}'
    control = (package/'DEBIAN/control').read_text()
    for line in ('Package: gainsec-gitm', 'Version: 0.2.1-1', 'Architecture: arm64',
                 'Homepage: https://github.com/GainSec/GITM-CardputorZero'):
        assert line in control.splitlines()
    dependencies = control.split('Depends: ')[1].split('\n')[0].split(', ')
    assert dependencies == ['python3 (>= 3.11)','python3-pygame','hostapd','dnsmasq-base','network-manager','nftables','iw','iproute2','systemd','adduser','sslsplit','tcpdump','openssl','python3-cryptography']
    for path in package.rglob('*'):
        if path.is_file():
            assert not (path.stat().st_mode & 0o6000), f'Unexpected setid: {path.relative_to(package)}'
            if path.suffix == '.key':
                assert path.stat().st_mode & 0o777 == 0o640
    report.update(ok=True, exact_source_and_payload_bytes=True, payload_files=len(mapping), dependencies=dependencies)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
