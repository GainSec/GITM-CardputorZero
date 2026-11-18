"""Certificate tests generate disposable material; no fixture keys on disk in source."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def ca(*, parent=None, ca_flag=True, signing=True, name='Ephemeral lab CA'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = parent[0].subject if parent else subject
    signer = parent[1] if parent else key
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, signing, signing, False, False), critical=True)
            .sign(signer, hashes.SHA256()))
    return cert, key


def material(pair):
    return (pair[0].public_bytes(serialization.Encoding.PEM),
            pair[1].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def test_custom_subordinate_requires_matching_ca_signing_key_and_complete_verified_chain():
    from gitm.certificates import validate_material
    root = ca(name='Root')
    sub = ca(parent=root, name='Sub')
    cert, key = material(sub)
    chain = material(root)[0]
    assert validate_material(cert, key, chain).fingerprint == sub[0].fingerprint(hashes.SHA256()).hex()
    for c, k, ch, message in [
        (cert, material(root)[1], chain, 'match'),
        (*material(ca(ca_flag=False)), b'', 'CA:TRUE'),
        (*material(ca(signing=False)), b'', 'keyCertSign'),
        (cert, key, b'', 'chain'),
        (cert, key, chain+b'garbage', 'PEM'),
        (cert, key, material(ca(name='Wrong root'))[0], 'issuer'),
        (cert+b'garbage', key, chain, 'PEM'),
        (cert, key+b'garbage', chain, 'PEM'),
    ]:
        with pytest.raises(ValueError, match=message): validate_material(c, k, ch)


def test_local_ca_generation_and_android_burp_exports_are_private_atomic_and_verifiable(tmp_path):
    from gitm.certificates import ensure_local_ca, export_material
    local = tmp_path / 'ca'
    mat = ensure_local_ca(local)
    assert ensure_local_ca(local).fingerprint == mat.fingerprint
    assert (local / 'ca.key').stat().st_mode & 0o777 == 0o600
    output = tmp_path / 'exports'
    paths = export_material(mat, output, android=True, burp=True)
    expected_hash = subprocess.run(['openssl', 'x509', '-subject_hash_old', '-noout'], input=mat.certificate, capture_output=True, check=True).stdout.decode().strip()
    assert Path(paths['android']).name == expected_hash+'.0'
    assert Path(paths['android']).read_bytes() == mat.certificate
    key, cert, _ = pkcs12.load_key_and_certificates(Path(paths['pkcs12']).read_bytes(), b'')
    assert cert.fingerprint(hashes.SHA256()).hex() == mat.fingerprint
    assert key is not None
    assert Path(paths['pem']).read_bytes() == mat.certificate+mat.private_key+mat.chain
    assert all(Path(p).stat().st_mode & 0o777 == 0o600 for p in paths.values())
    assert output.stat().st_mode & 0o777 == 0o700
    assert not list(output.glob('*.tmp'))


def test_profiles_are_exact_recovered_assets_and_fail_closed_on_tampering(tmp_path):
    from gitm.profiles import list_profiles, verify_profile, profile_info
    names = list_profiles()
    assert len(names) == 12
    assert set(names) == {f'{v}-g3{k}-{p}' for v in ('dv','ov','ev') for k in ('b','c') for p in ('aaa','emsign')}
    root = Path(__file__).parents[1] / 'profiles/emudhra'
    pins = json.loads((root / 'provenance.json').read_text())
    assert pins['validated_source_commit'] == 'ae20080ca2e4cfc6d0fcd399ea09c7068c88c15e'
    assert pins['repository'] == 'https://github.com/GainSec/GITM-CardputorZero'
    for name in names:
        mat = verify_profile(name)
        manifest = profile_info(name)
        assert mat.fingerprint.upper() == manifest['certificate_sha256']
        assert manifest['revocation']['status'] == 'revoked'
    for relative, sha in pins['sha256'].items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == sha
    with pytest.raises(ValueError, match='Unknown'): verify_profile('../../etc')
    with pytest.raises(ValueError, match='asset-unavailable'): verify_profile(names[0], root=tmp_path)


def test_recovered_profile_can_be_exported_without_losing_its_trust_anchor(tmp_path):
    from gitm.profiles import verify_profile
    from gitm.certificates import export_material
    for name in ('dv-g3b-aaa', 'dv-g3b-emsign'):
        paths = export_material(verify_profile(name), tmp_path / name, android=True, burp=True)
        assert Path(paths['pkcs12']).is_file()


def test_custom_ca_rejects_unrecognized_critical_extension():
    from gitm.certificates import validate_material
    cert, key = ca()
    modified = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
                .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
                .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
                .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.5'),b'\x05\x00'),critical=True)
                .sign(key,hashes.SHA256()))
    with pytest.raises(ValueError,match='critical'):
        validate_material(*material((modified,key)))
