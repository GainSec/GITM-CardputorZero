"""In-memory CA validation and private, atomic certificate exports."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

MAX_PEM_BYTES = 128 * 1024
CERT_RE = re.compile(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----')
KEY_RE = re.compile(rb'\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]+-----END \1-----\s*')


@dataclass(frozen=True)
class CAMaterial:
    certificate: bytes
    private_key: bytes = field(repr=False)
    chain: bytes = b''
    fingerprint: str = ''
    trust_anchor: bytes = b''


def certificates(pem: bytes) -> list[x509.Certificate]:
    if not pem or len(pem) > MAX_PEM_BYTES:
        raise ValueError('invalid PEM size')
    matches = list(CERT_RE.finditer(pem))
    remainder = CERT_RE.sub(b'', pem)
    if not matches or remainder.strip():
        raise ValueError('malformed certificate PEM')
    try:
        return [x509.load_pem_x509_certificate(m.group()) for m in matches]
    except ValueError as exc:
        raise ValueError('malformed certificate PEM') from exc


def _check_ca(cert: x509.Certificate) -> None:
    for extension in cert.extensions:
        if extension.critical and isinstance(extension.value, x509.UnrecognizedExtension):
            raise ValueError("unrecognized critical CA extension")
    try:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('CA:TRUE required')
    except x509.ExtensionNotFound as exc:
        raise ValueError('CA:TRUE required') from exc
    try:
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            raise ValueError('keyCertSign required')
    except x509.ExtensionNotFound as exc:
        raise ValueError('keyCertSign required') from exc
    current = datetime.now(timezone.utc)
    if hasattr(cert, 'not_valid_before_utc'):
        before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
    else:
        before, after = cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not before <= current <= after:
        raise ValueError('CA certificate outside validity period')


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    if cert.issuer != issuer.subject:
        raise ValueError('CA chain issuer mismatch')
    public = issuer.public_key()
    try:
        if isinstance(public, rsa.RSAPublicKey):
            parameters = getattr(cert, 'signature_algorithm_parameters', None) or padding.PKCS1v15()
            public.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            raise ValueError('unsupported CA public key algorithm')
    except InvalidSignature as exc:
        raise ValueError('CA chain signature verification failed') from exc


def validate_material(certificate: bytes, private_key: bytes, chain: bytes = b'') -> CAMaterial:
    certs = certificates(certificate)
    if len(certs) != 1:
        raise ValueError('CA certificate PEM must contain one certificate')
    if len(private_key) > MAX_PEM_BYTES or not KEY_RE.fullmatch(private_key):
        raise ValueError('malformed or encrypted private key PEM')
    try:
        key = serialization.load_pem_private_key(private_key, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError('invalid private key PEM') from exc
    cert = certs[0]
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(encoding, form) != cert.public_key().public_bytes(encoding, form):
        raise ValueError('CA certificate/private key mismatch')
    path = [cert, *(certificates(chain) if chain else [])]
    fingerprints = [c.fingerprint(hashes.SHA256()) for c in path]
    if len(set(fingerprints)) != len(path):
        raise ValueError('duplicate certificate in CA chain')
    for index, current in enumerate(path):
        _check_ca(current)
        constraints = current.extensions.get_extension_for_class(x509.BasicConstraints).value
        if constraints.path_length is not None and index > constraints.path_length:
            raise ValueError('CA chain path length exceeded')
        if index + 1 < len(path):
            _verify_signature(current, path[index + 1])
        elif current.issuer != current.subject:
            raise ValueError('complete CA chain through self-signed trust anchor required')
        else:
            _verify_signature(current, current)
    return CAMaterial(certificate, private_key, chain, cert.fingerprint(hashes.SHA256()).hex())


def read_private_input(path: Path, *, owner_uid: int | None = None) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PEM_BYTES:
            raise ValueError('CA input must be a bounded regular file')
        if owner_uid is not None and info.st_uid != owner_uid:
            raise ValueError('CA input must belong to requesting user')
        return os.read(fd, MAX_PEM_BYTES + 1)
    finally:
        os.close(fd)


def atomic_private(path: Path, content: bytes) -> None:
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_local_ca(directory: Path) -> CAMaterial:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    cert_path, key_path = directory / 'ca.crt', directory / 'ca.key'
    if cert_path.exists() or key_path.exists():
        return validate_material(read_private_input(cert_path), read_private_input(key_path))
    result = generate_local_ca()
    atomic_private(key_path, result.private_key)
    atomic_private(cert_path, result.certificate)
    return result


def export_material(material: CAMaterial, output: Path, *, android: bool = False, burp: bool = False) -> dict[str, str]:
    # Validation precedes any destination creation.
    validated = validate_material(material.certificate, material.private_key, material.chain + material.trust_anchor)
    material = replace(material, fingerprint=validated.fingerprint)
    contents = {'certificate': ('ca.crt', material.certificate)}
    if android:
        result = subprocess.run(['openssl', 'x509', '-subject_hash_old', '-noout'], input=material.certificate,
                                capture_output=True, check=True, timeout=10, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        name = result.stdout.decode('ascii').strip()
        if not re.fullmatch('[0-9a-f]{8}', name):
            raise ValueError('invalid Android subject hash')
        contents['android'] = (name + '.0', material.certificate)
    if burp:
        key = serialization.load_pem_private_key(material.private_key, password=None)
        cert = certificates(material.certificate)[0]
        parents = certificates(material.chain) if material.chain else []
        bundle = pkcs12.serialize_key_and_certificates(b'GainSec GITM', key, cert, parents or None, serialization.NoEncryption())
        contents['pkcs12'] = ('mitm.p12', bundle)
        contents['pem'] = ('mitm_combined.pem', material.certificate + material.private_key + material.chain)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink():
        raise ValueError('export directory cannot be a symlink')
    output.chmod(0o700)
    paths = {}
    for name, (filename, data) in contents.items():
        path = output / filename
        atomic_private(path, data)
        paths[name] = str(path)
    return paths


def generate_local_ca() -> CAMaterial:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'GainSec GITM local lab CA')])
    current = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(minutes=1))
            .not_valid_after(current + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return validate_material(cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
