#!/usr/bin/env python3
"""Installed ARM64 integration gates in an isolated container; no radio claims."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import pwd
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

import gitm
from gitm.certificates import atomic_private, ensure_local_ca, export_material
from gitm.helper import HelperEngine, ProcessIdentity, _process_identity, _owned_listener
from gitm.model import NetworkConfig
from gitm.plan import build_plan
from gitm.profiles import list_profiles, verify_profile
from gitm.worker import read_events


def until(predicate, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(description)


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, **kwargs)


def main():
    assert Path(gitm.__file__).is_relative_to('/usr/share/GITM'), gitm.__file__
    assert gitm.__version__ == '0.2.1'
    run('runuser', '-u', 'gitmqa', '--', 'gitm', 'verify-profile', 'dv-g3b-emsign')
    for name in list_profiles():
        assert verify_profile(name).fingerprint
    source = Path('/source')
    installed = Path('/usr/share/GITM')
    assert Path('/usr/share/doc/gainsec-gitm/README.md').read_bytes() == (source / 'README.md').read_bytes()
    for folder in ('assets', 'screenshots', 'profiles/emudhra'):
        for path in (source / folder).rglob('*'):
            if path.is_file():
                assert (installed / path.relative_to(source)).read_bytes() == path.read_bytes(), path
    print('PASS installed imports, unprivileged profile access, all 12 profiles, README/assets source bytes', flush=True)
    with tempfile.TemporaryDirectory(prefix='gitm-installed-') as temp:
        root = Path(temp)
        root.chmod(0o711)
        runtime = root / 'private'; runtime.mkdir(mode=0o700)
        data = root / 'data'; data.mkdir(mode=0o711)
        ca = ensure_local_ca(root / 'ca')
        outputs = export_material(ca, root / 'exports', android=True, burp=True)
        assert len(outputs) == 4
        run('openssl', 'pkcs12', '-in', outputs['pkcs12'], '-passin', 'pass:', '-noout')
        config = NetworkConfig('GITM-QA', 'ephemeral-qa-only', 'US', '192.168.77.0/24', '1.1.1.1', 'wlan1', 'eth0', tls=True, capture=True, live=True, lease_events=True)
        plan = build_plan(config)
        nft = root / 'nftables.conf'; nft.write_text(plan.files['/run/gainsec-gitm/private/nftables.conf'])
        run('nft', '--check', '-f', str(nft))
        # This dummy is in this disposable network namespace; it is not an AP/radio.
        run('ip', 'link', 'add', 'gitm-ap', 'type', 'dummy')
        run('ip', 'link', 'set', 'gitm-ap', 'up')
        run('ip', 'address', 'add', '192.168.77.1/24', 'dev', 'gitm-ap')
        engine = HelperEngine(runtime_dir=runtime, data_dir=data, sleeper=time.sleep)
        state = {'state': 'starting', 'owner': 'gainsec-gitm', 'resources': ['gitm-ap', 'gainsec_gitm'], 'previous_ipv4_forwarding': '0', 'processes': {}, 'optional_processes': ['tcpdump', 'sslsplit', 'live', 'leases']}
        pcap = data / 'traffic.pcap'
        lease_source = root / 'dnsmasq.leases'
        live_output = data / 'live.jsonl'
        lease_output = data / 'leases.jsonl'
        evidence_owner = pwd.getpwnam('gitmqa').pw_uid
        for path in (pcap, live_output, lease_output, data/'tls.log'):
            atomic_private(path, b'')
            os.chown(path, evidence_owner, -1)
        # Real tcpdump, real Linux worker identities, bounded on-disk output.
        engine._launch_process('tcpdump', ('tcpdump', '-i', 'lo', '-nn', '-p', '-U', '-s', '0', '-C', '1', '-W', '1', '-Z', 'root', '-w', str(pcap)), state)
        engine._launch_process('live', ('/usr/bin/python3', '-m', 'gitm.worker', 'live', '--output', str(live_output), '--interface', 'gitm-ap'), state)
        engine._launch_process('leases', ('/usr/bin/python3', '-m', 'gitm.worker', 'leases', '--output', str(lease_output), '--source', str(lease_source)), state)
        tls_server = socket.socket(); tls_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_server.bind(('127.0.0.1', 19443)); tls_server.listen(1); tls_server.settimeout(5)
        material_key = serialization.load_pem_private_key(ca.private_key, password=None)
        issuer = x509.load_pem_x509_certificate(ca.certificate)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        stamp = datetime.now(timezone.utc)
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject).public_key(material_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(stamp-timedelta(minutes=1)).not_valid_after(stamp+timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                .sign(material_key, hashes.SHA256()))
        atomic_private(root/'server.crt', leaf.public_bytes(serialization.Encoding.PEM))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'server.crt', root/'ca/ca.key')
        received = []; server_errors = []
        def serve():
            try:
                connection, _ = tls_server.accept()
                with context.wrap_socket(connection, server_side=True) as peer:
                    received.append(peer.recv(1024))
                    peer.sendall(b'controlled lab response')
            except Exception as exc:
                server_errors.append(str(exc))
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        tls_log = data/'tls.log'
        try:
            engine._launch_process('sslsplit', ('sslsplit', '-u', 'root', '-l', str(tls_log), '-k', str(root/'ca/ca.key'), '-c', str(root/'ca/ca.crt'), 'ssl', '127.0.0.1', '8443', '127.0.0.1', '19443'), state)
            until(lambda: _owned_listener(ProcessIdentity.from_dict(state['processes']['sslsplit']), '127.0.0.1'), 'owned TLS socket not listening')
            time.sleep(0.5)
            client_context = ssl.create_default_context(cafile=str(root/'ca/ca.crt'))
            with client_context.wrap_socket(socket.socket(), server_hostname='localhost') as client:
                client.settimeout(5)
                client.connect(('127.0.0.1', 8443))
                client.sendall(b'controlled lab request')
                assert client.recv(1024) == b'controlled lab response'
            thread.join(timeout=5)
            assert received == [b'controlled lab request'], (received, server_errors)
            # Generate enough localhost traffic to exercise rotation, not just initial file creation.
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); receiver.bind(('127.0.0.1', 0)); receiver.settimeout(1)
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _ in range(2500):
                sender.sendto(b'x'*1024, receiver.getsockname()); receiver.recvfrom(2048)
            sender.close(); receiver.close()
            lease_source.write_text('1234 aa:bb:cc:dd:ee:ff 192.168.77.10 lab *\n')
            until(lambda: bool(read_events(lease_output)), 'lease watcher did not persist event')
            assert read_events(lease_output)[0]['mac'] == 'aa:bb:cc:dd:ee:ff'
            # Craft only a metadata-bearing IPv4 UDP frame on the disposable dummy interface.
            packet = bytes.fromhex('ffffffffffffaabbccddeeff08004500001c0000000040110000c0a84d0ac0000201') + bytes.fromhex('303901bb00080000')
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:
                raw.bind(('gitm-ap', 0)); raw.send(packet)
            until(lambda: bool(read_events(live_output)), 'live worker did not persist metadata')
            assert read_events(live_output)[0]['protocol'] == 'UDP'
            assert pcap.exists(), [p.name for p in data.iterdir()]
            assert pcap.stat().st_size <= 1_000_000 + 262144
            for path in (pcap, live_output, lease_output, tls_log):
                assert path.stat().st_mode & 0o777 == 0o600
                assert path.stat().st_uid == evidence_owner
            run('runuser', '-u', 'gitmqa', '--', 'head', '-c', '24', str(pcap))
            assert tls_log.stat().st_size <= 512*1024
            assert 'controlled lab request' not in tls_log.read_text()
            for raw_identity in state['processes'].values():
                identity = ProcessIdentity.from_dict(raw_identity)
                assert _process_identity(identity.pid) == identity
            print('PASS real SSLsplit trusted-CA handshake, TCP capture rotation/exact path, live metadata and timestamped lease worker', flush=True)
        finally:
            errors = engine._stop_owned_processes(state)
            tls_server.close()
            run('ip', 'link', 'del', 'gitm-ap')
            assert not errors, errors
            assert all(_process_identity(raw['pid']) is None for raw in state['processes'].values())
        run('tcpdump', '-nn', '-r', str(pcap), '-c', '1')
        assert not list(data.glob('traffic.pcap*0')), [p.name for p in data.iterdir()]
        print('PASS direct-child identity teardown; no remaining owned workers; PCAP readable', flush=True)
    print('Installed ARM64 smoke PASS; device acceptance scope is documented in README', flush=True)


if __name__ == '__main__':
    main()
