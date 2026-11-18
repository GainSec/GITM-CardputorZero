"""Vertical feature behavior tests; baseline safety tests remain in place."""
from dataclasses import replace
import json

import pytest

from gitm.model import NetworkConfig
from gitm.plan import build_plan, OperationPlan
from gitm.helper import HelperEngine, HelperError, ProcessIdentity
from test_helper import FakeChild, RecordingRunner


def config(**features):
    return NetworkConfig("GITM-LAB", "ephemeral-lab-482", "US", "192.168.77.0/24", "1.1.1.1", "wlan1", "enp2s0", **features)


def test_capture_plan_is_bounded_scoped_and_roundtrips_without_writing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan = build_plan(config(capture=True, capture_mb=4))
    action = next(a for a in plan.actions if a.name == "start_tcpdump")
    assert action.argv[:4] == ("tcpdump", "-i", "gitm-ap", "-nn")
    assert action.argv[action.argv.index("-C") + 1] == "4"
    assert action.argv[action.argv.index("-W") + 1] == "1"
    assert action.argv[action.argv.index("-w") + 1] == plan.evidence_paths["pcap"]
    assert "-Z" in action.argv
    assert plan.capture_enabled
    assert OperationPlan.from_dict(plan.to_dict()) == plan
    assert list(tmp_path.iterdir()) == []


def test_capture_is_owned_live_and_retryably_stopped(tmp_path):
    live = {}
    launched = []
    resources = {"gitm-ap": True, "gainsec_gitm": True}
    def spawn(argv):
        name = argv[0]
        pid = 200 + len(launched)
        launched.append(name)
        live[pid] = ProcessIdentity(pid, pid * 10, name, "/usr/sbin/" + name)
        return FakeChild(pid)
    def run(argv):
        if argv[:2] == ("nft", "delete"): resources["gainsec_gitm"] = False
        if argv == ("iw", "dev", "gitm-ap", "del"): resources["gitm-ap"] = False
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    engine = HelperEngine(runtime_dir=tmp_path / "private", forwarding_path=forward,
                          runner=run, spawner=spawn, identity_provider=live.get,
                          killer=lambda pid, sig: live.pop(pid, None), sleeper=lambda _: None,
                          resource_liveness=lambda: resources, data_dir=tmp_path / "data")
    result = engine.start(build_plan(config(capture=True)))
    assert "tcpdump" in launched
    assert result["features"]["capture"] is True
    assert result["evidence"]["pcap"].endswith("/traffic.pcap")
    state = json.loads(engine.state_path.read_text())
    capture_pid = state["processes"]["tcpdump"]["pid"]
    assert engine.status()["ok"]
    live.pop(capture_pid)
    assert "tcpdump identity is not live" in engine.status()["errors"]
    assert engine.stop()["state"] == "inactive"
    assert not live
    assert forward.read_text() == "0\n"


@pytest.mark.parametrize("size", [0, -1, 65, True, "8"])
def test_capture_rejects_invalid_bounds(size):
    with pytest.raises(ValueError, match="capture"):
        build_plan(config(capture=True, capture_mb=size))


def test_live_and_lease_workers_are_planned_as_owned_bounded_services():
    plan = build_plan(config(live=True, lease_events=True))
    actions = {a.name: a.argv for a in plan.actions}
    assert actions["start_live"][0] == "/usr/bin/python3"
    assert actions["start_leases"][0] == "/usr/bin/python3"
    assert "gitm.worker" in actions["start_live"]
    assert "--interface" in actions["start_live"]
    assert "dhcp-leasefile=/run/gainsec-gitm/leases/dnsmasq.leases" in plan.files["/run/gainsec-gitm/private/dnsmasq.conf"]
    assert plan.evidence_paths["live"].endswith("/live.jsonl")
    assert plan.evidence_paths["leases"].endswith("/leases.jsonl")


def test_metadata_never_includes_packet_payload_or_terminal_controls():
    from gitm.worker import packet_metadata, safe_text
    import struct
    ethernet = b'\x00' * 12 + b'\x08\x00'
    ipv4 = bytes.fromhex('450000300001000040060000c0000201c6336402')
    tcp = struct.pack('!HH', 43210, 443) + b'\x00' * 16
    result = packet_metadata(ethernet + ipv4 + tcp + b'\x1b[31mSECRET')
    assert result["source"] == "192.0.2.1:43210"
    assert result["destination"] == "198.51.100.2:443"
    assert result["protocol"] == "TCP"
    assert "SECRET" not in json.dumps(result)
    assert safe_text('\x1b[31mhello\n<script>') == '?[31mhello??script?'
    assert packet_metadata(b'bad') is None


def test_lease_events_are_normalized_timestamped_deduplicated_and_bounded(tmp_path):
    from gitm.worker import lease_events, append_event, read_events
    leases = '1234 aa:bb:cc:dd:ee:ff 192.168.77.10 evil-host *\ninvalid line\n'
    first = lease_events(leases, set(), timestamp="2026-11-18T00:00:00Z")
    assert first == [{"timestamp": "2026-11-18T00:00:00Z", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.77.10"}]
    assert lease_events(leases, {("aa:bb:cc:dd:ee:ff", "192.168.77.10")}) == []
    target = tmp_path / "events.jsonl"
    for _ in range(100): append_event(target, first[0], max_bytes=512)
    assert target.stat().st_size <= 512
    assert len(read_events(target, limit=2)) <= 2
    assert target.stat().st_mode & 0o777 == 0o600


def test_every_optional_child_has_identity_liveness_and_cleanup(tmp_path):
    # Same public lifecycle, exercising worker executable identities too.
    live = {}
    resources = {"gitm-ap": True, "gainsec_gitm": True}
    def spawn(argv):
        name = argv[3] if argv[0] == "/usr/bin/python3" else argv[0]
        pid = 300 + len(live)
        comm = {"live": "gitm-live", "leases": "gitm-leases"}.get(name, name)
        executable = "/usr/bin/python3.11" if name in {"live", "leases"} else "/usr/sbin/" + name
        live[pid] = ProcessIdentity(pid, pid, comm, executable)
        return FakeChild(pid)
    def run(argv):
        if argv[:2] == ("nft", "delete"): resources["gainsec_gitm"] = False
        if argv == ("iw", "dev", "gitm-ap", "del"): resources["gitm-ap"] = False
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    engine = HelperEngine(runtime_dir=tmp_path / "private", data_dir=tmp_path / "data",
                          forwarding_path=forward, runner=run, spawner=spawn,
                          identity_provider=live.get, killer=lambda pid, _: live.pop(pid, None),
                          sleeper=lambda _: None, resource_liveness=lambda: resources)
    assert engine.start(build_plan(config(live=True, lease_events=True)))["ok"]
    assert len(live) == 4
    assert engine.status()["features"]["live"]
    assert engine.stop()["ok"]
    assert not live


def test_tls_plan_scopes_redirect_to_owned_ap_and_keeps_packet_contents_out_of_logs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan = build_plan(config(tls=True))
    assert plan.tls_interception_enabled
    nft = plan.files['/run/gainsec-gitm/private/nftables.conf']
    assert 'iifname "gitm-ap" ip saddr 192.168.77.0/24 tcp dport 443 redirect to :8443' in nft
    assert 'iifname "gitm-ap" tcp dport 8443 ct status dnat accept' in nft
    argv = next(a.argv for a in plan.actions if a.name == 'start_sslsplit')
    assert argv[0] == 'sslsplit'
    assert '-k' in argv and '-c' in argv and '-l' in argv
    assert '-S' not in argv and '-F' not in argv
    assert argv[-3:] == ('ssl', '192.168.77.1', '8443')
    assert list(tmp_path.iterdir()) == []


def test_tls_process_has_owned_identity_private_runtime_ca_and_no_persisted_key(tmp_path):
    live = {}
    resources = {'gitm-ap': True, 'gainsec_gitm': True}
    def spawn(argv):
        pid = 500 + len(live)
        live[pid] = ProcessIdentity(pid, pid, argv[0], '/usr/sbin/' + argv[0])
        return FakeChild(pid)
    def run(argv):
        if argv[:2] == ('nft', 'delete'): resources['gainsec_gitm'] = False
        if argv == ('iw', 'dev', 'gitm-ap', 'del'): resources['gitm-ap'] = False
    forward = tmp_path / 'forward'
    forward.write_text('0\n')
    engine = HelperEngine(runtime_dir=tmp_path / 'private', data_dir=tmp_path / 'data', forwarding_path=forward,
                          runner=run, spawner=spawn, identity_provider=live.get,
                          killer=lambda pid, _: live.pop(pid, None), sleeper=lambda _: None, resource_liveness=lambda: resources)
    result = engine.start(build_plan(config(tls=True)))
    assert result['features']['tls']
    assert (engine.runtime_dir / 'ca.key').stat().st_mode & 0o777 == 0o600
    assert 'PRIVATE KEY' not in engine.state_path.read_text()
    assert engine.status()['ok']
    assert engine.stop()['ok']
    assert not (engine.runtime_dir / 'ca.key').exists()
    assert not live


def test_custom_tls_validation_precedes_every_mutation(tmp_path):
    from gitm.certificates import CAMaterial
    from test_certificates import ca, material
    cert, key = material(ca())
    runner = RecordingRunner()
    forward = tmp_path / 'forward'
    forward.write_text('0\n')
    engine = HelperEngine(runtime_dir=tmp_path / 'private', data_dir=tmp_path / 'data', forwarding_path=forward, runner=runner)
    plan = build_plan(config(tls=True, ca_cert='/caller/ca.crt', ca_key='/caller/ca.key'))
    with pytest.raises(ValueError, match='PEM'):
        engine.start(plan, ca_material=CAMaterial(cert+b'garbage', key))
    assert not runner.calls
    assert not engine.runtime_dir.exists()
    assert not (tmp_path / 'data').exists()
    assert forward.read_text() == '0\n'


@pytest.mark.parametrize('features', [dict(ca_cert='/tmp/a'), dict(ca_key='/tmp/k'), dict(ca_chain='/tmp/c'), dict(profile='invalid'), dict(profile='dv-g3b-aaa', ca_cert='/a', ca_key='/b')])
def test_tls_rejects_incomplete_or_conflicting_ca_options(features):
    with pytest.raises(ValueError): build_plan(config(**features))


def test_helper_rejects_unrecognized_optional_process_evidence(tmp_path):
    state = {'state': 'active', 'owner': 'gainsec-gitm', 'resources': ['gitm-ap', 'gainsec_gitm'],
             'previous_ipv4_forwarding': '0', 'processes': {}, 'optional_processes': ['foreign']}
    assert not HelperEngine._is_owned_state(state)


def test_helper_binds_evidence_and_exports_to_socket_requester(tmp_path):
    engine = HelperEngine(runtime_dir=tmp_path / 'private', data_dir=tmp_path / 'data', runner=RecordingRunner())
    with pytest.raises(HelperError, match='requesting user'):
        engine.dispatch({'action': 'start', 'plan': build_plan(config(owner_uid=12345)).to_dict()}, requester_uid=12346)
    assert not (tmp_path / 'data').exists()


def test_spawn_enforces_kernel_file_limits_for_capture_and_tls(monkeypatch):
    import gitm.helper as helper
    observed = []
    monkeypatch.setattr(helper.subprocess, 'Popen', lambda argv, **kw: observed.append((argv, kw)))
    helper._spawn(('sslsplit', '-l', '/fixed/tls.log'))
    helper._spawn(('tcpdump', '-C', '4', '-W', '1', '-w', '/fixed/traffic.pcap'))
    assert all(row[1]['preexec_fn'] is not helper._unblock_child_termination_signals for row in observed)


def test_disk_or_child_failure_watchdog_rolls_back_owned_session(tmp_path):
    engine = HelperEngine(runtime_dir=tmp_path / 'private', data_dir=tmp_path / 'data', runner=RecordingRunner())
    engine.runtime_dir.mkdir()
    engine._save_state({'state': 'active', 'owner': 'gainsec-gitm', 'resources': ['gitm-ap', 'gainsec_gitm'],
                        'previous_ipv4_forwarding': '0', 'processes': {}})
    stopped = []
    engine.stop = lambda: stopped.append(True) or {'ok': True, 'state': 'inactive'}
    result = engine.watchdog()
    assert stopped
    assert result['ok'] is False
    assert 'hostapd' in str(result['errors'])


def test_ap_isolates_layer_two_clients_and_tls_listener_uses_only_ap_address():
    plan = build_plan(config(tls=True, capture=True))
    assert 'ap_isolate=1' in plan.files['/run/gainsec-gitm/private/hostapd.conf']
    tls = next(a.argv for a in plan.actions if a.name == 'start_sslsplit')
    assert tls[-3:] == ('ssl', '192.168.77.1', '8443')
    nft = plan.files['/run/gainsec-gitm/private/nftables.conf']
    assert 'ip daddr 192.168.77.1 tcp dport 8443 drop' in nft
    capture = next(a.argv for a in plan.actions if a.name == 'start_tcpdump')
    assert capture[capture.index('-s')+1] == '0'


@pytest.mark.parametrize('failed', ['tcpdump', 'sslsplit', 'live', 'leases'])
def test_optional_child_launch_failure_unwinds_every_owned_resource(tmp_path, failed):
    live = {}
    resources = {'gitm-ap': True, 'gainsec_gitm': True}
    children = []
    def spawn(argv):
        name = argv[3] if argv[0] == '/usr/bin/python3' else argv[0]
        if name == failed:
            raise OSError('injected optional child failure')
        pid = 900 + len(children)
        child = FakeChild(pid); children.append(child)
        live[pid] = ProcessIdentity(pid, pid, 'gitm-'+name if name in {'live','leases'} else name,
                                    '/usr/bin/python3.11' if name in {'live','leases'} else '/usr/sbin/'+name)
        return child
    def run(argv):
        if argv[:2] == ('nft','delete'): resources['gainsec_gitm'] = False
        if argv == ('iw','dev','gitm-ap','del'): resources['gitm-ap'] = False
    forward = tmp_path / 'forward'; forward.write_text('0\n')
    engine = HelperEngine(runtime_dir=tmp_path / 'private', data_dir=tmp_path / 'data', forwarding_path=forward,
                          runner=run, spawner=spawn, identity_provider=live.get,
                          killer=lambda pid, _: live.pop(pid,None), sleeper=lambda _:None, resource_liveness=lambda: resources)
    with pytest.raises(HelperError, match='injected optional'):
        engine.start(build_plan(config(capture=True, live=True, tls=True, lease_events=True)))
    assert not live
    assert not any(resources.values())
    assert forward.read_text() == '0\n'
    assert not (engine.runtime_dir/'ca.key').exists()


def test_lease_persistence_preserves_dnsmasq_privilege_drop():
    plan = build_plan(config(lease_events=True))
    dns = plan.files['/run/gainsec-gitm/private/dnsmasq.conf']
    assert 'user=root' not in dns
    assert 'dhcp-leasefile=/run/gainsec-gitm/leases/dnsmasq.leases' in dns
    worker = next(a.argv for a in plan.actions if a.name == 'start_leases')
    assert worker[-1] == '/run/gainsec-gitm/leases/dnsmasq.leases'


def test_tls_listener_probe_requires_the_owned_pid_socket_and_exact_address(tmp_path):
    from gitm.helper import _owned_listener
    import socket
    proc = tmp_path / '123'; (proc / 'fd').mkdir(parents=True); (proc / 'net').mkdir()
    (proc / 'fd/7').symlink_to('socket:[42]')
    address = socket.inet_aton('192.168.77.1')[::-1].hex().upper()
    (proc / 'net/tcp').write_text('header\n0: '+address+':20FB 00000000:0000 0A 0:0 00:0 0 0 0 42 1\n')
    identity = ProcessIdentity(123, 10, 'sslsplit', '/usr/bin/sslsplit')
    assert _owned_listener(identity, '192.168.77.1', proc_root=tmp_path)
    assert not _owned_listener(identity, '192.168.77.2', proc_root=tmp_path)
    (proc / 'fd/7').unlink()
    assert not _owned_listener(identity, '192.168.77.1', proc_root=tmp_path)


def test_watchdog_enforces_disk_reserve_even_when_every_process_is_live(tmp_path, monkeypatch):
    import shutil
    live = {1: ProcessIdentity(10, 20, 'hostapd', '/usr/sbin/hostapd'), 2: ProcessIdentity(11, 21, 'dnsmasq', '/usr/sbin/dnsmasq')}
    identities = {v.pid:v for v in live.values()}
    engine = HelperEngine(runtime_dir=tmp_path/'private', data_dir=tmp_path/'data', runner=RecordingRunner(), identity_provider=identities.get)
    engine.runtime_dir.mkdir()
    engine._save_state({'state':'active','owner':'gainsec-gitm','resources':['gitm-ap','gainsec_gitm'],
                        'previous_ipv4_forwarding':'0','processes':{'hostapd':live[1].to_dict(),'dnsmasq':live[2].to_dict()},
                        'evidence':{'pcap':str(tmp_path/'data/traffic.pcap')}})
    monkeypatch.setattr(shutil, 'disk_usage', lambda _: type('Usage',(),{'free':0})())
    stops=[]; engine.stop=lambda:stops.append(True)
    assert 'evidence disk reserve exhausted' in engine.watchdog()['errors']
    assert stops


@pytest.mark.parametrize('name',['tcpdump','sslsplit','live','leases'])
def test_optional_process_identity_mismatch_is_never_killed_and_teardown_retries(tmp_path, name):
    expected=ProcessIdentity(555,111,'gitm-'+name if name in {'live','leases'} else name,
                             '/usr/bin/python3.11' if name in {'live','leases'} else '/usr/sbin/'+name)
    changed=replace(expected,start_time=999)
    identities={555:changed}; killed=[]
    engine=HelperEngine(runtime_dir=tmp_path/'private', runner=RecordingRunner(), identity_provider=identities.get,
                        killer=lambda pid,_:(killed.append(pid),identities.pop(pid,None)), sleeper=lambda _:None)
    state={'processes':{name:expected.to_dict()}}
    assert 'identity mismatch' in ';'.join(engine._stop_owned_processes(state))
    assert not killed
    identities[555]=expected
    assert not engine._stop_owned_processes(state)
    assert killed == [555]


def test_owned_listener_accepts_only_kernel_proven_same_executable_direct_proxy_child(tmp_path):
    from gitm.helper import _owned_listener
    import socket
    def process(pid, parent, start):
        root=tmp_path/str(pid)
        (root/'fd').mkdir(parents=True);(root/'net').mkdir();(root/'task'/str(pid)).mkdir(parents=True)
        fields=['S',str(parent)]+['0']*17+[str(start)]
        (root/'stat').write_text(f'{pid} (sslsplit) '+ ' '.join(fields))
        (root/'comm').write_text('sslsplit\n');(root/'exe').symlink_to('/usr/bin/sslsplit')
        (root/'task'/str(pid)/'children').write_text('')
        (root/'net/tcp').write_text('header\n')
        return root
    parent=process(123,1,10);child=process(124,123,11)
    (parent/'task/123/children').write_text('124 ')
    (child/'fd/8').symlink_to('socket:[42]')
    address=socket.inet_aton('192.168.77.1')[::-1].hex().upper()
    (child/'net/tcp').write_text('header\n0: '+address+':20FB 00000000:0000 0A 0:0 00:0 0 0 0 42 1\n')
    identity=ProcessIdentity(123,10,'sslsplit','/usr/bin/sslsplit')
    assert _owned_listener(identity,'192.168.77.1',proc_root=tmp_path)
    (parent/'task/123/children').write_text('')
    assert not _owned_listener(identity,'192.168.77.1',proc_root=tmp_path)


def test_registered_proxy_process_gets_persisted_identity_and_liveness(tmp_path):
    parent=ProcessIdentity(123,10,'sslsplit','/usr/bin/sslsplit')
    child=ProcessIdentity(124,11,'sslsplit','/usr/bin/sslsplit')
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=RecordingRunner(),proxy_children=lambda identity:(child,))
    engine.runtime_dir.mkdir()
    state={'processes':{'sslsplit':parent.to_dict()},'optional_processes':['sslsplit']}
    engine._register_proxy(state)
    assert state['processes']['sslsplit_worker'] == child.to_dict()
    assert 'sslsplit_worker' in state['optional_processes']
    assert json.loads(engine.state_path.read_text())['processes']['sslsplit_worker'] == child.to_dict()


def test_proxy_startup_allows_device_key_generation_beyond_cleanup_wait_budget(tmp_path):
    parent=ProcessIdentity(123,10,'sslsplit','/usr/bin/sslsplit')
    child=ProcessIdentity(124,11,'sslsplit','/usr/bin/sslsplit')
    calls=[]; delays=[]
    def children(_identity):
        calls.append(True)
        return (child,) if len(calls)>=48 else ()
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=RecordingRunner(),proxy_children=children,sleeper=delays.append)
    engine.runtime_dir.mkdir()
    state={'processes':{'sslsplit':parent.to_dict()},'optional_processes':['sslsplit']}
    engine._register_proxy(state)
    assert state['processes']['sslsplit_worker']==child.to_dict()
    assert sum(delays) >= 2
    assert engine.wait_attempts == 10  # Teardown stays independently bounded.


def test_proxy_startup_timeout_remains_finite_and_does_not_invent_identity(tmp_path):
    parent=ProcessIdentity(123,10,'sslsplit','/usr/bin/sslsplit');calls=[]
    def children(_):calls.append(True);return ()
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=RecordingRunner(),proxy_children=children,proxy_wait_attempts=3,sleeper=lambda _:None)
    state={'processes':{'sslsplit':parent.to_dict()},'optional_processes':['sslsplit']}
    with pytest.raises(HelperError,match='proxy identity'):
        engine._register_proxy(state)
    assert len(calls)==3
    assert 'sslsplit_worker' not in state['processes']


def test_python_worker_startup_has_a_separate_device_import_budget(tmp_path):
    child=FakeChild(444);calls=[];delays=[]
    identity=ProcessIdentity(444,20,'gitm-leases','/usr/bin/python3.11')
    def identify(_):
        calls.append(True)
        return identity if len(calls)>=30 else None
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=RecordingRunner(),spawner=lambda _:child,identity_provider=identify,sleeper=delays.append)
    engine.runtime_dir.mkdir()
    state={}
    assert engine._launch_process('leases',('/usr/bin/python3','-m','gitm.worker','leases'),state)==identity
    assert sum(delays)>1
    assert engine.wait_attempts==10


def test_never_ready_worker_startup_is_bounded_and_reaps_the_direct_child(tmp_path):
    child=FakeChild(445);calls=[]
    def identify(_):calls.append(True);return None
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=RecordingRunner(),spawner=lambda _:child,identity_provider=identify,startup_wait_attempts=3,sleeper=lambda _:None)
    engine.runtime_dir.mkdir()
    with pytest.raises(HelperError,match='expected identity'):
        engine._launch_process('leases',('/usr/bin/python3','-m','gitm.worker','leases'),{})
    assert len(calls)==3
    assert child.returncode is not None
    assert not engine._children
