from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

import pytest

from gitm.helper import HelperEngine, HelperError, ProcessIdentity, _handle_connection, _process_identity, _spawn, probe_owned_resources, validate_plan_for_helper
from gitm.model import InterfaceDiscovery, NetworkConfig
from gitm.plan import OperationPlan, build_plan


def config():
    return NetworkConfig(
        ssid="GITM-C0-7A2F",
        passphrase="vivid-nimbus-4821",
        country="US",
        subnet="192.168.77.0/24",
        resolver="1.1.1.1",
        ap_interface="wlan1",
        wan_interface="enp2s0",
    )


def test_helper_accepts_only_exact_rederived_plan():
    plan = build_plan(config())
    assert validate_plan_for_helper(plan) == plan
    altered = replace(plan, nft_table="foreign")
    with pytest.raises(HelperError, match="plan does not match"):
        validate_plan_for_helper(altered)


def test_helper_rejects_state_path_escape_and_future_modules():
    plan = build_plan(config())
    with pytest.raises(HelperError):
        validate_plan_for_helper(replace(plan, files={"/etc/hostapd.conf": "bad"}))
    with pytest.raises(HelperError):
        validate_plan_for_helper(replace(plan, capture_enabled=True))


class RecordingRunner:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def __call__(self, argv):
        self.calls.append(tuple(argv))
        if self.fail_at and argv[0] == self.fail_at:
            raise RuntimeError("injected failure")


def test_process_identity_uses_cmdline_when_privilege_drop_hides_exe(tmp_path, monkeypatch):
    proc = tmp_path / "321"
    proc.mkdir()
    proc.joinpath("stat").write_text("321 (dnsmasq) S " + " ".join(["0"] * 18 + ["987"]) + "\n")
    proc.joinpath("comm").write_text("dnsmasq\n")
    proc.joinpath("cmdline").write_bytes(b"dnsmasq\0--keep-in-foreground\0")

    monkeypatch.setattr("gitm.helper.os.readlink", lambda _path: (_ for _ in ()).throw(PermissionError(13, "denied")))
    monkeypatch.setattr("gitm.helper.shutil.which", lambda command, path: f"/usr/sbin/{command}")

    assert _process_identity(321, proc_root=tmp_path) == ProcessIdentity(
        321, 987, "dnsmasq", "/usr/sbin/dnsmasq"
    )


def live_evidence(ap=("wlan1",), wan=("enp2s0",), networks=()):
    return InterfaceDiscovery(ap_interfaces=ap, wan_interfaces=wan, existing_networks=networks)


@pytest.mark.parametrize(
    ("evidence", "message"),
    [
        (live_evidence(ap=()), "AP interface"),
        (live_evidence(wan=()), "WAN interface"),
        (live_evidence(ap=("wlan9",)), "AP interface"),
        (live_evidence(networks=(__import__("ipaddress").ip_network("192.168.77.0/24"),)), "overlaps"),
    ],
)
def test_direct_helper_start_rejects_plan_without_fresh_matching_live_evidence(tmp_path, evidence, message):
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    engine = HelperEngine(
        runtime_dir=tmp_path / "private",
        forwarding_path=forward,
        runner=RecordingRunner(),
        evidence_provider=lambda: evidence,
    )
    with pytest.raises(HelperError, match=message):
        engine.start(build_plan(config()))
    assert forward.read_text() == "0\n"


@pytest.mark.parametrize("existing_state", ["starting", "active", "stopping", "cleanup_failed"])
def test_start_rejects_every_valid_package_owned_state_until_stop_recovers(tmp_path, existing_state):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").write_text(json.dumps({
        "state": existing_state,
        "owner": "gainsec-gitm",
        "resources": ["gitm-ap", "gainsec_gitm"],
        "previous_ipv4_forwarding": "0",
        "processes": {},
    }))
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    runner = RecordingRunner()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=runner)

    with pytest.raises(HelperError, match="stop/recovery required"):
        engine.start(build_plan(config()))

    assert runner.calls == []
    assert json.loads((runtime / "state.json").read_text())["state"] == existing_state


def test_engine_records_and_restores_forwarding_and_owned_resources(tmp_path):
    runtime = tmp_path / "run" / "private"
    forward = tmp_path / "ip_forward"
    forward.write_text("0\n")
    identities = {
        123: ProcessIdentity(123, 10, "hostapd", "/usr/sbin/hostapd"),
        456: ProcessIdentity(456, 11, "dnsmasq", "/usr/sbin/dnsmasq"),
    }
    resources = {"gitm-ap": False, "gainsec_gitm": False}

    class Runner(RecordingRunner):
        def __call__(self, argv):
            super().__call__(argv)
            if tuple(argv) == ("iw", "dev", "gitm-ap", "del"):
                resources["gitm-ap"] = False
            elif argv[0] == "iw":
                resources["gitm-ap"] = True
            elif tuple(argv[:2]) == ("nft", "-f"):
                resources["gainsec_gitm"] = True
            elif tuple(argv[:2]) == ("nft", "delete"):
                resources["gainsec_gitm"] = False

    runner = Runner()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=runner, spawner=lambda argv: FakeChild(456 if argv[0] == "dnsmasq" else 123), identity_provider=lambda pid: identities.get(pid), killer=lambda pid, _sig: identities.pop(pid, None), sleeper=lambda _delay: None, resource_liveness=lambda: dict(resources))
    result = engine.start(build_plan(config()))
    assert result["state"] == "active"
    assert forward.read_text() == "1\n"
    assert json.loads((runtime / "state.json").read_text())["previous_ipv4_forwarding"] == "0"
    event_text = (runtime.parent / "events.log").read_text()
    assert "AP session started" in event_text
    assert "authorized AP session started" not in event_text
    stopped = engine.stop()
    assert stopped["state"] == "inactive"
    assert forward.read_text() == "0\n"
    assert ("nft", "delete", "table", "inet", "gainsec_gitm") in runner.calls
    assert ("iw", "dev", "gitm-ap", "del") in runner.calls
    assert ("ip", "link", "delete", "gitm-ap") not in runner.calls
    assert not (runtime / "hostapd.conf").exists()
    assert not (runtime / "dnsmasq.conf").exists()
    assert not (runtime / "nftables.conf").exists()


def test_start_failure_rolls_back_forwarding_and_owned_state(tmp_path):
    runtime = tmp_path / "run" / "private"
    forward = tmp_path / "ip_forward"
    forward.write_text("0\n")
    dnsmasq = ProcessIdentity(456, 11, "dnsmasq", "/usr/sbin/dnsmasq")
    live = {456: dnsmasq}
    killed = []
    resources = {"gitm-ap": False, "gainsec_gitm": False}

    class FailingRunner(RecordingRunner):
        def __call__(self, argv):
            if tuple(argv) == ("iw", "dev", "gitm-ap", "del"):
                resources["gitm-ap"] = False
            elif argv[0] == "iw":
                resources["gitm-ap"] = True
            elif tuple(argv[:2]) == ("nft", "-f"):
                resources["gainsec_gitm"] = True
            elif tuple(argv[:2]) == ("nft", "delete"):
                resources["gainsec_gitm"] = False
            super().__call__(argv)

    runner = FailingRunner()

    def spawn(argv):
        if argv[0] == "hostapd":
            raise RuntimeError("injected failure")
        return FakeChild(456)

    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=runner, spawner=spawn, identity_provider=lambda pid: live.get(pid), killer=lambda pid, _sig: (killed.append(pid), live.pop(pid, None)), sleeper=lambda _delay: None, resource_liveness=lambda: dict(resources))
    with pytest.raises(HelperError, match="start failed"):
        engine.start(build_plan(config()))
    assert forward.read_text() == "0\n"
    assert not (runtime / "state.json").exists()
    assert killed == [456]
    assert ("nft", "delete", "table", "inet", "gainsec_gitm") in runner.calls


def test_failure_before_ap_creation_does_not_delete_absent_network_resources(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    runner = RecordingRunner(fail_at="iw")
    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=forward,
        runner=runner,
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )

    with pytest.raises(HelperError, match="start failed"):
        engine.start(build_plan(config()))

    assert not any(call[:2] in {("nft", "delete"), ("ip", "link")} for call in runner.calls[1:])
    assert not (runtime / "state.json").exists()


def test_failure_between_resource_steps_removes_only_live_ap_and_confirms_absence(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    live = {"gitm-ap": False, "gainsec_gitm": False}
    probes = []

    class Runner(RecordingRunner):
        def __call__(self, argv):
            super().__call__(argv)
            if tuple(argv) == ("iw", "dev", "gitm-ap", "del"):
                live["gitm-ap"] = False
            elif tuple(argv[:2]) == ("iw", "dev"):
                live["gitm-ap"] = True
            elif tuple(argv[:3]) == ("ip", "address", "add"):
                raise RuntimeError("injected failure")

    def liveness():
        probes.append(dict(live))
        return dict(live)

    runner = Runner()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=runner, resource_liveness=liveness)
    with pytest.raises(HelperError, match="start failed"):
        engine.start(build_plan(config()))

    assert ("iw", "dev", "gitm-ap", "del") in runner.calls
    assert ("ip", "link", "delete", "gitm-ap") not in runner.calls
    assert ("nft", "delete", "table", "inet", "gainsec_gitm") not in runner.calls
    assert probes[-1]["gitm-ap"] is False
    assert not (runtime / "state.json").exists()


def test_cleanup_retry_converges_when_owned_resources_were_removed_externally(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").write_text(json.dumps({
        "state": "cleanup_failed",
        "owner": "gainsec-gitm",
        "previous_ipv4_forwarding": "0",
        "resources": ["gitm-ap", "gainsec_gitm"],
        "processes": {},
        "cleanup_errors": ["prior deletion failed"],
    }))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    runner = RecordingRunner()
    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=forward,
        runner=runner,
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )

    assert engine.stop()["state"] == "inactive"
    assert runner.calls == []
    assert not (runtime / "state.json").exists()


def test_helper_kills_only_persisted_exact_process_identities(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir(parents=True)
    hostapd = ProcessIdentity(123, 10, "hostapd", "/usr/sbin/hostapd")
    (runtime / "state.json").write_text(json.dumps({
        "state": "active",
        "owner": "gainsec-gitm",
        "previous_ipv4_forwarding": "0",
        "resources": ["gitm-ap", "gainsec_gitm"],
        "processes": {"hostapd": hostapd.to_dict()},
    }))
    (tmp_path / "forward").write_text("1\n")
    killed = []
    live = {123: hostapd}
    resources = {"gitm-ap": True, "gainsec_gitm": True}
    runner = RecordingRunner()

    def run(argv):
        runner(argv)
        if tuple(argv[:2]) == ("nft", "delete"):
            resources["gainsec_gitm"] = False
        elif tuple(argv) == ("iw", "dev", "gitm-ap", "del"):
            resources["gitm-ap"] = False

    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=tmp_path / "forward",
        runner=run,
        identity_provider=lambda pid: live.get(pid),
        killer=lambda pid, _sig: (killed.append(pid), live.pop(pid)),
        sleeper=lambda _delay: None,
        resource_liveness=lambda: dict(resources),
    )
    engine.stop()
    assert killed == [123]


def test_helper_fixed_action_dispatch_rejects_unknown_action(tmp_path):
    engine = HelperEngine(runtime_dir=tmp_path / "private", forwarding_path=tmp_path / "forward", runner=RecordingRunner())
    with pytest.raises(HelperError, match="unknown action"):
        engine.dispatch({"action": "run-anything", "argv": ["sh"]})


def test_signal_cleanup_calls_stop(tmp_path):
    engine = HelperEngine(runtime_dir=tmp_path / "private", forwarding_path=tmp_path / "forward", runner=RecordingRunner())
    with pytest.raises(SystemExit):
        engine.handle_signal(15, None)
    assert engine.status()["state"] == "inactive"


def test_default_resource_probe_detects_owned_names_only():
    def probe(argv):
        if tuple(argv) == ("ip", "link", "show", "gitm-ap"):
            return True
        if tuple(argv) == ("nft", "list", "table", "inet", "gainsec_gitm"):
            return False
        raise AssertionError(argv)

    assert probe_owned_resources(probe) == ("AP surface gitm-ap already exists",)


def test_stop_without_valid_ownership_state_is_non_mutating(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "hostapd.pid").write_text("123\n")
    killed = []
    runner = RecordingRunner()
    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=tmp_path / "forward",
        runner=runner,
        killer=lambda pid, _sig: killed.append(pid),
    )
    assert engine.stop()["state"] == "inactive"
    assert runner.calls == []
    assert killed == []


def test_stop_attempts_all_cleanup_when_forward_restore_fails(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").write_text(json.dumps({
        "state": "active",
        "owner": "gainsec-gitm",
        "previous_ipv4_forwarding": "0",
        "resources": ["gitm-ap", "gainsec_gitm"],
    }))
    (runtime / "hostapd.conf").write_text("secret")
    forward_directory = tmp_path / "forward-dir"
    forward_directory.mkdir()
    runner = RecordingRunner()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward_directory, runner=runner)
    with pytest.raises(HelperError, match="cleanup"):
        engine.stop()
    retained = json.loads((runtime / "state.json").read_text())
    assert retained["state"] == "cleanup_failed"
    assert (runtime / "hostapd.conf").exists()
    assert ("nft", "delete", "table", "inet", "gainsec_gitm") in runner.calls


def test_stop_attempts_every_owned_pid_when_one_kill_fails(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    hostapd = ProcessIdentity(123, 10, "hostapd", "/usr/sbin/hostapd")
    dnsmasq = ProcessIdentity(456, 11, "dnsmasq", "/usr/sbin/dnsmasq")
    (runtime / "state.json").write_text(json.dumps({
        "state": "active",
        "owner": "gainsec-gitm",
        "previous_ipv4_forwarding": "0",
        "resources": ["gitm-ap", "gainsec_gitm"],
        "processes": {"hostapd": hostapd.to_dict(), "dnsmasq": dnsmasq.to_dict()},
    }))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    attempted = []
    live = {123: hostapd, 456: dnsmasq}

    def killer(pid, _signal):
        attempted.append(pid)
        if pid == 123:
            raise PermissionError("injected")
        live.pop(pid, None)

    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=forward,
        runner=RecordingRunner(),
        identity_provider=lambda pid: live.get(pid),
        killer=killer,
        sleeper=lambda _delay: None,
    )
    with pytest.raises(HelperError, match="cleanup"):
        engine.stop()
    assert attempted == [123, 456]


def test_existing_unreadable_state_path_is_preserved_without_creating_configs(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").mkdir()
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner())
    with pytest.raises(HelperError, match="state recovery required"):
        engine.start(build_plan(config()))
    assert not (runtime / "hostapd.conf").exists()
    assert not (runtime / "dnsmasq.conf").exists()


def test_stop_rolls_back_even_when_stopping_state_write_fails(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").write_text(json.dumps({
        "state": "active",
        "owner": "gainsec-gitm",
        "previous_ipv4_forwarding": "0",
        "resources": ["gitm-ap", "gainsec_gitm"],
    }))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    runner = RecordingRunner()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=runner)
    engine._save_state = lambda _state: (_ for _ in ()).throw(OSError("injected state failure"))

    with pytest.raises(HelperError, match="cleanup"):
        engine.stop()

    assert forward.read_text() == "0\n"
    assert ("nft", "delete", "table", "inet", "gainsec_gitm") in runner.calls
    assert ("iw", "dev", "gitm-ap", "del") in runner.calls
    assert ("ip", "link", "delete", "gitm-ap") not in runner.calls
    assert (runtime / "state.json").exists()


def test_cleanup_retries_retained_state_and_deletes_it_only_after_success(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state = {"state": "active", "owner": "gainsec-gitm", "previous_ipv4_forwarding": "0", "resources": ["gitm-ap", "gainsec_gitm"], "processes": {}}
    (runtime / "state.json").write_text(json.dumps(state))
    (runtime / "hostapd.conf").write_text("secret")
    bad_forward = tmp_path / "forward-dir"
    bad_forward.mkdir()
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=bad_forward, runner=RecordingRunner(), resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False})
    with pytest.raises(HelperError, match="cleanup"):
        engine.stop()
    good_forward = tmp_path / "forward"
    good_forward.write_text("1\n")
    engine.forwarding_path = good_forward
    assert engine.stop()["state"] == "inactive"
    assert not (runtime / "state.json").exists()
    assert not (runtime / "hostapd.conf").exists()


def test_private_cleanup_failure_retains_atomic_cleanup_state_and_defers_state_unlink(tmp_path, monkeypatch):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state = {"state": "active", "owner": "gainsec-gitm", "previous_ipv4_forwarding": "0", "resources": ["gitm-ap", "gainsec_gitm"], "processes": {}}
    (runtime / "state.json").write_text(json.dumps(state))
    (runtime / "hostapd.conf").write_text("secret")
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    original_unlink = Path.unlink
    unlinks = []

    def failing_unlink(path, *args, **kwargs):
        unlinks.append(path.name)
        if path == runtime / "hostapd.conf":
            raise PermissionError("injected unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(), resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False})
    with pytest.raises(HelperError, match="remove hostapd.conf"):
        engine.stop()

    retained = json.loads((runtime / "state.json").read_text())
    assert retained["state"] == "cleanup_failed"
    assert "remove hostapd.conf" in retained["cleanup_errors"][0]
    assert "state.json" not in unlinks


def test_final_state_unlink_failure_rewrites_recovery_evidence(tmp_path, monkeypatch):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state = {"state": "active", "owner": "gainsec-gitm", "previous_ipv4_forwarding": "0", "resources": ["gitm-ap", "gainsec_gitm"], "processes": {}}
    (runtime / "state.json").write_text(json.dumps(state))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    original_unlink = Path.unlink
    failures = 0

    def fail_state_once(path, *args, **kwargs):
        nonlocal failures
        if path == runtime / "state.json" and failures == 0:
            failures += 1
            raise PermissionError("injected final unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_state_once)
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(), resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False})
    with pytest.raises(HelperError, match="remove state.json"):
        engine.stop()

    retained = json.loads((runtime / "state.json").read_text())
    assert retained["state"] == "cleanup_failed"
    assert "remove state.json" in retained["cleanup_errors"][0]


def test_cleanup_never_signals_reused_or_same_name_spoofed_pid(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    recorded = ProcessIdentity(123, 100, "hostapd", "/usr/sbin/hostapd")
    state = {"state": "active", "owner": "gainsec-gitm", "previous_ipv4_forwarding": "0", "resources": ["gitm-ap", "gainsec_gitm"], "processes": {"hostapd": recorded.to_dict()}}
    (runtime / "state.json").write_text(json.dumps(state))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    killed = []
    for current in (
        ProcessIdentity(123, 101, "hostapd", "/usr/sbin/hostapd"),
        ProcessIdentity(123, 100, "hostapd", "/tmp/hostapd"),
    ):
        engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(), identity_provider=lambda _pid, value=current: value, killer=lambda pid, sig: killed.append((pid, sig)))
        with pytest.raises(HelperError, match="identity"):
            engine.stop()
    assert killed == []
    assert (runtime / "state.json").exists()


def test_start_rejects_immediate_foreground_child_death_and_rolls_back(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")

    live = {11: ProcessIdentity(11, 10, "dnsmasq", "/usr/sbin/dnsmasq")}
    killed = []

    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(), spawner=lambda argv: FakeChild(11 if argv[0] == "dnsmasq" else 12), identity_provider=lambda pid: live.get(pid), killer=lambda pid, _sig: (killed.append(pid), live.pop(pid, None)), sleeper=lambda _delay: None, resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False})
    with pytest.raises(HelperError, match="hostapd.*not live"):
        engine.start(build_plan(config()))
    assert killed == [11]
    assert not (runtime / "state.json").exists()
    assert engine._children == {}
    assert not any(runtime.glob("*.pid"))


def test_start_rejects_child_death_during_stabilization_and_rolls_back(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }
    sleeps = []
    killed = []
    resources = {"gitm-ap": True, "gainsec_gitm": True}

    class Runner(RecordingRunner):
        def __call__(self, argv):
            super().__call__(argv)
            if tuple(argv) == ("iw", "dev", "gitm-ap", "del"):
                resources["gitm-ap"] = False
            elif tuple(argv[:2]) == ("nft", "delete"):
                resources["gainsec_gitm"] = False

    def sleep(delay):
        sleeps.append(delay)
        if delay == 0.5:
            identities.pop(101, None)

    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=forward,
        runner=Runner(),
        spawner=lambda argv: FakeChild(101 if argv[0] == "dnsmasq" else 102),
        identity_provider=lambda pid: identities.get(pid),
        killer=lambda pid, _sig: (killed.append(pid), identities.pop(pid, None)),
        sleeper=sleep,
        stabilization_interval=0.5,
        resource_liveness=lambda: dict(resources),
    )

    with pytest.raises(HelperError, match="dnsmasq identity is not live"):
        engine.start(build_plan(config()))

    assert sleeps == [0.5]
    assert killed == [102]
    assert forward.read_text() == "0\n"
    assert not (runtime / "state.json").exists()
    assert engine._children == {}


def test_status_blocks_when_owned_resource_has_drifted(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    identities = {
        "hostapd": ProcessIdentity(12, 10, "hostapd", "/usr/sbin/hostapd"),
        "dnsmasq": ProcessIdentity(11, 10, "dnsmasq", "/usr/sbin/dnsmasq"),
    }
    state = {"state": "active", "owner": "gainsec-gitm", "previous_ipv4_forwarding": "0", "resources": ["gitm-ap", "gainsec_gitm"], "processes": {name: identity.to_dict() for name, identity in identities.items()}}
    (runtime / "state.json").write_text(json.dumps(state))
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=tmp_path / "forward", runner=RecordingRunner(), identity_provider=lambda pid: identities["hostapd"] if pid == 12 else identities["dnsmasq"], resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": True})
    result = engine.status()
    assert result["ok"] is False
    assert result["state"] == "blocked"
    assert "gitm-ap" in result["errors"][0]


def test_serving_boundary_times_out_partial_request_without_newline(tmp_path):
    server, client = socket.socketpair()
    try:
        client.sendall(b'{"action":')
        engine = HelperEngine(runtime_dir=tmp_path / "private", forwarding_path=tmp_path / "forward", runner=RecordingRunner())
        _handle_connection(server, engine, timeout=0.01)
        response = json.loads(client.recv(4096))
        assert response["ok"] is False
        assert "timed out" in response["error"]
    finally:
        server.close()
        client.close()


class FakeChild:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -signal.SIGTERM

    def kill(self):
        self.returncode = -signal.SIGKILL

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["fake-child"], timeout)
        return self.returncode


def test_foreground_children_are_spawned_directly_and_exact_identity_is_persisted(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    spawned = []
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }

    def spawner(argv):
        spawned.append(tuple(argv))
        return FakeChild(100 + len(spawned))

    engine = HelperEngine(
        runtime_dir=runtime,
        forwarding_path=forward,
        runner=RecordingRunner(),
        spawner=spawner,
        identity_provider=lambda pid: identities.get(pid),
    )
    assert engine.start(build_plan(config()))["state"] == "active"
    persisted = json.loads((runtime / "state.json").read_text())
    assert persisted["processes"] == {
        "dnsmasq": identities[101].to_dict(),
        "hostapd": identities[102].to_dict(),
    }
    assert spawned[0][0] == "dnsmasq"
    assert "--keep-in-foreground" in spawned[0]
    assert spawned[1][0] == "hostapd"
    assert "-B" not in spawned[1]
    assert not any(runtime.glob("*.pid"))


def test_parent_reaps_foreground_children_during_owned_stop(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }
    state = {
        "state": "active", "owner": "gainsec-gitm", "resources": ["gitm-ap", "gainsec_gitm"],
        "previous_ipv4_forwarding": "0",
        "processes": {"dnsmasq": identities[101].to_dict(), "hostapd": identities[102].to_dict()},
    }
    (runtime / "state.json").write_text(json.dumps(state))
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    polled = []

    class ReapableChild(FakeChild):
        def poll(self):
            polled.append(self.pid)
            identities.pop(self.pid, None)
            return 0

    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        identity_provider=lambda pid: identities.get(pid), killer=lambda _pid, _sig: None,
        sleeper=lambda _delay: None,
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )
    engine._children = {101: ReapableChild(101), 102: ReapableChild(102)}
    assert engine.stop()["state"] == "inactive"
    assert polled == [102, 101]


@pytest.mark.parametrize("content", ["{", "[]", "", "{}", '{"owner":"gainsec-gitm"'])
def test_corrupt_state_blocks_start_status_and_stop_without_overwrite(tmp_path, content):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state_path = runtime / "state.json"
    state_path.write_text(content)
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner())

    assert engine._load_state().kind.name == "CORRUPT"
    with pytest.raises(HelperError, match="recovery required"):
        engine.start(build_plan(config()))
    assert engine.status()["state"] == "blocked"
    with pytest.raises(HelperError, match="recovery required"):
        engine.stop()
    assert state_path.read_text() == content


def test_unreadable_state_blocks_without_overwrite(tmp_path, monkeypatch):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state_path = runtime / "state.json"
    state_path.write_text("preserve-me")
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    original = Path.read_text

    def denied(path, *args, **kwargs):
        if path == state_path:
            raise PermissionError("injected")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner())
    assert engine.status()["state"] == "blocked"
    with pytest.raises(HelperError, match="recovery required"):
        engine.stop()
    assert state_path.read_bytes() == b"preserve-me"


def test_foreign_state_is_distinct_and_non_mutating(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    foreign = json.dumps({"owner": "someone-else", "state": "active"})
    (runtime / "state.json").write_text(foreign)
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner())
    assert engine._load_state().kind.name == "FOREIGN"
    assert engine.status()["state"] == "blocked"
    with pytest.raises(HelperError, match="foreign"):
        engine.stop()
    assert (runtime / "state.json").read_text() == foreign


def test_signal_mask_covers_spawn_identity_and_atomic_identity_save(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    events = []
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }

    def mask(how, signals):
        events.append((how, frozenset(signals)))
        return frozenset()

    def spawner(argv):
        events.append(("spawn", argv[0]))
        return FakeChild(101 if argv[0] == "dnsmasq" else 102)

    def hook(point, name):
        events.append((point, name))

    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        spawner=spawner, identity_provider=lambda pid: identities[pid], signal_masker=mask,
        transition_hook=hook,
    )
    engine.start(build_plan(config()))
    blocks = [index for index, event in enumerate(events) if event[0] == signal.SIG_BLOCK]
    restores = [index for index, event in enumerate(events) if event[0] == signal.SIG_SETMASK]
    spawns = [index for index, event in enumerate(events) if event[0] == "spawn"]
    identity_saves = [index for index, event in enumerate(events) if event[0] == "identity_saved"]
    assert len(blocks) == len(restores) == len(spawns) == 2
    assert all(block < spawn < saved < restore for block, spawn, saved, restore in zip(blocks, spawns, identity_saves, restores))


@pytest.mark.parametrize("boundary", ["launch_intent_saved", "child_spawned", "identity_captured", "identity_saved", "active_saved"])
def test_interruption_at_every_launch_boundary_fails_closed(tmp_path, boundary):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }
    killed = []

    def hook(point, _name):
        if point == boundary:
            raise RuntimeError("injected interruption")

    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        spawner=lambda argv: FakeChild(101 if argv[0] == "dnsmasq" else 102), identity_provider=lambda pid: identities.get(pid),
        killer=lambda pid, _sig: (killed.append(pid), identities.pop(pid, None)),
        transition_hook=hook, sleeper=lambda _delay: None,
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )
    with pytest.raises(HelperError, match="start failed"):
        engine.start(build_plan(config()))
    if boundary == "identity_saved":
        assert killed == [101]
    elif boundary == "active_saved":
        assert killed == [102, 101]
    else:
        assert killed == []
    if boundary in {"child_spawned", "identity_captured"}:
        assert not (runtime / "state.json").exists()
        assert engine._children == {}


def test_identity_state_save_failure_never_makes_unpersisted_identity_signalable(tmp_path):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    identity = ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq")
    killed = []
    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        spawner=lambda _argv: FakeChild(101), identity_provider=lambda _pid: identity,
        killer=lambda pid, sig: killed.append((pid, sig)), sleeper=lambda _delay: None,
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )
    original_save = engine._save_state

    def fail_identity_save(state):
        if state.get("processes"):
            raise OSError("injected identity save failure")
        original_save(state)

    engine._save_state = fail_identity_save
    with pytest.raises(HelperError, match="identity save failure"):
        engine.start(build_plan(config()))
    assert killed == []


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("boundary", ["launch_intent_saved", "child_spawned", "identity_captured", "identity_saved", "active_saved"])
def test_signals_at_every_launch_boundary_never_target_unproven_identity(tmp_path, boundary, signum):
    runtime = tmp_path / "private"
    forward = tmp_path / "forward"
    forward.write_text("0\n")
    identities = {
        101: ProcessIdentity(101, 1001, "dnsmasq", "/usr/sbin/dnsmasq"),
        102: ProcessIdentity(102, 1002, "hostapd", "/usr/sbin/hostapd"),
    }
    killed = []
    pending = [False]
    engine = None

    def masker(how, _signals):
        if how == signal.SIG_SETMASK and pending[0]:
            pending[0] = False
            assert engine is not None
            engine.handle_signal(signum, None)
        return frozenset()

    def hook(point, _name):
        if point != boundary:
            return
        assert engine is not None
        if point in {"launch_intent_saved", "active_saved"}:
            engine.handle_signal(signum, None)
        else:
            pending[0] = True

    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        spawner=lambda argv: FakeChild(101 if argv[0] == "dnsmasq" else 102),
        identity_provider=lambda pid: identities.get(pid),
        killer=lambda pid, _sig: (killed.append(pid), identities.pop(pid, None)),
        signal_masker=masker, transition_hook=hook, sleeper=lambda _delay: None,
        resource_liveness=lambda: {"gitm-ap": True, "gainsec_gitm": True},
    )
    with pytest.raises(SystemExit, match=str(128 + int(signum))):
        engine.start(build_plan(config()))
    if boundary in {"child_spawned", "identity_captured", "identity_saved"}:
        assert killed == [101]
    elif boundary == "active_saved":
        assert killed == [102, 101]
    else:
        assert killed == []


def test_restart_never_recovers_launch_intent_from_pid_file_or_reused_pid(tmp_path):
    runtime = tmp_path / "private"
    runtime.mkdir()
    (runtime / "state.json").write_text(json.dumps({
        "state": "cleanup_failed", "owner": "gainsec-gitm",
        "resources": ["gitm-ap", "gainsec_gitm"], "previous_ipv4_forwarding": "0",
        "launches": {"dnsmasq": {"status": "intent", "argv": ["dnsmasq", "--keep-in-foreground"]}},
        "cleanup_errors": ["dnsmasq identity was not persisted"],
    }))
    (runtime / "dnsmasq.pid").write_text("88\n")
    forward = tmp_path / "forward"
    forward.write_text("1\n")
    killed = []
    reused = ProcessIdentity(88, 999, "dnsmasq", "/usr/sbin/dnsmasq")
    engine = HelperEngine(
        runtime_dir=runtime, forwarding_path=forward, runner=RecordingRunner(),
        identity_provider=lambda _pid: reused, killer=lambda pid, sig: killed.append((pid, sig)),
        resource_liveness=lambda: {"gitm-ap": False, "gainsec_gitm": False},
    )
    with pytest.raises(HelperError, match="identity"):
        engine.stop()
    assert killed == []
    assert (runtime / "state.json").exists()


def test_state_load_distinguishes_absent_and_valid_owned(tmp_path):
    runtime = tmp_path / "private"
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=tmp_path / "forward", runner=RecordingRunner())
    assert engine._load_state().kind.name == "ABSENT"
    runtime.mkdir()
    owned = {
        "state": "active", "owner": "gainsec-gitm",
        "resources": ["gitm-ap", "gainsec_gitm"], "processes": {},
        "previous_ipv4_forwarding": "0",
    }
    (runtime / "state.json").write_text(json.dumps(owned))
    loaded = engine._load_state()
    assert loaded.kind.name == "VALID_OWNED"
    assert loaded.state == owned


@pytest.mark.parametrize("bad_field", [
    {"processes": "invalid"},
    {"processes": {"dnsmasq": {"pid": 12}}},
    {"launches": {"dnsmasq": {"status": "intent", "argv": "dnsmasq"}}},
    {"previous_ipv4_forwarding": "invalid"},
])
def test_malformed_package_owned_state_is_corrupt_and_never_cleaned(tmp_path, bad_field):
    runtime = tmp_path / "private"
    runtime.mkdir()
    state = {
        "state": "active", "owner": "gainsec-gitm",
        "resources": ["gitm-ap", "gainsec_gitm"], "processes": {},
        "previous_ipv4_forwarding": "0",
    }
    state.update(bad_field)
    original = json.dumps(state, sort_keys=True)
    (runtime / "state.json").write_text(original)
    engine = HelperEngine(runtime_dir=runtime, forwarding_path=tmp_path / "forward", runner=RecordingRunner())
    assert engine._load_state().kind.name == "CORRUPT"
    with pytest.raises(HelperError, match="recovery required"):
        engine.stop()
    assert (runtime / "state.json").read_text() == original


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signal masks required")
def test_production_spawner_unblocks_termination_signals_in_real_child():
    termination_signals = {signal.SIGTERM, signal.SIGINT}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, termination_signals)
    child = None
    try:
        child = _spawn((sys.executable, "-c", "import time; time.sleep(30)"))
        assert termination_signals <= signal.pthread_sigmask(signal.SIG_BLOCK, set())
        child.terminate()
        assert child.wait(timeout=2) == -signal.SIGTERM
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask


def _launch_failure_engine(tmp_path, child, identity_provider, transition_hook=None):
    runtime = tmp_path / "private"
    runtime.mkdir()
    return HelperEngine(
        runtime_dir=runtime,
        forwarding_path=tmp_path / "forward",
        runner=RecordingRunner(),
        spawner=lambda _argv: child,
        identity_provider=identity_provider,
        transition_hook=transition_hook,
        sleeper=lambda _delay: None,
        wait_attempts=1,
        child_cleanup_timeout=0.01,
    )


def test_identity_provider_failure_terminates_reaps_and_forgets_direct_child(tmp_path):
    child = FakeChild(6101)
    engine = _launch_failure_engine(
        tmp_path, child,
        lambda _pid: (_ for _ in ()).throw(OSError("identity probe failed")),
    )

    with pytest.raises(OSError, match="identity probe failed"):
        engine._launch_process("dnsmasq", ("dnsmasq", "--keep-in-foreground"), {})

    assert child.returncode == -signal.SIGTERM
    assert engine._children == {}


def test_identity_state_save_failure_terminates_reaps_and_forgets_direct_child(tmp_path):
    child = FakeChild(6102)
    identity = ProcessIdentity(child.pid, 22, "dnsmasq", "/usr/sbin/dnsmasq")
    engine = _launch_failure_engine(tmp_path, child, lambda _pid: identity)
    real_save = engine._save_state
    saves = 0

    def fail_second_save(state):
        nonlocal saves
        saves += 1
        if saves == 2:
            raise OSError("identity state save failed")
        real_save(state)

    engine._save_state = fail_second_save
    with pytest.raises(OSError, match="identity state save failed"):
        engine._launch_process("dnsmasq", ("dnsmasq", "--keep-in-foreground"), {})

    assert child.returncode == -signal.SIGTERM
    assert engine._children == {}


@pytest.mark.parametrize("failure_point", ["child_spawned", "identity_captured", "identity_saved"])
def test_transition_hook_failure_terminates_reaps_and_forgets_direct_child(tmp_path, failure_point):
    child = FakeChild(6103)
    identity = ProcessIdentity(child.pid, 23, "dnsmasq", "/usr/sbin/dnsmasq")

    def hook(point, _name):
        if point == failure_point:
            raise RuntimeError(f"hook failed at {point}")

    engine = _launch_failure_engine(tmp_path, child, lambda _pid: identity, hook)
    with pytest.raises(RuntimeError, match="hook failed"):
        engine._launch_process("dnsmasq", ("dnsmasq", "--keep-in-foreground"), {})

    assert child.returncode == -signal.SIGTERM
    assert engine._children == {}


def test_sigterm_ignoring_real_child_is_killed_reaped_and_not_left_live(tmp_path):
    marker = tmp_path / "ready"
    spawned = []

    def spawner(argv):
        child = _spawn(argv)
        spawned.append(child)
        return child

    def no_identity(_pid):
        for _attempt in range(200):
            if marker.exists():
                break
            __import__("time").sleep(0.01)
        assert marker.exists(), "child did not install its SIGTERM handler"
        return None

    engine = HelperEngine(
        runtime_dir=tmp_path / "private",
        forwarding_path=tmp_path / "forward",
        runner=RecordingRunner(),
        spawner=spawner,
        identity_provider=no_identity,
        sleeper=lambda _delay: None,
        wait_attempts=1,
        child_cleanup_timeout=0.05,
    )
    (tmp_path / "private").mkdir()
    script = (
        "import pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(marker)!r}).write_text('ready'); "
        "time.sleep(30)"
    )

    with pytest.raises(HelperError, match="not live"):
        engine._launch_process("not-the-python-name", (sys.executable, "-c", script), {})

    child = spawned[0]
    assert child.returncode == -signal.SIGKILL
    assert child.poll() is not None
    assert engine._children == {}
    with pytest.raises(ProcessLookupError):
        os.kill(child.pid, 0)


def test_unreapable_direct_child_failure_is_fatal_and_child_is_forgotten(tmp_path):
    class UnreapableChild(FakeChild):
        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(["stuck-child"], timeout)

    child = UnreapableChild(6104)
    engine = _launch_failure_engine(tmp_path, child, lambda _pid: None)

    with pytest.raises(SystemExit, match="cannot prove direct child exit"):
        engine._launch_process("dnsmasq", ("dnsmasq", "--keep-in-foreground"), {})

    assert engine._children == {}


@pytest.mark.parametrize("fail_after_spawn", [False, True])
def test_parent_signal_mask_is_restored_exactly_on_launch_failures(tmp_path, fail_after_spawn):
    prior_mask = frozenset({signal.SIGUSR1})
    calls = []
    child = FakeChild(6105)

    def masker(how, signals):
        calls.append((how, frozenset(signals)))
        return prior_mask

    def spawner(_argv):
        if not fail_after_spawn:
            raise OSError("spawn failed")
        return child

    engine = HelperEngine(
        runtime_dir=tmp_path / "private",
        forwarding_path=tmp_path / "forward",
        runner=RecordingRunner(),
        spawner=spawner,
        identity_provider=lambda _pid: None,
        sleeper=lambda _delay: None,
        wait_attempts=1,
        signal_masker=masker,
        child_cleanup_timeout=0.01,
    )
    (tmp_path / "private").mkdir()

    with pytest.raises((OSError, HelperError)):
        engine._launch_process("dnsmasq", ("dnsmasq", "--keep-in-foreground"), {})

    assert calls[0] == (signal.SIG_BLOCK, frozenset({signal.SIGTERM, signal.SIGINT}))
    assert calls[-1] == (signal.SIG_SETMASK, prior_mask)
