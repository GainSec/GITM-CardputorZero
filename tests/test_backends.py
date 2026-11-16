from pathlib import Path

import pytest

from gitm.backends.base import BackendUnavailable
from gitm.backends.select import select_backend
from gitm.backends.sim import SimBackend
from gitm.backends.system import SystemBackend
import gitm.backends.system as system_backend
from gitm.model import NetworkConfig
from gitm.plan import build_plan


def test_simulator_is_deterministic_and_complete():
    first = SimBackend(seed=42)
    second = SimBackend(seed=42)
    assert first.preflight().to_dict() == second.preflight().to_dict()
    assert first.preflight().ok
    assert first.discovery().ap_interfaces == ("wlan1",)
    assert first.discovery().wan_interfaces == ("enp2s0",)


def test_auto_uses_simulator_off_device():
    assert isinstance(select_backend("auto", is_device=False), SimBackend)


def test_auto_never_silently_uses_simulator_on_device():
    assert isinstance(select_backend("auto", is_device=True), SystemBackend)


def test_system_preflight_fails_closed_when_helper_or_tools_missing(tmp_path):
    backend = SystemBackend(
        helper_socket=tmp_path / "missing.sock",
        which=lambda _name: None,
        runner=lambda _argv: (_ for _ in ()).throw(AssertionError("runner must not execute")),
    )
    report = backend.preflight()
    assert not report.ok
    assert "privileged helper unavailable" in report.errors
    assert any(error.startswith("missing required tool:") for error in report.errors)


def test_system_preflight_requires_networkmanager_cli(tmp_path):
    helper = tmp_path / "helper.sock"
    helper.touch()
    backend = SystemBackend(
        helper_socket=helper,
        which=lambda name: None if name == "nmcli" else f"/usr/bin/{name}",
        runner=lambda _argv: (_ for _ in ()).throw(AssertionError("runner must not execute")),
    )
    report = backend.preflight()
    assert report.ok is False
    assert report.errors == ("missing required tool: nmcli",)


def test_system_start_refuses_to_run_after_failed_preflight(tmp_path):
    backend = SystemBackend(helper_socket=tmp_path / "missing.sock", which=lambda _name: None)
    with pytest.raises(BackendUnavailable, match="preflight"):
        backend.start(None)


def test_explicit_sim_and_system_selection():
    assert isinstance(select_backend("sim"), SimBackend)
    assert isinstance(select_backend("system"), SystemBackend)
    with pytest.raises(ValueError, match="backend"):
        select_backend("unknown")


def test_source_has_no_unsafe_process_apis():
    source_root = Path(__file__).parents[1] / "src" / "gitm"
    combined = "\n".join(path.read_text() for path in source_root.rglob("*.py"))
    for forbidden in ("shell=True", "os.system(", "eval(", "exec(", "killall", "iptables -F", "flush ruleset"):
        assert forbidden not in combined


class Result:
    def __init__(self, stdout):
        self.stdout = stdout


def test_system_preflight_requires_live_ap_and_carrier_evidence(tmp_path):
    helper = tmp_path / "helper.sock"
    helper.touch()
    outputs = {
        ("ip", "-d", "-json", "link", "show"): "[]",
        ("ip", "-json", "address", "show"): "[]",
        ("iw", "list"): "Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n",
        ("iw", "dev"): "phy#0\n\tInterface wlan1\n\t\ttype managed\n",
    }
    backend = SystemBackend(
        helper_socket=helper,
        which=lambda name: f"/usr/bin/{name}",
        runner=lambda argv: Result(outputs[tuple(argv)]),
    )
    report = backend.preflight()
    assert not report.ok
    assert "no AP-capable wireless interface found" in report.errors
    assert "no linked wired Ethernet WAN found" in report.errors


def valid_system_outputs(addresses="[]"):
    return {
        ("ip", "-d", "-json", "link", "show"): IP_LINK,
        ("ip", "-json", "address", "show"): addresses,
        ("iw", "list"): IW_LIST,
        ("iw", "dev"): IW_DEV,
    }


IP_LINK = '[{"ifname":"end0","flags":["UP","LOWER_UP"],"operstate":"UP","link_type":"ether"},{"ifname":"mlan0","flags":["UP"],"operstate":"DOWN","link_type":"ether"}]'
IW_LIST = 'Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n'
IW_DEV = 'phy#0\n\tInterface mlan0\n\t\ttype managed\n'


def test_system_preflight_proves_helper_is_reachable(tmp_path):
    helper = tmp_path / "helper.sock"
    helper.touch()
    outputs = valid_system_outputs()
    backend = SystemBackend(helper_socket=helper, which=lambda name: f"/usr/bin/{name}", runner=lambda argv: Result(outputs[tuple(argv)]), physical_detector=lambda name: name == "end0")
    backend._request = lambda _payload: (_ for _ in ()).throw(BackendUnavailable("permission denied"))
    report = backend.preflight()
    assert not report.ok
    assert "privileged helper unavailable" in report.errors[0]


def test_system_preflight_rejects_default_subnet_overlap(tmp_path):
    helper = tmp_path / "helper.sock"
    helper.touch()
    addresses = '[{"ifname":"end0","addr_info":[{"family":"inet","local":"192.168.77.9","prefixlen":24,"scope":"global"}]}]'
    outputs = valid_system_outputs(addresses)
    backend = SystemBackend(helper_socket=helper, which=lambda name: f"/usr/bin/{name}", runner=lambda argv: Result(outputs[tuple(argv)]), physical_detector=lambda name: name == "end0")
    backend._request = lambda _payload: {"ok": True, "state": "inactive"}
    report = backend.preflight()
    assert not report.ok
    assert "overlaps" in report.errors[0]


def test_system_default_tool_lookup_uses_trusted_system_path(tmp_path, monkeypatch):
    calls = []

    def fake_which(name, path=None):
        calls.append((name, path))
        return f"/usr/sbin/{name}"

    monkeypatch.setattr(system_backend.shutil, "which", fake_which)
    backend = SystemBackend(helper_socket=tmp_path / "missing.sock")
    backend._basic_preflight()
    assert calls
    assert {path for _name, path in calls} == {"/usr/sbin:/usr/bin:/sbin:/bin"}


def test_system_default_runner_executes_with_trusted_system_path(monkeypatch):
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return Result("")

    monkeypatch.setattr(system_backend.subprocess, "run", fake_run)
    system_backend._default_runner(("ip", "-d", "-json", "link", "show"))
    assert observed["argv"] == ["ip", "-d", "-json", "link", "show"]
    assert observed["kwargs"]["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert "shell" not in observed["kwargs"]


def test_system_preflight_rejects_an_existing_owned_session(tmp_path):
    helper = tmp_path / "helper.sock"
    helper.touch()
    outputs = valid_system_outputs()
    backend = SystemBackend(
        helper_socket=helper,
        which=lambda name: f"/usr/bin/{name}",
        runner=lambda argv: Result(outputs[tuple(argv)]),
        physical_detector=lambda name: name == "end0",
    )
    backend._request = lambda _payload: {"ok": True, "state": "active"}
    report = backend.preflight()
    assert not report.ok
    assert "occupied" in report.errors[0]


def _plan(ap="mlan0", wan="end0", subnet="192.168.77.0/24"):
    return build_plan(NetworkConfig("GITM-TEST", "safe-pass-123", "US", subnet, "1.1.1.1", ap, wan))


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        (_plan(ap="wlan9"), "AP interface"),
        (_plan(wan="eth9"), "WAN interface"),
        (_plan(subnet="10.23.0.0/16"), "overlaps"),
    ],
)
def test_system_start_binds_fresh_preflight_to_exact_plan(tmp_path, plan, message):
    helper = tmp_path / "helper.sock"
    helper.touch()
    addresses = '[{"ifname":"end0","addr_info":[{"family":"inet","local":"10.23.4.8","prefixlen":16,"scope":"global"}]}]'
    outputs = valid_system_outputs(addresses)
    backend = SystemBackend(
        helper_socket=helper,
        which=lambda name: f"/usr/bin/{name}",
        runner=lambda argv: Result(outputs[tuple(argv)]),
        physical_detector=lambda name: name == "end0",
    )
    backend._request = lambda _payload: {"ok": True, "state": "inactive"}
    with pytest.raises(BackendUnavailable, match=message):
        backend.start(plan)
