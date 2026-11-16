"""Narrow system backend; state changes are delegated to the owned helper."""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Callable, Sequence

from ..discovery import discover_interfaces
from ..model import InterfaceDiscovery, NetworkConfig
from ..plan import OperationPlan
from ..validation import ValidationError, validate_config
from .base import BackendUnavailable, PreflightReport


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
PhysicalDetector = Callable[[str], bool]
TRUSTED_TOOL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def _default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PATH": TRUSTED_TOOL_PATH}
    return subprocess.run(list(argv), check=True, capture_output=True, text=True, env=environment)


def _trusted_which(name: str) -> str | None:
    return shutil.which(name, path=TRUSTED_TOOL_PATH)


def _physical_device(name: str) -> bool:
    return (Path("/sys/class/net") / name / "device").exists()


class SystemBackend:
    name = "system"
    required_tools = ("ip", "iw", "nmcli", "nft", "hostapd", "dnsmasq")

    def __init__(
        self,
        helper_socket: Path = Path("/run/gainsec-gitm/helper.sock"),
        which: Callable[[str], str | None] | None = None,
        runner: Runner = _default_runner,
        physical_detector: PhysicalDetector = _physical_device,
    ):
        self.helper_socket = helper_socket
        self.which = which or _trusted_which
        self.runner = runner
        self.physical_detector = physical_detector

    def _basic_preflight(self) -> tuple[str, ...]:
        errors = [f"missing required tool: {tool}" for tool in self.required_tools if not self.which(tool)]
        if not self.helper_socket.exists():
            errors.append("privileged helper unavailable")
        return tuple(errors)

    def preflight(self) -> PreflightReport:
        errors = list(self._basic_preflight())
        if errors:
            return PreflightReport(ok=False, errors=tuple(errors))
        try:
            evidence = self.discovery()
        except (BackendUnavailable, subprocess.SubprocessError, OSError, ValueError, json.JSONDecodeError) as exc:
            return PreflightReport(ok=False, errors=(f"interface discovery failed: {exc}",))
        if not evidence.ap_interfaces:
            errors.append("no AP-capable wireless interface found")
        if not evidence.wan_interfaces:
            errors.append("no linked wired Ethernet WAN found")
        if errors:
            return PreflightReport(ok=False, errors=tuple(errors))
        candidate = NetworkConfig(
            ssid="GITM-PREFLIGHT",
            passphrase="preflight-only-123",
            country="US",
            subnet="192.168.77.0/24",
            resolver="1.1.1.1",
            ap_interface=evidence.ap_interfaces[0],
            wan_interface=evidence.wan_interfaces[0],
        )
        try:
            validate_config(candidate, evidence.existing_networks)
        except ValidationError as exc:
            return PreflightReport(ok=False, errors=(str(exc),))
        try:
            helper = self._request({"action": "status"})
        except BackendUnavailable as exc:
            return PreflightReport(ok=False, errors=(f"privileged helper unavailable: {exc}",))
        if not helper.get("ok"):
            detail = helper.get("error") or "; ".join(helper.get("errors", ())) or "helper rejected preflight"
            return PreflightReport(ok=False, errors=(str(detail),))
        helper_state = helper.get("state")
        if helper_state != "inactive":
            return PreflightReport(
                ok=False,
                errors=(f"required resources occupied: helper state is {helper_state or 'unknown'}",),
            )
        return PreflightReport(ok=not errors, errors=tuple(errors))

    def discovery(self) -> InterfaceDiscovery:
        errors = self._basic_preflight()
        if errors:
            raise BackendUnavailable("system preflight failed: " + "; ".join(errors))
        links = self.runner(("ip", "-d", "-json", "link", "show")).stdout
        addresses = self.runner(("ip", "-json", "address", "show")).stdout
        iw_list = self.runner(("iw", "list")).stdout
        iw_dev = self.runner(("iw", "dev")).stdout
        parsed_links = json.loads(links)
        physical = {
            item["ifname"] for item in parsed_links
            if isinstance(item, dict) and isinstance(item.get("ifname"), str)
            and self.physical_detector(item["ifname"])
        }
        return discover_interfaces(links, iw_list, iw_dev, addresses, physical_interfaces=physical)

    def _request(self, payload: dict[str, object]) -> dict[str, object]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5.0)
                client.connect(str(self.helper_socket))
                client.sendall(json.dumps(payload, sort_keys=True).encode() + b"\n")
                data = client.makefile("rb").readline(1_048_576)
        except (OSError, TimeoutError) as exc:
            raise BackendUnavailable(f"privileged helper request failed: {exc}") from exc
        if not data:
            raise BackendUnavailable("privileged helper returned no response")
        try:
            response = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BackendUnavailable(f"privileged helper returned invalid JSON: {exc}") from exc
        if not isinstance(response, dict):
            raise BackendUnavailable("privileged helper returned an invalid response type")
        return response

    def start(self, plan: OperationPlan | None) -> dict[str, object]:
        if plan is None:
            raise BackendUnavailable("system preflight requires a validated operation plan")
        errors = list(self._basic_preflight())
        try:
            evidence = self.discovery()
        except (BackendUnavailable, subprocess.SubprocessError, OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"interface discovery failed: {exc}")
        else:
            if plan.config.ap_interface not in evidence.ap_interfaces:
                errors.append(f"selected AP interface {plan.config.ap_interface} is no longer AP-capable")
            if plan.config.wan_interface not in evidence.wan_interfaces:
                errors.append(f"selected WAN interface {plan.config.wan_interface} is not linked physical Ethernet")
            try:
                validate_config(plan.config, evidence.existing_networks)
            except ValidationError as exc:
                errors.append(str(exc))
        if errors:
            raise BackendUnavailable("system preflight failed: " + "; ".join(errors))
        helper = self._request({"action": "status"})
        if not helper.get("ok") or helper.get("state") != "inactive":
            raise BackendUnavailable("system preflight failed: required resources occupied")
        return self._request({"action": "start", "plan": plan.to_dict()})

    def stop(self) -> dict[str, object]:
        if not self.helper_socket.exists():
            raise BackendUnavailable("privileged helper unavailable")
        return self._request({"action": "stop"})

    def status(self) -> dict[str, object]:
        if not self.helper_socket.exists():
            return {"ok": False, "state": "unavailable", "backend": self.name}
        return self._request({"action": "status"})
