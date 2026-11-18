"""Pure application state machine."""

import secrets

from .backends.base import Backend, BackendUnavailable
from .model import AppState, NetworkConfig
from .plan import OperationPlan, build_plan
from .validation import validate_config


def generate_session_config(backend: Backend) -> NetworkConfig:
    discovery = backend.discovery()
    if not discovery.ap_interfaces:
        raise BackendUnavailable("no AP-capable wireless interface found")
    if not discovery.wan_interfaces:
        raise BackendUnavailable("no linked wired Ethernet WAN found")
    config = NetworkConfig(
        ssid=f"GITM-C0-{secrets.token_hex(3).upper()}",
        passphrase=secrets.token_urlsafe(12),
        country="US",
        subnet="192.168.77.0/24",
        resolver="1.1.1.1",
        ap_interface=discovery.ap_interfaces[0],
        wan_interface=discovery.wan_interfaces[0],
        lease_events=True,
    )
    return validate_config(config, discovery.existing_networks)


class Controller:
    def __init__(self, backend: Backend):
        self.backend = backend
        self.state = AppState.PREFLIGHT
        self.config: NetworkConfig | None = None
        self.plan: OperationPlan | None = None
        self.authorized = False
        self.error = ""

    def preflight(self) -> None:
        self.error = ""
        report = self.backend.preflight()
        if not report.ok:
            self.error = report.errors[0] if report.errors else "preflight failed"
            self.state = AppState.ERROR
            return
        try:
            self.config = self.config or generate_session_config(self.backend)
            self.plan = build_plan(self.config)
        except (BackendUnavailable, ValueError) as exc:
            self.error = str(exc)
            self.state = AppState.ERROR
            return
        self.state = AppState.REVIEW

    def update_config(self, config: NetworkConfig) -> None:
        if self.state in {AppState.STARTING, AppState.ACTIVE, AppState.STOPPING}:
            raise ValueError("stop session before editing configuration")
        self.config = config
        self.plan = None
        self.authorized = False
        # Retain incomplete edits so a certificate/key pair can be entered one field at a time.
        self.plan = build_plan(config)

    def set_authorized(self, acknowledged: bool) -> None:
        self.authorized = acknowledged

    def start(self, on_transition=None) -> None:
        if self.state is not AppState.REVIEW or self.plan is None:
            raise RuntimeError("start is available only after successful review")
        if not self.authorized:
            raise PermissionError("acknowledge authorized devices before start")
        self.state = AppState.STARTING
        if on_transition is not None:
            on_transition(self.state)
        try:
            response = self.backend.start(self.plan)
            if not response.get("ok"):
                raise BackendUnavailable(str(response.get("error", "start failed")))
        except (BackendUnavailable, OSError, ValueError) as exc:
            self.error = str(exc)[:120]
            self.state = AppState.ERROR
            return
        self.state = AppState.ACTIVE

    def stop(self, on_transition=None) -> None:
        if self.state is not AppState.ACTIVE:
            return
        self.state = AppState.STOPPING
        if on_transition is not None:
            on_transition(self.state)
        try:
            response = self.backend.stop()
            if not response.get("ok"):
                raise BackendUnavailable(str(response.get("error", "stop failed")))
        except (BackendUnavailable, OSError, ValueError) as exc:
            self.error = str(exc)[:120]
            self.state = AppState.ERROR
            return
        self.state = AppState.REVIEW

    def back(self) -> None:
        if self.state in (AppState.REVIEW, AppState.ERROR):
            self.state = AppState.PREFLIGHT
            self.error = ""
