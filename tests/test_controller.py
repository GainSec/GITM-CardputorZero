import itertools

import pytest

from gitm.backends.base import BackendUnavailable
from gitm.backends.sim import SimBackend
from gitm.controller import Controller, generate_session_config
from gitm.model import AppState
from gitm.model import InterfaceDiscovery
from ipaddress import ip_network


def test_session_credentials_are_randomized_and_valid():
    values = [generate_session_config(SimBackend()) for _ in range(8)]
    assert len({item.ssid for item in values}) == len(values)
    assert len({item.passphrase for item in values}) == len(values)
    assert all(item.ssid.startswith("GITM-C0-") for item in values)
    assert all(8 <= len(item.passphrase) <= 63 for item in values)


def test_preflight_success_moves_to_review_and_exposes_evidence():
    controller = Controller(SimBackend())
    assert controller.state is AppState.PREFLIGHT
    controller.preflight()
    assert controller.state is AppState.REVIEW
    assert controller.config.ap_interface == "wlan1"
    assert controller.config.wan_interface == "enp2s0"


def test_authorization_acknowledgement_is_required_before_start():
    controller = Controller(SimBackend())
    controller.preflight()
    with pytest.raises(PermissionError, match="authorized devices"):
        controller.start()
    assert controller.state is AppState.REVIEW


def test_controller_start_and_stop_transitions():
    controller = Controller(SimBackend())
    controller.preflight()
    controller.set_authorized(True)
    controller.start()
    assert controller.state is AppState.ACTIVE
    controller.stop()
    assert controller.state is AppState.REVIEW


def test_start_and_stop_expose_transition_state_before_backend_call():
    controller = Controller(SimBackend())
    controller.preflight()
    controller.set_authorized(True)
    seen = []
    controller.start(on_transition=lambda state: seen.append(state))
    controller.stop(on_transition=lambda state: seen.append(state))
    assert seen == [AppState.STARTING, AppState.STOPPING]


class BrokenBackend(SimBackend):
    def start(self, plan):
        raise BackendUnavailable("helper denied request")


def test_backend_error_becomes_concise_error_state():
    controller = Controller(BrokenBackend())
    controller.preflight()
    controller.set_authorized(True)
    controller.start()
    assert controller.state is AppState.ERROR
    assert controller.error == "helper denied request"


def test_back_transitions_do_not_stop_an_active_session():
    controller = Controller(SimBackend())
    controller.preflight()
    controller.back()
    assert controller.state is AppState.PREFLIGHT
    controller.preflight()
    controller.set_authorized(True)
    controller.start()
    controller.back()
    assert controller.state is AppState.ACTIVE


class OverlapBackend(SimBackend):
    def discovery(self):
        return InterfaceDiscovery(
            ap_interfaces=("wlan1",),
            wan_interfaces=("enp2s0",),
            evidence={},
            existing_networks=(ip_network("192.168.77.128/25"),),
        )


def test_controller_fails_closed_on_discovered_subnet_overlap():
    controller = Controller(OverlapBackend())
    controller.preflight()
    assert controller.state is AppState.ERROR
    assert "overlaps" in controller.error
