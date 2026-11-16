import json
import os
from pathlib import Path
import subprocess
import sys

import pygame

from gitm.backends.sim import SimBackend
from gitm.cli import _run_gui, _stop_owned_session, main
from gitm.controller import Controller
from gitm.model import AppState


def test_status_preflight_and_render_plan_use_simulator(capsys):
    assert main(["status", "--backend", "sim"]) == 0
    assert json.loads(capsys.readouterr().out)["backend"] == "sim"
    assert main(["preflight", "--backend", "sim"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert main(["render-plan", "--backend", "sim"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["nft_table"] == "gainsec_gitm"
    assert plan["tls_interception_enabled"] is False


def test_gui_screenshot_mode_writes_selected_demo_state(tmp_path):
    target = tmp_path / "active.png"
    assert main(["gui", "--backend", "sim", "--screenshot", str(target), "--demo-state", "ACTIVE"]) == 0
    assert pygame.image.load(target).get_size() == (320, 170)


def test_system_backend_failure_is_not_replaced_by_simulator(capsys):
    assert main(["preflight", "--backend", "system"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    assert "backend" not in output or output.get("backend") != "sim"


def test_python_m_gitm_delegates_to_cli(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    result = subprocess.run(
        [sys.executable, "-m", "gitm", "status", "--backend", "sim"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert json.loads(result.stdout)["backend"] == "sim"


def test_gui_initial_frame_does_not_run_preflight(monkeypatch):
    class Backend(SimBackend):
        def __init__(self):
            super().__init__()
            self.preflight_calls = 0

        def preflight(self):
            self.preflight_calls += 1
            return super().preflight()

    backend = Backend()
    monkeypatch.setattr("gitm.cli.select_backend", lambda _name: backend)
    monkeypatch.setattr(pygame.event, "get", lambda: [pygame.event.Event(pygame.QUIT)])
    assert _run_gui("sim", None, "PREFLIGHT") == 0
    assert backend.preflight_calls == 0


def test_ui_finalizer_stops_backend_owned_active_session():
    backend = SimBackend()
    controller = Controller(backend)
    controller.preflight()
    controller.set_authorized(True)
    controller.start()
    assert backend.status()["state"] == "active"
    _stop_owned_session(controller)
    assert backend.status()["state"] == "inactive"


def test_ui_finalizer_attempts_stop_even_when_status_probe_fails():
    class Backend(SimBackend):
        def __init__(self):
            super().__init__()
            self.stop_calls = 0

        def status(self):
            raise RuntimeError("injected status failure")

        def stop(self):
            self.stop_calls += 1
            return super().stop()

    backend = Backend()
    controller = Controller(backend)
    controller.state = AppState.ACTIVE
    _stop_owned_session(controller)
    assert backend.stop_calls == 1
