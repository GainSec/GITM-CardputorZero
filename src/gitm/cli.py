"""Command-line and APPLaunch entry points."""

import argparse
import json
from pathlib import Path
import signal

import pygame

from .backends.base import BackendUnavailable
from .backends.select import select_backend
from .controller import Controller, generate_session_config
from .framebuffer import FramebufferSink
from .gui import HEIGHT, WIDTH, ViewData, render_state, save_screenshot
from .input import InputMapper, UiAction
from .model import AppState
from .plan import build_plan


def _backend_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=("auto", "sim", "system"), default="auto")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gitm", description="GainSec GITM for CardputerZero")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    gui = commands.add_parser("gui", help="run the native 320x170 interface")
    _backend_arg(gui)
    gui.add_argument("--screenshot", type=Path)
    gui.add_argument("--demo-state", choices=tuple(state.value for state in AppState), default="PREFLIGHT")
    for name in ("status", "preflight", "render-plan"):
        command = commands.add_parser(name)
        _backend_arg(command)
    return parser


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _run_gui(backend_name: str, screenshot: Path | None, demo_state: str) -> int:
    backend = select_backend(backend_name)
    if screenshot is not None:
        surface = render_state(AppState(demo_state), deterministic=True)
        save_screenshot(surface, screenshot)
        return 0
    controller = Controller(backend)
    pygame.display.init()
    pygame.font.init()
    screen = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("GainSec GITM")
    mapper = InputMapper()
    sink = FramebufferSink()
    running = True
    clock = pygame.time.Clock()
    previous_handlers = {}

    def request_exit(_signum, _frame):
        nonlocal running
        running = False

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_exit)

    def draw() -> None:
        frame = _controller_frame(controller, sink if sink.available else None)
        screen.blit(frame, (0, 0))
        pygame.display.flip()
    try:
        draw()
        while running:
            for event in pygame.event.get():
                action = mapper.map_event(event)
                if action is UiAction.QUIT:
                    running = False
                elif action is UiAction.BACK:
                    controller.back()
                elif action is UiAction.SELECT:
                    if controller.state is AppState.PREFLIGHT:
                        controller.preflight()
                    elif controller.state is AppState.REVIEW and not controller.authorized:
                        controller.set_authorized(True)
                    elif controller.state is AppState.REVIEW:
                        controller.start(on_transition=lambda _state: draw())
                    elif controller.state is AppState.ACTIVE:
                        controller.stop(on_transition=lambda _state: draw())
            draw()
            clock.tick(20)
    finally:
        _stop_owned_session(controller)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return 0


def _controller_frame(controller: Controller, sink=None):
    config = controller.config
    view = ViewData(
        ap_interface=config.ap_interface if config else "unavailable",
        wan_interface=config.wan_interface if config else "unavailable",
        country=config.country if config else "--",
        subnet=config.subnet if config else "--",
        resolver=config.resolver if config else "--",
        ssid=config.ssid if config else "--",
        passphrase=config.passphrase if config else "--",
        authorized=controller.authorized,
        backend=controller.backend.name,
    )
    return render_state(controller.state, error=controller.error, view=view, sink=sink)


def _stop_owned_session(controller: Controller) -> None:
    must_stop = controller.state in (AppState.STARTING, AppState.ACTIVE, AppState.STOPPING)
    try:
        status = controller.backend.status()
        must_stop = must_stop or status.get("state") in {"starting", "active", "stopping"}
    except Exception:
        pass
    if not must_stop:
        return
    try:
        if controller.state is AppState.ACTIVE:
            controller.stop()
        else:
            controller.backend.stop()
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    backend = select_backend(args.backend)
    if args.command == "gui":
        return _run_gui(args.backend, args.screenshot, args.demo_state)
    if args.command == "status":
        result = backend.status()
        _print(result)
        return 0 if result.get("ok") else 2
    if args.command == "preflight":
        report = backend.preflight()
        _print(report.to_dict())
        return 0 if report.ok else 2
    if args.command == "render-plan":
        report = backend.preflight()
        if not report.ok:
            _print(report.to_dict())
            return 2
        try:
            plan = build_plan(generate_session_config(backend))
        except (BackendUnavailable, ValueError) as exc:
            _print({"ok": False, "errors": [str(exc)]})
            return 2
        _print(plan.to_dict())
        return 0
    return 2
