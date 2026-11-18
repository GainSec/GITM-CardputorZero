"""Command-line and APPLaunch entry points."""

import argparse
from dataclasses import replace
import os
import json
from pathlib import Path
import signal
import time

import pygame

from .backends.base import BackendUnavailable
from .backends.select import select_backend
from .certificates import export_material
from .configuration import load_config, save_config, load_ca_material
from .model import NetworkConfig
from .profiles import list_profiles, profile_info, verify_profile
from .validation import validate_config
from .controller import Controller, generate_session_config
from .framebuffer import FramebufferSink, mirror
from .feature_ui import FeatureUI
from .gui import HEIGHT, WIDTH, ViewData, render_state, save_screenshot
from .input import InputMapper, UiAction
from .native_input import EvdevKeyboard
from .model import AppState
from .plan import build_plan


def _backend_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backend", choices=("auto", "sim", "system"), default="auto")


def _config_args(parser):
    parser.add_argument("--config", type=Path)
    for name in ("ssid", "passphrase", "country", "subnet", "resolver", "ap-interface", "wan-interface", "ca-cert", "ca-key", "ca-chain"):
        parser.add_argument("--" + name)
    parser.add_argument("--dump", "--capture", dest="capture", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--strip", "--tls", dest="tls", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--live", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--lease-events", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--capture-mb", type=int)
    parser.add_argument("--emudhra", dest="profile", nargs="?", const="dv-g3b-aaa")


def _configuration(args, backend):
    if args.config and args.config.exists():
        config = load_config(args.config)
    elif args.ap_interface and args.wan_interface:
        import secrets
        config = NetworkConfig("GITM-C0-" + secrets.token_hex(3).upper(), secrets.token_urlsafe(12), "US", "192.168.77.0/24", "1.1.1.1", args.ap_interface, args.wan_interface, lease_events=True)
    elif args.command == "export":
        config = NetworkConfig("GITM-EXPORT", "export-only-unused", "US", "192.168.77.0/24", "1.1.1.1", "wlan1", "end0")
    else:
        config = generate_session_config(backend)
    changes = {name: getattr(args, name) for name in config.__dataclass_fields__ if hasattr(args, name) and getattr(args, name) is not None}
    changes["owner_uid"] = os.getuid()
    if changes.get("profile") or changes.get("ca_cert"):
        changes["tls"] = True
    return validate_config(replace(config, **changes))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gitm", description="GainSec GITM for CardputerZero")
    parser.add_argument("--version", action="version", version="%(prog)s 0.2.1")
    commands = parser.add_subparsers(dest="command", required=True)
    gui = commands.add_parser("gui", help="run the native 320x170 interface")
    _backend_arg(gui)
    _config_args(gui)
    gui.add_argument("--screenshot", type=Path)
    gui.add_argument("--demo-state", choices=tuple(state.value for state in AppState), default="PREFLIGHT")
    for name in ("status", "preflight", "stop", "inspect"):
        command = commands.add_parser(name)
        _backend_arg(command)
        if name == "inspect":
            command.add_argument("--kind", choices=("live", "leases", "tls"), default="live")
            command.add_argument("--limit", type=int, default=20)
    for name in ("render-plan", "configure", "start", "export"):
        command = commands.add_parser(name)
        _backend_arg(command)
        _config_args(command)
        if name == "start":
            command.add_argument("--authorized", action="store_true")
            command.add_argument("--dry-run", action="store_true")
        if name == "export":
            command.add_argument("--output-dir", type=Path, required=True)
            command.add_argument("--android", action="store_true")
            command.add_argument("--burp", action="store_true")
    commands.add_parser("profiles")
    for name in ("profile-info", "verify-profile"):
        command = commands.add_parser(name)
        command.add_argument("profile_name")
    return parser


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _run_gui(backend_name: str, screenshot: Path | None, demo_state: str, initial_config=None) -> int:
    backend = select_backend(backend_name)
    if screenshot is not None:
        surface = render_state(AppState(demo_state), deterministic=True)
        save_screenshot(surface, screenshot)
        return 0
    controller = Controller(backend)
    if initial_config is not None:
        controller.update_config(initial_config)
    feature_ui = FeatureUI(controller)
    sink = FramebufferSink()
    if sink.available:
        os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
    pygame.display.init()
    pygame.font.init()
    screen = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("GainSec GITM")
    mapper = InputMapper()
    keyboard = EvdevKeyboard() if sink.available and pygame.display.get_driver() == "dummy" else None
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
        if feature_ui.page == "overview":
            frame = _controller_frame(controller, sink if sink.available else None)
        else:
            frame = feature_ui.render()
            mirror(frame, sink if sink.available else None)
        screen.blit(frame, (0, 0))
        pygame.display.flip()
    try:
        draw()
        last_refresh = 0.0
        while running:
            if time.monotonic() - last_refresh >= 1.0:
                feature_ui.refresh()
                last_refresh = time.monotonic()
            for event in pygame.event.get() + (keyboard.poll() if keyboard else []):
                mapper.text_entry = feature_ui.editing
                if event.type == pygame.KEYDOWN and event.key == pygame.K_TAB and not feature_ui.editing:
                    feature_ui.turn_page(1)
                    continue
                action = mapper.map_event(event)
                if action is UiAction.QUIT:
                    running = False
                elif action is UiAction.BACK:
                    if feature_ui.editing:
                        feature_ui.editing = False
                    elif feature_ui.page != "overview":
                        feature_ui.page = "overview"
                    else:
                        controller.back()
                elif action is UiAction.TEXT:
                    feature_ui.text(event)
                elif action in {UiAction.LEFT, UiAction.RIGHT} and not feature_ui.editing:
                    feature_ui.turn_page(-1 if action is UiAction.LEFT else 1)
                elif action in {UiAction.UP, UiAction.DOWN} and not feature_ui.editing:
                    feature_ui.move(-1 if action is UiAction.UP else 1)
                elif action is UiAction.SELECT:
                    if feature_ui.page != "overview":
                        feature_ui.select()
                        continue
                    if controller.state is AppState.PREFLIGHT:
                        controller.preflight()
                    elif controller.state is AppState.REVIEW and not controller.authorized:
                        controller.set_authorized(True)
                    elif controller.state is AppState.REVIEW and controller.plan is None:
                        controller.error = "Fix incomplete configuration in SETTINGS"
                        controller.state = AppState.ERROR
                    elif controller.state is AppState.REVIEW:
                        controller.start(on_transition=lambda _state: draw())
                    elif controller.state is AppState.ACTIVE:
                        controller.stop(on_transition=lambda _state: draw())
            draw()
            clock.tick(20)
    finally:
        if keyboard:
            keyboard.close()
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
        capture=bool(config and config.capture),
        live=bool(config and config.live),
        tls=bool(config and config.tls),
        leases=bool(config and config.lease_events),
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
    try:
        if args.command == "profiles":
            _print({"ok": True, "profiles": list_profiles()})
            return 0
        if args.command == "profile-info":
            _print(profile_info(args.profile_name))
            return 0
        if args.command == "verify-profile":
            material = verify_profile(args.profile_name)
            _print({"ok": True, "profile": args.profile_name, "fingerprint": material.fingerprint})
            return 0
        backend = select_backend(args.backend)
        if args.command == "gui":
            initial = _configuration(args, backend) if args.config or any(getattr(args, name, None) is not None for name in NetworkConfig.__dataclass_fields__ if name != "owner_uid") else None
            return _run_gui(args.backend, args.screenshot, args.demo_state, initial)
        if args.command == "status":
            result = backend.status()
        elif args.command == "preflight":
            result = backend.preflight().to_dict()
        elif args.command == "stop":
            result = backend.stop()
        elif args.command == "inspect":
            result = backend.inspect(kind=args.kind, limit=args.limit)
        else:
            config = _configuration(args, backend)
            load_ca_material(config)  # Read-only validation, including every dry-run.
            if args.command == "configure":
                if args.config is None:
                    raise ValueError("configure requires --config destination")
                save_config(config, args.config)
                result = {"ok": True, "config_path": str(args.config)}
            elif args.command == "export":
                material = backend.ca_material(config)
                result = {"ok": True, "paths": export_material(material, args.output_dir, android=args.android, burp=args.burp), "fingerprint": material.fingerprint, "simulated": backend.name == "sim"}
            else:
                plan = build_plan(config)
                if args.command == "render-plan" or args.dry_run:
                    _print(plan.to_dict())
                    return 0
                if not args.authorized:
                    raise ValueError("start requires --authorized for the test devices")
                result = backend.start(plan)
        _print(result)
        return 0 if result.get("ok") else 2
    except (BackendUnavailable, OSError, ValueError, KeyError) as exc:
        _print({"ok": False, "errors": [str(exc)[:300]]})
        return 2
