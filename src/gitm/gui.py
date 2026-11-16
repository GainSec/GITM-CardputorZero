"""Native deterministic 320×170 pygame interface."""

import base64
from dataclasses import dataclass, field
import hashlib
from pathlib import Path

import pygame

from .framebuffer import FrameSink, mirror
from .model import AppState
from . import theme


WIDTH = 320
HEIGHT = 170


STATE_COPY = {
    AppState.PREFLIGHT: ("PREFLIGHT", "CHECK HARDWARE", "AP + ETHERNET EVIDENCE"),
    AppState.REVIEW: ("REVIEW", "AUTHORIZED DEVICES ONLY", "C TO ACKNOWLEDGE + START"),
    AppState.STARTING: ("STARTING", "BUILDING PRIVATE AP", "OWNED SERVICES ONLY"),
    AppState.ACTIVE: ("ACTIVE", "AP ONLINE", "C TO STOP"),
    AppState.STOPPING: ("STOPPING", "RESTORING SYSTEM STATE", "CLEANING OWNED RESOURCES"),
    AppState.ERROR: ("ERROR", "START BLOCKED", "Z / ESC TO GO BACK"),
}


@dataclass(frozen=True)
class ViewData:
    ap_interface: str = "wlan1"
    wan_interface: str = "enp2s0"
    country: str = "US"
    subnet: str = "192.168.77.0/24"
    resolver: str = "1.1.1.1"
    ssid: str = field(default_factory=lambda: _demo_credentials()[0])
    passphrase: str = field(default_factory=lambda: _demo_credentials()[1])
    authorized: bool = False
    backend: str = "sim"


def _demo_credentials() -> tuple[str, str]:
    digest = hashlib.sha256(b"gainsec-gitm-deterministic-frame-v1").digest()
    ssid = f"GITM-C0-{digest[:3].hex().upper()}"
    passphrase = base64.b32encode(digest[3:13]).decode("ascii").rstrip("=")
    return ssid, passphrase


def demo_view(state: AppState) -> ViewData:
    return ViewData(authorized=state in (AppState.STARTING, AppState.ACTIVE, AppState.STOPPING))


def visible_lines(state: AppState, view: ViewData) -> tuple[str, ...]:
    return (
        f"AP {view.ap_interface}  >  WAN {view.wan_interface}",
        f"{view.country}  {view.subnet}  DNS {view.resolver}",
        f"SSID {view.ssid}",
        f"KEY  {view.passphrase}",
        f"AUTHORIZED {'YES' if view.authorized else 'NO'}",
        f"{view.backend.upper()} / {state.value}",
        "TLS OFF  ·  CAPTURE OFF",
    )


def _init_subsystems() -> None:
    if not pygame.display.get_init():
        pygame.display.init()
    if not pygame.font.get_init():
        pygame.font.init()


def fit_text(text: str, font: pygame.font.Font, max_width: int) -> str:
    if font.size(text)[0] <= max_width:
        return text
    suffix = "…"
    while text and font.size(text + suffix)[0] > max_width:
        text = text[:-1]
    return text + suffix


def _label(surface: pygame.Surface, text: str, pos: tuple[int, int], font, color, max_width: int) -> None:
    clipped = fit_text(text, font, max_width)
    surface.blit(font.render(clipped, False, color), pos)


def render_state(
    state: AppState,
    *,
    deterministic: bool = False,
    error: str = "privileged helper unavailable",
    view: ViewData | None = None,
    sink: FrameSink | None = None,
) -> pygame.Surface:
    _init_subsystems()
    surface = pygame.Surface((WIDTH, HEIGHT))
    surface.fill(theme.BLACK)
    tiny = pygame.font.Font(None, 13)
    small = pygame.font.Font(None, 15)
    medium = pygame.font.Font(None, 18)
    view = view or demo_view(state)

    title, heading, hint = STATE_COPY[state]
    accent = theme.GREEN if state is AppState.ACTIVE else theme.RED
    if state in (AppState.STARTING, AppState.STOPPING):
        accent = theme.YELLOW
    pygame.draw.rect(surface, accent, (0, 0, 7, HEIGHT))
    pygame.draw.rect(surface, theme.PANEL, (13, 29, 294, 120), border_radius=8)
    pygame.draw.rect(surface, accent, (13, 29, 294, 120), width=2, border_radius=8)

    _label(surface, "GAINSEC / C0  v0.1.0", (16, 9), small, theme.WHITE, 180)
    _label(surface, title, (246, 10), tiny, accent, 58)
    _label(surface, heading, (23, 35), medium, theme.WHITE, 273)
    for index, line in enumerate(visible_lines(state, view)):
        color = theme.YELLOW if index in (3, 4) else theme.WHITE
        if index in (5, 6):
            color = theme.MUTED
        _label(surface, line, (23, 55 + index * 13), small if index < 5 else tiny, color, 273)
    if state is AppState.REVIEW:
        hint = "C TO START" if view.authorized else "C TO ACKNOWLEDGE"
    footer = error if state is AppState.ERROR else hint
    _label(surface, footer, (17, 154), tiny, theme.YELLOW, 286)
    mirror(surface, sink)
    return surface


def save_screenshot(surface: pygame.Surface, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pygame.image.save(surface, str(path))
