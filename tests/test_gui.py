from pathlib import Path

import pygame
import pytest

from gitm.framebuffer import FramebufferSink, rgb565_bytes
from gitm.gui import HEIGHT, WIDTH, ViewData, demo_view, fit_text, render_state, save_screenshot, visible_lines
from gitm.model import AppState


@pytest.mark.parametrize("state", list(AppState))
def test_every_meaningful_state_renders_exact_native_dimensions(state, tmp_path):
    surface = render_state(state, deterministic=True)
    assert surface.get_size() == (320, 170)
    output = tmp_path / f"{state.value.lower()}.png"
    save_screenshot(surface, output)
    assert pygame.image.load(output).get_size() == (320, 170)


def test_long_labels_are_clipped_to_available_width():
    pygame.font.init()
    font = pygame.font.Font(None, 18)
    value = fit_text("AP interface with a label that is much too long to fit", font, 110)
    assert value.endswith("…")
    assert font.size(value)[0] <= 110


def test_rgb565_frame_is_exact_size_and_byte_order():
    surface = pygame.Surface((2, 1))
    surface.set_at((0, 0), (255, 0, 0))
    surface.set_at((1, 0), (0, 255, 0))
    assert rgb565_bytes(surface) == b"\x00\xf8\xe0\x07"


def test_framebuffer_open_failure_disables_mirror_without_crashing_ui(tmp_path):
    framebuffer = tmp_path / "fb_lcd"
    framebuffer.mkdir()
    sink = FramebufferSink(framebuffer)
    surface = render_state(AppState.PREFLIGHT, deterministic=True, sink=sink)
    assert surface.get_size() == (320, 170)
    assert sink.available is False
    assert sink.error is not None


def test_gui_never_calls_global_pygame_init():
    source = (Path(__file__).parents[1] / "src" / "gitm" / "gui.py").read_text()
    assert "pygame.init(" not in source


def test_review_lines_show_every_required_datum_and_disabled_modules():
    view = ViewData(
        ap_interface="mlan0",
        wan_interface="end0",
        country="GB",
        subnet="192.168.88.0/24",
        resolver="9.9.9.9",
        ssid="GITM-C0-AB12",
        passphrase="amber-tiger-1937",
        authorized=True,
        backend="system",
    )
    text = " | ".join(visible_lines(AppState.REVIEW, view))
    for expected in (
        "mlan0",
        "end0",
        "GB",
        "192.168.88.0/24",
        "9.9.9.9",
        "GITM-C0-AB12",
        "amber-tiger-1937",
        "AUTHORIZED YES",
        "SYSTEM / REVIEW",
        "TLS OFF",
        "CAPTURE OFF",
    ):
        assert expected in text


def test_demo_view_authorization_matches_session_state():
    assert demo_view(AppState.PREFLIGHT).authorized is False
    assert demo_view(AppState.REVIEW).authorized is False
    assert demo_view(AppState.STARTING).authorized is True
    assert demo_view(AppState.ACTIVE).authorized is True
    assert demo_view(AppState.STOPPING).authorized is True


def test_demo_credentials_are_deterministic_but_not_literal_passwords():
    first = demo_view(AppState.REVIEW)
    second = demo_view(AppState.REVIEW)
    assert first.ssid == second.ssid
    assert first.passphrase == second.passphrase
    source = (Path(__file__).parents[1] / "src/gitm/gui.py").read_text()
    assert first.passphrase not in source
    assert first.ssid not in source
