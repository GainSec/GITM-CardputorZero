"""Backend selection that never masks system failures on target."""

from pathlib import Path

from .sim import SimBackend
from .system import SystemBackend


def is_cardputerzero() -> bool:
    return Path("/etc/cardputerzero-release").exists() or Path("/dev/fb_lcd").exists()


def select_backend(name: str, *, is_device: bool | None = None):
    if name == "sim":
        return SimBackend()
    if name == "system":
        return SystemBackend()
    if name != "auto":
        raise ValueError(f"unknown backend: {name}")
    target = is_cardputerzero() if is_device is None else is_device
    return SystemBackend() if target else SimBackend()
