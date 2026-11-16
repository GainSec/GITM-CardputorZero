"""Injectable RGB565 framebuffer mirroring."""

from pathlib import Path
from typing import Protocol

import pygame


class FrameSink(Protocol):
    def write(self, frame: bytes) -> None: ...


def rgb565_bytes(surface: pygame.Surface) -> bytes:
    width, height = surface.get_size()
    output = bytearray(width * height * 2)
    index = 0
    for y in range(height):
        for x in range(width):
            red, green, blue, _alpha = surface.get_at((x, y))
            value = ((red & 0xF8) << 8) | ((green & 0xFC) << 3) | (blue >> 3)
            output[index] = value & 0xFF
            output[index + 1] = value >> 8
            index += 2
    return bytes(output)


class FramebufferSink:
    def __init__(self, path: Path = Path("/dev/fb_lcd")):
        self.path = path
        self.error: str | None = None
        self._disabled = False

    @property
    def available(self) -> bool:
        return not self._disabled and self.path.exists()

    def write(self, frame: bytes) -> None:
        if not self.available:
            return
        try:
            with self.path.open("wb", buffering=0) as device:
                written = device.write(frame)
                if written != len(frame):
                    raise OSError(f"short framebuffer write: {written}/{len(frame)}")
        except OSError as exc:
            self.error = str(exc)
            self._disabled = True


def mirror(surface: pygame.Surface, sink: FrameSink | None) -> None:
    if sink is not None:
        sink.write(rgb565_bytes(surface))
