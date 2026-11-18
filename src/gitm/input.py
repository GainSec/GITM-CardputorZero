"""Keyboard mapping compatible with APPLaunch Escape ownership."""

from enum import Enum

import pygame


class UiAction(str, Enum):
    LEFT = "left"
    RIGHT = "right"
    UP = "up"
    DOWN = "down"
    SELECT = "select"
    BACK = "back"
    TEXT = "text"
    QUIT = "quit"


class InputMapper:
    def __init__(self):
        self.text_entry = False
        self._escape_down = False

    def map_event(self, event: pygame.event.Event) -> UiAction | None:
        if event.type == pygame.QUIT:
            return UiAction.QUIT
        if event.type == pygame.KEYUP and event.key == pygame.K_ESCAPE:
            self._escape_down = False
            return None
        if event.type != pygame.KEYDOWN:
            return None
        if event.key == pygame.K_ESCAPE:
            if self._escape_down:
                return None
            self._escape_down = True
            return UiAction.BACK
        if self.text_entry and event.key == pygame.K_SPACE:
            return UiAction.TEXT
        native = {
            pygame.K_LEFT: UiAction.LEFT,
            pygame.K_RIGHT: UiAction.RIGHT,
            pygame.K_UP: UiAction.UP,
            pygame.K_DOWN: UiAction.DOWN,
            pygame.K_RETURN: UiAction.SELECT,
            pygame.K_SPACE: UiAction.SELECT,
        }
        if event.key in native:
            return native[event.key]
        aliases = {
            pygame.K_w: UiAction.UP,
            pygame.K_s: UiAction.DOWN,
            pygame.K_f: UiAction.LEFT,
            pygame.K_x: UiAction.RIGHT,
            pygame.K_z: UiAction.BACK,
            pygame.K_c: UiAction.SELECT,
        }
        if event.key in aliases:
            return UiAction.TEXT if self.text_entry else aliases[event.key]
        return UiAction.TEXT if self.text_entry else None
