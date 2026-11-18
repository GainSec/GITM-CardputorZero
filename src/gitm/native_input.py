"""Nonblocking C0 keyboard input when SDL has no desktop input seat.

Read the stable device link without EVIOCGRAB: APPLaunch retains Escape-hold
ownership. No keyboard enumeration, privileged opens, or external dependency.
"""
import os
from pathlib import Path
import struct

import pygame

_RECORD = struct.Struct('llHHi')
_KEYS = {
    1: pygame.K_ESCAPE, 14: pygame.K_BACKSPACE, 15: pygame.K_TAB,
    28: pygame.K_RETURN, 42: pygame.K_LSHIFT, 54: pygame.K_RSHIFT,
    58: pygame.K_CAPSLOCK, 103: pygame.K_UP, 105: pygame.K_LEFT,
    106: pygame.K_RIGHT, 108: pygame.K_DOWN,
}
_TEXT = dict(zip(range(2, 14), '1234567890-='))
_TEXT.update(zip(range(16, 28), 'qwertyuiop[]'))
_TEXT.update(zip(range(30, 42), "asdfghjkl;'`"))
_TEXT.update(zip(range(44, 54), 'zxcvbnm,./'))
_TEXT.update({43: '\\', 57: ' '})
# C0 Fn firmware emits these codes; matches tca8418_keypad_m5stack_keymap.map.
_C0_SYMBOLS = {26:'!',27:'@',39:'#',40:'$',41:'%',43:'^',51:'&',52:'*',53:'(',94:')',
               55:'~',69:'`',70:'_',71:'-',72:'+',73:'=',74:'[',75:']',76:'{',77:'}',
               79:';',80:':',81:"'",82:'"',83:'<',85:'>',86:'\\',89:'|',90:',',91:'.',92:'/',93:'?'}
_TEXT.update(_C0_SYMBOLS)
_SHIFT = dict(zip("1234567890-=[];'`,./\\", '!@#$%^&*()_+{}:\"~<>?|'))


class EvdevKeyboard:
    def __init__(self, path: Path = Path('/dev/input/cardputer-zero-internal')):
        self.fd: int | None = None
        self._buffer = b''
        self._shift: set[int] = set()
        self._caps = False
        try:
            self.fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            pass  # Desktop SDL remains usable when this C0 device is absent.

    def poll(self) -> list:
        if self.fd is None:
            return []
        try:
            self._buffer += os.read(self.fd, _RECORD.size * 64)
        except BlockingIOError:
            return []
        except OSError:
            self.close()
            return []
        events = []
        while len(self._buffer) >= _RECORD.size:
            record, self._buffer = self._buffer[:_RECORD.size], self._buffer[_RECORD.size:]
            _sec, _usec, kind, code, value = _RECORD.unpack(record)
            if kind != 1 or value not in (0, 1, 2):
                continue
            if code in (42, 54):
                self._shift.add(code) if value else self._shift.discard(code)
            if code == 58 and value == 1:
                self._caps = not self._caps
            text = _TEXT.get(code, '')
            key = ord(text) if text else _KEYS.get(code)
            if key is None:
                continue
            if text.isalpha():
                text = text.upper() if bool(self._shift) != self._caps else text
            elif self._shift and code not in _C0_SYMBOLS:
                text = _SHIFT.get(text, text)
            events.append(pygame.event.Event(
                pygame.KEYDOWN if value else pygame.KEYUP, key=key,
                unicode=text if value else '', repeat=value == 2))
        return events

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
