"""Exercise the C0 evdev path without a display server or a grabbed keyboard."""
import os
import struct

import pygame


def event(code, value=1, kind=1):
    return struct.pack('llHHi', 0, 0, kind, code, value)


def test_native_keyboard_reads_partial_records_without_blocking_or_grabbing(tmp_path):
    from gitm.native_input import EvdevKeyboard
    path = tmp_path / 'keyboard'
    os.mkfifo(path)
    keyboard = EvdevKeyboard(path)
    writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        assert keyboard.poll() == []
        record = event(46)
        os.write(writer, record[:9])
        assert keyboard.poll() == []
        os.write(writer, record[9:] + event(46, 0) + event(0, 0, 0))
        events = keyboard.poll()
        assert [(e.type, e.key, e.unicode) for e in events] == [
            (pygame.KEYDOWN, pygame.K_c, 'c'), (pygame.KEYUP, pygame.K_c, '')]
        fd = keyboard.fd
        keyboard.close()
        import pytest
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        keyboard.close()
        os.close(writer)


def test_native_keyboard_preserves_shift_caps_punctuation_and_escape_repeat(tmp_path):
    from gitm.native_input import EvdevKeyboard
    path = tmp_path / 'keyboard'
    os.mkfifo(path)
    keyboard = EvdevKeyboard(path)
    writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        os.write(writer, b''.join(event(code, value) for code, value in [
            (42,1),(46,1),(42,0),(58,1),(46,1),(42,1),(46,1),(2,1),
            (42,0),(57,1),(15,1),(28,1),(14,1),(106,1),(1,1),(1,2),(1,0)]))
        events = keyboard.poll()
        assert [e.unicode for e in events if e.type == pygame.KEYDOWN and e.key == pygame.K_c] == ['C','C','c']
        assert next(e for e in events if e.key == pygame.K_1).unicode == '!'
        assert next(e for e in events if e.key == pygame.K_SPACE).unicode == ' '
        assert {pygame.K_TAB, pygame.K_RETURN, pygame.K_BACKSPACE, pygame.K_RIGHT} <= {e.key for e in events}
        escape = [e for e in events if e.key == pygame.K_ESCAPE]
        assert [e.type for e in escape] == [pygame.KEYDOWN, pygame.KEYDOWN, pygame.KEYUP]
        assert [e.repeat for e in escape] == [False, True, False]
    finally:
        keyboard.close()
        os.close(writer)


def test_missing_native_keyboard_is_nonfatal(tmp_path):
    from gitm.native_input import EvdevKeyboard
    keyboard = EvdevKeyboard(tmp_path / 'absent')
    assert keyboard.poll() == []
    keyboard.close()


def test_applaunch_gui_selects_framebuffer_and_consumes_native_keyboard(monkeypatch):
    import gitm.cli as cli
    from gitm.backends.sim import SimBackend
    class Backend(SimBackend):
        calls = 0
        def preflight(self):
            self.calls += 1
            return super().preflight()
    backend = Backend()
    keyboards = []
    class Keyboard:
        def __init__(self):
            self.closed = False
            self.count = 0
            keyboards.append(self)
        def poll(self):
            self.count += 1
            if self.count == 1:
                return [pygame.event.Event(pygame.KEYDOWN, key=pygame.K_c, unicode='c')]
            return [pygame.event.Event(pygame.QUIT)]
        def close(self):
            self.closed = True
    class Sink:
        available = True
        def write(self, frame):
            assert len(frame) == 108800
    monkeypatch.delenv('SDL_VIDEODRIVER', raising=False)
    original_init = pygame.display.init
    def init():
        selected = os.environ.get('SDL_VIDEODRIVER')
        os.environ['SDL_VIDEODRIVER'] = 'dummy'
        original_init()
        assert selected == 'dummy', 'APPLaunch must render directly to fb_lcd without a display server'
    monkeypatch.setattr(pygame.display, 'init', init)
    monkeypatch.setattr(cli, 'FramebufferSink', Sink)
    monkeypatch.setattr(cli, 'EvdevKeyboard', Keyboard, raising=False)
    monkeypatch.setattr(cli, 'select_backend', lambda name: backend)
    monkeypatch.setattr(pygame.event, 'get', lambda: [])
    assert cli._run_gui('sim', None, 'PREFLIGHT') == 0
    assert backend.calls == 1
    assert keyboards and keyboards[0].closed


def test_c0_fn_layer_symbols_follow_the_shipped_keyboard_map(tmp_path):
    from gitm.native_input import EvdevKeyboard
    path = tmp_path / 'keyboard'
    os.mkfifo(path)
    keyboard = EvdevKeyboard(path)
    writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    symbols = {26:'!',27:'@',39:'#',40:'$',41:'%',43:'^',51:'&',52:'*',53:'(',94:')',
               55:'~',69:'`',70:'_',71:'-',72:'+',73:'=',74:'[',75:']',76:'{',77:'}',
               79:';',80:':',81:"'",82:'"',83:'<',85:'>',86:'\\',89:'|',90:',',91:'.',92:'/',93:'?'}
    try:
        os.write(writer, b''.join(event(code) for code in symbols))
        events = keyboard.poll()
        assert ''.join(e.unicode for e in events) == ''.join(symbols.values())
        assert all(e.key == ord(e.unicode) for e in events)
    finally:
        keyboard.close()
        os.close(writer)
