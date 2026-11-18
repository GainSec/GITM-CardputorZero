import pygame

from gitm.input import InputMapper, UiAction


def keydown(key, repeat=False):
    return pygame.event.Event(pygame.KEYDOWN, key=key, repeat=repeat, unicode="")


def keyup(key):
    return pygame.event.Event(pygame.KEYUP, key=key)


def test_native_arrows_and_bare_aliases_map_to_actions():
    mapper = InputMapper()
    assert mapper.map_event(keydown(pygame.K_LEFT)) is UiAction.LEFT
    assert mapper.map_event(keydown(pygame.K_RIGHT)) is UiAction.RIGHT
    assert mapper.map_event(keydown(pygame.K_f)) is UiAction.LEFT
    assert mapper.map_event(keydown(pygame.K_x)) is UiAction.RIGHT
    assert mapper.map_event(keydown(pygame.K_z)) is UiAction.BACK
    assert mapper.map_event(keydown(pygame.K_c)) is UiAction.SELECT


def test_bare_aliases_are_text_when_text_entry_is_active():
    mapper = InputMapper()
    mapper.text_entry = True
    assert mapper.map_event(keydown(pygame.K_f)) is UiAction.TEXT
    assert mapper.map_event(keydown(pygame.K_c)) is UiAction.TEXT


def test_escape_repeat_is_suppressed_until_release():
    mapper = InputMapper()
    assert mapper.map_event(keydown(pygame.K_ESCAPE)) is UiAction.BACK
    assert mapper.map_event(keydown(pygame.K_ESCAPE, repeat=True)) is None
    assert mapper.map_event(keydown(pygame.K_ESCAPE)) is None
    assert mapper.map_event(keyup(pygame.K_ESCAPE)) is None
    assert mapper.map_event(keydown(pygame.K_ESCAPE)) is UiAction.BACK


def test_escape_stays_back_during_text_entry():
    mapper = InputMapper()
    mapper.text_entry = True
    assert mapper.map_event(keydown(pygame.K_ESCAPE)) is UiAction.BACK


def test_text_entry_preserves_spaces_and_navigation_aliases_as_text():
    mapper = InputMapper()
    mapper.text_entry = True
    for key, text in ((pygame.K_SPACE, ' '), (pygame.K_c, 'c'), (pygame.K_x, 'x')):
        assert mapper.map_event(pygame.event.Event(pygame.KEYDOWN, key=key, unicode=text)) == UiAction.TEXT


def test_physical_keyboard_can_navigate_rows_without_arrow_keys():
    mapper=InputMapper()
    for key, expected in ((pygame.K_w,UiAction.UP),(pygame.K_s,UiAction.DOWN)):
        event=pygame.event.Event(pygame.KEYDOWN,key=key,unicode=chr(key))
        assert mapper.map_event(event) == expected
        mapper.text_entry=True
        assert mapper.map_event(event) == UiAction.TEXT
        mapper.text_entry=False
