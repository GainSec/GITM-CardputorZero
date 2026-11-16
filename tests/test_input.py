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
