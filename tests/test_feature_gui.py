from dataclasses import replace
from pathlib import Path
import pygame

from gitm.backends.sim import SimBackend
from gitm.controller import Controller
from gitm.gui import ViewData, visible_lines
from gitm.model import AppState


def test_gui_feature_flags_show_actual_selected_and_running_states():
    view = ViewData(capture=True, live=True, tls=True, leases=True)
    review = ' '.join(visible_lines(AppState.REVIEW, view))
    assert 'TLS ON' in review and 'CAPTURE ON' in review
    assert 'LIVE ON' in review


def test_keyboard_settings_cover_network_features_custom_ca_and_exports(tmp_path):
    from gitm.feature_ui import FeatureUI
    controller = Controller(SimBackend())
    controller.preflight()
    ui = FeatureUI(controller, export_dir=tmp_path / 'exports')
    names = [name for name, _ in ui.settings]
    for required in ('ssid', 'passphrase', 'country', 'subnet', 'resolver', 'ap_interface', 'wan_interface',
                     'capture', 'capture_mb', 'live', 'tls', 'lease_events', 'ca_cert', 'ca_key', 'ca_chain'):
        assert required in names
    ui.page = 'settings'
    ui.selection = names.index('capture')
    ui.select()
    assert controller.config.capture
    assert controller.plan.capture_enabled
    ui.selection = names.index('ssid')
    ui.select()
    ui.text_buffer = 'Edited Lab'
    ui.select()
    assert controller.config.ssid == 'Edited Lab'
    assert not ui.editing
    assert ui.render().get_size() == (320,170)
    controller.set_authorized(True)
    controller.start()
    ui.refresh()
    assert ui.runtime['simulated']
    ui.page = 'traffic'
    assert ui.render().get_size() == (320,170)
    assert not ui.editable
    controller.stop()


def test_native_profile_verification_and_export_pages_have_real_actions(tmp_path):
    from gitm.feature_ui import FeatureUI
    controller = Controller(SimBackend())
    controller.preflight()
    ui = FeatureUI(controller, export_dir=tmp_path / 'exports')
    ui.page = 'profiles'
    ui.select()
    assert controller.config.profile
    assert controller.plan.tls_interception_enabled
    assert 'verified' in ui.notice.lower()
    ui.page = 'exports'
    ui.selection = 2
    ui.select()
    assert any(path.endswith('.p12') for path in ui.export_paths.values())
    assert all(Path(path).exists() for path in ui.export_paths.values())
    for page in ui.pages:
        ui.page = page
        assert ui.render().get_size() == (320, 170)


def test_gui_can_inspect_lease_and_tls_metadata_without_a_terminal():
    from gitm.feature_ui import FeatureUI
    controller = Controller(SimBackend()); controller.preflight()
    ui = FeatureUI(controller); ui.page = 'traffic'
    assert ui.kind == 'live'
    ui.select(); assert ui.kind == 'leases'
    ui.select(); assert ui.kind == 'tls'
    ui.select(); assert ui.kind == 'live'
