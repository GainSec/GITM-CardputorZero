#!/usr/bin/env python3
"""Render native simulator screens without starting any system service."""
import os
from pathlib import Path
import sys

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from gitm.backends.sim import SimBackend
from gitm.controller import Controller
from gitm.feature_ui import FeatureUI
from gitm.gui import ViewData, render_state, save_screenshot
from gitm.model import AppState, NetworkConfig


def main():
    for state in AppState:
        save_screenshot(render_state(state, deterministic=True), ROOT / 'screenshots' / (state.value.lower() + '.png'))
    controller = Controller(SimBackend())
    controller.update_config(NetworkConfig('GITM-C0-DEMO', 'demo-screen-only', 'US', '192.168.77.0/24', '1.1.1.1', 'wlan1', 'enp2s0', capture=True, tls=True, live=True, lease_events=True))
    ui = FeatureUI(controller, export_dir=Path('gitm-exports'))
    ui.events = [{'timestamp': '2026-11-18T00:00:00Z', 'protocol': 'TCP', 'source': '192.168.77.10:48120', 'destination': '192.0.2.20:443'},
                 {'timestamp': '2026-11-18T00:00:00Z', 'protocol': 'UDP', 'source': '192.168.77.10:53210', 'destination': '192.168.77.1:53'}]
    for page in ('settings', 'traffic', 'profiles', 'exports'):
        ui.page = page
        ui.selection = 0
        ui.notice = 'SIMULATOR / EXAMPLE METADATA' if page == 'traffic' else ''
        save_screenshot(ui.render(), ROOT / 'screenshots' / (page + '.png'))


if __name__ == '__main__':
    main()
