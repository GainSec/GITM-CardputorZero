"""Keyboard pages for settings, bounded evidence, profiles and certificate exports."""

from dataclasses import replace
from pathlib import Path
import textwrap

import pygame

from .backends.base import BackendUnavailable
from .certificates import export_material
from .controller import Controller, generate_session_config
from .gui import WIDTH, HEIGHT, _init_subsystems, _label
from .model import AppState, NetworkConfig
from .profiles import list_profiles, profile_info, verify_profile
from .worker import safe_text
from . import theme


class FeatureUI:
    pages = ('overview', 'settings', 'traffic', 'evidence', 'profiles', 'exports')
    settings = (
        ('capture', 'PCAP capture'), ('capture_mb', 'PCAP size MB'), ('live', 'Live metadata'),
        ('tls', 'TLS interception'), ('lease_events', 'Lease events'), ('ssid', 'SSID'),
        ('passphrase', 'WPA2 key'), ('country', 'Country'), ('subnet', 'AP subnet'),
        ('resolver', 'DNS resolver'), ('ap_interface', 'AP interface'), ('wan_interface', 'Ethernet WAN'),
        ('ca_cert', 'Custom CA cert'), ('ca_key', 'Custom CA key'), ('ca_chain', 'Complete CA chain'),
        ('profile', 'CA profile'), ('export_dir', 'Export directory'),
    )

    def __init__(self, controller: Controller, *, export_dir: Path | None = None):
        self.controller = controller
        self.export_dir = export_dir or Path.home() / '.local/share/gainsec-gitm/exports'
        self.export_paths = {}
        self.page = 'overview'
        self.selection = 0
        self.editing = False
        self.text_buffer = ''
        self.notice = ''
        self.runtime = {}
        self.events = []
        self.kind = "live"
        self.evidence_lines = []

    @property
    def editable(self):
        return self.controller.state in {AppState.PREFLIGHT, AppState.REVIEW, AppState.ERROR}

    def turn_page(self, direction):
        if not self.editing:
            self.page = self.pages[(self.pages.index(self.page) + direction) % len(self.pages)]
            self.selection = 0
            self.notice = ''

    def move(self, direction):
        self.selection = max(0, min(self.selection + direction, self.row_count() - 1))

    def row_count(self):
        return {'settings': len(self.settings), 'profiles': len(list_profiles()) + 1, 'exports': 3,
                'traffic': max(len(self.events), 1), 'evidence': max(len(self.evidence_lines), 1)}.get(self.page, 1)

    def _ensure_config(self):
        if self.controller.config is None:
            try:
                self.controller.update_config(generate_session_config(self.controller.backend))
            except (BackendUnavailable, ValueError):
                self.controller.update_config(NetworkConfig('GITM-LAB', 'configure-me-4821', 'US', '192.168.77.0/24', '1.1.1.1', 'wlan1', 'end0'))

    def select(self):
        try:
            if self.page == 'settings' and self.editable:
                self._ensure_config()
                name, _label_text = self.settings[self.selection]
                value = str(self.export_dir) if name == 'export_dir' else getattr(self.controller.config, name)
                if type(value) is bool:
                    self.controller.update_config(replace(self.controller.config, **{name: not value}))
                elif self.editing:
                    self.editing = False
                    if name == 'export_dir':
                        self.export_dir = Path(self.text_buffer).expanduser()
                    else:
                        value = int(self.text_buffer) if name == 'capture_mb' else self.text_buffer
                        self.controller.update_config(replace(self.controller.config, **{name: value}))
                else:
                    self.text_buffer, self.editing = str(value), True
            elif self.page == 'profiles' and self.editable:
                self._ensure_config()
                if self.selection == len(list_profiles()):
                    self.controller.update_config(replace(self.controller.config, profile='', ca_cert='', ca_key='', ca_chain=''))
                    self.notice = 'Local CA selected'
                else:
                    name = list_profiles()[self.selection]
                    material = verify_profile(name)
                    info = profile_info(name)
                    self.controller.update_config(replace(self.controller.config, profile=name, ca_cert='', ca_key='', ca_chain='', tls=True))
                    self.notice = 'Verified ' + material.fingerprint[:16]
                    self.evidence_lines = [name, info['name'], 'Revoked / isolated labs', info['issued_by'], material.fingerprint]
            elif self.page == 'traffic':
                kinds = ('live', 'leases', 'tls')
                self.kind = kinds[(kinds.index(self.kind) + 1) % len(kinds)]
                self.events = []
                self.notice = self.kind.upper() + ' / C NEXT LOG'
            elif self.page == 'exports':
                self._ensure_config()
                material = self.controller.backend.ca_material(self.controller.config)
                self.export_paths = export_material(material, self.export_dir, android=self.selection in {0, 2}, burp=self.selection in {1, 2})
                self.notice = 'Export ready; paths on EVIDENCE'
                self.evidence_lines = [line for name, path in self.export_paths.items() for line in [name.upper(), *textwrap.wrap(path, 43, break_long_words=True, break_on_hyphens=False)]]
        except (BackendUnavailable, OSError, ValueError) as exc:
            self.notice = safe_text(exc)

    def text(self, event):
        if event.key == pygame.K_BACKSPACE:
            self.text_buffer = self.text_buffer[:-1]
        elif event.unicode and len(self.text_buffer) < 4096:
            self.text_buffer += ''.join(c for c in event.unicode if c.isprintable())

    def refresh(self):
        if self.controller.state is not AppState.ACTIVE:
            return
        try:
            self.runtime = self.controller.backend.status()
            if not self.runtime.get('ok') or self.runtime.get('state') != 'active':
                self.controller.error = safe_text(self.runtime.get('error') or '; '.join(self.runtime.get('errors', [])) or 'Session is no longer active')
                self.controller.state = AppState.ERROR
                return
            if self.page == 'traffic':
                self.events = self.controller.backend.inspect(kind=self.kind, limit=20).get('events', [])
            if self.page == 'evidence' and not self.export_paths:
                self.evidence_lines = [line for name, path in self.runtime.get('evidence', {}).items() for line in [name.upper(), *textwrap.wrap(path, 43, break_long_words=True, break_on_hyphens=False)]]
        except (BackendUnavailable, OSError, ValueError) as exc:
            self.notice = safe_text(exc)

    def render(self):
        _init_subsystems()
        surface = pygame.Surface((WIDTH, HEIGHT))
        surface.fill(theme.BLACK)
        tiny, small = pygame.font.Font(None, 14), pygame.font.Font(None, 17)
        _label(surface, 'GAINSEC / ' + self.page.upper(), (12, 8), small, theme.WHITE, 298)
        rows = []
        if self.page == 'settings':
            self._ensure_config()
            for name, label in self.settings:
                value = str(self.export_dir) if name == 'export_dir' else getattr(self.controller.config, name)
                if type(value) is bool:
                    value = 'ON' if value else 'OFF'
                rows.append(f'{label}: {value or "local / none"}')
        elif self.page == 'profiles':
            rows = [*list_profiles(), 'Local / custom CA']
        elif self.page == 'exports':
            rows = ['Prepare Android certificate', 'Prepare Burp PKCS12 + PEM', 'Prepare Android + Burp']
        elif self.page == 'traffic':
            if self.kind == 'leases':
                rows = [f'{e.get("mac", "")} {e.get("ip", "")}' for e in self.events]
            elif self.kind == 'tls':
                rows = [e.get('connection', '') for e in self.events]
            else:
                rows = [f'{e.get("protocol", "")} {e.get("source", "")} > {e.get("destination", "")}' for e in self.events]
            rows = rows or ['No metadata yet', 'Enable LIVE in settings', 'SIM emits no hardware traffic' if self.controller.backend.name == 'sim' else 'Waiting for AP traffic']
        elif self.page == 'evidence':
            rows = self.evidence_lines or ['Evidence paths appear after start', 'Export paths appear after prepare']
        start = max(0, self.selection - 4)
        for index, row in enumerate(rows[start:start + 6], start):
            y = 33 + (index - start) * 17
            selected = index == self.selection
            if selected:
                pygame.draw.rect(surface, theme.PANEL, (8, y - 2, 305, 17), border_radius=3)
            _label(surface, ('> ' if selected else '  ') + safe_text(row, 4096), (10, y), tiny, theme.GREEN if selected else theme.WHITE, 300)
        if self.editing:
            pygame.draw.rect(surface, theme.PANEL, (8, 113, 305, 36))
            _label(surface, 'EDIT: ' + self.settings[self.selection][1], (12, 116), tiny, theme.YELLOW, 294)
            _label(surface, self.text_buffer[-48:] + '_', (12, 132), tiny, theme.WHITE, 294)
        footer = 'ENTER SAVE / ESC CANCEL' if self.editing else (self.notice or 'F/X PAGE  W/S ROW  C SELECT')
        _label(surface, footer, (10, 154), tiny, theme.YELLOW, 300)
        return surface
