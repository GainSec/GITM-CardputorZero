from dataclasses import replace
import json
from pathlib import Path

import pytest

from gitm.cli import main
from gitm.backends.sim import SimBackend
from gitm.backends.system import SystemBackend
from gitm.certificates import atomic_private
from test_features import config
from gitm.plan import build_plan


def test_cli_plan_config_parity_has_no_filesystem_mutation(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(['render-plan', '--backend', 'sim', '--dump', '--live', '--strip', '--lease-events', '--capture-mb', '3']) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan['capture_enabled'] and plan['tls_interception_enabled']
    assert plan['config']['live'] and plan['config']['lease_events']
    assert plan['config']['capture_mb'] == 3
    assert list(tmp_path.iterdir()) == []
    assert main(['start', '--backend', 'sim', '--dump', '--dry-run']) == 0
    assert json.loads(capsys.readouterr().out)['capture_enabled']
    assert list(tmp_path.iterdir()) == []


def test_cli_configuration_and_safe_simulated_start_status_stop(tmp_path, monkeypatch, capsys):
    backend = SimBackend()
    monkeypatch.setattr('gitm.cli.select_backend', lambda _: backend)
    destination = tmp_path / 'session.json'
    assert main(['configure', '--backend', 'sim', '--config', str(destination), '--ssid', 'Lab', '--country', 'GB', '--dump', '--live', '--strip', '--lease-events']) == 0
    capsys.readouterr()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert main(['start', '--backend', 'sim', '--config', str(destination), '--authorized']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['simulated']
    assert all(result['features'][x] for x in ('capture', 'live', 'tls', 'leases'))
    assert main(['status', '--backend', 'sim']) == 0
    assert json.loads(capsys.readouterr().out)['features']['capture']
    assert main(['inspect', '--backend', 'sim', '--limit', '2']) == 0
    assert len(json.loads(capsys.readouterr().out)['events']) <= 2
    assert main(['stop', '--backend', 'sim']) == 0
    assert json.loads(capsys.readouterr().out)['state'] == 'inactive'


def test_cli_profiles_verifies_without_mutation_and_export_is_explicit(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(['profiles']) == 0
    assert len(json.loads(capsys.readouterr().out)['profiles']) == 12
    assert main(['verify-profile', 'dv-g3b-aaa']) == 0
    assert json.loads(capsys.readouterr().out)['ok']
    assert main(['profile-info', 'dv-g3b-emsign']) == 0
    assert json.loads(capsys.readouterr().out)['chain'].endswith('/chain.pem')
    assert list(tmp_path.iterdir()) == []
    output = tmp_path / 'exports'
    assert main(['export', '--backend', 'sim', '--android', '--burp', '--output-dir', str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert Path(result['paths']['android']).exists()
    assert Path(result['paths']['pkcs12']).exists()
    assert 'PRIVATE KEY' not in json.dumps(result)


def test_custom_ca_plan_validation_fails_before_creating_exports(tmp_path, capsys):
    cert = tmp_path / 'bad.crt'; key = tmp_path / 'bad.key'
    atomic_private(cert, b'bad'); atomic_private(key, b'bad')
    output = tmp_path / 'exports'
    assert main(['export', '--backend', 'sim', '--ca-cert', str(cert), '--ca-key', str(key), '--output-dir', str(output)]) == 2
    assert not output.exists()
    assert not json.loads(capsys.readouterr().out)['ok']


def test_system_backend_passes_custom_ca_in_memory_outside_plan(tmp_path):
    from test_certificates import ca, material
    cert, key = material(ca())
    cp, kp = tmp_path / 'cert', tmp_path / 'key'
    atomic_private(cp, cert); atomic_private(kp, key)
    backend = SystemBackend()
    calls = []
    backend._request = lambda payload: calls.append(payload) or {'ok': True, 'ca_material': {'certificate': cert.decode(), 'private_key': key.decode(), 'chain': ''}}
    # export does not need any live network/discovery probe.
    result = backend.ca_material(config(ca_cert=str(cp), ca_key=str(kp), tls=True))
    assert result.private_key == key
    assert 'plan' not in calls[-1]
    assert calls[-1]['action'] == 'prepare-ca'
