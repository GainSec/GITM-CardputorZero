import json
import os
from pathlib import Path

from PIL import Image
import pytest

from tools.stage_package import stage_package
import tools.stage_package as package_stager


ROOT = Path(__file__).parents[1]


def test_store_metadata_is_complete_and_honest():
    metadata = json.loads((ROOT / "app-builder.json").read_text())
    assert metadata["package_name"] == "gainsec-gitm"
    assert metadata["version"] == "0.2.1"
    assert metadata["app_name"] == "GainSec GITM"
    store = metadata["store"]
    assert store["categories"] == ["Security", "System Tools"]
    assert store["license"] == "MIT"
    assert store["share_code"] == "GITM"
    assert store["author"] == {"display_name": "GainSec"}
    assert store["source_repo"] == "https://github.com/GainSec/GITM-CardputorZero"
    assert store["permissions"] == {
        "camera": False,
        "microphone": False,
        "imu": False,
        "network": True,
        "additional_hardware": False,
        "background_service": True,
        "external_display": False,
    }
    assert 1 <= len(store["screenshots"]) <= 6


def test_original_icons_have_required_dimensions():
    with Image.open(ROOT / "assets" / "gitm-icon-256.png") as store_icon:
        assert store_icon.size == (256, 256)
    with Image.open(ROOT / "assets" / "gitm.png") as launcher:
        assert launcher.size[0] == launcher.size[1]
        assert 64 <= launcher.size[0] <= 256


def test_stage_contains_required_runtime_wrappers_docs_and_metadata(tmp_path):
    package = stage_package(tmp_path / "pkg")
    required = {
        "DEBIAN/control",
        "DEBIAN/postinst",
        "DEBIAN/postrm",
        "usr/bin/gitm",
        "usr/libexec/gainsec-gitm-helper",
        "usr/share/GITM/bin/gitm",
        "usr/share/GITM/gitm/__init__.py",
        "usr/share/GITM/assets/gitm-icon-256.png",
        "usr/share/APPLaunch/applications/gitm.desktop",
        "usr/share/APPLaunch/share/images/gitm.png",
        "usr/share/doc/gainsec-gitm/LICENSE",
        "lib/systemd/system/gainsec-gitm-helper.socket",
        "lib/systemd/system/gainsec-gitm-helper.service",
    }
    files = {str(path.relative_to(package)) for path in package.rglob("*") if path.is_file()}
    assert required <= files
    assert not any("sudoers" in item.lower() for item in files)
    assert "usr/share/doc/gainsec-gitm/historical/gitm.sh" not in files


def test_wrappers_and_desktop_have_exact_semantics(tmp_path):
    package = stage_package(tmp_path / "pkg")
    general = package / "usr/bin/gitm"
    app = package / "usr/share/GITM/bin/gitm"
    desktop = (package / "usr/share/APPLaunch/applications/gitm.desktop").read_text()
    assert '"$@"' in general.read_text()
    assert "gui --backend auto" not in general.read_text()
    assert 'gui --backend auto "$@"' in app.read_text()
    assert "Exec=/usr/share/GITM/bin/gitm" in desktop
    assert "Terminal=false" in desktop
    assert "Icon=share/images/gitm.png" in desktop
    assert general.stat().st_mode & 0o111
    assert app.stat().st_mode & 0o111
    assert (package / "DEBIAN/postinst").stat().st_mode & 0o111


def test_control_and_postinst_match_contract(tmp_path):
    package = stage_package(tmp_path / "pkg")
    control = (package / "DEBIAN/control").read_text()
    assert "Package: gainsec-gitm" in control
    assert "Version: 0.2.1-1" in control
    assert "Architecture: arm64" in control
    assert "Maintainer: GainSec <gainsec@users.noreply.github.com>" in control
    assert "Depends: python3 (>= 3.11), python3-pygame, hostapd, dnsmasq-base, network-manager, nftables, iw, iproute2, systemd, adduser" in control
    assert ", dnsmasq," not in control
    postinst = (package / "DEBIAN/postinst").read_text()
    assert "/usr/bin/python3 -m compileall -q /usr/share/GITM/gitm" in postinst
    assert "sudoers" not in postinst


def test_debian_lifecycle_preserves_upgrade_and_manages_socket(tmp_path):
    package = stage_package(tmp_path / "pkg")
    prerm = (package / "DEBIAN/prerm").read_text()
    postinst = (package / "DEBIAN/postinst").read_text()
    postrm = (package / "DEBIAN/postrm").read_text()
    assert 'if [ "$1" = "remove" ]' in prerm
    assert "/usr/libexec/gainsec-gitm-helper stop" in prerm
    assert "stop gainsec-gitm-helper.socket gainsec-gitm-helper.service" in prerm
    assert "stop gainsec-gitm-helper.socket gainsec-gitm-helper.service >/dev/null 2>&1 || true" not in prerm
    assert "daemon-reload" in postinst
    assert "enable --now gainsec-gitm-helper.socket" in postinst
    assert "try-restart gainsec-gitm-helper.socket" in postinst
    assert 'if [ "$1" = "remove" ] || [ "$1" = "purge" ]' in postrm
    assert "disable gainsec-gitm-helper.socket" in postrm
    assert "daemon-reload" in postrm


def test_staged_package_excludes_secrets_captures_and_generated_ca(tmp_path):
    package = stage_package(tmp_path / "pkg")
    forbidden_suffixes = {".key", ".crt", ".pem", ".pcap", ".cap", ".p12"}
    for path in package.rglob("*"):
        if path.is_file():
            if path.is_relative_to(package / "usr/share/GITM/profiles/emudhra"):
                import hashlib
                relative = str(path.relative_to(package / "usr/share/GITM/profiles/emudhra"))
                pins = json.loads((ROOT / 'profiles/emudhra/provenance.json').read_text())['sha256']
                assert relative == 'provenance.json' or hashlib.sha256(path.read_bytes()).hexdigest() == pins[relative]
                if path.suffix == '.key':
                    assert path.stat().st_mode & 0o777 == 0o640
            else:
                assert path.suffix.lower() not in forbidden_suffixes
            assert "password" not in path.name.lower()
    combined = "\n".join(path.read_text(errors="ignore") for path in package.rglob("*") if path.is_file() and not path.is_relative_to(package / "usr/share/GITM/profiles/emudhra"))
    assert "BEGIN PRIVATE KEY" not in combined
    assert "BEGIN RSA PRIVATE KEY" not in combined
    assert 'PASSWORD="' not in combined
    assert "killall" not in combined
    assert "iptables -F" not in combined
    assert "flush ruleset" not in combined


def test_systemd_creates_private_bounded_log_directory(tmp_path):
    package = stage_package(tmp_path / "pkg")
    service = (package / "lib/systemd/system/gainsec-gitm-helper.service").read_text()
    assert "LogsDirectory=gainsec-gitm" in service
    assert "LogsDirectoryMode=0700" in service
    assert "KillMode=control-group" in service


def test_systemd_grants_dnsmasq_required_network_and_privilege_drop_capabilities(tmp_path):
    package = stage_package(tmp_path / "pkg")
    service = (package / "lib/systemd/system/gainsec-gitm-helper.service").read_text()
    expected = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_KILL CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER"
    assert f"CapabilityBoundingSet={expected}" in service
    assert f"AmbientCapabilities={expected}" in service


def test_systemd_socket_parent_is_traversable_but_socket_is_group_restricted(tmp_path):
    package = stage_package(tmp_path / "pkg")
    socket_unit = (package / "lib/systemd/system/gainsec-gitm-helper.socket").read_text()
    service = (package / "lib/systemd/system/gainsec-gitm-helper.service").read_text()
    assert "DirectoryMode=0755" in socket_unit
    assert "SocketMode=0660" in socket_unit
    assert "SocketGroup=gainsec-gitm" in socket_unit
    assert "RuntimeDirectoryMode=0755" in service


def test_store_assets_are_tracked_outside_ignored_dist():
    metadata = json.loads((ROOT / "app-builder.json").read_text())
    for relative in metadata["store"]["screenshots"]:
        assert relative.startswith("screenshots/")
        assert (ROOT / relative).is_file()


def test_stage_rejects_broad_or_unowned_existing_deletion_targets(tmp_path, monkeypatch):
    unowned = tmp_path / "unowned"
    unowned.mkdir()

    def destructive_call_would_be_a_bug(_path):
        raise AssertionError("rmtree must not be reached for an unsafe target")

    monkeypatch.setattr(package_stager.shutil, "rmtree", destructive_call_would_be_a_bug)
    for unsafe in (Path("/"), Path.home(), ROOT, unowned):
        with pytest.raises(ValueError, match="staging destination"):
            stage_package(unsafe)



def test_full_feature_package_has_exact_dependencies_state_directory_and_source_bytes(tmp_path):
    package = stage_package(tmp_path / "pkg")
    control = (package / "DEBIAN/control").read_text()
    for dependency in ('sslsplit', 'tcpdump', 'openssl', 'python3-cryptography'):
        assert dependency in control.split('Depends: ')[1].split('\n')[0].split(', ')
    assert (package / 'usr/share/doc/gainsec-gitm/README.md').read_bytes() == (ROOT/'README.md').read_bytes()
    assert (package / 'usr/share/GITM/profiles/emudhra/provenance.json').read_bytes() == (ROOT/'profiles/emudhra/provenance.json').read_bytes()
    service = (package / 'lib/systemd/system/gainsec-gitm-helper.service').read_text()
    assert 'StateDirectory=gainsec-gitm' in service
    assert 'StateDirectoryMode=0711' in service
    assert '/var/lib/gainsec-gitm' in service
    postinst = (package / 'DEBIAN/postinst').read_text()
    assert 'chgrp gainsec-gitm' in postinst
    assert 'ca.key' in postinst


def test_debian_copyright_file_preserves_license_bytes(tmp_path):
    package = stage_package(tmp_path/'pkg')
    assert (package/'usr/share/doc/gainsec-gitm/copyright').read_bytes() == (ROOT/'LICENSE').read_bytes()


def test_helper_normal_signal_shutdown_is_successful_under_the_service_policy(tmp_path):
    import configparser
    import signal
    from gitm.helper import HelperEngine
    policy=configparser.ConfigParser()
    policy.read(ROOT/'packaging/systemd/gainsec-gitm-helper.service')
    accepted={int(code) for code in policy.get('Service','SuccessExitStatus',fallback='').split()}
    engine=HelperEngine(runtime_dir=tmp_path/'private',runner=lambda _:None)
    for signum in (signal.SIGTERM,signal.SIGINT):
        with pytest.raises(SystemExit) as exited:
            engine.handle_signal(signum,None)
        assert exited.value.code in accepted


def test_stopping_helper_cannot_unlink_the_still_active_activation_socket():
    import configparser
    service = configparser.ConfigParser(interpolation=None)
    activation = configparser.ConfigParser(interpolation=None)
    service.read(ROOT / 'packaging/systemd/gainsec-gitm-helper.service')
    activation.read(ROOT / 'packaging/systemd/gainsec-gitm-helper.socket')
    endpoint = Path(activation['Socket']['ListenStream'])
    for directory in service['Service'].get('RuntimeDirectory', '').split():
        if endpoint.is_relative_to(Path('/run') / directory):
            assert service['Service'].get('RuntimeDirectoryPreserve') == 'yes', (
                'service stop removes its runtime directory while the socket unit still owns a listener there')
