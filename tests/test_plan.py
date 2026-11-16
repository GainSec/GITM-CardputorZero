import json
from pathlib import PurePosixPath

from gitm.model import NetworkConfig
from gitm.plan import NFT_TABLE, RUNTIME_DIR, build_plan


def config():
    return NetworkConfig(
        ssid="GITM-C0-7A2F",
        passphrase="vivid-nimbus-4821",
        country="US",
        subnet="192.168.77.0/24",
        resolver="1.1.1.1",
        ap_interface="wlan1",
        wan_interface="enp2s0",
    )


def test_plan_uses_only_structured_argv_actions():
    plan = build_plan(config())
    assert plan.actions
    assert all(isinstance(action.argv, tuple) and action.argv for action in plan.actions)
    assert all(action.argv[0] not in {"sh", "bash", "zsh", "sudo"} for action in plan.actions)
    encoded = json.dumps(plan.to_dict())
    assert "shell" not in encoded.lower()


def test_plan_owns_dedicated_nftables_table_and_blocks_ipv6():
    plan = build_plan(config())
    nft = plan.files[f"{RUNTIME_DIR}/nftables.conf"]
    assert f"table inet {NFT_TABLE}" in nft
    assert "meta nfproto ipv6 drop" in nft
    assert "flush ruleset" not in nft
    assert "iptables" not in nft


def test_plan_blocks_ap_clients_from_unrelated_local_services():
    nft = build_plan(config()).files[f"{RUNTIME_DIR}/nftables.conf"]
    assert "iifname \"gitm-ap\" udp dport { 53, 67 } accept" in nft
    assert "iifname \"gitm-ap\" drop" in nft
    assert "oifname \"gitm-ap\" drop" in nft


def test_plan_keeps_configs_and_state_in_private_runtime_tree():
    plan = build_plan(config())
    assert all(PurePosixPath(path).is_relative_to(RUNTIME_DIR) for path in plan.files)
    assert plan.runtime_mode == 0o700
    assert plan.log_policy.max_bytes <= 512 * 1024
    assert plan.log_policy.backups <= 3
    assert plan.capture_enabled is False
    assert plan.tls_interception_enabled is False


def test_plan_has_private_hostapd_and_dnsmasq_paths_and_random_secret_not_default():
    plan = build_plan(config())
    assert plan.files[f"{RUNTIME_DIR}/hostapd.conf"].find("wpa_passphrase=vivid-nimbus-4821") >= 0
    assert "dhcp-leasefile=/dev/null" in plan.files[f"{RUNTIME_DIR}/dnsmasq.conf"]
    assert "log-facility=-" in plan.files[f"{RUNTIME_DIR}/dnsmasq.conf"]
    assert "password123" not in json.dumps(plan.to_dict()).lower()


def test_networkmanager_releases_ap_vif_before_addressing_or_enabling_it():
    actions = list(build_plan(config()).actions)
    names = [action.name for action in actions]
    assert names.index("create_ap") < names.index("unmanage_ap") < names.index("address_ap") < names.index("enable_ap")
    assert actions[names.index("unmanage_ap")].argv == (
        "nmcli", "device", "set", "gitm-ap", "managed", "no",
    )


def test_daemon_actions_run_in_foreground_without_pid_files():
    actions = {action.name: action.argv for action in build_plan(config()).actions}
    dnsmasq = actions["start_dnsmasq"]
    hostapd = actions["start_hostapd"]
    assert "--keep-in-foreground" in dnsmasq
    assert "--pid-file=" in dnsmasq
    assert "-B" not in hostapd
    assert "-P" not in hostapd
