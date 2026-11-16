"""Build a serializable, package-owned network operation plan."""

from dataclasses import asdict, dataclass
from ipaddress import IPv4Network, ip_network
from typing import Any, Mapping

from .model import NetworkConfig
from .validation import validate_config


RUNTIME_DIR = "/run/gainsec-gitm/private"
LOG_DIR = "/var/log/gainsec-gitm"
NFT_TABLE = "gainsec_gitm"
AP_SURFACE = "gitm-ap"


@dataclass(frozen=True)
class Action:
    name: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class LogPolicy:
    path: str = f"{LOG_DIR}/events.log"
    mode: int = 0o600
    max_bytes: int = 256 * 1024
    backups: int = 3


@dataclass(frozen=True)
class OperationPlan:
    config: NetworkConfig
    actions: tuple[Action, ...]
    files: Mapping[str, str]
    runtime_mode: int = 0o700
    log_policy: LogPolicy = LogPolicy()
    capture_enabled: bool = False
    tls_interception_enabled: bool = False
    nft_table: str = NFT_TABLE
    ap_surface: str = AP_SURFACE

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": asdict(self.config),
            "actions": [{"name": item.name, "argv": list(item.argv)} for item in self.actions],
            "files": dict(self.files),
            "runtime_mode": self.runtime_mode,
            "log_policy": asdict(self.log_policy),
            "capture_enabled": self.capture_enabled,
            "tls_interception_enabled": self.tls_interception_enabled,
            "nft_table": self.nft_table,
            "ap_surface": self.ap_surface,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OperationPlan":
        return cls(
            config=NetworkConfig(**value["config"]),
            actions=tuple(Action(item["name"], tuple(item["argv"])) for item in value["actions"]),
            files=dict(value["files"]),
            runtime_mode=int(value["runtime_mode"]),
            log_policy=LogPolicy(**value["log_policy"]),
            capture_enabled=bool(value["capture_enabled"]),
            tls_interception_enabled=bool(value["tls_interception_enabled"]),
            nft_table=str(value["nft_table"]),
            ap_surface=str(value["ap_surface"]),
        )


def _hostapd(config: NetworkConfig) -> str:
    return "\n".join(
        (
            f"interface={AP_SURFACE}",
            "driver=nl80211",
            f"ssid={config.ssid}",
            f"country_code={config.country}",
            "hw_mode=g",
            "channel=6",
            "ieee80211n=1",
            "wpa=2",
            f"wpa_passphrase={config.passphrase}",
            "wpa_key_mgmt=WPA-PSK",
            "rsn_pairwise=CCMP",
            "logger_syslog=-1",
            "logger_syslog_level=2",
            "",
        )
    )


def _dnsmasq(config: NetworkConfig, network: IPv4Network) -> str:
    hosts = list(network.hosts())
    start = hosts[min(9, len(hosts) - 1)]
    end = hosts[min(199, len(hosts) - 1)]
    gateway = hosts[0]
    return "\n".join(
        (
            "bind-interfaces",
            f"interface={AP_SURFACE}",
            "except-interface=lo",
            f"dhcp-range={start},{end},{network.netmask},12h",
            f"dhcp-option=option:router,{gateway}",
            f"dhcp-option=option:dns-server,{gateway}",
            f"server={config.resolver}",
            "dhcp-leasefile=/dev/null",
            "log-facility=-",
            "no-resolv",
            "",
        )
    )


def _nftables(config: NetworkConfig, network: IPv4Network) -> str:
    return f"""table inet {NFT_TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname \"{AP_SURFACE}\" udp dport {{ 53, 67 }} accept
    iifname \"{AP_SURFACE}\" tcp dport 53 accept
    iifname \"{AP_SURFACE}\" drop
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname \"{AP_SURFACE}\" meta nfproto ipv6 drop
    oifname \"{AP_SURFACE}\" meta nfproto ipv6 drop
    iifname \"{AP_SURFACE}\" oifname \"{config.wan_interface}\" accept
    iifname \"{config.wan_interface}\" oifname \"{AP_SURFACE}\" ct state established,related accept
    oifname \"{AP_SURFACE}\" drop
    iifname \"{AP_SURFACE}\" drop
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname \"{config.wan_interface}\" ip saddr {network} masquerade
  }}
}}
"""


def build_plan(config: NetworkConfig) -> OperationPlan:
    validate_config(config)
    network = ip_network(config.subnet, strict=True)
    gateway = next(network.hosts())
    files = {
        f"{RUNTIME_DIR}/hostapd.conf": _hostapd(config),
        f"{RUNTIME_DIR}/dnsmasq.conf": _dnsmasq(config, network),
        f"{RUNTIME_DIR}/nftables.conf": _nftables(config, network),
    }
    actions = (
        Action("create_ap", ("iw", "dev", config.ap_interface, "interface", "add", AP_SURFACE, "type", "__ap")),
        Action("unmanage_ap", ("nmcli", "device", "set", AP_SURFACE, "managed", "no")),
        Action("address_ap", ("ip", "address", "add", f"{gateway}/{network.prefixlen}", "dev", AP_SURFACE)),
        Action("enable_ap", ("ip", "link", "set", AP_SURFACE, "up")),
        Action("install_firewall", ("nft", "-f", f"{RUNTIME_DIR}/nftables.conf")),
        Action("start_dnsmasq", ("dnsmasq", "--keep-in-foreground", "--pid-file=", f"--conf-file={RUNTIME_DIR}/dnsmasq.conf")),
        Action("start_hostapd", ("hostapd", f"{RUNTIME_DIR}/hostapd.conf")),
    )
    return OperationPlan(config=config, actions=actions, files=files)
