"""Build a serializable, package-owned network operation plan."""

from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Network, ip_network
from typing import Any, Mapping

from .model import NetworkConfig
from .validation import validate_config


RUNTIME_DIR = "/run/gainsec-gitm/private"
LOG_DIR = "/var/log/gainsec-gitm"
NFT_TABLE = "gainsec_gitm"
AP_SURFACE = "gitm-ap"
DATA_DIR = "/var/lib/gainsec-gitm"
LEASE_DIR = "/run/gainsec-gitm/leases"


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
    evidence_paths: Mapping[str, str] = field(default_factory=dict)

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
            "evidence_paths": dict(self.evidence_paths),
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
            evidence_paths=dict(value.get("evidence_paths", {})),
        )


def _hostapd(config: NetworkConfig) -> str:
    return "\n".join(
        (
            f"interface={AP_SURFACE}",
            "driver=nl80211",
            "ap_isolate=1",
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
            f"dhcp-leasefile={LEASE_DIR}/dnsmasq.leases" if config.lease_events else "dhcp-leasefile=/dev/null",
            "log-facility=-",
            "no-resolv",
            "",
        )
    )


def _nftables(config: NetworkConfig, network: IPv4Network) -> str:
    tls_accept = f'iifname "{AP_SURFACE}" tcp dport 8443 ct status dnat accept\n    ip daddr {next(network.hosts())} tcp dport 8443 drop' if config.tls else ''
    redirect = f'''
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "{AP_SURFACE}" ip saddr {network} tcp dport 443 redirect to :8443
  }}
''' if config.tls else ''
    return f"""table inet {NFT_TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname \"{AP_SURFACE}\" udp dport {{ 53, 67 }} accept
    iifname \"{AP_SURFACE}\" tcp dport 53 accept
    {tls_accept}
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
{redirect}
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
    evidence = {}
    if config.capture:
        pcap = f"{DATA_DIR}/users/{config.owner_uid}/traffic.pcap"
        evidence["pcap"] = pcap
        actions += (Action("start_tcpdump", ("tcpdump", "-i", AP_SURFACE, "-nn", "-U", "-s", "0", "-C", str(config.capture_mb), "-W", "1", "-Z", "root", "-w", pcap)),)
    for mode, enabled in (("live", config.live), ("leases", config.lease_events)):
        if enabled:
            output = f"{DATA_DIR}/users/{config.owner_uid}/{mode}.jsonl"
            evidence[mode] = output
            args = ("/usr/bin/python3", "-m", "gitm.worker", mode, "--output", output)
            args += ("--interface", AP_SURFACE) if mode == "live" else ("--source", f"{LEASE_DIR}/dnsmasq.leases")
            actions += (Action(f"start_{mode}", args),)
    if config.tls:
        connection_log = f"{DATA_DIR}/users/{config.owner_uid}/tls.log"
        evidence["tls"] = connection_log
        argv = ("sslsplit", "-u", "root", "-l", connection_log, "-k", f"{RUNTIME_DIR}/ca.key", "-c", f"{RUNTIME_DIR}/ca.crt")
        if config.ca_chain or config.profile.endswith("-emsign"):
            argv += ("-C", f"{RUNTIME_DIR}/chain.pem")
        argv += ("ssl", str(gateway), "8443")
        actions += (Action("start_sslsplit", argv),)
        evidence["certificate"] = f"{DATA_DIR}/users/{config.owner_uid}/ca.crt"
    # Bring up the beacon only after optional services have started.
    actions = tuple(a for a in actions if a.name != "start_hostapd") + tuple(a for a in actions if a.name == "start_hostapd")
    return OperationPlan(config=config, actions=actions, files=files, capture_enabled=config.capture, tls_interception_enabled=config.tls, evidence_paths=evidence)
