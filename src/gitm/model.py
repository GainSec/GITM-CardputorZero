"""Immutable domain models shared by every backend."""

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Network
from typing import Mapping


class AppState(str, Enum):
    PREFLIGHT = "PREFLIGHT"
    REVIEW = "REVIEW"
    STARTING = "STARTING"
    ACTIVE = "ACTIVE"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class NetworkConfig:
    ssid: str
    passphrase: str
    country: str
    subnet: str
    resolver: str
    ap_interface: str
    wan_interface: str


@dataclass(frozen=True)
class LinkEvidence:
    name: str
    carrier: bool
    link_type: str
    kind: str | None = None


@dataclass(frozen=True)
class InterfaceDiscovery:
    ap_interfaces: tuple[str, ...]
    wan_interfaces: tuple[str, ...]
    evidence: Mapping[str, str] = field(default_factory=dict)
    existing_networks: tuple[IPv4Network, ...] = ()
