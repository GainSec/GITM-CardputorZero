"""Deterministic parsers for Linux interface evidence."""

from dataclasses import dataclass
import json
from ipaddress import IPv4Network, ip_network
import re

from .model import InterfaceDiscovery, LinkEvidence


def parse_iw_list(output: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    current: str | None = None
    in_modes = False
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Wiphy "):
            current = line.split(maxsplit=1)[1]
            result[current] = set()
            in_modes = False
        elif line == "Supported interface modes:":
            in_modes = True
        elif in_modes and line.startswith("*") and current:
            result[current].add(line[1:].strip())
        elif in_modes and line and not line.startswith("*"):
            in_modes = False
    return result


def parse_ip_link_json(output: str) -> dict[str, LinkEvidence]:
    parsed = json.loads(output)
    return {
        item["ifname"]: LinkEvidence(
            name=item["ifname"],
            carrier="LOWER_UP" in item.get("flags", []) and item.get("operstate") == "UP",
            link_type=item.get("link_type", "unknown"),
            kind=item.get("linkinfo", {}).get("info_kind"),
        )
        for item in parsed
    }


def parse_ip_address_json(output: str) -> tuple[IPv4Network, ...]:
    networks: set[IPv4Network] = set()
    for interface in json.loads(output):
        for address in interface.get("addr_info", []):
            if address.get("family") != "inet" or address.get("scope") == "host":
                continue
            try:
                networks.add(ip_network(f"{address['local']}/{address['prefixlen']}", strict=False))
            except (KeyError, ValueError):
                continue
    return tuple(sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)))


def _parse_iw_dev(output: str) -> dict[str, str]:
    phy: str | None = None
    result: dict[str, str] = {}
    for raw in output.splitlines():
        line = raw.strip()
        match = re.fullmatch(r"phy#(\d+)", line)
        if match:
            phy = f"phy{match.group(1)}"
        elif line.startswith("Interface ") and phy:
            result[line.split(maxsplit=1)[1]] = phy
    return result


def discover_interfaces(
    ip_link_json: str,
    iw_list: str,
    iw_dev: str,
    ip_address_json: str = "[]",
    *,
    physical_interfaces: set[str] | frozenset[str] = frozenset(),
) -> InterfaceDiscovery:
    links = parse_ip_link_json(ip_link_json)
    modes = parse_iw_list(iw_list)
    wireless = _parse_iw_dev(iw_dev)
    ap = tuple(
        sorted(
            name
            for name, phy in wireless.items()
            if "AP" in modes.get(phy, set())
            and name in links
            and not links[name].carrier
        )
    )
    wan = tuple(
        sorted(
            name
            for name, link in links.items()
            if link.link_type == "ether"
            and link.carrier
            and link.kind is None
            and name in physical_interfaces
            and name not in wireless
        )
    )
    evidence = {name: f"{wireless[name]} supports AP" for name in ap}
    evidence.update({name: "Physical Ethernet carrier present" for name in wan})
    return InterfaceDiscovery(
        ap_interfaces=ap,
        wan_interfaces=wan,
        evidence=evidence,
        existing_networks=parse_ip_address_json(ip_address_json),
    )
