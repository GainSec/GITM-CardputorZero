from gitm.discovery import discover_interfaces, parse_ip_address_json, parse_iw_list, parse_ip_link_json


IW_LIST = """
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\tBand 1:
Wiphy phy1
\tSupported interface modes:
\t\t * managed
"""

IP_LINK = """[
  {"ifindex": 2, "ifname": "enp2s0", "flags": ["BROADCAST", "UP", "LOWER_UP"], "operstate": "UP", "link_type": "ether"},
  {"ifindex": 3, "ifname": "wlan1", "flags": ["BROADCAST", "UP"], "operstate": "DOWN", "link_type": "ether"},
  {"ifindex": 4, "ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN", "link_type": "loopback"}
]"""

IW_DEV = """
phy#0
\tInterface wlan1
\t\tifindex 3
\t\ttype managed
"""

IP_ADDRESS = """[
  {"ifname": "enp2s0", "addr_info": [{"family": "inet", "local": "10.23.4.8", "prefixlen": 16, "scope": "global"}]},
  {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]}
]"""


def test_parses_ap_capability_evidence_per_phy():
    assert parse_iw_list(IW_LIST) == {"phy0": {"managed", "AP"}, "phy1": {"managed"}}


def test_parses_ethernet_carrier_evidence():
    links = parse_ip_link_json(IP_LINK)
    assert links["enp2s0"].carrier is True
    assert links["wlan1"].carrier is False


def test_discovers_only_ap_capable_radio_and_linked_wired_wan():
    result = discover_interfaces(IP_LINK, IW_LIST, IW_DEV, physical_interfaces={"enp2s0"})
    assert result.ap_interfaces == ("wlan1",)
    assert result.wan_interfaces == ("enp2s0",)
    assert result.evidence["wlan1"] == "phy0 supports AP"
    assert result.evidence["enp2s0"] == "Physical Ethernet carrier present"


def test_discovery_rejects_an_associated_sta_as_the_ap_radio():
    associated = IP_LINK.replace(
        '"ifname": "wlan1", "flags": ["BROADCAST", "UP"], "operstate": "DOWN"',
        '"ifname": "wlan1", "flags": ["BROADCAST", "UP", "LOWER_UP"], "operstate": "UP"',
    )
    result = discover_interfaces(associated, IW_LIST, IW_DEV, physical_interfaces={"enp2s0"})
    assert result.ap_interfaces == ()
    assert result.wan_interfaces == ("enp2s0",)


def test_discovery_does_not_assume_interface_names():
    renamed = IP_LINK.replace("enp2s0", "end0").replace("wlan1", "mlan0")
    result = discover_interfaces(
        renamed, IW_LIST, IW_DEV.replace("wlan1", "mlan0"), physical_interfaces={"end0"}
    )
    assert result.ap_interfaces == ("mlan0",)
    assert result.wan_interfaces == ("end0",)


def test_parses_existing_non_loopback_ipv4_networks_for_overlap_checks():
    assert tuple(map(str, parse_ip_address_json(IP_ADDRESS))) == ("10.23.0.0/16",)


def test_discovery_carries_existing_network_evidence():
    result = discover_interfaces(IP_LINK, IW_LIST, IW_DEV, IP_ADDRESS, physical_interfaces={"enp2s0"})
    assert tuple(map(str, result.existing_networks)) == ("10.23.0.0/16",)


def test_discovery_excludes_virtual_and_device_facing_ethernet():
    links = """[
      {"ifname":"end0","flags":["UP","LOWER_UP"],"operstate":"UP","link_type":"ether"},
      {"ifname":"br0","flags":["UP","LOWER_UP"],"operstate":"UP","link_type":"ether","linkinfo":{"info_kind":"bridge"}},
      {"ifname":"veth0","flags":["UP","LOWER_UP"],"operstate":"UP","link_type":"ether","linkinfo":{"info_kind":"veth"}},
      {"ifname":"usb0","flags":["UP","LOWER_UP"],"operstate":"UP","link_type":"ether"},
      {"ifname":"mlan0","flags":["UP"],"operstate":"DOWN","link_type":"ether"}
    ]"""
    result = discover_interfaces(
        links, IW_LIST, IW_DEV.replace("wlan1", "mlan0"),
        physical_interfaces={"end0", "br0", "veth0"},
    )
    assert result.wan_interfaces == ("end0",)


def test_cardputer_internal_usb_ethernet_qualifies_with_sysfs_device_evidence():
    links = IP_LINK.replace("enp2s0", "usb0")
    result = discover_interfaces(links, IW_LIST, IW_DEV, physical_interfaces={"usb0"})
    assert result.wan_interfaces == ("usb0",)
