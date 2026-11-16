"""Pure validation for the authorized wired-WAN slice."""

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import re
from typing import Iterable

from .model import NetworkConfig


class ValidationError(ValueError):
    """A user configuration is unsafe or unsupported."""


ISO_ALPHA2 = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split()
)
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def _fail(message: str) -> None:
    raise ValidationError(message)


def validate_config(
    config: NetworkConfig, existing_networks: Iterable[IPv4Network] = ()
) -> NetworkConfig:
    if not config.ssid.strip() or not 1 <= len(config.ssid.encode("utf-8")) <= 32 or any(ord(c) < 32 for c in config.ssid):
        _fail("SSID must contain 1-32 printable UTF-8 bytes")
    if not 8 <= len(config.passphrase) <= 63 or any(ord(c) < 32 or ord(c) > 126 for c in config.passphrase):
        _fail("WPA2 passphrase must contain 8-63 printable ASCII characters")
    if config.country not in ISO_ALPHA2:
        _fail("country must be an uppercase ISO alpha-2 code")
    try:
        subnet = ip_network(config.subnet, strict=True)
    except ValueError as exc:
        raise ValidationError("subnet must be a canonical IPv4 network") from exc
    if not isinstance(subnet, IPv4Network) or subnet.prefixlen < 16 or subnet.prefixlen > 28 or not subnet.is_private:
        _fail("subnet must be a private IPv4 /16 through /28")
    try:
        resolver = ip_address(config.resolver)
    except ValueError as exc:
        raise ValidationError("resolver must be a usable IPv4 address") from exc
    if not isinstance(resolver, IPv4Address) or resolver.is_unspecified or resolver.is_loopback or resolver.is_multicast:
        _fail("resolver must be a usable non-local IPv4 address")
    if not IFACE_RE.fullmatch(config.ap_interface) or not IFACE_RE.fullmatch(config.wan_interface):
        _fail("interface names are invalid")
    if config.ap_interface == config.wan_interface:
        _fail("AP and WAN interfaces must be different")
    wireless_prefixes = ("wl", "wlan", "mlan", "wifi")
    if config.wan_interface.lower().startswith(wireless_prefixes):
        _fail("WAN must be wired Ethernet; same-radio STA+AP is unsupported")
    for existing in existing_networks:
        if subnet.overlaps(existing):
            _fail(f"AP subnet overlaps existing network {existing}")
    return config
