from ipaddress import ip_network

import pytest

from gitm.model import NetworkConfig
from gitm.validation import ValidationError, validate_config


def valid_config(**overrides):
    values = {
        "ssid": "GITM-C0-7A2F",
        "passphrase": "vivid-nimbus-4821",
        "country": "US",
        "subnet": "192.168.77.0/24",
        "resolver": "1.1.1.1",
        "ap_interface": "wlan1",
        "wan_interface": "enp2s0",
    }
    values.update(overrides)
    return NetworkConfig(**values)


@pytest.mark.parametrize("ssid", ["", " " * 3, "x" * 33, "bad\nname"])
def test_rejects_invalid_ssid(ssid):
    with pytest.raises(ValidationError, match="SSID"):
        validate_config(valid_config(ssid=ssid))


@pytest.mark.parametrize("passphrase", ["short", "x" * 64, "bad\npass"])
def test_rejects_invalid_wpa2_passphrase(passphrase):
    with pytest.raises(ValidationError, match="passphrase"):
        validate_config(valid_config(passphrase=passphrase))


@pytest.mark.parametrize("country", ["USA", "u1", "us", ""])
def test_rejects_non_iso_alpha2_country(country):
    with pytest.raises(ValidationError, match="country"):
        validate_config(valid_config(country=country))


@pytest.mark.parametrize("subnet", ["not-a-network", "0.0.0.0/0", "192.168.77.1/24", "2001:db8::/64"])
def test_rejects_unsafe_ap_subnet(subnet):
    with pytest.raises(ValidationError, match="subnet"):
        validate_config(valid_config(subnet=subnet))


@pytest.mark.parametrize("resolver", ["invalid", "127.0.0.1", "0.0.0.0", "2001:4860:4860::8888"])
def test_rejects_unsafe_resolver(resolver):
    with pytest.raises(ValidationError, match="resolver"):
        validate_config(valid_config(resolver=resolver))


def test_rejects_same_interface_for_ap_and_wan():
    with pytest.raises(ValidationError, match="different"):
        validate_config(valid_config(wan_interface="wlan1"))


def test_rejects_same_radio_sta_plus_ap():
    with pytest.raises(ValidationError, match="wired Ethernet"):
        validate_config(valid_config(wan_interface="wlp2s0"))


def test_rejects_subnet_overlap_with_existing_networks():
    with pytest.raises(ValidationError, match="overlaps"):
        validate_config(valid_config(), existing_networks=[ip_network("192.168.77.128/25")])


def test_accepts_valid_wired_wan_configuration():
    assert validate_config(valid_config(), existing_networks=[ip_network("10.0.0.0/8")]) == valid_config()


@pytest.mark.parametrize('field,value', [('ssid', None), ('country', []), ('subnet', {}), ('resolver', 123), ('ap_interface', None)])
def test_network_configuration_rejects_wrong_types_with_validation_error(field, value):
    from dataclasses import replace
    from gitm.model import NetworkConfig
    candidate = NetworkConfig('Lab', 'lab-test-4821', 'US', '192.168.77.0/24', '1.1.1.1', 'wlan1', 'end0')
    with pytest.raises(ValueError, match='text'):
        validate_config(replace(candidate, **{field: value}))
