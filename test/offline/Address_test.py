import json

import pytest

from pyASA.address import AnyAddress, Address


class Test_AnyAddress(object):
    def test_to_dict(self):
        assert AnyAddress().to_dict() == {"kind": "AnyIPAddress", "value": "any"}

    def test_to_json(self):
        assert AnyAddress().to_json() == json.dumps({"kind": "AnyIPAddress", "value": "any"}, indent=2)


class Test_Address(object):
    def test_init_fail(self):
        with pytest.raises(ValueError):
            Address("apiureu4wor")
        with pytest.raises(ValueError):
            Address("5.3.2.4.5")
        with pytest.raises(ValueError):
            Address("asa.local")
        with pytest.raises(ValueError):
            Address("any")
        with pytest.raises(ValueError):
            Address(3)
        with pytest.raises(ValueError):
            Address(None)

    def test_init_okay(self):
        assert Address("4.3.2.1").to_dict() == {"kind": "IPv4Address", "value": "4.3.2.1"}
        assert Address("4.1").to_dict() == {"kind": "IPv4Address", "value": "4.1.0.0"}
        assert Address("::1/128").to_dict() == {"kind": "IPv6Address", "value": "::1"}
        assert Address("2001:a::ffd").to_dict() == {"kind": "IPv6Address", "value": "2001:a::ffd"}
        assert Address("10.5.3.0/24").to_dict() == {"kind": "IPv4Network", "value": "10.5.3.0/24"}
        assert Address("200a:a7::/32").to_dict() == {"kind": "IPv6Network", "value": "200a:a7::/32"}
        assert Address("2001:1234:0000:00:0000:0::7890").to_dict() == {"kind": "IPv6Address",
                                                                       "value": "2001:1234::7890"}
        assert Address("2001:adf:7::/16").to_dict() == {"kind": "IPv6Network", "value": "2001::/16"}

    def test_from_dict_any(self):
        assert type(Address.from_dict({"kind": "AnyAddress", "value": "any"})) is AnyAddress
