from abc import abstractmethod
from netaddr import IPAddress, IPNetwork
from pyASA.baseconfigobject import BaseConfigObject


class BaseAddress(BaseConfigObject):
    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict) -> object:
        raise NotImplementedError()

    @abstractmethod
    def to_dict(self):
        raise NotImplementedError()


class AnyAddress(BaseAddress):
    """
    Class used to represent ASA "any" keyword, meaning any IPv4 OR IPv6 address
    """

    @classmethod
    def from_dict(cls, data: dict):
        return cls()

    def to_dict(self):
        return dict(kind="AnyIPAddress", value="any")


class Address(BaseAddress, IPNetwork):
    def __init__(self, address: [str, IPAddress, IPNetwork]):
        if isinstance(address, str):
            if address == "any4":
                IPNetwork.__init__(self, "0.0.0.0/0")
            elif address == "any6":
                IPNetwork.__init__(self, "::/0")
            elif address == "any":
                raise ValueError("please use AnyAddress() object for \"any\" (IPv4+v6)")
            else:
                # This creates an IPNetwork object, then uses .cidr to correct possible wrong CIDR notations for a new object
                try:
                    IPNetwork.__init__(self, IPNetwork(address).cidr)
                except:
                    raise ValueError(f"{address} is not a valid or supported address")
        elif isinstance(address, IPAddress):
            IPNetwork.__init__(self, address)
        elif isinstance(address, IPNetwork):
            IPNetwork.__init__(self, address.cidr)
        else:
            raise ValueError(f"{type(address)} is not a valid argument type")

    @classmethod
    def from_dict(cls, data: dict) -> object:
        if data["kind"] in ["IPv4Address", "IPv6Address", "IPv4Network", "IPv6Network", "AnyIPv4Address",
                            "AnyIPv6Address"]:
            return cls(data["value"])
        elif data["kind"] in ["AnyAddress"]:
            return AnyAddress()
        else:
            raise ValueError(f"Object of kind '{data['kind']}' not supported")

    def to_dict(self):
        return dict(kind=f"IPv{self.version}Network", value=str(self.cidr))
