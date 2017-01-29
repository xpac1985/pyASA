from abc import abstractmethod
from netaddr import IPAddress, IPNetwork
from pyASA.baseconfigobject import BaseConfigObject


class BaseAddress(BaseConfigObject):
    """
    Abstract base class from which all Address classes are to be derived.
    """

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict) -> object:
        raise NotImplementedError()

    @abstractmethod
    def to_dict(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def to_dict(self) -> dict:
        raise NotImplementedError()


class AnyAddress(BaseAddress):
    """
    Class used to represent ASA "any" keyword, meaning any IPv4 AND IPv6 address.
    Used as this can not be represented by an IPNetwork object.
    """

    @classmethod
    def from_dict(cls, data: dict):
        return cls()

    def to_cli(self) -> str:
        return "any"

    def to_dict(self) -> dict:
        return dict(kind="AnyIPAddress", value="any")

    def __contains__(self, item) -> bool:
        """
        As "any" covers every valid IPv4 or IPv6 address, this is always true if tested with such an object.

        Args:
            item: object to be tested if contained in this object

        Returns:
            True if contained, False if not
        """
        if isinstance(item, [IPAddress, IPNetwork]):
            return True
        else:
            return False


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
                # This creates an IPNetwork object, then uses .cidr to correct possible wrong CIDR notations
                # Example: This converts "192.168.23.7/8" to "192.0.0.0/8"
                try:
                    address = address.replace(" ", "/")
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
    def from_cli(cls, line: str) -> object:
        """
        Return Address object based on part of ASA CLI address data.

        Args:
            line: string of CLI address line representation
             e.g. "host 192.168.23.4", "17.0.0.0/8", "2001:a::b/128", "host 2001:a::b", "2001:a::/32"

        Returns:
            new Address object, created from CLI data
        """
        line = line.replace("host ", "")
        return Address(line)

    def to_cli(self) -> str:
        """
        Return CLI string representation of Address object.

        Returns:
            string containing CLI representation
        """
        if self.version == 4:
            if str(self) == "0.0.0.0/0":
                return "any4"
            elif self.prefixlen == 32:
                return f"host {self.ip}"
            else:
                return f"{self.network} {self.netmask}"
        elif self.version == 6:
            if str(self) == "::/0":
                return "any6"
            elif self.prefixlen == 128:
                return f"host {self.ip}"
            else:
                return f"{self.cidr}"

    @classmethod
    def from_dict(cls, data: dict) -> object:
        """
        Return Address object based on part of ASA API JSON data.

        Args:
            line: dict containing JSON data from API
             e.g. {"kind": "IPv4Address", "value": "192.168.42.0/24"}

        Returns:
            new Address object, created from JSON data
        """
        if data["kind"] in ["IPv4Address", "IPv6Address", "IPv4Network", "IPv6Network", "AnyIPv4Address",
                            "AnyIPv6Address"]:
            return cls(data["value"])
        elif data["kind"] in ["AnyAddress"]:
            return AnyAddress()
        else:
            raise ValueError(f"Object of kind '{data['kind']}' not supported")

    def to_dict(self) -> dict:
        """
        Return API dict representation of Address object.

        Returns:
            dict structured like API JSON data for Address objects
        """
        if (self.version == 4 and self.prefixlen == 32) or (self.version == 6 and self.prefixlen == 128):
            return {"kind": f"IPv{self.version}Address", "value": str(self.ip)}
        elif self.prefixlen == 0:
            return {"kind": "AnyIPAddress", "value": f"any{self.version}"}
        else:
            return {"kind": f"IPv{self.version}Network", "value": str(self.cidr)}
