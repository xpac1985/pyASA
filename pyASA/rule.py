import copy
from enum import Enum
from netaddr import IPAddress, IPNetwork
from pyASA.address import BaseAddress, Address, AnyAddress
from pyASA.aliases import Aliases
from pyASA.baseconfigobject import BaseConfigObject
from pyASA.rulelogging import RuleLogging, LogLevel
import re


class ServiceComparator(Enum):
    EQUAL = ""
    NOT_EQUAL = "!="
    LESSER = "<"
    GREATER = ">"


def rule_from_dict(data: dict) -> object:
    if any(any(proto in value for proto in ("tcp", "udp")) for value in
           (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleTCPUDP.from_dict(data)
    elif any(any(proto in value for proto in ("icmp", "icmp6")) for value in
             (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleICMP.from_dict(data)
    else:
        return RuleGeneric.from_dict(data)


class RuleGeneric(BaseConfigObject):
    def __init__(self, permit: bool = False, protocol: [int, str] = "ip",
                 src: [str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: [str, IPAddress, IPNetwork, BaseAddress] = "any", remark: [None, str, list] = None,
                 active: bool = True,
                 logging: [RuleLogging, None] = None, position: int = 0, is_access_rule: bool = False, objectid: int = 0):

        self._permit = False
        self._protocol = 0
        self._src = AnyAddress()
        self._dst = AnyAddress()
        self._remark = []
        self._active = True
        self._logging = RuleLogging()
        self._position = 0
        self._is_access_rule = False
        self._objectid = 0

        self.permit = permit
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.remark = remark
        self.active = active
        self.logging = logging
        self.position = position
        self.is_access_rule = is_access_rule
        self.objectid = objectid

    @property
    def permit(self) -> bool:
        return self._permit

    @permit.setter
    def permit(self, value: bool):
        if isinstance(value, bool):
            self._permit = bool(value)
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def protocol(self) -> int:
        return self._protocol

    @protocol.setter
    def protocol(self, value: [int, str]):
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, str):
            if value in ["icmp", "icmp6"]:
                raise ValueError("Use a RuleICMP object for icmp/icmp6 rules")
            elif value in ["tcp", "udp"]:
                raise ValueError("Use a RuleTCPUDP object for tcp/udp rules")
            elif value in Aliases.by_alias["protocol"]:
                self._protocol = Aliases.by_alias["protocol"][value]
            else:
                raise ValueError(f"'{value}' is not a valid protocol alias")
        elif isinstance(value, int):
            if 0 <= value <= 255:
                if value not in [1, 6, 17, 58]:
                    self._protocol = value
                elif value in [1, 58]:
                    raise ValueError("Use a RuleICMP object for icmp/icmp6 rules")
                elif value in [6, 17]:
                    raise ValueError("Use a RuleTCPUDP object for tcp/udp rules")
            else:
                raise ValueError("protocol must be in range 0..255")
        else:
            raise ValueError("protocol must be an integer in range 0..255 or a valid protocol alias string")

    @property
    def protocol_alias(self) -> str:
        if self._protocol in Aliases.by_number["protocol"]:
            return Aliases.by_number["protocol"][self._protocol]
        else:
            return str(self._protocol)

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @src.setter
    def src(self, address: [str, IPAddress, IPNetwork, BaseAddress]):
        self._src = RuleGeneric._parse_address(address)

    @dst.setter
    def dst(self, address: [str, IPAddress, IPNetwork, BaseAddress]):
        self._dst = RuleGeneric._parse_address(address)

    @staticmethod
    def _parse_address(address: [str, IPAddress, IPNetwork, BaseAddress]):
        if isinstance(address, str):
            if address == "any":
                return AnyAddress()
            else:
                return Address(address)
        elif isinstance(address, BaseAddress):
            return copy.deepcopy(address)
        elif isinstance(address, (IPAddress, IPNetwork)):
            return Address(address)
        else:
            raise ValueError(f"{type(address)} is not a valid argument type")

    @property
    def remark(self) -> list:
        return self._remark

    @remark.setter
    def remark(self, value: [None, str, list]):
        if value is None:
            self._remark = []
        elif isinstance(value, str):
            self._remark = [str(value)]
        elif isinstance(value, list):
            self._remark = list(value)
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def active(self):
        return self._active

    @active.setter
    def active(self, value: bool):
        if isinstance(value, bool):
            self._active = bool(value)
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def logging(self):
        return self._logging

    @logging.setter
    def logging(self, value: RuleLogging):
        if value is None:
            self._logging = RuleLogging()
        elif isinstance(value, RuleLogging):
            self._logging = value
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def position(self):
        return self._position

    @position.setter
    def position(self, value: int):
        if isinstance(value, int):
            if value >= 0:
                self._position = int(value)
            else:
                raise ValueError("position must a positive integer")
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def is_access_rule(self):
        return self._is_access_rule

    @is_access_rule.setter
    def is_access_rule(self, value: bool):
        if isinstance(value, bool):
            self._is_access_rule = bool(value)
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @property
    def objectid(self):
        return self._objectid

    @objectid.setter
    def objectid(self, value: int):
        if isinstance(value, int):
            if value >= 0:
                self._objectid = int(value)
            else:
                raise ValueError("objectid must be a positive integer")
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @staticmethod
    def _parse_protocol_json(data: dict) -> int:
        _protocol = data["value"]
        if _protocol.isdigit():
            return int(_protocol)
        elif _protocol in Aliases.by_alias["protocol"]:
            return Aliases.by_alias["protocol"][_protocol]
        else:
            raise ValueError(f"{_protocol} is not a valid protocol alias")

    @classmethod
    def from_dict(cls, data: dict):
        permit = data["permit"]
        src = data["sourceAddress"]["value"]
        dst = data["destinationAddress"]["value"]
        protocol = RuleGeneric._parse_protocol_json(data["sourceService"])
        remark = data["remarks"]
        active = data["active"]
        logging = RuleLogging.from_dict(data["ruleLogging"]) if "ruleLogging" in data else None
        position = data["position"] if "position" in data else 0
        is_access_rule = data["isAccessRule"] if "isAccessRule" in data else False
        objectid = int(data["objectId"]) if "objectId" in data else 0
        return cls(permit, protocol, src, dst, remark, active, logging, position, is_access_rule, objectid)

    def to_dict(self) -> dict:
        result = {}
        result["permit"] = self._permit
        result["sourceAddress"] = self._src.to_dict()
        result["destinationAddress"] = self._dst.to_dict()
        result["sourceService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        result["destinationService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        result["active"] = self._active
        result["remarks"] = self._remark
        result["ruleLogging"] = self._logging.to_dict()
        if self._position > 0:
            result["position"] = self._position
        result["isAccessRule"] = self._is_access_rule
        if self._objectid > 0:
            result["objectId"] = self._objectid
        return result

    def __eq__(self, other):
        if isinstance(other, RuleGeneric):
            return self.to_dict() == other.to_dict()
        else:
            return False


class RuleTCPUDP(RuleGeneric):
    def __init__(self, permit: bool = False, protocol: [int, str] = "tcp",
                 src: [str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: [str, IPAddress, IPNetwork, BaseAddress] = "any",
                 src_port: [int, str] = "any", dst_port: [int, str] = "any",
                 src_comparator: ServiceComparator = ServiceComparator.EQUAL,
                 dst_comparator: ServiceComparator = ServiceComparator.EQUAL,
                 remark: [None, str, list] = None, active: bool = True, logging: [RuleLogging, None] = None,
                 position: int = 0, is_access_rule: bool = False, objectid: int = 0):

        RuleGeneric.__init__(self, permit, protocol, src, dst, remark, active, logging, position, is_access_rule,
                             objectid)

        self._src_port = -1
        self._dst_port = -1
        self._src_comparator = ServiceComparator.EQUAL
        self._dst_comparator = ServiceComparator.EQUAL

        self.src_port = src_port
        self.dst_port = dst_port
        self.src_comparator = src_comparator
        self.dst_comparator = dst_comparator

    @property
    def protocol(self) -> int:
        return self._protocol

    @protocol.setter
    def protocol(self, value: [int, str]):
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, int):
            if value in [6, 17]:
                self._protocol = value
            elif value in [1, 58]:
                raise ValueError("Use a RuleICMP object for ICMP/ICMP6 rules")
            else:
                raise ValueError("Use a RuleGeneric object for non TCP/UDP rules")
        elif type(value) is str:
            if value in ["tcp", "udp"]:
                self._protocol = Aliases.by_alias["protocol"][value]
            elif value in ["icmp", "icmp6"]:
                raise ValueError("Use a RuleICMP object for ICMP/ICMP6 rules")
            else:
                raise ValueError("Use a RuleGeneric object for non TCP/UDP rules")
        else:
            raise ValueError("protocol must be either 6 for tcp, 17 for udp or \"tcp\" or \"udp\" protcol alias string")

    @property
    def protocol_alias(self):
        return "tcp" if self._protocol == 6 else "udp"

    @property
    def src_port(self):
        return self._src_port

    @property
    def dst_port(self):
        return self._dst_port

    @src_port.setter
    def src_port(self, value: [int, str]):
        self._src_port = self._parse_port(value)

    @dst_port.setter
    def dst_port(self, value: [int, str]):
        self._dst_port = self._parse_port(value)

    def _parse_port(self, port: [int, str]) -> int:
        if isinstance(port, str) and (port.isdigit() or port == "-1"):
            port = int(port)
        if isinstance(port, str):
            if port in Aliases.by_alias[self.protocol_alias]:
                return Aliases.by_alias[self.protocol_alias][port]
            else:
                raise ValueError(f"{type} is not a valid {self.protocol_alias} service alias")
        elif isinstance(port, int):
            if 1 <= port <= 65535 or port == -1:
                return int(port)
            else:
                raise ValueError("port must be in range 1..65535 or -1 for any")
        else:
            raise ValueError(f"{type(port)} is not a valid argument type")

    @property
    def src_port_alias(self):
        return self._get_port_alias(self._src_port)

    @property
    def dst_port_alias(self):
        return self._get_port_alias(self._dst_port)

    def _get_port_alias(self, port: int) -> str:
        if port == -1:
            return "any"
        elif port in Aliases.by_number[self.protocol_alias]:
            return Aliases.by_number[self.protocol_alias][port]
        else:
            return str(port)

    @property
    def src_comparator(self):
        return self._src_comparator

    @property
    def dst_comparator(self):
        return self._dst_comparator

    @src_comparator.setter
    def src_comparator(self, value: ServiceComparator):
        self._src_comparator = self._set_comparator(value)

    @dst_comparator.setter
    def dst_comparator(self, value: ServiceComparator):
        self._dst_comparator = self._set_comparator(value)

    @staticmethod
    def _set_comparator(value: [ServiceComparator, str]) -> ServiceComparator:
        if isinstance(value, ServiceComparator):
            return value
        if isinstance(value, str):
            if value in [enum.value for enum in ServiceComparator]:
                return ServiceComparator(value)
            else:
                raise ValueError(f"{value} is not a valid ServiceComparator alias")
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @staticmethod
    def _parse_port_json(data: dict) -> tuple:
        regex = re.compile(r"^(|(?:!=)?|<?|>?)(tcp|udp)/([a-z-]+|[0-9]+)$")
        if data["kind"] == "NetworkProtocol":
            protocol = data["value"]
            port = "any"
            comparator = ServiceComparator.EQUAL
        else:
            finder = regex.match(data["value"])
            if finder is not None:
                comparator = ServiceComparator(finder.group(1))
                protocol = finder.group(2)
                port = finder.group(3)
                if port.isdigit():
                    port = int(port)
            else:
                raise ValueError(f"{data} is not valid Service JSON data")
        return protocol, port, comparator

    @classmethod
    def from_dict(cls, data: dict):
        permit = data["permit"]
        src = data["sourceAddress"]["value"]
        dst = data["destinationAddress"]["value"]
        protocol, src_port, src_comparator = RuleTCPUDP._parse_port_json(data["sourceService"])
        __, dst_port, dst_comparator = RuleTCPUDP._parse_port_json(data["destinationService"])
        remark = data["remarks"]
        active = data["active"]
        logging = RuleLogging.from_dict(data["ruleLogging"]) if "ruleLogging" in data else None
        position = data["position"] if "position" in data else 0
        is_access_rule = data["isAccessRule"] if "isAccessRule" in data else False
        objectid = int(data["objectId"]) if "objectId" in data else 0
        return cls(permit, protocol, src, dst, src_port, dst_port, src_comparator, dst_comparator, remark, active,
                   logging, position, is_access_rule, objectid)

    def to_dict(self) -> dict:
        result = RuleGeneric.to_dict(self)
        if self._src_port == -1:
            result["sourceService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            result["sourceService"] = {
                "kind": "TcpUdpService",
                "value": f"{self._src_comparator.value}{self.protocol_alias}/{self.src_port_alias}"
            }
        if self._dst_port == -1:
            result["destinationService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            result["destinationService"] = {
                "kind": "TcpUdpService",
                "value": f"{self._dst_comparator.value}{self.protocol_alias}/{self.dst_port_alias}"
            }
        return result


class RuleICMP(RuleGeneric):
    def __init__(self, permit: bool = False, protocol: [int, str] = "icmp",
                 src: [str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: [str, IPAddress, IPNetwork, BaseAddress] = "any", icmp_type: [str, int] = "any",
                 icmp_code: [int, str] = "any", remark: [None, str, list] = None, active: bool = True,
                 logging: [RuleLogging, None] = None,
                 position: int = 0, is_access_rule: bool = False, objectid: int = 0):

        RuleGeneric.__init__(self, permit, protocol, src, dst, remark, active, logging, position, is_access_rule,
                             objectid)

        self._icmp_type = -1
        self._icmp_code = -1

        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    @property
    def protocol(self) -> int:
        return self._protocol

    @protocol.setter
    def protocol(self, value: [int, str]):
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        if isinstance(value, int):
            if value in [1, 58]:
                self._protocol = value
            elif value in [6, 17]:
                raise ValueError("Use a RuleTCPUDP object for TCP/UDP rules")
            else:
                raise ValueError("Use a RuleGeneric object for non ICMP/ICMP6 rules")
        elif type(value) is str:
            if value in ["icmp", "icmp6"]:
                self._protocol = Aliases.by_alias["protocol"][value]
            elif value in ["tcp", "udp"]:
                raise ValueError("Use a RuleICMP object for TCP/UDP rules")
            else:
                raise ValueError("Use a RuleGeneric object for non ICMP/ICMP6 rules")
        else:
            raise ValueError(
                "protocol must be either 1 for icmp, 58 for icmp6 or \"icmp\" or \"icmp6\" protcol alias string")

    @property
    def protocol_alias(self):
        return "icmp" if self._protocol == 1 else "icmp6"

    @property
    def icmp_type(self):
        return self._icmp_type

    @icmp_type.setter
    def icmp_type(self, icmp_type: [int, str]):
        if isinstance(icmp_type, str) and (icmp_type.isdigit() or icmp_type == "-1"):
            icmp_type = int(icmp_type)
        if isinstance(icmp_type, str):
            if icmp_type in Aliases.by_alias[self.protocol_alias]:
                self._icmp_type = Aliases.by_alias[self.protocol_alias][icmp_type]
            else:
                raise ValueError(f"{type} is not a valid {self.protocol_alias} service alias")
        elif isinstance(icmp_type, int):
            if -1 <= icmp_type <= 255:
                self._icmp_type = int(icmp_type)
            else:
                raise ValueError("icmp_type must be in range 0..255 or -1 for any")
        else:
            raise ValueError(f"{type(icmp_type)} is not a valid argument type")

    @property
    def icmp_type_alias(self):
        if self._icmp_type in Aliases.by_number[self.protocol_alias]:
            return Aliases.by_number[self.protocol_alias][self._icmp_type]
        else:
            return str(self._icmp_type)

    @property
    def icmp_code(self):
        return self._icmp_code

    @icmp_code.setter
    def icmp_code(self, icmp_code: [int, str]):
        if isinstance(icmp_code, str) and (icmp_code.isdigit() or icmp_code == "-1"):
            icmp_code = int(icmp_code)
        if isinstance(icmp_code, str):
            if icmp_code == "any":
                self._icmp_code = -1
            else:
                raise ValueError("icmp_code only allows \"any\" as string argument")
        elif isinstance(icmp_code, int):
            if -1 <= icmp_code <= 255:
                self._icmp_code = int(icmp_code)
            else:
                raise ValueError("icmp_code must be in range 0..255 or -1 for any")
        else:
            raise ValueError(f"{type(icmp_code)} is not a valid argument type")

    @staticmethod
    def _parse_icmp_json(data: dict) -> tuple:
        regex = re.compile(r"^(icmp6?)/([a-z-]+|[0-9]+)/?(\d{0,3})$")
        if data["kind"] == "NetworkProtocol" and data["value"] in ["icmp", "icmp6"]:
            protocol = data["value"]
            icmp_type = -1
            icmp_code = -1
        elif data["kind"] == "ICMPService":
            finder = regex.match(data["value"])
            if finder is not None:
                protocol = finder.group(1)
                icmp_type = finder.group(2)
                if icmp_type.isdigit():
                    icmp_type = int(icmp_type)
                icmp_code = -1
                if finder.group(3).isdigit():
                    icmp_code = int(finder.group(3))
            else:
                raise ValueError(f"{data} is no valid ICMP/ICMP6 Service JSON data")
        else:
            raise ValueError(f"{data} is no valid ICMP/ICMP6 Service JSON data")
        return protocol, icmp_type, icmp_code

    @classmethod
    def from_dict(cls, data: dict):
        permit = data["permit"]
        src = data["sourceAddress"]["value"]
        dst = data["destinationAddress"]["value"]
        protocol, icmp_type, icmp_code = RuleICMP._parse_icmp_json(data["destinationService"])
        remark = data["remarks"]
        active = data["active"]
        logging = RuleLogging.from_dict(data["ruleLogging"]) if "ruleLogging" in data else None
        position = data["position"] if "position" in data else 0
        is_access_rule = data["isAccessRule"] if "isAccessRule" in data else False
        objectid = int(data["objectId"]) if "objectId" in data else 0
        return cls(permit, protocol, src, dst, icmp_type, icmp_code, remark, active, logging, position, is_access_rule,
                   objectid)

    def to_dict(self) -> dict:
        result = RuleGeneric.to_dict(self)
        result["sourceService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        if self._icmp_type == -1:
            result["destinationService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            if self._icmp_code == -1:
                result["destinationService"] = {
                    "kind": "ICMPService",
                    "value": f"{self.protocol_alias}/{self.icmp_type_alias}"
                }
            else:
                result["destinationService"] = {
                    "kind": "ICMPService",
                    "value": f"{self.protocol_alias}/{self.icmp_type_alias}/{self.icmp_code}"
                }
        return result
