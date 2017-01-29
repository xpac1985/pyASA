import copy
import re
from enum import Enum
from random import randint, choice, getrandbits

from netaddr import IPAddress, IPNetwork

from pyASA.address import BaseAddress, Address, AnyAddress
from pyASA.aliases import Aliases
from pyASA.baseconfigobject import BaseConfigObject
from pyASA.rulelogging import RuleLogging, LogLevel


class ServiceComparator(Enum):
    EQUAL = ""
    NOT_EQUAL = "!="
    LESSER = "<"
    GREATER = ">"

    def to_cli(self) -> str:
        translate = {self.EQUAL: "eq", self.NOT_EQUAL: "neq", self.LESSER: "lt", self.GREATER: "gt"}
        return translate[self]

    @classmethod
    def from_cli(cls, line: str) -> object:
        translate = {"eq": cls.EQUAL, "neq": cls.NOT_EQUAL, "lt": cls.LESSER, "gt": cls.GREATER}
        return translate[line]


def rule_from_cli(line: str) -> object:
    # very complex regular expression roughly validating and seperating valid ASA ACL CLI lines.
    # For understanding and debugging see https://regex101.com/ or https://www.debuggex.com/
    cli_line_regex = r"^(?:(?:access-list (?P<acl>[\w\d]+) (?:line (?P<line>\d+) )?)?extended )?(?P<permit>deny|permit) (?P<proto>\w+) (?P<src>any[46]?|host \d{1,3}(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3} \d{1,3}(?:\.\d{1,3}){3}|(?:host )?(?:[0-9a-f]{0,4}:){2,7}(?::|[0-9a-f]{0,4})(?:\/\d{1,3})?)(?: (?P<srccomp>eq|neq|gt|lt) (?P<srcport>\d{1,5}|[\d\w-]+))? (?P<dst>any[46]?|host \d{1,3}(?:\.\d{1,3}){3}|\d{1,3}(?:\.\d{1,3}){3} \d{1,3}(?:\.\d{1,3}){3}|(?:host )?(?:[0-9a-f]{0,4}:){2,7}(?::|[0-9a-f]{0,4})(?:\/\d{1,3})?)(?:(?: (?P<dstcomp>eq|neq|gt|lt) (?P<dstport>\d{1,5}|[\d\w-]+))|\s(?P<icmptype>[a-z\d-]+)\s?(?P<icmpcode>\d{1,3})?)?(?: log (?P<level>\w+)(?: interval (?P<interval>\d+))?(?: (?P<active>inactive))?)?$"
    regex = re.compile(cli_line_regex)
    finder = regex.fullmatch(line)
    if finder is None:
        raise ValueError("line parameter is not a valid ACL cli line")
    permit = True if finder.group("permit") == "permit" else False
    active = False if finder.group("active") else True
    proto = Aliases.by_alias["protocol"][finder.group("proto")] if finder.group("proto") in Aliases.by_alias[
        "protocol"] else int(finder.group("proto"))
    src = Address.from_cli(finder.group("src")) if finder.group("src") != "any" else AnyAddress()
    dst = Address.from_cli(finder.group("dst")) if finder.group("dst") != "any" else AnyAddress()
    if finder.group("level"):
        if finder.group("interval"):
            log = RuleLogging(interval=int(finder.group("interval")), level=LogLevel.from_cli(finder.group("level")))
        else:
            log = RuleLogging(level=LogLevel.from_cli(finder.group("level")))
    else:
        log = RuleLogging()
    position = int(finder.group("line")) if finder.group("line") else 0
    if proto in [6, 17]:
        srcport = finder.group("srcport") if finder.group("srcport") else -1
        dstport = finder.group("dstport") if finder.group("srcport") else -1
        srccomp = ServiceComparator.from_cli(finder.group("srccomp")) if finder.group(
            "srccomp") else ServiceComparator.EQUAL
        dstcomp = ServiceComparator.from_cli(finder.group("dstcomp")) if finder.group(
            "srccomp") else ServiceComparator.EQUAL
        return RuleTCPUDP(permit=permit, protocol=proto, src=src, dst=dst, active=active, logging=log, src_port=srcport,
                          dst_port=dstport, src_comparator=srccomp, dst_comparator=dstcomp, position=position)
    elif proto in [1, 58]:
        type = finder.group("icmptype") if finder.group("icmptype") else -1
        code = int(finder.group("icmpcode")) if finder.group("icmpcode") else -1
        return RuleICMP(permit=permit, protocol=proto, src=src, dst=dst, active=active, logging=log, icmp_type=type,
                        icmp_code=code, position=position)
    else:
        return RuleGeneric(permit=permit, protocol=proto, src=src, dst=dst, active=active, logging=log,
                           position=position)


def random_rule() -> object:
    type = randint(1, 4)
    if type == 1:
        return RuleTCPUDP.random_rule()
    elif type == 2:
        return RuleICMP.random_rule()
    else:
        return RuleGeneric.random_rule()


class RuleGeneric(BaseConfigObject):
    def __init__(self, permit: bool = False, protocol: [int, str] = "ip",
                 src: [str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: [str, IPAddress, IPNetwork, BaseAddress] = "any", remark: [None, str, list] = None,
                 active: bool = True,
                 logging: [RuleLogging, None] = None, position: int = 0, is_access_rule: bool = False,
                 objectid: int = 0):

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

    @classmethod
    def _parse_address(cls, address: [str, IPAddress, IPNetwork, BaseAddress]):
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

    @property
    def objectid_hexhash(self):
        return hex(self._objectid)

    @classmethod
    def _parse_protocol_json(cls, data: dict) -> int:
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

    def to_cli(self, acl: [None, str] = None) -> str:
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {self.dst.to_cli()} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

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

    def copy(self):
        rule = copy.deepcopy(self)
        rule.objectid = 0
        return rule

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RuleGeneric):
            return self.to_dict() == other.to_dict()
        else:
            return False

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, RuleGeneric):
            return False
        if item.permit != self.permit:
            return False
        if 0 < self.protocol != item.protocol:
            return False
        if not isinstance(self.src, AnyAddress) and item.src not in self.src:
            return False
        if not isinstance(self.dst, AnyAddress) and item.dst not in self.dst:
            return False
        if item.active != self.active:
            return False
        return True

    @classmethod
    def random_rule(cls) -> object:
        """
        Return a non-[TCP/UDP/ICMP/ICMP6] rule, with all values besides remark and is_access_rule randomly chosen.

        Mainly used for testing

        Returns:
            random rule object
        """
        permit = choice([True, False])
        active = choice([True, False])
        protocol = choice([i for i in range(0, 256) if i not in [1, 6, 17, 58]])
        if choice([4, 6]) == 6:
            if choice([True, False]):
                src = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                src = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                dst = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
        else:
            if choice([True, False]):
                src = IPAddress(randint(0, 4294967295), version=4)
            else:
                src = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 4294967295), version=4)
            else:
                dst = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
        log = RuleLogging(choice([level for level in LogLevel]), randint(1, 300))
        position = randint(0, 65535)
        objectid = randint(0, 4294967295)
        rule = cls(permit=permit, protocol=protocol, src=src, dst=dst, logging=log, active=active, position=position,
                   objectid=objectid)
        return rule


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
                raise ValueError(f"{port} is not a valid {self.protocol_alias} service alias")
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

    @classmethod
    def _set_comparator(cls, value: [ServiceComparator, str]) -> ServiceComparator:
        if isinstance(value, ServiceComparator):
            return value
        if isinstance(value, str):
            if value in [enum.value for enum in ServiceComparator]:
                return ServiceComparator(value)
            else:
                raise ValueError(f"{value} is not a valid ServiceComparator alias")
        else:
            raise ValueError(f"{type(value)} is not a valid argument type")

    @classmethod
    def _parse_port_json(cls, data: dict) -> tuple:
        regex = re.compile(r"^(|(?:!=)?|<?|>?)(tcp|udp)/([a-z0-9-]+)$")
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
    def from_dict(cls, data: dict) -> object:
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

    def to_cli(self, acl: [None, str] = None) -> str:
        src_port = "" if self.src_port == -1 else f"{self.src_comparator.to_cli()} {self.src_port_alias}"
        dst_port = "" if self.dst_port == -1 else f"{self.dst_comparator.to_cli()} {self.dst_port_alias}"
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {src_port} {self.dst.to_cli()} {dst_port} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

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

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, RuleTCPUDP):
            return False
        if not RuleGeneric.__contains__(self, item):
            return False
        if self.src_port != -1:
            if item.src_port == -1:
                return False
            if self.src_comparator in [ServiceComparator.EQUAL, ServiceComparator.NOT_EQUAL]:
                if item.src_comparator != self.src_comparator:
                    return False
                elif item.src_port != self.src_port:
                    return False
            elif self.src_comparator == ServiceComparator.GREATER:
                if item.src_comparator in [ServiceComparator.LESSER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.src_comparator == ServiceComparator.EQUAL:
                    if item.src_port <= self.src_port:
                        return False
                elif item.src_comparator == ServiceComparator.GREATER:
                    if item.src_port < self.src_port:
                        return False
            elif self.src_comparator == ServiceComparator.LESSER:
                if item.src_comparator in [ServiceComparator.GREATER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.src_comparator == ServiceComparator.EQUAL:
                    if item.src_port >= self.src_port:
                        return False
                elif item.src_comparator == ServiceComparator.LESSER:
                    if item.src_port > self.src_port:
                        return False
        if self.dst_port != -1:
            if item.dst_port == -1:
                return False
            if self.dst_comparator in [ServiceComparator.EQUAL, ServiceComparator.NOT_EQUAL]:
                if item.dst_comparator != self.dst_comparator:
                    return False
                elif item.dst_port != self.dst_port:
                    return False
            elif self.dst_comparator == ServiceComparator.GREATER:
                if item.dst_comparator in [ServiceComparator.LESSER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.dst_comparator == ServiceComparator.EQUAL:
                    if item.dst_port <= self.dst_port:
                        return False
                elif item.dst_comparator == ServiceComparator.GREATER:
                    if item.dst_port < self.dst_port:
                        return False
            elif self.dst_comparator == ServiceComparator.LESSER:
                if item.dst_comparator in [ServiceComparator.GREATER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.dst_comparator == ServiceComparator.EQUAL:
                    if item.dst_port >= self.dst_port:
                        return False
                elif item.dst_comparator == ServiceComparator.LESSER:
                    if item.dst_port > self.dst_port:
                        return False
        return True

    @classmethod
    def random_rule(cls) -> object:
        """
        Return a random TCP or UDP rule, with all values besides remark and is_access_rule randomly chosen.

        Mainly used for testing

        Returns:
            random rule object
        """
        permit = choice([True, False])
        active = choice([True, False])
        protocol = choice(["tcp", "udp"])
        if choice([4, 6]) == 6:
            if choice([True, False]):
                src = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                src = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                dst = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
        else:
            if choice([True, False]):
                src = IPAddress(randint(0, 4294967295), version=4)
            else:
                src = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 4294967295), version=4)
            else:
                dst = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
        src_port = randint(0, 65535)
        if src_port == 0:
            src_port = -1
        dst_port = randint(0, 65535)
        if dst_port == 0:
            dst_port = -1
        src_comp = choice([comp for comp in ServiceComparator])
        dst_comp = choice([comp for comp in ServiceComparator])
        log = RuleLogging(choice([level for level in LogLevel]), randint(1, 300))
        position = randint(0, 65535)
        objectid = randint(0, 4294967295)
        rule = cls(permit=permit, protocol=protocol, src=src, dst=dst, src_port=src_port, dst_port=dst_port,
                   src_comparator=src_comp, dst_comparator=dst_comp, logging=log, active=active,
                   position=position, objectid=objectid)
        return rule


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

    @classmethod
    def _parse_icmp_json(cls, data: dict) -> tuple:
        regex = re.compile(r"^(icmp6?)/([a-z-]+|[0-9]+)/?(\d{0,3})$")
        if data["kind"] == "NetworkProtocol" and data["value"] in ["icmp", "icmp6"]:
            protocol = data["value"]
            icmp_type = -1
            icmp_code = -1
        elif data["kind"] in ["ICMPService", "ICMP6Service"]:
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

    def to_cli(self, acl: [None, str] = None) -> str:
        if self.icmp_type == -1:
            icmp = ""
        else:
            if self.icmp_code == -1:
                icmp = f"{self.icmp_type_alias}"
            else:
                icmp = f"{self.icmp_type_alias} {self.icmp_code}"
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {self.dst.to_cli()} {icmp} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

    def to_dict(self) -> dict:
        result = RuleGeneric.to_dict(self)
        result["sourceService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        if self._icmp_type == -1:
            result["destinationService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            if self._icmp_code == -1:
                result["destinationService"] = {
                    "kind": f"{self.protocol_alias.upper()}Service",
                    "value": f"{self.protocol_alias}/{self.icmp_type_alias}"
                }
            else:
                result["destinationService"] = {
                    "kind": f"{self.protocol_alias.upper()}Service",
                    "value": f"{self.protocol_alias}/{self.icmp_type_alias}/{self.icmp_code}"
                }
        return result

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, RuleICMP):
            return False
        if not RuleGeneric.__contains__(self, item):
            return False
        if self.icmp_type != -1:
            if item.icmp_type != self.icmp_type:
                return False
            if self.icmp_code != -1:
                if item.icmp_code != self.icmp_code:
                    return False
        return True

    @classmethod
    def random_rule(cls) -> object:
        """
        Return a random ICMP or ICMP6 rule, with all values besides remark and is_access_rule randomly chosen.

        Mainly used for testing

        Returns:
            random rule object
        """
        permit = choice([True, False])
        active = choice([True, False])
        protocol = choice(["icmp", "icmp6"])
        if protocol == "icmp6":
            if choice([True, False]):
                src = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                src = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)
            else:
                dst = IPNetwork(
                    f"{IPAddress(randint(0, 340282366920938463463374607431768211455), version=6)}/{randint(1, 127)}").cidr
        else:
            if choice([True, False]):
                src = IPAddress(randint(0, 4294967295), version=4)
            else:
                src = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
            if choice([True, False]):
                dst = IPAddress(randint(0, 4294967295), version=4)
            else:
                dst = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}", version=4).cidr
        icmp_type = randint(-1, 255)
        icmp_code = randint(-1, 255)
        log = RuleLogging(choice([level for level in LogLevel]), randint(1, 300))
        position = randint(0, 65535)
        objectid = randint(0, 4294967295)
        rule = cls(permit=permit, protocol=protocol, src=src, dst=dst, icmp_type=icmp_type, icmp_code=icmp_code,
                   logging=log, active=active, position=position, objectid=objectid)
        return rule


def rule_from_dict(data: dict) -> RuleGeneric:
    if any(any(proto in value for proto in ("tcp", "udp")) for value in
           (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleTCPUDP.from_dict(data)
    elif any(any(proto in value for proto in ("icmp", "icmp6")) for value in
             (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleICMP.from_dict(data)
    else:
        return RuleGeneric.from_dict(data)
