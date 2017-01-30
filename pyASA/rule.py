import copy
import re
from enum import Enum
from random import randint, choice
from typing import Union, Optional, List, Any, Dict, Tuple

from netaddr import IPAddress, IPNetwork

from pyASA import address
from pyASA.address import BaseAddress, Address, AnyAddress
from pyASA.aliases import Aliases
from pyASA.baseconfigobject import BaseConfigObject
from pyASA.rulelogging import RuleLogging, LogLevel


class ServiceComparator(Enum):
    """
    Class used to represent comparison operators used on TCP/UDP rules for port numbers
    """
    EQUAL = ""
    NOT_EQUAL = "!="
    LESSER = "<"
    GREATER = ">"

    def to_cli(self) -> str:
        """
        Convert ServiceComparator to string corresponding to CLI style comparator.

        Returns:
            comparator string as used on CLI
        """
        translate = {self.EQUAL: "eq", self.NOT_EQUAL: "neq", self.LESSER: "lt", self.GREATER: "gt"}
        return translate[self]

    @classmethod
    def from_cli(cls, line: str) -> "ServiceComparator":
        """
        Return ServiceComparator from CLI style string.

        Returns:
            ServiceComparator matching CLI string
        """
        translate = {"eq": cls.EQUAL, "neq": cls.NOT_EQUAL, "lt": cls.LESSER, "gt": cls.GREATER}
        return translate[line]


class RuleGeneric(BaseConfigObject):
    """
    Class representing ASA firewall rules that use neither TCP/UDP nor ICMP/ICMP6 protocol
    """

    def __init__(self, permit: bool = False, protocol: Union[int, str] = "ip",
                 src: Union[str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: Union[str, IPAddress, IPNetwork, BaseAddress] = "any", remark: Union[None, str, list] = None,
                 active: bool = True, logging: Optional[RuleLogging] = None, position: int = 0,
                 is_access_rule: bool = False,
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
        """
        Return/set if rule is a permit or deny rule.

        Returns:
            True if rule permits what it describes, False if it denies
        """
        return self._permit

    @permit.setter
    def permit(self, permit: bool):
        if not isinstance(permit, bool):
            raise TypeError(f"{type(permit)} is not a valid argument type")
        self._permit = bool(permit)

    @property
    def protocol(self) -> int:
        """
        Return/set IP protocol value. Accepts integer as well as ASA protocol aliases as strings.

        Checks that protocol is neither TCP/UDP nor ICMP/ICMP6, as specific classes for those rules exist.

        Returns:
            IP protocol number
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: Union[int, str]):
        if isinstance(protocol, str) and protocol.isdigit():
            protocol = int(protocol)
        if isinstance(protocol, str):
            if protocol in ["icmp", "icmp6"]:
                raise ValueError("Use a RuleICMP object for icmp/icmp6 rules")
            elif protocol in ["tcp", "udp"]:
                raise ValueError("Use a RuleTCPUDP object for tcp/udp rules")
            elif protocol in Aliases.by_alias["protocol"]:
                self._protocol = Aliases.by_alias["protocol"][protocol]
            else:
                raise ValueError(f"'{protocol}' is not a valid protocol alias")
        elif isinstance(protocol, int):
            if 0 <= protocol <= 255:
                if protocol not in [1, 6, 17, 58]:
                    self._protocol = protocol
                elif protocol in [1, 58]:
                    raise ValueError("Use a RuleICMP object for icmp/icmp6 rules")
                elif protocol in [6, 17]:
                    raise ValueError("Use a RuleTCPUDP object for tcp/udp rules")
            else:
                raise ValueError("protocol must be in range 0..255")
        else:
            raise TypeError("protocol must be an integer in range 0..255 or a valid protocol alias string")

    @property
    def protocol_alias(self) -> str:
        """
        Return IP protocol alias, if available, else IP protocol number as string.

        Returns:
            IP protocol alias, if available, else IP Protocol number as string
        """
        if self._protocol in Aliases.by_number["protocol"]:
            return Aliases.by_number["protocol"][self._protocol]
        else:
            return str(self._protocol)

    @property
    def src(self) -> BaseAddress:
        """
        Return/set source address for rule.

        Returns:
            Either AnyAddress or Address object
        """
        return self._src

    @property
    def dst(self) -> BaseAddress:
        """
        Return/set destination address for rule.

        Returns:
            Either AnyAddress or Address object
        """
        return self._dst

    @src.setter
    def src(self, addr: Union[str, IPAddress, IPNetwork, BaseAddress]):
        self._src = address.parse_address(addr)

    @dst.setter
    def dst(self, addr: Union[str, IPAddress, IPNetwork, BaseAddress]):
        self._dst = address.parse_address(addr)

    @property
    def remark(self) -> List[Optional[str]]:
        """
        Return/set remarks (comments) for this rule.

        In Cisco ASA CLI logic, all remark line before this rule in the ACL are considered remarks belonging
         to this rule. Accordingly, multiple remark strings are being turned into multiple remark lines when this
         rule is being sent to the ASA, inserted before this rule.

        Returns:
            A list containing none, one or multiple strings containing the remarks
        """
        return self._remark

    @remark.setter
    def remark(self, remark: Union[None, str, list]):
        if remark is None:
            self._remark = []
        elif isinstance(remark, str):
            self._remark = [str(remark)]
        elif isinstance(remark, list):
            if not all([isinstance(line, str) for line in remark]):
                raise TypeError(f"list contains non-string values")
            else:
                self._remark = copy.copy(remark)
        else:
            raise TypeError(f"{type(remark)} is not a valid argument type")

    @property
    def active(self) -> bool:
        """
        Return/set if rule is actually being used. Inactive rules are being skipped when matching traffic to an ACL.

        Returns:
            True if rule is active, False if not
        """
        return self._active

    @active.setter
    def active(self, active: bool):
        if not isinstance(active, bool):
            raise TypeError(f"{type(active)} is not a valid argument type")
        self._active = bool(active)

    @property
    def logging(self) -> RuleLogging:
        """
        Return/set logging settings for this rule by use of a RuleLogging object.

        Returns:
            RuleLogging object containing logging level and interval
        """
        return self._logging

    @logging.setter
    def logging(self, log: RuleLogging):
        if log is None:
            self._logging = RuleLogging()
        elif isinstance(log, RuleLogging):
            self._logging = log
        else:
            raise TypeError(f"{type(log)} is not a valid argument type")

    @property
    def position(self) -> int:
        """
        Return/set position of rule in ACL.

         Position is being determined when rule is retrieved from ASA, or can be used to determine position in new ACL
         it is being appended to.
         In contrast to the ASA CLI line number, the position value used by the API only counts 'real' rules,
         no remark lines.

         Example:
             line 1 remark allow all tcp traffic
             line 2 extended permit tcp any any
             line 3 remark deny all non tcp traffic
             line 4 extended deny ip any any

             The "deny any" rule is in position 2, when retrieved by the API, not in position 4

        Returns:
            0 if no position is configured, positive integer if a position has been set
        """
        return self._position

    @position.setter
    def position(self, pos: int):
        if isinstance(pos, int):
            if pos >= 0:
                self._position = int(pos)
            else:
                raise ValueError("position must a positive integer")
        else:
            raise ValueError(f"{type(pos)} is not a valid argument type")

    @property
    def is_access_rule(self) -> bool:
        """
        Return/set if rule is an access rule.

         This value is only useful when rule is being retrieved from the ASA API, as it is an read-only value.
         Changing it has no effect and is being ignored when rule is pushed to ASA.
         Changing the value is only used for test and debugging purposes.

        Returns:
            True if rule is an access rule, False if not
        """
        return self._is_access_rule

    @is_access_rule.setter
    def is_access_rule(self, is_access_rule: bool):
        if isinstance(is_access_rule, bool):
            self._is_access_rule = bool(is_access_rule)
        else:
            raise ValueError(f"{type(is_access_rule)} is not a valid argument type")

    @property
    def objectid(self) -> int:
        """
        Return/set objectid of rule.

         The objectid is the integer (base 10) equivalent to the hex value shown on the CLI by the
         "show access-list" command and is a hash calculated by the ASA based on a rule's properties.
         It is mainly used to identify a rule on the CLI or in the log, and changes when the rule properties
         change. This does not happen automatically, as the hash algorithm used by the ASA is not public and
         the only way to retrieve the value is by getting the rule from the ASA.

        Returns:
            0 if no objectid is set, else positive integer
        """
        return self._objectid

    @objectid.setter
    def objectid(self, objectid: int):
        if isinstance(objectid, int):
            if objectid >= 0:
                self._objectid = int(objectid)
            else:
                raise ValueError("objectid must be a positive integer")
        else:
            raise ValueError(f"{type(objectid)} is not a valid argument type")

    @property
    def objectid_hexhash(self) -> str:
        """
        Return a string representing the objectid of the rule as hex (called hash on the ASA CLI).

        Returns:
            string hex representation of objectid
        """
        return hex(self._objectid)

    @staticmethod
    def _parse_protocol_json(proto: str) -> int:
        """
        Convert protocol string to int, either using a matching protocol alias or via int-to-str conversion.

        Args:
            proto: protocol string as received from API

        Returns:
            protocol value
        """
        if proto.isdigit():
            return int(proto)
        elif proto in Aliases.by_alias["protocol"]:
            return Aliases.by_alias["protocol"][proto]
        else:
            raise ValueError(f"{proto} is not a valid protocol alias")

    @classmethod
    def from_dict(cls, data: dict) -> "RuleGeneric":
        """
        Uses a dictionary representation of a rule (most likely converted from JSON data) to create a rule object.

        Args:
            data: dict to create rule object from, structured like the JSON responses from the API

        Returns:
            rule object equivalent to the provided data
        """
        permit = data["permit"]
        src = data["sourceAddress"]["value"]
        dst = data["destinationAddress"]["value"]
        protocol = cls._parse_protocol_json(data["sourceService"]["value"])
        remark = data["remarks"]
        active = data["active"]
        logging = RuleLogging.from_dict(data["ruleLogging"]) if "ruleLogging" in data else None
        position = data.get("position", 0)
        is_access_rule = data.get("isAccessRule", False)
        objectid = data.get("objectId", 0)
        return cls(permit, protocol, src, dst, remark, active, logging, position, is_access_rule, objectid)

    def to_cli(self, acl: Optional[str] = None) -> str:
        """
        Return a CLI-style representation of the rule.

        Args:
            acl: ACL name as string to preprend to the rule in form of "access-list NAME"

        Returns:
            string containing CLI-style representation
        """
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {self.dst.to_cli()} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

    def to_dict(self) -> Dict[str, Any]:
        """
        Return rule data as dict representation in API JSON style.

        Returns:
            dict of rule values that can be easily converted to JSON for use with API
        """
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

    def clone(self):
        """
        Return a identical copy of this rule.

         Uses copy.deepcopy, but resets objectid to 0.

        Returns:
            rule object identical to this rule
        """
        rule = copy.deepcopy(self)
        rule.objectid = 0
        return rule

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RuleGeneric):
            return self.to_dict() == other.to_dict()
        else:
            return False

    def __contains__(self, item: object) -> bool:
        """
        Verify if this rule shadows another rule object. Overloads python "in" operator.

         Shadowing means that the defintion of this rule object is broad enough to completely cover all packets
         that the other rule would match.
         Compares source and destination address, protocol, permit and active states.

        Examples:
            (RuleGeneric("tcp", "any", "any") in RuleGeneric("ip", "any", "any")) == True

            rule_a = RuleGeneric()
            rule_a.active = False
            rule_b = RuleGeneric()
            (rule_b in rule_a) == True
            rule_b.active = True
            (rule_b in rule_a) == False

        Args:
            item: object to check if it is being shadowed by this rule

        Returns:
            True if this rule shadows the other rule, False if not
        """
        if not isinstance(item, RuleGeneric):
            return False
        if item.permit != self.permit:
            return False
        # if rule protocol is 0 (=IP), it covers all other IP protocols
        if self.protocol > 0 and self.protocol != item.protocol:
            return False
        if not isinstance(self.src, AnyAddress) and item.src not in self.src:
            return False
        if not isinstance(self.dst, AnyAddress) and item.dst not in self.dst:
            return False
        if item.active != self.active:
            return False
        return True

    @classmethod
    def random_rule(cls) -> "RuleGeneric":
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


class RuleICMP(RuleGeneric):
    """
    Class representing ASA firewall rules that use either ICMP or ICMP6 protocol
    """

    def __init__(self, permit: bool = False, protocol: Union[int, str] = "icmp",
                 src: Union[str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: Union[str, IPAddress, IPNetwork, BaseAddress] = "any", icmp_type: Union[str, int] = "any",
                 icmp_code: Union[int, str] = "any", remark: Union[None, str, list] = None, active: bool = True,
                 logging: Optional[RuleLogging] = None, position: int = 0, is_access_rule: bool = False,
                 objectid: int = 0):

        RuleGeneric.__init__(self, permit, protocol, src, dst, remark, active, logging, position, is_access_rule,
                             objectid)

        self._icmp_type = -1
        self._icmp_code = -1

        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    @property
    def protocol(self) -> int:
        """
        Return/set IP protocol value. Accepts integer as well as ASA protocol aliases as strings.

        Checks that protocol is ICMP/ICMP6, as this class only supports these protocols.

        Returns:
            IP protocol number
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: Union[int, str]):
        if isinstance(protocol, str) and protocol.isdigit():
            protocol = int(protocol)
        if isinstance(protocol, int):
            if protocol in [1, 58]:
                self._protocol = protocol
            elif protocol in [6, 17]:
                raise ValueError("Use a RuleTCPUDP object for TCP/UDP rules")
            else:
                raise ValueError("Use a RuleGeneric object for non ICMP/ICMP6 rules")
        elif type(protocol) is str:
            if protocol in ["icmp", "icmp6"]:
                self._protocol = Aliases.by_alias["protocol"][protocol]
            elif protocol in ["tcp", "udp"]:
                raise ValueError("Use a RuleICMP object for TCP/UDP rules")
            else:
                raise ValueError("Use a RuleGeneric object for non ICMP/ICMP6 rules")
        else:
            raise ValueError(
                "protocol must be either 1 for icmp, 58 for icmp6 or \"icmp\" or \"icmp6\" protcol alias string")

    @property
    def icmp_type(self) -> int:
        """
        Return/set ICMP type used in this rule. Defaults to -1 for any.

        Returns:
            ICMP type number
        """
        return self._icmp_type

    @icmp_type.setter
    def icmp_type(self, icmp_type: Union[int, str]):
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
    def icmp_type_alias(self) -> str:
        """
        Return ICMP type alias if available, else ICMP type number as string.

        Returns:

        """
        return Aliases.by_number[self.protocol_alias].get(self._icmp_type, str(self._icmp_type))

    @property
    def icmp_code(self):
        """
        Return/set ICMP code used in this rule. Defaults to -1 for any.

         Only has effect if icmp_type is not set to -1

        Returns:
            ICMP code number
        """
        return self._icmp_code

    @icmp_code.setter
    def icmp_code(self, icmp_code: Union[str, int]):
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
    def _parse_icmp_json(cls, data: dict) -> Tuple:
        """
        Utility function to parse ICMP type and code from an JSON dict.

        Args:
            data: dict with JSON data to parse

        Returns:
            ICMP type and code as tuple
        """
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
    def from_dict(cls, data: Dict[str, Any]) -> "RuleICMP":
        """
        Uses a dictionary representation of a rule (most likely converted from JSON data) to create a rule object.

        Args:
            data: dict to create rule object from, structured like the JSON responses from the API

        Returns:
            rule object equivalent to the provided data
        """
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

    def to_cli(self, acl: Optional[str] = None) -> str:
        """
        Return a CLI-style representation of the rule.

        Args:
            acl: ACL name as string to preprend to the rule in form of "access-list NAME"

        Returns:
            string containing CLI-style representation
        """
        if self.icmp_type == -1:
            icmp = ""
        else:
            if self.icmp_code == -1:
                icmp = f"{self.icmp_type_alias}"
            else:
                icmp = f"{self.icmp_type_alias} {self.icmp_code}"
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {self.dst.to_cli()} {icmp} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

    def to_dict(self) -> Dict[str, Any]:
        """
        Return rule data as dict representation in API JSON style.

        Returns:
            dict of rule values that can be easily converted to JSON for use with API
        """
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
        """
        Verify if this rule shadows another rule object. Overloads python "in" operator.

         For details on shadowing, see RuleGeneric.__contains__ documentation.

        Args:
            item: object to check if it is being shadowed by this rule

        Returns:
            True if this rule shadows the other rule, False if not
        """
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
    def random_rule(cls) -> "RuleICMP":
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


class RuleTCPUDP(RuleGeneric):
    """
    Class representing ASA firewall rules that use either TCP or UDP protocol
    """

    def __init__(self, permit: bool = False, protocol: Union[int, str] = "tcp",
                 src: Union[str, IPAddress, IPNetwork, BaseAddress] = "any",
                 dst: Union[str, IPAddress, IPNetwork, BaseAddress] = "any",
                 src_port: Union[int, str] = "any", dst_port: Union[int, str] = "any",
                 src_comp: Union[ServiceComparator, str] = ServiceComparator.EQUAL,
                 dst_comp: Union[ServiceComparator, str] = ServiceComparator.EQUAL,
                 remark: Union[None, str, list] = None, active: bool = True, logging: Optional[RuleLogging] = None,
                 position: int = 0, is_access_rule: bool = False, objectid: int = 0):

        RuleGeneric.__init__(self, permit, protocol, src, dst, remark, active, logging, position, is_access_rule,
                             objectid)

        self._src_port = -1
        self._dst_port = -1
        self._src_comp = ServiceComparator.EQUAL
        self._dst_comp = ServiceComparator.EQUAL

        self.src_port = src_port
        self.dst_port = dst_port
        self.src_comp = src_comp
        self.dst_comp = dst_comp

    @property
    def protocol(self) -> int:
        """
        Return/set IP protocol value. Accepts integer as well as ASA protocol aliases as strings.

        Checks that protocol is TCP/UDP, as this class only supports these protocols.

        Returns:
            IP protocol number
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol: Union[int, str]):
        if isinstance(protocol, str) and protocol.isdigit():
            protocol = int(protocol)
        if isinstance(protocol, int):
            if protocol in [6, 17]:
                self._protocol = protocol
            elif protocol in [1, 58]:
                raise ValueError("Use a RuleICMP object for ICMP/ICMP6 rules")
            else:
                raise ValueError("Use a RuleGeneric object for non TCP/UDP rules")
        elif type(protocol) is str:
            if protocol in ["tcp", "udp"]:
                self._protocol = Aliases.by_alias["protocol"][protocol]
            elif protocol in ["icmp", "icmp6"]:
                raise ValueError("Use a RuleICMP object for ICMP/ICMP6 rules")
            else:
                raise ValueError("Use a RuleGeneric object for non TCP/UDP rules")
        else:
            raise ValueError("protocol must be either 6 for tcp, 17 for udp or \"tcp\" or \"udp\" protcol alias string")

    @property
    def src_port(self) -> int:
        """
        Return/set TCP/UDP source port for this rule. Defaults to -1 which means "any"

         Checks that port is valid (in range 1..65535).
        """
        return self._src_port

    @property
    def dst_port(self) -> int:
        """
        Return/set TCP/UDP destination port for this rule. Defaults to -1 which means "any"

         Checks that port is valid (in range 1..65535).
        """
        return self._dst_port

    @src_port.setter
    def src_port(self, port: Union[int, str]):
        self._src_port = self._parse_port(port)

    @dst_port.setter
    def dst_port(self, port: Union[int, str]):
        self._dst_port = self._parse_port(port)

    def _parse_port(self, port: Union[int, str]) -> int:
        """
        Parse port functionality. Used in src_port/dst_port setters.

        Args:
            port: port data to be parsed, accepts port numbers or port aliases

        Returns:
            port value converted to integer
        """
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
            raise TypeError(f"{type(port)} is not a valid argument type")

    @property
    def src_port_alias(self) -> str:
        """
        Return source port alias, if available, else port number as string

        Returns:
            port alias or number
        """
        return Aliases.by_number[self.protocol_alias].get(self._src_port, str(self._src_port))

    @property
    def dst_port_alias(self) -> str:
        """
        Return destination port alias, if available, else port number as string

        Returns:
            port alias or number
        """
        return Aliases.by_number[self.protocol_alias].get(self._dst_port, str(self._dst_port))

    @property
    def src_comp(self) -> ServiceComparator:
        """
        Return/set source comparator for comparison of the source port.
        
        Returns:
            Source port comparator
        """
        return self._src_comp

    @property
    def dst_comp(self) -> ServiceComparator:
        """
        Return/set destination comparator for comparison of the destination port.

        Returns:
            Destination port comparator
        """
        return self._dst_comp

    @src_comp.setter
    def src_comp(self, comp: Union[ServiceComparator, str]):
        self._src_comp = self._set_comparator(comp)

    @dst_comp.setter
    def dst_comp(self, comp: Union[ServiceComparator, str]):
        self._dst_comp = self._set_comparator(comp)

    @classmethod
    def _set_comparator(cls, comp: Union[ServiceComparator, str]) -> ServiceComparator:
        """
        Utility function to parse src_comp/dst_comp setter values for validity and return corresponding value

        Args:
            comp: value to be parsed

        Returns:
            ServiceComparator object
        """
        if isinstance(comp, ServiceComparator):
            return comp
        if isinstance(comp, str):
            if comp in [enum.value for enum in ServiceComparator]:
                return ServiceComparator(comp)
            else:
                raise ValueError(f"{comp} is not a valid ServiceComparator alias")
        else:
            raise ValueError(f"{type(comp)} is not a valid argument type")

    @classmethod
    def _parse_port_json(cls, data: dict) -> Tuple:
        """
        Utility function to parse TCP/UDP port and comparator data from an JSON dict.

        Args:
            data: dict with JSON data to parse

        Returns:
            TCP/UDP port and comparator as tuple
        """
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
    def from_dict(cls, data: dict) -> "RuleTCPUDP":
        """
        Uses a dictionary representation of a rule (most likely converted from JSON data) to create a rule object.

        Args:
            data: dict to create rule object from, structured like the JSON responses from the API

        Returns:
            rule object equivalent to the provided data
        """
        permit = data["permit"]
        src = data["sourceAddress"]["value"]
        dst = data["destinationAddress"]["value"]
        protocol, src_port, src_comp = RuleTCPUDP._parse_port_json(data["sourceService"])
        __, dst_port, dst_comp = RuleTCPUDP._parse_port_json(data["destinationService"])
        remark = data["remarks"]
        active = data["active"]
        logging = RuleLogging.from_dict(data["ruleLogging"]) if "ruleLogging" in data else None
        position = data["position"] if "position" in data else 0
        is_access_rule = data["isAccessRule"] if "isAccessRule" in data else False
        objectid = int(data["objectId"]) if "objectId" in data else 0
        return cls(permit, protocol, src, dst, src_port, dst_port, src_comp, dst_comp, remark, active,
                   logging, position, is_access_rule, objectid)

    def to_cli(self, acl: Optional[str] = None) -> str:
        """
        Return a CLI-style representation of the rule.

        Args:
            acl: ACL name as string to preprend to the rule in form of "access-list NAME"

        Returns:
            string containing CLI-style representation
        """
        src_port = "" if self.src_port == -1 else f"{self.src_comp.to_cli()} {self.src_port_alias}"
        dst_port = "" if self.dst_port == -1 else f"{self.dst_comp.to_cli()} {self.dst_port_alias}"
        result = f"{'' if acl is None else f'access-list {acl}'} extended {'permit' if self.permit else 'deny'} {self.protocol_alias} {self.src.to_cli()} {src_port} {self.dst.to_cli()} {dst_port} {self.logging.to_cli()} {'inactive' if not self.active else ''}"
        return result.strip().replace("  ", " ")

    def to_dict(self) -> Dict[str, Any]:
        """
        Return rule data as dict representation in API JSON style.

        Returns:
            dict of rule values that can be easily converted to JSON for use with API
        """
        result = RuleGeneric.to_dict(self)
        if self._src_port == -1:
            result["sourceService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            result["sourceService"] = {
                "kind": "TcpUdpService",
                "value": f"{self._src_comp.value}{self.protocol_alias}/{self.src_port_alias}"
            }
        if self._dst_port == -1:
            result["destinationService"] = {"kind": "NetworkProtocol", "value": self.protocol_alias}
        else:
            result["destinationService"] = {
                "kind": "TcpUdpService",
                "value": f"{self._dst_comp.value}{self.protocol_alias}/{self.dst_port_alias}"
            }
        return result

    def __contains__(self, item: object) -> bool:
        """
        Verify if this rule shadows another rule object. Overloads python "in" operator.

         For details on shadowing, see RuleGeneric.__contains__ documentation.

        Args:
            item: object to check if it is being shadowed by this rule

        Returns:
            True if this rule shadows the other rule, False if not
        """
        if not isinstance(item, RuleTCPUDP):
            return False
        if not RuleGeneric.__contains__(self, item):
            return False
        if self.src_port != -1:
            if item.src_port == -1:
                return False
            if self.src_comp in [ServiceComparator.EQUAL, ServiceComparator.NOT_EQUAL]:
                if item.src_comp != self.src_comp:
                    return False
                elif item.src_port != self.src_port:
                    return False
            elif self.src_comp == ServiceComparator.GREATER:
                if item.src_comp in [ServiceComparator.LESSER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.src_comp == ServiceComparator.EQUAL:
                    if item.src_port <= self.src_port:
                        return False
                elif item.src_comp == ServiceComparator.GREATER:
                    if item.src_port < self.src_port:
                        return False
            elif self.src_comp == ServiceComparator.LESSER:
                if item.src_comp in [ServiceComparator.GREATER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.src_comp == ServiceComparator.EQUAL:
                    if item.src_port >= self.src_port:
                        return False
                elif item.src_comp == ServiceComparator.LESSER:
                    if item.src_port > self.src_port:
                        return False
        if self.dst_port != -1:
            if item.dst_port == -1:
                return False
            if self.dst_comp in [ServiceComparator.EQUAL, ServiceComparator.NOT_EQUAL]:
                if item.dst_comp != self.dst_comp:
                    return False
                elif item.dst_port != self.dst_port:
                    return False
            elif self.dst_comp == ServiceComparator.GREATER:
                if item.dst_comp in [ServiceComparator.LESSER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.dst_comp == ServiceComparator.EQUAL:
                    if item.dst_port <= self.dst_port:
                        return False
                elif item.dst_comp == ServiceComparator.GREATER:
                    if item.dst_port < self.dst_port:
                        return False
            elif self.dst_comp == ServiceComparator.LESSER:
                if item.dst_comp in [ServiceComparator.GREATER, ServiceComparator.NOT_EQUAL]:
                    return False
                elif item.dst_comp == ServiceComparator.EQUAL:
                    if item.dst_port >= self.dst_port:
                        return False
                elif item.dst_comp == ServiceComparator.LESSER:
                    if item.dst_port > self.dst_port:
                        return False
        return True

    @classmethod
    def random_rule(cls) -> "RuleTCPUDP":
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
                   src_comp=src_comp, dst_comp=dst_comp, logging=log, active=active,
                   position=position, objectid=objectid)
        return rule


def rule_from_dict(data: dict) -> RuleGeneric:
    """
    Determines which class of rule object to use for a given JSON dict.

     Invokes class specific from_rule() and returns the object.

    Args:
        data: dict to determine rule type from, structured like the JSON responses from the API

    Returns:
        rule object equivalent to the provided data
    """
    if any(any(proto in value for proto in ("tcp", "udp")) for value in
           (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleTCPUDP.from_dict(data)
    elif any(any(proto in value for proto in ("icmp", "icmp6")) for value in
             (data["sourceService"]["value"], data["destinationService"]["value"])):
        return RuleICMP.from_dict(data)
    else:
        return RuleGeneric.from_dict(data)


def rule_from_cli(line: str) -> RuleGeneric:
    """
    Determines which class of rule object to use for a given CLI like .

     Invokes class specific from_rule() and returns the object.

    Args:
        line: CLI line to determine rule type from, structured like the JSON responses from the API

    Returns:
        rule object equivalent to the provided data
    """
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
                          dst_port=dstport, src_comp=srccomp, dst_comp=dstcomp, position=position)
    elif proto in [1, 58]:
        icmp_type = finder.group("icmptype") if finder.group("icmptype") else -1
        icmp_code = int(finder.group("icmpcode")) if finder.group("icmpcode") else -1
        return RuleICMP(permit=permit, protocol=proto, src=src, dst=dst, active=active, logging=log,
                        icmp_type=icmp_type,
                        icmp_code=icmp_code, position=position)
    else:
        return RuleGeneric(permit=permit, protocol=proto, src=src, dst=dst, active=active, logging=log,
                           position=position)


def random_rule() -> RuleGeneric:
    """
    Return a random rule of any of the three classes, invoking the random_rule() from that class.

    Mainly used for testing

    Returns:
        random rule object
    """
    ruletype = randint(1, 4)
    if ruletype == 1:
        return RuleTCPUDP.random_rule()
    elif ruletype == 2:
        return RuleICMP.random_rule()
    else:
        return RuleGeneric.random_rule()
