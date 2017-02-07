import logging
from time import sleep
from typing import List, Dict
from typing import Optional

import requests.status_codes

from pyASA.caller import Caller
from pyASA.rule import RuleGeneric, rule_from_dict


class ACL(object):
    """
    Encapsulates all ACL related functionality of pyASA.

    Accessible on every ASA instance as asa.acl

    ACLs are implicitely created by adding the first entry and implicetely deleted by removing the last entry.

    """

    def __init__(self, caller: Caller):
        self._logger = logging.getLogger("pyASA")
        if isinstance(caller, Caller):
            self._caller = caller
        else:
            ValueError(f"{type(caller)} is not a valid caller argument type")

    def exists(self, acl: str) -> bool:
        """
        Check if a given ACL exists on the ASA.

        Args:
            acl: name of ACL to check

        Returns:
            True if ACL exists, False if not
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        response = self._caller.get(f"objects/extendedacls/{acl}")
        if response.status_code == requests.codes.ok:
            return True
        elif response.status_code == requests.codes.not_found:
            return False
        else:
            raise RuntimeError(
                f"ACL exists check for acl {acl} failed with HTTP {response.status_code}: {response.json()}")

    def delete_rule(self, acl: str, objectid: int):
        """
        Delete single rule from ACL, identified by objectid.

        Args:
            acl: name of ACL from which rule is to be deleted
            objectid: id of rule to delete
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if isinstance(objectid, int):
            response = self._caller.delete(f"objects/extendedacls/{acl}/aces/{objectid}")
            if response.status_code == requests.codes.no_content:
                pass
            else:
                raise RuntimeError(
                    f"Deletion of ACL {acl} rule {objectid} failed with HTTP {response.status_code}: {response.json()}")
        else:
            raise ValueError(f"{type(objectid)} is not a valid rule argument type")

    def delete_rules(self, acl: str, objectids: Optional[List[int]] = None):
        """
        Delete multiple or all rules from ACL.

        Can be called with a list of objectids of rules to delete, or None to delete whole ACL.

        Args:
            acl: name of ACL from which rules are to be deleted
            objectids: list of ids of rules to be deleted, or None to delete whole ACL. Defaults to None
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if not isinstance(objectids, (type(None), list)):
            raise ValueError(f"{type(acl)} is not a valid objectids argument type")
        if isinstance(objectids, list):
            if not all([isinstance(objectid, int) for objectid in objectids]):
                raise ValueError("objectids argument list contains non-int object")
        if objectids is None:
            rules = self.get_rules(acl)
            objectids = [rule.objectid for rule in rules]
        count = 0
        total = len(objectids)
        while count < total:
            data = []
            _objectids = objectids[count:count + 500]
            for objectid in _objectids:
                data.append(
                    {"resourceUri": f"/api/objects/extendedacls/{acl}/aces/{objectid}", "method": "Delete"})
            response = self._caller.post("", data)
            if response.status_code == requests.codes.server_error:
                raise RuntimeError(
                    f"Bulk rule deletion of {len(rules)} rules failed with HTTP {response.status_code}")
            elif response.status_code != requests.codes.ok:
                raise RuntimeError(
                    f"Bulk rule deletion of {len(rules)} rules failed with HTTP {response.status_code}: {response.json()}")
            else:
                sleep(0.5)
            count += 500

    def get_rule_count(self, acl: str) -> int:
        """
        Return count of rules in an ACL.

        Fails if ACL does not exist.

        Args:
            acl: name of ACL of which rule count is to be returned

        Returns:
            count of rules in ACL
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        response = self._caller.get(f"objects/extendedacls/{acl}/aces", {"offset": 0, "limit": 0})
        if response.status_code != requests.codes.ok:
            raise RuntimeError(
                f"Getting rule count for ACL {acl} failed with HTTP {response.status_code}")
        return response.json()["rangeInfo"]["total"]

    def get_rules(self, acl: str) -> List[RuleGeneric]:
        """
        Return all rules in an ACL.

        If ACL contains more than 100 rules, rules are fetched in multiple steps as the API enforces paging of results

        Args:
            acl: name of ACL to get rules from

        Returns:
            list of rule objects in ACL
        """
        total = 1
        count = 0
        rules = []
        while count < total:
            response = self._caller.get(f"objects/extendedacls/{acl}/aces", {"offset": count})
            response_json = response.json()
            if response.status_code == requests.codes.ok:
                total = response_json["rangeInfo"]["total"]
                count = response_json["rangeInfo"]["offset"] + response_json["rangeInfo"]["limit"]
                rules += [rule_from_dict(entry) for entry in response_json["items"]]
            elif response.status_code == requests.codes.not_found:
                raise ValueError(f"ACL {acl} not found")
            else:
                raise RuntimeError(
                    f"Requesting ACL {acl} failed with HTTP {response.status_code}: {response.json()['messages']['details']}")
        return rules

    def get_acls(self) -> List[str]:
        """
        Get list of all ACLs on ASA

        Returns:
            list of strings representing ACL names
        """
        response = self._caller.get("objects/extendedacls")
        if response.status_code == requests.codes.ok:
            names = [entry["name"] for entry in response.json()["items"]]
            return names
        elif response.status_code == requests.codes.server_error:
            raise RuntimeError(
                f"Requesting ACL names failed with HTTP {response.status_code}")
        else:
            raise RuntimeError(
                f"Requesting ACL names failed with HTTP {response.status_code}: {response.json()}")

    def append_rule(self, acl: str, rule: RuleGeneric):
        """
        Append rule to ACL.

        Uses position of rule object if position > 0, else appends to end of ACL.

        Args:
            acl: name of ACL to which rule is to be appended
            rule: rule object to append
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if not isinstance(rule, RuleGeneric):
            raise ValueError(f"{type(rule)} is not a valid rule argument type")
        response = self._caller.post(f"objects/extendedacls/{acl}/aces", rule.to_dict())
        if response.status_code == requests.codes.bad_request and "messages" in response.json() and "code" in \
                response.json()["messages"] and response.json()["messages"]["code"] == "DUPLICATE":
            raise ValueError(
                f"Rule creation denied because rule is duplicate of rule object {response.json()['messages']['details']}")
        elif response.status_code != requests.codes.created:
            raise RuntimeError(
                f"Appending rule to ACL {acl} failed with HTTP {response.status_code}: {response.json()}")

    def append_rules(self, acl: str, rules: List[RuleGeneric]):
        """
        Append multiple rules to an ACL.

        If more than 100 rule objects are given, appends in steps of 100 to circumvent API failure.
         Enforces some wait time between steps as API tends to fail if too many rules are submitted too quickly.

        Args:
            acl: name of ACL which rules are to be appended to
            rules: list of rule objects which are to be appended
        """
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if not isinstance(rules, list):
            raise ValueError(f"{type(rules)} is not a valid rules argument type")
        if not all([isinstance(rule, RuleGeneric) for rule in rules]):
            raise ValueError("rules argument list contains invalid objects")
        count = 0
        total = len(rules)
        while count < total:
            data = []
            _rules = rules[count:count + 100]
            for rule in _rules:
                data.append(
                    {"resourceUri": f"/api/objects/extendedacls/{acl}/aces", "data": rule.to_dict(), "method": "Post"})
            response = self._caller.post("", data)
            if response.status_code == requests.codes.server_error:
                raise RuntimeError(
                    f"Bulk rule creation of {len(rules)} rules failed after 3 tries in step {count}-{total if total < count+100 else count+100} with HTTP {response.status_code}")
            elif response.status_code != requests.codes.ok:
                raise RuntimeError(
                    f"Bulk rule creation of {len(rules)} rules failed after 3 tries in step {count}-{total if total < count+100 else count+100} with HTTP {response.status_code}: {response.json()}")
            else:
                sleep(3)
            count += 100

    @staticmethod
    def match_shadow_rules(rules: List[RuleGeneric]) -> Dict[int, Dict[RuleGeneric, List[RuleGeneric]]]:
        """
        Return rules which shadow other rules in the list.

        Shadowing means that a rule with a broader definition contains all cases a second rule covers.
        E.g. a rule with IP Protocol 0 (IP) and src + dst set to any would shadow every other rule.

        Uses 'in' operator, which in turn uses __contains__ method of rule objects to check shadowing.

        Args:
            rules: list of rule objects to match against each other

        Returns:
            A dictionary of all rules shadowing other rules.
            Structured as {rule_a.objectid: {"shadow": rule that shadows, "matches": list of shadowed rules} }
        """
        matches = {}
        while len(rules) > 0:
            rule_a = rules.pop(0)
            for rule_b in rules:
                if rule_a is not rule_b:
                    if rule_a in rule_b:
                        if rule_b.objectid in matches:
                            matches[rule_b.objectid]["matches"].append(rule_a)
                        else:
                            matches[rule_b.objectid] = {}
                            matches[rule_b.objectid]["shadow"] = rule_b
                            matches[rule_b.objectid]["matches"] = []
                            matches[rule_b.objectid]["matches"].append(rule_a)
                    if rule_b in rule_a:
                        if rule_a.objectid in matches:
                            matches[rule_a.objectid]["matches"].append(rule_b)
                        else:
                            matches[rule_a.objectid] = {}
                            matches[rule_a.objectid]["shadow"] = rule_a
                            matches[rule_a.objectid]["matches"] = []
                            matches[rule_a.objectid]["matches"].append(rule_b)
        return matches
