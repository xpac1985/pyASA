import logging
from pyASA.logme import LogMe
from pyASA.caller import Caller
from pyASA.rule import RuleGeneric, rule_from_dict
import requests.status_codes
from time import sleep


class ACL(object):
    def __init__(self, caller: Caller):
        self._logger = logging.getLogger("pyASA")
        if isinstance(caller, Caller):
            self._caller = caller
        else:
            ValueError(f"{type(caller)} is not a valid caller argument type")

    @LogMe
    def exists(self, acl: str) -> bool:
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

    @LogMe
    def delete_rule(self, acl: str, objectid: int):
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

    @LogMe
    def delete_rules(self, acl: str, objectids: [None, list] = None):
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if not isinstance(objectids, (type(None), list)):
            raise ValueError(f"{type(acl)} is not a valid objectids argument type")
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

    @LogMe
    def get_rule_count(self, acl: str) -> int:
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        response = self._caller.get(f"objects/extendedacls/{acl}/aces", {"offset": 0, "limit": 0})
        if response.status_code != requests.codes.ok:
            raise RuntimeError(
                f"Getting rule count for ACL {acl} failed with HTTP {response.status_code}")
        return response.json()["rangeInfo"]["total"]

    @LogMe
    def get_rules(self, acl: str) -> list:
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

    @LogMe
    def get_acls(self) -> list:
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

    @LogMe
    def append_rule(self, acl: str, rule: RuleGeneric):
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

    @LogMe
    def append_rules(self, acl: str, rules: [RuleGeneric]):
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

    @LogMe
    def match_shadow_rules(self, rules: list) -> list:
        matches = []
        while len(rules) > 0:
            rule_a = rules.pop(0)
            for rule_b in rules:
                if rule_a is not rule_b:
                    if rule_a in rule_b:
                        matches.append((rule_b, rule_a))
                    if rule_b in rule_a:
                        matches.append((rule_a, rule_b))
        return matches
