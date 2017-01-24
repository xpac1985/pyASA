from pyASA.caller import Caller
from pyASA.rule import RuleGeneric, rule_from_dict
import requests.status_codes


class ACL(object):
    def __init__(self, caller: Caller):
        if isinstance(caller, Caller):
            self._caller = caller
        else:
            ValueError(f"{type(caller)} is not a valid caller argument type")

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

    def delete_rule(self, acl: str, objectid: int, save_config: bool = False):
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if isinstance(objectid, int):
            response = self._caller.delete(f"objects/extendedacls/{acl}/aces/{objectid}")
            if response.status_code == requests.codes.no_content:
                if save_config:
                    self._caller.save_config()
            else:
                raise RuntimeError(
                    f"Deletion of ACL {acl} rule {objectid} failed with HTTP {response.status_code}: {response.json()}")
        else:
            raise ValueError(f"{type(objectid)} is not a valid rule argument type")

    def delete_rules(self, acl: str, objectids: [None, list] = None, save_config: bool = False):
        data = []
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if not isinstance(objectids, (type(None), list)):
            raise ValueError(f"{type(acl)} is not a valid objectids argument type")
        if objectids is None:
            rules = self.get_rules(acl)
            objectids = [rule.objectid for rule in rules]
        for objectid in objectids:
            if isinstance(objectid, int):
                data.append({"resourceUri": f"/api/objects/extendedacls/{acl}/aces/{objectid}", "method": "Delete"})
            else:
                raise ValueError(f"{type(objectid)} is not a valid objectid argument type")
        response = self._caller.post("", data)
        if response.status_code == requests.codes.ok:
            if save_config:
                self._caller.save_config()
        else:
            raise RuntimeError(
                f"Bulk rule deletion of {len(rules)} rules failed with HTTP {response.status_code}: {response.json()}")

    def get_rules(self, acl: str) -> list:
        total = 0
        count = -1
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

    def get_acls(self) -> list:
        response = self._caller.get("objects/extendedacls")
        if response.status_code == requests.codes.ok:
            names = [entry["name"] for entry in response.json()["items"]]
            return names
        else:
            raise RuntimeError(
                f"Requesting ACL names failedfailed with HTTP {response.status_code}: {response.json()}")

    def append_rule(self, acl: str, rule: RuleGeneric, save_config: bool = False):
        if isinstance(rule, RuleGeneric):
            if isinstance(acl, str):
                response = self._caller.post(f"objects/extendedacls/{acl}/aces", rule.to_dict())
                if response.status_code == requests.codes.created:
                    if save_config:
                        self._caller.save_config()
                elif response.status_code == requests.codes.bad_request and response.json()["messages"][
                    "code"] == "DUPLICATE":
                    raise ValueError(
                        f"Rule creation denied because rule is duplicate of rule object {response.json()['messages']['details']}")
                else:
                    raise RuntimeError(
                        f"Appending rule to ACL {acl} failed with HTTP {response.status_code}: {response.json()}")
            else:
                raise ValueError(f"{type(acl)} is not a valid acl argument type")
        else:
            raise ValueError(f"{type(rule)} is not a valid rule argument type")

    def append_rules(self, acl: str, rules: [RuleGeneric], save_config: bool = False):
        data = []
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        for rule in rules:
            if isinstance(rule, RuleGeneric):
                data.append(
                    {"resourceUri": f"/api/objects/extendedacls/{acl}/aces", "data": rule.to_dict(), "method": "Post"})
            else:
                raise ValueError(f"{type(rule)} is not a valid rule argument type")
        response = self._caller.post("", data)
        if response.status_code == requests.codes.ok:
            if save_config:
                self._caller.save_config()
        else:
            raise RuntimeError(
                f"Bulk rule creation of {len(rules)} rules failed with HTTP {response.status_code}: {response.json()}")
