from pyASA.caller import Caller
from pyASA.rule import RuleGeneric, rule_from_dict
import requests.status_codes


class ACL(object):
    def __init__(self, caller: Caller):
        if type(caller) is Caller:
            self._caller = caller
        else:
            ValueError("argument asa must be of type of ASA")

    def exists_acl(self, acl: str) -> bool:
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        response = self._caller.get(f"objects/extendedacls/{acl}")
        if response.status_code == requests.codes.ok:
            return True
        elif response.status_code == requests.codes.not_found:
            return False
        else:
            raise RuntimeError(f"ACL exists check for acl {acl} failed with HTTP {response.status_code}: {response.json()['messages']['details']}")

    def delete_rule(self, acl: str, objectid: int):
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        if isinstance(objectid, int):
            response = self._caller.delete(f"objects/extendedacls/{acl}/aces/{objectid}")
            if response.status_code == requests.codes.no_content:
                print(f"Rule {objectid} successfully deleted")
            else:
                raise RuntimeError(
                    f"Deletion of ACL {acl} rule {objectid} failed with HTTP {response.status_code}: {response.json()['messages']['details']}")
        else:
            raise ValueError(f"{type(rule)} is not a valid rule argument type")

    def get_acl(self, acl: str) -> dict:
        response = self._caller.get(f"objects/extendedacls/{acl}/aces")
        if response.status_code == requests.codes.ok:
            rules = {}
            for entry in response.json()["items"]:
                rules[entry["position"]] = rule_from_dict(entry)
            return rules
        elif response.status_code == requests.codes.not_found:
            raise ValueError(f"ACL {acl} not found")
        else:
            raise RuntimeError(
                f"Requesting ACL {acl} failed with HTTP {response.status_code}: {response.json()['messages']['details']}")

    def get_acl_list(self) -> list:
        response = self._caller.get("objects/extendedacls")
        if response.status_code == requests.codes.ok:
            names = [entry["name"] for entry in response.json()["items"]]
            return names
        else:
            raise RuntimeError(
                f"Requesting ACL names failedfailed with HTTP {response.status_code}: {response.json()['messages']['details']}")

    def append_rule(self, acl: str, rule: RuleGeneric):
        if isinstance(rule, RuleGeneric):
            if isinstance(acl, str):
                response = self._caller.post(f"objects/extendedacls/{acl}/aces", rule.to_dict())
                if response.status_code == requests.codes.created:
                    print("Rule successfully created")
                elif response.status_code == requests.codes.bad_request and response.json()["messages"][
                    "code"] == "DUPLICATE":
                    raise ValueError(
                        f"Rule creation denied because rule is duplicate of rule object {response.json()['messages']['details']}")
                else:
                    raise RuntimeError(
                        f"Appending rule to ACL {acl} failed with HTTP {response.status_code}: {response.json()['messages']['details']}")
            else:
                raise ValueError(f"{type(acl)} is not a valid acl argument type")
        else:
            raise ValueError(f"{type(rule)} is not a valid rule argument type")

    def append_rules(self, acl: str, rules: [RuleGeneric]):
        data = []
        if not isinstance(acl, str):
            raise ValueError(f"{type(acl)} is not a valid acl argument type")
        for rule in rules:
            if isinstance(rule, RuleGeneric):
                data.append(
                    {"resourceUri": f"/api/objects/extendedacls/{acl}/aces", "data": rule.to_dict(), "method": "Post"})
            else:
                raise ValueError(f"{type(rule)} is not a valid rule argument type")
        print(data)
        response = self._caller.post("", data)
        if response.status_code == requests.codes.ok:
            print("Bulk rule creation successful")
        else:
            print(response.json())
            raise RuntimeError(
                f"Bulk rule creation of {len(rules)} rules failed with HTTP {response.status_code}: {response.json()['commonMessages'][0]['code']}")
