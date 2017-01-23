import json

from pyASA.asa import ASA
from pyASA.rule import RuleGeneric, RuleTCPUDP, RuleICMP

print("START Test")

asa = ASA("bespin.areafunky.net", user="admin", password="cisco", port=41443, use_https=True, url_prefix="/",
          validate_cert=True, debug=True)
if asa.test_connection():
    print(asa.acl.get_acl_list())
    # print(asa.acl.get_acl("TEST"))#

    # rule = RuleTCPUDP()
    # rule.protocol = "tcp"
    # for port in range(1, 256):
    #     rule.dst_port = port
    #     asa.acl.append_rule("ALIASES", rule)

    # rules = []
    # for port in range(99, 100):
    #     rule = RuleTCPUDP()
    #     rule.protocol = "udp"
    #     rule.dst_port = port
    #     rules.append(rule)
    # # rules.append(rule)
    # asa.acl.append_rules("ALIASES-UDP", rules)
    if asa.acl.exists_acl("ALIASES-UDP"):
        rules = asa.acl.get_acl("ALIASES-UDP")
        # print(rules)
        objectids = [rule.objectid for __, rule in rules.items()]
        for objectid in objectids:
            asa.acl.delete_rule("ALIASES-UDP", objectid)



print("END Test")
