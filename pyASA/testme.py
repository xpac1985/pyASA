import json

from pyASA.asa import ASA
from pyASA.rule import RuleGeneric, RuleTCPUDP, RuleICMP

print("START Test")

asa = ASA("bespin.areafunky.net", user="admin", password="cisco", port=41443, use_https=True, url_prefix="/",
          validate_cert=True, debug=True)
if asa.test_connection():
    print(asa.acl.get_acls())
    # print(asa.acl.get_acl("TEST"))#

    # rule = RuleTCPUDP()
    # rule.protocol = "tcp"
    # for port in range(1, 256):
    #     rule.dst_port = port
    #     asa.acl.append_rule("ALIASES", rule)

    # if asa.acl.exists("TESTTEST"):
    #     rules = asa.acl.get_rules("TESTTEST")
    #     objectids = [rule.objectid for  rule in rules]
    #     for objectid in objectids:
    #         asa.acl.delete_rule("TESTTEST", objectid)

    if asa.acl.exists("TESTTEST"):
        asa.acl.delete_rules("TESTTEST")

    rules = []
    for port in range(1, 11):
        rule = RuleTCPUDP()
        rule.protocol = "udp"
        rule.dst_port = port + 33
        rule.position = 0
        rules.append(rule)
    asa.acl.append_rules("TESTTEST", rules)

    print(asa.acl.get_rules("TESTTEST"))

    if asa.acl.exists("TESTTEST"):
        rules = asa.acl.get_rules("TESTTEST")
        objectids = [rule.objectid for rule in rules]
        asa.acl.delete_rules("TESTTEST", objectids)

    rules = []
    for port in range(1, 11):
        rule = RuleTCPUDP()
        rule.protocol = "udp"
        rule.dst_port = port + 66
        rule.position = 0
        rules.append(rule)
    asa.acl.append_rules("TESTTEST", rules)

print("END Test")
