from netaddr import IPAddress, IPNetwork
from pyASA.address import Address
from pyASA.rule import RuleTCPUDP, RuleICMP, ServiceComparator
import pytest
from random import randint, getrandbits, choice
from test.online import settings


@pytest.mark.skipif(not settings.online, reason="ASA not available for online tests")
class Test_ACL(object):
    @pytest.fixture(scope="class")
    def asa(self):
        asa = settings.asa
        if asa.acl.exists(settings.test_acl):
            asa.acl.delete_rules(settings.test_acl)
        yield settings.asa
        # if asa.acl.exists(settings.test_acl):
        #     settings.asa.acl.delete_rules(settings.test_acl)

    def test_test_connection(self, asa):
        asa.test_connection()

    def test_append_rule(self, asa):
        rule = RuleTCPUDP()
        rule.src = IPAddress(randint(0, 4294967295))
        rule.dst = IPAddress(randint(0, 4294967295))
        rule.src_port = randint(1, 65535)
        rule.dst_port = randint(1, 65535)
        asa.acl.append_rule(settings.test_acl, rule)

    def test_append_rules(self, asa):
        rules = []
        for i in range(1, 351):
            protocol = choice(["tcp", "udp"])
            if bool(getrandbits(1)):
                src = IPAddress(randint(0, 4294967295))
            else:
                src = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}").cidr
            if bool(getrandbits(1)):
                dst = IPAddress(randint(0, 4294967295))
            else:
                dst = IPNetwork(f"{IPAddress(randint(0, 4294967295))}/{randint(0, 31)}").cidr
            dst_port = randint(1, 65535)
            src_comp = choice([comp for comp in ServiceComparator])
            dst_comp = choice([comp for comp in ServiceComparator])
            rule = RuleTCPUDP(protocol=protocol, src=src, dst=dst, src_port=i, dst_port=dst_port, src_comparator=src_comp, dst_comparator=dst_comp)
            rules.append(rule)
        asa.acl.append_rules(settings.test_acl, rules)
