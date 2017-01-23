from pyASA.aliases import Aliases


class Test_Aliases(object):
    def test_by_alias(self):
        assert Aliases.by_alias["tcp"]["whois"] == 43
        assert Aliases.by_alias["udp"]["snmp"] == 161
        assert Aliases.by_alias["protocol"]["eigrp"] == 88
        assert Aliases.by_alias["icmp"]["echo"] == 8
        assert Aliases.by_alias["icmp6"]["router-advertisement"] == 134

    def test_by_number(self):
        assert Aliases.by_number["tcp"][22] == "ssh"
        assert Aliases.by_number["udp"][517] == "talk"
        assert Aliases.by_number["protocol"][6] == "tcp"
        assert Aliases.by_number["icmp"][16] == "information-reply"
        assert Aliases.by_number["icmp6"][138] == "router-renumbering"
