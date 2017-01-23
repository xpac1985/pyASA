import json
import os


class Aliases(object):
    by_alias, by_number = {}, {}

    def __init__(self):
        Aliases.by_alias, Aliases.by_number = Aliases.load_aliases()

    @staticmethod
    def load_aliases_file(filename: str) -> dict:
        """
        Returns dict of ip protocol/tcp+udp service/icmp+icmp6 message type aliases used on ASA
        Taken from https://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/ref-ports.html#ID-2120-00000219
        :return: dict from file json content
        """
        directory = f"{os.path.dirname(os.path.realpath(__file__))}{os.path.sep}aliases_json"
        with open(f"{directory}{os.path.sep}{filename}", newline="") as aliases_file:
            aliases = json.load(aliases_file)
        return aliases

    @staticmethod
    def load_aliases() -> (dict, dict):
        aliases = {}
        aliases["icmp"] = Aliases.load_aliases_file("icmp.json")
        aliases["icmp6"] = Aliases.load_aliases_file("icmp6.json")
        aliases["protocol"] = Aliases.load_aliases_file("protocol.json")
        aliases["tcp"] = Aliases.load_aliases_file("tcp.json")
        aliases["udp"] = Aliases.load_aliases_file("udp.json")

        aliases_inv = {}
        for proto, entries in aliases.items():
            aliases_inv[proto] = {}
            for alias, port in entries.items():
                aliases_inv[proto][port] = alias

        return aliases, aliases_inv


Aliases()
