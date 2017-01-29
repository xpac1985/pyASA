import json
import os
from pyASA.logme import LogMe


class Aliases(object):
    """
    Aliases is a helper class, that is automatically instantiated on import and loads multiple aliases definitions from
    JSON files to allow for conversion from TCP+UDP port/IP protocol/ICMP+ICMP6 type numbers to aliases and vice versa.
    """

    by_alias, by_number = {}, {}

    def __init__(self):
        """
        Loads aliases definitions from JSON files into class variables.
        """
        Aliases.by_alias, Aliases.by_number = Aliases.load_aliases()

    @classmethod
    def load_aliases_file(cls, filename: str) -> dict:
        """
        Return dict of ip protocol/tcp+udp service/icmp+icmp6 type aliases loaded from JSON file.

        Taken from https://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/ref-ports.html#ID-2120-00000219
        Some fixes applied, as official documentation contains some errors

        Args:
            filename: string containing filename of JSON file to load data from

        Returns:
            dict: mapping of alias name -> number
        """
        directory = f"{os.path.dirname(os.path.realpath(__file__))}{os.path.sep}aliases_json"
        with open(f"{directory}{os.path.sep}{filename}", newline="") as aliases_file:
            aliases = json.load(aliases_file)
        return aliases

    @classmethod
    def load_aliases(cls) -> (dict, dict):
        """
        Return dicts containing subdicts for mappings of alias name -> number and number -> alias name

        Returns:
            (dict, dict): First dict allows lookup of aliases by number, second dict numbers by alias
        """
        aliases = {}
        aliases["icmp"] = Aliases.load_aliases_file("icmp.json")
        aliases["icmp6"] = Aliases.load_aliases_file("icmp6.json")
        aliases["protocol"] = Aliases.load_aliases_file("protocol.json")
        aliases["tcp"] = Aliases.load_aliases_file("tcp.json")
        aliases["udp"] = Aliases.load_aliases_file("udp.json")

        # Creating inverted version to allow number lookup by alias
        aliases_inv = {}
        for proto, entries in aliases.items():
            aliases_inv[proto] = {}
            for alias, port in entries.items():
                aliases_inv[proto][port] = alias

        return aliases, aliases_inv


Aliases()
