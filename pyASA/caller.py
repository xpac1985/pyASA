import json
import logging
import requests
from time import sleep
from pyASA.logme import LogMe


class Caller(object):
    def __init__(self, baseurl: str, http_auth: tuple, validate_cert: bool, debug: bool, timeout: int, retries: int):
        self.headers = {
            'content-type': 'application/json',
            "user-agent": "pyASA"
        }

        self.baseurl = baseurl
        self.http_auth = http_auth
        self.validate_cert = validate_cert
        self.debug = debug
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger("pyASA")

    def update(self, baseurl: str = None, http_auth: tuple = None, validate_cert: bool = None, debug: bool = None,
               timeout: int = None, retries: int = None):
        if baseurl:
            self.baseurl = baseurl
        if http_auth:
            self.http_auth = http_auth
        if validate_cert:
            self.validate_cert = validate_cert
        if debug:
            self.debug = debug
        if timeout:
            self.timeout = timeout
        if retries:
            self.retries = retries

    @LogMe
    def delete(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        if parameters is None:
            parameters = {}
        elif isinstance(parameters, dict):
            parameters = dict(parameters)
        else:
            raise ValueError(f"{type(parameters)} is not a valid parameters argument type")
        tries = 0
        code = 500
        while code == 500 and tries <= self.retries:
            self.logger.debug(f"DELETE REQ {self.baseurl}/{url} --- parameters: {parameters}")
            response = requests.delete(f"{self.baseurl}/{url}", params=parameters, auth=self.http_auth,
                                       headers=self.headers, verify=self.validate_cert)
            self.logger.debug(
                f"DELETE RSP HTTP  code {response.status_code}, history {response.history}, header {response.headers}")
            self.logger.debug(f"DELETE BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                sleep(tries)
        return response

    @LogMe
    def get(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        if parameters is None:
            parameters = {}
        elif isinstance(parameters, dict):
            parameters = dict(parameters)
        else:
            raise ValueError(f"{type(parameters)} is not a valid parameters argument type")
        tries = 0
        code = 500
        while code == 500 and tries <= self.retries:
            self.logger.debug(f"GET REQ {self.baseurl}/{url} --- parameters: {parameters}")
            response = requests.get(f"{self.baseurl}/{url}", params=parameters, auth=self.http_auth,
                                    headers=self.headers,
                                    verify=self.validate_cert)
            self.logger.debug(
                f"GET RSP HTTP code {response.status_code}, history {response.history}, header {response.headers}")
            self.logger.debug(f"GET BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                sleep(tries)
        return response

    @LogMe
    def post(self, url: str, data: [dict, None] = None) -> requests.Response:
        if data is not None:
            data = json.dumps(data)
        tries = 0
        code = 500
        while code == 500 and tries <= self.retries:
            self.logger.debug(f"POST REQ {self.baseurl}/{url} --- data: {data}")
            response = requests.post(f"{self.baseurl}/{url}", data=data, auth=self.http_auth, headers=self.headers,
                                     verify=self.validate_cert)
            self.logger.debug(
                f"POST RSP HTTP code {response.status_code}, history {response.history}, header {response.headers}")
            self.logger.debug(f"POST BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                sleep(tries)
        return response

    @LogMe
    def test_connection(self) -> bool:
        try:
            r = self.get("mgmtaccess")
            return r.status_code == requests.codes.ok
        except Exception as e:
            self.logger.warning(f"ASA connection test failed: {e}")
            return False

    @LogMe
    def save_config(self):
        response = self.post("commands/writemem")
        if response.status_code != requests.codes.ok:
            raise RuntimeError(
                f"Config save failed with HTTP {response.status_code}: {response.json()}")
