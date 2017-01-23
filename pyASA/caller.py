import json
import logging
import requests


class Caller(object):
    def __init__(self, baseurl: str, http_auth: tuple, validate_cert: bool, debug: bool, timeout: int):
        self.headers = {
            'content-type': 'application/json',
            "user-agent": "pyASA"
        }

        self.baseurl = baseurl
        self.http_auth = http_auth
        self.validate_cert = validate_cert
        self.debug = debug
        self.timeout = timeout
        self.logger = logging.getLogger("pyASA")

    def update(self, baseurl: str = None, http_auth: tuple = None, validate_cert: bool = None, debug: bool = None,
               timeout: int = None):
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

    def delete(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        if parameters is None:
            parameters = {}
        elif isinstance(parameters, dict):
            parameters = dict(parameters)
        else:
            raise ValueError(f"{type(parameters)} is not a valid parameters argument type")
        self.logger.debug(f"DELETE {self.baseurl}/{url} --- parameters: {parameters}")
        response = requests.delete(f"{self.baseurl}/{url}", params=parameters, auth=self.http_auth,
                                   headers=self.headers, verify=self.validate_cert)
        self.logger.debug(f"DELETE HTTP response code {response.status_code}, history {response.history}, header {response.headers}")
        self.logger.debug(f"DELETE {response.text}")
        return response

    def get(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        if parameters is None:
            parameters = {}
        elif isinstance(parameters, dict):
            parameters = dict(parameters)
        else:
            raise ValueError(f"{type(parameters)} is not a valid parameters argument type")
        self.logger.debug(f"GET {self.baseurl}/{url} --- parameters: {parameters}")
        response = requests.get(f"{self.baseurl}/{url}", params=parameters, auth=self.http_auth, headers=self.headers,
                                verify=self.validate_cert)
        self.logger.debug(f"GET HTTP response code {response.status_code}, history {response.history}, header {response.headers}")
        self.logger.debug(f"GET {response.text}")
        return response

    def post(self, url: str, data: [dict, None] = None) -> requests.Response:
        if data is not None:
            data = json.dumps(data)
        self.logger.debug(f"POST {self.baseurl}/{url} --- data: {data}")
        response = requests.post(f"{self.baseurl}/{url}", data=data, auth=self.http_auth, headers=self.headers,
                                 verify=self.validate_cert)
        self.logger.debug(f"POST HTTP response code {response.status_code}, history {response.history}, header {response.headers}")
        self.logger.debug(f"POST {response.text}")
        return response
