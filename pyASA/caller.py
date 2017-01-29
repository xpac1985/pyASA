import json
import logging

import copy
import requests
from time import sleep
from pyASA.logme import LogMe


class Caller(object):
    """
    Utility class to facilitate actual HTTP(S) requests to API.
    Is spawned by creation of ASA object, updated from there and referenced to other classes, like ACL.
    Provides some additional utility methods for connection testing, etc.
    """

    def __init__(self, baseurl: str, http_auth: tuple, validate_cert: bool, timeout: int, retries: int):
        # HTTP headers used when connectiong to API
        self.headers = {
            'content-type': 'application/json',
            "user-agent": "pyASA"
        }

        self.baseurl = baseurl
        self.http_auth = http_auth
        self.validate_cert = validate_cert
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger("pyASA")

    def update(self, baseurl: str = None, http_auth: tuple = None, validate_cert: bool = None, timeout: int = None,
               retries: int = None):
        """
        Update one or more of the settings used to connect to the API via HTTP(S).

        Usually invoked by parent ASA object, which does the input validation before.

        Args:
            baseurl: Base URL used to connect to ASA REST API
            http_auth: Username and password tuple, for authentication
            validate_cert: Whether to validate SSL certs on HTTPS connections
            timeout (): Timeout value to use for connections
            retries (): Number of retries when an API call fails with HTTP 500
        """
        if baseurl:
            self.baseurl = baseurl
        if http_auth:
            self.http_auth = http_auth
        if validate_cert:
            self.validate_cert = validate_cert
        if timeout:
            self.timeout = timeout
        if retries:
            self.retries = retries

    def delete(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        """
        Call API using HTTP DELETE with baseurl plus supplied url argument, return Response object

        Args:
            url: API url part to concat to the baseurl for specific API function
            parameters: Parameters to use in call, if supplied. Defaults to None

        Returns:
            Response: Response object containing received server headers, status code and body
        """
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
                f"DELETE RSP HTTP  code {response.status_code}, header {response.headers}")
            self.logger.debug(f"DELETE BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                # If API call failed with HTTP 500, wait for next call the longer the more tries already failed
                sleep(tries)
        return response

    def get(self, url: str, parameters: [dict, None] = None) -> requests.Response:
        """
        Call API using HTTP GET with baseurl plus supplied url argument, return Response object

        Args:
            url: API url part to concat to the baseurl for specific API function
            parameters: Parameters to use in call, if supplied. Defaults to None

        Returns:
            Response: Response object containing received server headers, status code and body
        """
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
                f"GET RSP HTTP code {response.status_code}, header {response.headers}")
            self.logger.debug(f"GET BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                # If API call failed with HTTP 500, wait for next call the longer the more tries already failed
                sleep(tries)
        return response

    def post(self, url: str, data: [dict, list, None] = None) -> requests.Response:
        """
        Call API using HTTP POST with baseurl plus supplied url argument, return Response object

        Args:
            url: API url part to concat to the baseurl for specific API function
            data: Request body to use in call, if supplied. Defaults to None

        Returns:
            Response: Response object containing received server headers, status code and body
        """
        if data is None:
            data = json.dumps({})
        elif isinstance(data, (dict, list)):
            data = json.dumps(data)
        else:
            raise ValueError(f"{type(data)} is not a valid parameters argument type")
        tries = 0
        code = 500
        while code == 500 and tries <= self.retries:
            self.logger.debug(f"POST REQ {self.baseurl}/{url} --- data: {data}")
            response = requests.post(f"{self.baseurl}/{url}", data=data, auth=self.http_auth, headers=self.headers,
                                     verify=self.validate_cert)
            self.logger.debug(
                f"POST RSP HTTP code {response.status_code}, header {response.headers}")
            self.logger.debug(f"POST BDY {response.text}")
            tries += 1
            code = response.status_code
            if code == 500:
                # If API call failed with HTTP 500, wait for next call the longer the more tries already failed
                sleep(tries)
        return response

    def test_connection(self) -> bool:
        try:
            r = self.get("mgmtaccess")
            return r.status_code == requests.codes.ok
        except Exception as e:
            self.logger.warning(f"ASA connection test failed: {e}")
            return False
