import json
import logging
from time import sleep
from typing import Optional, Dict, List, Tuple, Union

import requests


class Caller(object):
    """
    Utility class to facilitate actual HTTP(S) requests to API.
    Is spawned by creation of ASA object, updated from there and referenced to other classes, like ACL.
    Provides some additional utility methods for connection testing, etc.
    """

    def __init__(self):
        # HTTP headers used when connectiong to API
        self.headers = {
            'content-type': 'application/json',
            "user-agent": "pyASA"
        }

        # Create variables and set to defaults in case of uncaught failure
        self.logger = logging.getLogger("pyASA")

        self.host = ""
        self.user = ""
        self.password = ""
        self.use_https = True
        self.port = 443
        self.url_prefix = ""
        self.validate_cert = True
        self.timeout = 10
        self.retries = 2

    # Properties #

    @property
    def baseurl(self) -> str:
        """
        Return URL used for API requests, composed from configured host, port, HTTP/HTTPs and url prefix.

        Returns:
            URL used for API requests
        """
        if self.use_https:
            return f"https://{self.host}{f':{self.port}' if self.port != 443 else ''}{self.url_prefix}/api"
        else:
            return f"http://{self.host}{f':{self.port}' if self.port != 80 else ''}{self.url_prefix}/api"

    @property
    def http_auth(self) -> Tuple[str, str]:
        return self.user, self.password

    # Methods #

    def delete(self, url: str, parameters: Optional[Dict] = None) -> requests.Response:
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
        response = None
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

    def get(self, url: str, parameters: Optional[Dict] = None) -> requests.Response:
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
        response = None
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

    def post(self, url: str, data: Union[None, Dict, List] = None) -> requests.Response:
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
        response = None
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
                # If API call fails with HTTP 500, wait for next call the longer the more tries already failed
                sleep(tries)
        return response

    def test_connection(self) -> bool:
        """
        Make a simple call to the API to test the connection to the ASA.
        Returns:
            True if successful, False if not
        """
        try:
            r = self.get("mgmtaccess")
            return r.status_code == requests.codes.ok
        except Exception as e:
            self.logger.warning(f"ASA connection test failed: {e}")
            return False
