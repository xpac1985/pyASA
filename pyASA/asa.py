import logging

import requests
from netaddr import IPAddress
from pyASA.acl import ACL
from pyASA.caller import Caller
from pyASA.logme import LogMe
import re
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class ASA(object):
    """
    Central class, which is the starting point for everything in pyASA.
    An instance of ASA class allows for connection setup and includes all other modules.
    """

    def __init__(self, host: str, user: str, password: str, port: int = 443, use_https: bool = True,
                 url_prefix: str = "/", validate_cert: bool = True, debug: bool = False, timeout: int = 10,
                 retries: int = 2):

        self._logger = logging.getLogger("pyASA")
        if debug:
            self._logger.setLevel(logging.DEBUG)

        # Create variables and set to defaults in case of uncaught failure
        self._host = ""
        self._user = ""
        self._password = ""
        self._use_https = True
        self._port = 443
        self._url_prefix = "/"
        self._validate_cert = True
        self._debug = False
        self._timeout = 10
        self._retries = 2

        # Set variables to provided values
        self._caller = None
        self.host = host
        self.user = user
        self.password = password
        self.use_https = use_https
        self.port = port
        self.url_prefix = url_prefix
        self.validate_cert = validate_cert
        self.debug = debug
        self.timeout = timeout
        self.retries = retries
        self._caller = Caller(self.baseurl, self._http_auth, self.validate_cert, self.timeout, self.retries)
        self.acl = ACL(self._caller)

    # Property getters and setters #

    @property
    def host(self) -> str:
        """
        Return/set the hostname or IP used for HTTP connections.

        Setter strips whitespace and checks if string is actually a valid hostname or IP, else raises ValueError.

        Returns:
            Sanitized hostname as used in HTTP connections
        """
        return self._host

    @host.setter
    def host(self, host: str):
        temp_host = str(host).strip()
        if ASA._validate_hostname(temp_host) or ASA._validate_ip(temp_host):
            self._host = temp_host
            if self._caller:
                self._caller.update(baseurl=self.baseurl)
        else:
            raise ValueError(f"String '{temp_host}' is not a valid hostname or IP address.")

    @property
    def user(self) -> str:
        """
        Return/set the username or IP used for HTTP(S) authentication.

        Setter strips whitespace.

        Returns:
            Sanitized username as used in HTTP(S) connections
        """
        return self._user

    @user.setter
    def user(self, user: str):
        self._user = str(user).strip()
        if self._caller:
            self._caller.update(http_auth=self._http_auth)

    @property
    def password(self) -> str:
        """
        Return/set the password or IP used for HTTP(S) authentication.

        Setter strips whitespace.

        Returns:
            Sanitized password as used in HTTP(S) authentication
        """
        return self._password

    @password.setter
    def password(self, password: str):
        self._password = str(password).strip()
        if self._caller:
            self._caller.update(http_auth=self._http_auth)

    @property
    def use_https(self) -> bool:
        """
        Return/set use of HTTPS instead of HTTP for API requests.

        Returns:
            True if HTTPS is used, False if not
        """
        return self._use_https

    @use_https.setter
    def use_https(self, use_https: bool):
        self._use_https = bool(use_https)
        if self._caller:
            self._caller.update(baseurl=self.baseurl)

    @property
    def port(self) -> int:
        """
        Return/set port used in HTTP connections.

        Setter checks if port is in range 1..65535.

        Returns:
            Port number used for API requests
        """
        return self._port

    @port.setter
    def port(self, port: int):
        if 1 <= int(port) <= 65535:
            self._port = int(port)
            if self._caller:
                self._caller.update(baseurl=self.baseurl)
        else:
            raise ValueError(f"{port} is outside of valid port range 1 - 65535")

    @property
    def url_prefix(self) -> str:
        """
        Return/set prefix used for API requests.

        Necessary if API url is non default, e.g. modified by a reverse proxy.
        Setter validates that there is either no prefix or one starting and ending with a '/'

        Returns:
            Sanitized prefix used for API requests
        """
        return self._url_prefix

    @url_prefix.setter
    def url_prefix(self, url_prefix: str):
        # Replace // with single /
        url_prefix = re.sub(r'/{2,}', r'/', str(url_prefix).strip())
        if url_prefix in ("", None):
            self._url_prefix = ""
        else:
            if url_prefix[0] == "/":
                if url_prefix[-1:] == "/":
                    self._url_prefix = url_prefix[:-1]
                else:
                    self._url_prefix = f"{url_prefix}"
            else:
                if url_prefix[-1:] == "/":
                    self._url_prefix = f"/{url_prefix}"
                else:
                    self._url_prefix = f"/{url_prefix}[:-1]"
        if self._caller:
            self._caller.update(baseurl=self.baseurl)

    @property
    def validate_cert(self) -> bool:
        """
        Return/set validation of certificates if HTTPS is used.

        Necessary if ASA uses self-signed or otherwise invalid SSL certificates.

        Returns:
            True if certificate validation is active, False if not
        """
        return self._validate_cert

    @validate_cert.setter
    def validate_cert(self, validate_cert: bool):
        self._validate_cert = bool(validate_cert)
        if not validate_cert:
            # Warnings in urllib3 can only be disabled, not reenabled
            urllib3.disable_warnings(InsecureRequestWarning)
        if self._caller:
            self._caller.update(validate_cert=self._validate_cert)

    @property
    def debug(self) -> bool:
        """
        Return/set debug mode status.

        If True, logger will output a lot of debug information for analysis.

        Returns:
            True if debug is enabled, False if not
        """
        return self._debug

    @debug.setter
    def debug(self, debug: bool):
        self._debug = bool(debug)

    @property
    def timeout(self) -> int:
        """
        Return/set timeout for HTTP(S) connections.

        Setter checks if value is within range of 1..300 seconds.

        Returns:
            Timeout used for API requests
        """
        return self._timeout

    @timeout.setter
    def timeout(self, timeout: int):
        if 1 <= int(timeout) <= 300:
            self._timeout = int(timeout)
            if self._caller:
                self._caller.update(timeout=self.timeout)
        else:
            raise ValueError(f"{timeout} is outside of valid timeout range 1 - 300 seconds")

    @property
    def retries(self):
        """
        Return/set retries when an bulk API request fails.

        As the ASA API agent tends to crash especially on bulk operations, some retries are made before failing.

        Returns:
            Count of retries for bulk API requests
        """
        return self._retries

    @retries.setter
    def retries(self, retries: int):
        if not isinstance(retries, int):
            raise ValueError(f"{type(retries)} is not a valid retry argument type")
        if not (0 <= retries <= 10):
            raise ValueError(f"retries must be in range 0..10")
        self._retries = int(retries)
        if self._caller:
            self._caller.update(retries=self._retries)

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
    def _http_auth(self) -> (str, str):
        return self.user, self.password

    ### Methods ###

    def save_config(self):
        """
        Call API to make the ASA write the running config to the startup config file.
        """
        response = self._caller.post("commands/writemem")
        if response.status_code != requests.codes.ok:
            raise RuntimeError(
                f"Config save failed with HTTP {response.status_code}: {response.json()}")

    def get_management_access_info(self) -> dict:
        """
        Get ASA management settings via API call.

        Returns a dictionary containing several settings for management access, like SSH, HTTP(S) and others.

        Returns:
            dict containing ASA management settings
        """
        response = self._caller.get("mgmtaccess")
        if response.status_code != requests.codes.ok:
            raise RuntimeError(f"Fetching management access settings failed with HTTP {response.status_code}")
        return response.json()

    def test_connection(self) -> bool:
        """
        Check if connection to ASA can be established.

        Checks if use of HTTPS and port number match and logs a warning if they don't.

        Returns:
            bool: True if connection could be made, False if not
        """
        if self.use_https and self.port == 80:
            self._logger.warning("You are using HTTPS with port 80. This is most likely not correct.")
        if not self.use_https and self.port == 443:
            self._logger.warning("You are using HTTP with port 443. This is most likely not correct.")
        return self._caller.test_connection()

    @classmethod
    def _validate_hostname(cls, hostname: str) -> bool:
        """
        Check if argument is a valid hostname using regex.

        Args:
            hostname: hostname to be validated

        Returns:
            bool: True if argument is a valid hostname, False if not
        """
        hostname_regex = re.compile(
            r"(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?")
        return bool(hostname_regex.fullmatch(hostname))

    @classmethod
    def _validate_ip(cls, ip: str) -> bool:
        """
        Check if argument is a valid IPv4 or IPv6 address.

        Args:
            ip: IP string to be checked

        Returns:
            bool: True if argument is a valid IP, False if not
        """
        try:
            IPAddress(ip)
            return True
        except:
            return False
