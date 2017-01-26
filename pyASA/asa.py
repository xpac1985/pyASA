import logging
import re
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from netaddr import IPAddress

from pyASA.acl import ACL
from pyASA.caller import Caller
from pyASA.logme import LogMe


class ASA(object):
    def __init__(self, host: str, user: str, password: str, port: int = 443, use_https: bool = True,
                 url_prefix: str = "/", validate_cert: bool = True, debug: bool = False, timeout: int = 10,
                 retries: int = 2):

        self._logger = logging.getLogger("pyASA")
        if debug:
            self._logger.setLevel(logging.DEBUG)

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
        self._caller = Caller(self.baseurl, self._http_auth, self.validate_cert, self.debug, self.timeout, self.retries)
        self.acl = ACL(self._caller)

    ### Property getter and setter ###

    @property
    def host(self) -> str:
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
        return self._user

    @user.setter
    def user(self, user: str):
        self._user = str(user).strip()
        if self._caller:
            self._caller.update(http_auth=self._http_auth)

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, password: str):
        self._password = str(password).strip()
        if self._caller:
            self._caller.update(http_auth=self._http_auth)

    @property
    def use_https(self) -> bool:
        return self._use_https

    @use_https.setter
    def use_https(self, use_https: bool):
        self._use_https = bool(use_https)
        if self._caller:
            self._caller.update(baseurl=self.baseurl)

    @property
    def port(self) -> int:
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
        return self._url_prefix

    @url_prefix.setter
    def url_prefix(self, url_prefix: str):
        """Ensures that url_prefix is either '' or starts with a '/' and ends without '/' and contains no double '/'"""
        temp_url_prefix = re.sub(r'/{2,}', r'/', str(url_prefix).strip())
        if temp_url_prefix in ("", None):
            self._url_prefix = ""
        else:
            if temp_url_prefix[0] == "/":
                if temp_url_prefix[-1:] == "/":
                    self._url_prefix = temp_url_prefix[:-1]
                else:
                    self._url_prefix = f"{temp_url_prefix}"
            else:
                if temp_url_prefix[-1:] == "/":
                    self._url_prefix = f"/{temp_url_prefix}"
                else:
                    self._url_prefix = f"/{temp_url_prefix}[:-1]"
        if self._caller:
            self._caller.update(baseurl=self.baseurl)

    @property
    def validate_cert(self) -> bool:
        return self._validate_cert

    @validate_cert.setter
    def validate_cert(self, validate_cert: bool):
        self._validate_cert = bool(validate_cert)
        if not validate_cert:
            urllib3.disable_warnings(InsecureRequestWarning)
        if self._caller:
            self._caller.update(validate_cert=self._validate_cert)

    @property
    def debug(self) -> bool:
        return self._debug

    @debug.setter
    def debug(self, debug: bool):
        self._debug = bool(debug)
        if self._caller:
            self._caller.update(debug=self._debug)

    @property
    def timeout(self) -> int:
        return self._timeout

    @timeout.setter
    def timeout(self, timeout: int):
        if 0.001 <= int(timeout) <= 300:
            self._timeout = int(timeout)
            if self._caller:
                self._caller.update(timeout=self.timeout)
        else:
            raise ValueError(f"{timeout} is outside of valid timeout range 0.001 - 300 seconds")

    @property
    def retries(self):
        return self._retries

    @retries.setter
    def retries(self, retries: int):
        if not isinstance(retries, int):
            raise ValueError(f"{retries} is outside of valid timeout range 0.001 - 300 seconds")
        if not (0 <= retries <= 8):
            raise ValueError(f"retries must be in range 0..8")
        self._retries = int(retries)
        if self._caller:
            self._caller.update(retries=self._retries)

    @property
    def baseurl(self) -> str:
        """
        Returns base URL string used to connect to API.
        Only uses port if not default http/https port
        """
        if self.use_https:
            return f"https://{self.host}{f':{self.port}' if self.port != 443 else ''}{self.url_prefix}/api"
        else:
            return f"http://{self.host}{f':{self.port}' if self.port != 80 else ''}{self.url_prefix}/api"

    @property
    def _http_auth(self) -> tuple:
        return self.user, self.password

    ### Methods ###

    @LogMe
    def save_config(self):
        self._caller.save_config()

    @LogMe
    def get_management_access_info(self) -> dict:
        r = self._caller.get("mgmtaccess")
        return r.json()

    @LogMe
    def test_connection(self) -> bool:
        if self.use_https and self.port == 80:
            self._logger.warning("You are using HTTPS with port 80. This is most likely not correct.")
        if not self.use_https and self.port == 443:
            self._logger.warning("You are using HTTP with port 443. This is most likely not correct.")
        return self._caller.test_connection()

    @classmethod
    @LogMe
    def _validate_hostname(cls, hostname: str) -> bool:
        hostname_regex = re.compile(
            r"(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?")
        return bool(hostname_regex.fullmatch(hostname))

    @classmethod
    @LogMe
    def _validate_ip(cls, ip: str) -> bool:
        try:
            IPAddress(ip)
            return True
        except:
            return False
