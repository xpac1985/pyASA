from pyASA.asa import ASA
host = "asa"
user = "admin"
password = "cisco"
port = 443
use_https = True
url_prefix = "/"
validate_cert = True
debug = True
timeout = 10

asa = ASA(host, user, password, port, use_https, url_prefix, validate_cert, debug, timeout)
