from pyASA.asa import ASA


class Test_ASA(object):
    def test_validate_ip_okay(self):
        assert ASA._validate_ip("10.3.5.8")
        assert ASA._validate_ip("200a:2::7")

    def test_validate_ip_fail(self):
        assert not ASA._validate_ip("10.3..4")
        assert not ASA._validate_ip("2001:2:6")

    def test_validate_hostname_okay(self):
        assert ASA._validate_hostname("asa")
        assert ASA._validate_hostname("some.better.host.domain.tld")

    def test_validate_hostname_fail(self):
        assert not ASA._validate_hostname("..some.bad.hostname")
        assert not ASA._validate_hostname("-some.invalid.hostname")
