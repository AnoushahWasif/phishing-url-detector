import pytest

from phishing import attacks
from phishing.data import hostname
from phishing.features import extract

HOSTS = [
    "secure-login-paypal123.xyz",
    "a.b.example.co.uk",
    "single",
    "192.168.1.10",
    "",
]


@pytest.mark.parametrize("name", list(attacks.ATTACKS))
@pytest.mark.parametrize("host", HOSTS)
def test_every_attack_gives_a_url_the_extractor_accepts(name, host):
    url = attacks.ATTACKS[name](host)
    assert url.startswith("https://")
    features = extract(url)
    assert features["host_length"] >= 0


@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_attacks_are_deterministic(name):
    fn = attacks.ATTACKS[name]
    assert fn("evil-site99.top") == fn("evil-site99.top")


def test_long_path_leaves_the_hostname_alone():
    assert hostname(attacks.long_path("evil.top")) == "evil.top"


def test_homoglyph_url_is_not_plain_ascii():
    url = attacks.homoglyph_unicode("paypal.com")
    assert "paypal.com" not in url
    assert not url.isascii()
    assert url.endswith(".com/login")  # the TLD is left alone


def test_unicode_and_punycode_homoglyphs_give_identical_features():
    # The fix for the Day 6 finding: both spellings of the same domain look the same to the model.
    a = extract(attacks.homoglyph_unicode("paypal.com"))
    b = extract(attacks.homoglyph_punycode("paypal.com"))
    assert a == b
    assert a["has_punycode"] == 1


def test_strip_hyphens_digits():
    assert (
        hostname(attacks.strip_hyphens_digits("secure-login-1.evil-2.xyz"))
        == "securelogin.evil.xyz"
    )


def test_strip_never_empties_a_label():
    assert hostname(attacks.strip_hyphens_digits("123.xyz")) == "123.xyz"


def test_tld_swap():
    assert hostname(attacks.tld_to_com("evil.xyz")) == "evil.com"
    assert hostname(attacks.tld_to_com("single")) == "single.com"


def test_ip_hosts_are_left_alone_where_the_trick_does_not_apply():
    for fn in (attacks.homoglyph_unicode, attacks.strip_hyphens_digits, attacks.tld_to_com):
        assert hostname(fn("10.0.0.1")) == "10.0.0.1"


def test_brand_subdomain_and_free_hosting():
    assert hostname(attacks.brand_subdomain("evil.xyz")) == "accounts.google.com.evil.xyz"
    assert hostname(attacks.free_hosting("evil.xyz")) == "evil.web.app"
    assert extract(attacks.free_hosting("evil.xyz"))["on_free_host"] == 1


def test_shortener_hides_the_real_host():
    assert hostname(attacks.shortener("anything.xyz")) == "bit.ly"
