"""Evasion tricks an attacker controls, applied to phishing hostnames the models already catch.

Each attack takes a hostname and returns a full URL, because the scoring path starts
from a URL. All of them are deterministic so results can be reproduced.
"""

from phishing.data import to_punycode
from phishing.features import is_ip

# Cyrillic letters that render the same as Latin ones in most fonts.
HOMOGLYPHS = str.maketrans(
    {"a": "а", "c": "с", "e": "е", "i": "і", "o": "о", "p": "р", "x": "х", "y": "у"}
)
SHORTENER = "bit.ly"
BRAND_PREFIX = "accounts.google.com"
FREE_HOST = "web.app"


def _split(host: str) -> tuple[list[str], str]:
    labels = host.split(".")
    return (labels[:-1], labels[-1]) if len(labels) > 1 else (labels, "")


def _join(names: list[str], tld: str) -> str:
    return ".".join([*names, tld]) if tld else ".".join(names)


def _url(host: str, path: str = "/login") -> str:
    return f"https://{host}{path}"


def homoglyph_unicode(host: str) -> str:
    if is_ip(host):
        return _url(host)
    names, tld = _split(host)
    return _url(_join([n.translate(HOMOGLYPHS) for n in names], tld))


def homoglyph_punycode(host: str) -> str:
    if is_ip(host):
        return _url(host)
    names, tld = _split(host)
    return _url(to_punycode(_join([n.translate(HOMOGLYPHS) for n in names], tld)))


def shortener(host: str) -> str:
    # The real host is only known after following the redirect, which a URL-only model can't do.
    return _url(SHORTENER, "/3xAmpl3")


def brand_subdomain(host: str) -> str:
    return _url(f"{BRAND_PREFIX}.{host}")


def strip_hyphens_digits(host: str) -> str:
    if is_ip(host):
        return _url(host)
    names, tld = _split(host)
    cleaned = ["".join(ch for ch in n if ch.isalpha()) or n for n in names]
    return _url(_join(cleaned, tld))


def tld_to_com(host: str) -> str:
    if is_ip(host):
        return _url(host)
    names, tld = _split(host)
    return _url(_join(names, "com") if tld else f"{host}.com")


def free_hosting(host: str) -> str:
    first = host.split(".")[0] or "site"
    return _url(f"{first}.{FREE_HOST}")


def long_path(host: str) -> str:
    # Control case: features are hostname-only, so this must not change any score.
    return _url(host, "/" + "account/" * 40 + "?session=" + "a" * 300)


ATTACKS = {
    "long_path": long_path,
    "homoglyph_unicode": homoglyph_unicode,
    "homoglyph_punycode": homoglyph_punycode,
    "strip_hyphens_digits": strip_hyphens_digits,
    "tld_to_com": tld_to_com,
    "brand_subdomain": brand_subdomain,
    "free_hosting": free_hosting,
    "shortener": shortener,
}
