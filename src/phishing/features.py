import ipaddress
import math
import re
from collections import Counter

import pandas as pd

from phishing.data import hostname

# Free hosting and site builders seen in the EDA. Anyone can get a subdomain on these,
# so the registered domain says nothing about who runs the site.
FREE_HOSTS = (
    "web.app",
    "firebaseapp.com",
    "github.io",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "godaddysites.com",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "glitch.me",
    "herokuapp.com",
    "ipfs.dweb.link",
    "cloudflare-ipfs.com",
)

CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]+")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def on_free_host(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in FREE_HOSTS)


def extract(url: str) -> dict:
    """Numeric features from the hostname of `url`. No network access."""
    host = hostname(url)
    labels = host.split(".") if host else []
    ip = is_ip(host)
    digits = sum(ch.isdigit() for ch in host)
    runs = CONSONANT_RUN.findall(host)

    return {
        "host_length": len(host),
        "n_labels": len(labels),
        "n_hyphens": host.count("-"),
        "n_digits": digits,
        "digit_ratio": digits / len(host) if host else 0.0,
        "longest_label": max((len(label) for label in labels), default=0),
        "longest_consonant_run": max((len(r) for r in runs), default=0),
        "entropy": entropy(host),
        "is_ip": int(ip),
        "has_punycode": int("xn--" in host),
        "on_free_host": int(on_free_host(host)),
        "tld": "" if ip or not labels else labels[-1],
    }


def extract_many(urls) -> pd.DataFrame:
    return pd.DataFrame([extract(u) for u in urls])


NUMERIC_FEATURES = [k for k in extract("example.com") if k != "tld"]
CATEGORICAL_FEATURES = ["tld"]
