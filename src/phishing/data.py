import hashlib
import os
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd

URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
ZIP_NAME = "phiusiil.zip"
CSV_NAME = "PhiUSIIL_Phishing_URL_Dataset.csv"


def data_dir() -> Path:
    return Path(os.environ.get("PHISHING_DATA_DIR", "data/raw"))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(dest_dir: Path | None = None) -> Path:
    dest_dir = dest_dir or data_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / ZIP_NAME

    if not path.exists():
        tmp = path.with_suffix(".part")
        urllib.request.urlretrieve(URL, tmp)
        tmp.replace(path)

    actual = sha256_of(path)
    if actual != SHA256:
        raise ValueError(f"Checksum mismatch for {path}: expected {SHA256}, got {actual}")
    return path


def hostname(url: str) -> str:
    """Host part only, lower-cased, without scheme, port or a leading 'www.'."""
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]
    # In an IPv6 literal like [::1]:8080 the colons belong to the address, not a port.
    ipv6 = host.startswith("[")
    host = host[: host.find("]") + 1] if ipv6 else host.split(":", 1)[0]
    host = host.lower()
    return host.removeprefix("www.")


def load(path: Path | None = None) -> pd.DataFrame:
    """URL, hostname and is_phishing (1 = phishing) for every row.

    The dataset's own `label` is 1 for *legitimate*, which is easy to get backwards,
    so it's flipped here once. The page-content columns are dropped on purpose:
    this project only uses what's in the URL.
    """
    path = path or data_dir() / ZIP_NAME
    with zipfile.ZipFile(path) as z, z.open(CSV_NAME) as f:
        df = pd.read_csv(f, usecols=["URL", "label"])

    df = df.rename(columns={"URL": "url"})
    df["is_phishing"] = 1 - df.pop("label")
    df["hostname"] = df["url"].map(hostname)
    return df[["url", "hostname", "is_phishing"]]


if __name__ == "__main__":
    print(download())
