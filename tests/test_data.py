import zipfile

import pytest

from phishing import data


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.example.com", "example.com"),
        ("http://Example.COM/login?x=1", "example.com"),
        ("https://user:pw@evil.com:8080/path", "evil.com"),
        ("https://paypal.com@evil.com/", "evil.com"),
        ("https://sub.www.example.com/", "sub.www.example.com"),
        ("https://xn--pypal-4ve.com/#a", "xn--pypal-4ve.com"),
        ("example.com/no-scheme", "example.com"),
    ],
)
def test_hostname(url, expected):
    assert data.hostname(url) == expected


def test_load_flips_label_so_one_means_phishing(tmp_path):
    csv = "URL,label,URLLength\nhttps://www.good.org,1,20\nhttp://bad.xyz/login,0,20\n"
    path = tmp_path / data.ZIP_NAME
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(data.CSV_NAME, csv)

    df = data.load(path)

    assert list(df.columns) == ["url", "hostname", "is_phishing"]
    assert df["is_phishing"].tolist() == [0, 1]
    assert df["hostname"].tolist() == ["good.org", "bad.xyz"]


def test_download_rejects_bad_checksum(tmp_path):
    (tmp_path / data.ZIP_NAME).write_bytes(b"not the real file")
    with pytest.raises(ValueError, match="Checksum mismatch"):
        data.download(tmp_path)
