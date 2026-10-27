import pytest

from phishing import features


def test_simple_domain():
    f = features.extract("https://www.example.com/login")
    assert f["host_length"] == len("example.com")
    assert f["n_labels"] == 2
    assert f["n_hyphens"] == 0
    assert f["n_digits"] == 0
    assert f["tld"] == "com"
    assert f["is_ip"] == 0
    assert f["on_free_host"] == 0


def test_path_and_scheme_do_not_change_features():
    # The dataset shortcut lives in scheme, www and path; none of it may leak into features.
    a = features.extract("https://www.example.com")
    b = features.extract("http://example.com/very/long/path?with=query#frag")
    assert a == b


def test_counts_hyphens_and_digits():
    f = features.extract("http://secure-login-0x42.example.net")
    assert f["n_hyphens"] == 2
    assert f["n_digits"] == 3
    assert f["digit_ratio"] == pytest.approx(3 / len("secure-login-0x42.example.net"))


@pytest.mark.parametrize("url", ["http://192.168.10.5/admin", "http://[::1]:8080/"])
def test_ip_hosts(url):
    f = features.extract(url)
    assert f["is_ip"] == 1
    assert f["tld"] == ""


def test_punycode():
    assert features.extract("https://xn--pypal-4ve.com")["has_punycode"] == 1
    assert features.extract("https://paypal.com")["has_punycode"] == 0


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("caseid123.firebaseapp.com", 1),
        ("user.github.io", 1),
        ("github.io", 1),
        ("github.com", 0),
        ("notgithub.io", 0),
    ],
)
def test_free_host(host, expected):
    assert features.extract(f"https://{host}/")["on_free_host"] == expected


def test_entropy_bounds():
    assert features.entropy("") == 0
    assert features.entropy("aaaa") == 0
    assert features.entropy("abcd") == pytest.approx(2.0)


def test_random_looking_host_scores_higher():
    plain = features.extract("https://google.com")
    random = features.extract("https://xkqzvbtrwplm8f3h.com")
    assert random["entropy"] > plain["entropy"]
    assert random["longest_consonant_run"] > plain["longest_consonant_run"]


def test_empty_url_does_not_crash():
    f = features.extract("")
    assert f["host_length"] == 0
    assert f["longest_label"] == 0


def test_extract_many_columns():
    df = features.extract_many(["https://a.com", "http://b.org"])
    assert list(df.columns) == [
        *features.NUMERIC_FEATURES,
        *features.CATEGORICAL_FEATURES,
        features.TEXT_FEATURE,
    ]
    assert list(df["host"]) == ["a.com", "b.org"]
    assert len(df) == 2
