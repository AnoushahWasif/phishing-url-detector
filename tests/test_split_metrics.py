import numpy as np
import pandas as pd
import pytest

from phishing.metrics import evaluate, threshold_at_fpr
from phishing.split import grouped_split, registered_domain


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.example.com", "example.com"),
        ("example.com", "example.com"),
        ("news.bbc.co.uk", "bbc.co.uk"),
        ("abc.web.app", "abc.web.app"),
        ("x.y.github.io", "y.github.io"),
        ("192.168.0.1", "192.168.0.1"),
        ("[::1]", "[::1]"),
    ],
)
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_grouped_split_keeps_domains_on_one_side():
    hosts = [f"{sub}.site{i}.com" for i in range(100) for sub in ("a", "b", "c")]
    df = pd.DataFrame({"hostname": hosts, "is_phishing": [i % 2 for i in range(len(hosts))]})
    train, test = grouped_split(df, test_size=0.2, seed=0)

    train_domains = set(train["hostname"].map(registered_domain))
    test_domains = set(test["hostname"].map(registered_domain))
    assert train_domains.isdisjoint(test_domains)
    assert len(train) + len(test) == len(df)
    assert 0.1 < len(test) / len(df) < 0.3


def test_grouped_split_is_reproducible():
    df = pd.DataFrame({"hostname": [f"h{i}.com" for i in range(50)], "is_phishing": 0})
    a, _ = grouped_split(df, seed=7)
    b, _ = grouped_split(df, seed=7)
    assert a.index.equals(b.index)


def test_threshold_respects_max_fpr():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(1000), np.ones(1000)]
    scores = np.r_[rng.normal(0, 1, 1000), rng.normal(2, 1, 1000)]
    t = threshold_at_fpr(y, scores, max_fpr=0.01)
    fpr = (scores[y == 0] >= t).mean()
    assert fpr <= 0.01


def test_evaluate_counts():
    y = [1, 1, 1, 0, 0, 0, 0]
    scores = [0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1]
    m = evaluate(y, scores, threshold=0.5)
    assert m["missed_phishing"] == 1
    assert m["false_alarms"] == 1
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(1 / 4)
    assert m["precision"] == pytest.approx(2 / 3)


def test_evaluate_handles_no_positive_predictions():
    m = evaluate([1, 0], [0.1, 0.2], threshold=0.9)
    assert m["recall"] == 0
    assert m["precision"] == 0
