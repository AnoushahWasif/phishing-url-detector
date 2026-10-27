import numpy as np
import pytest

from phishing.features import extract_many
from phishing.plots import plot_recall_vs_fpr, spread_labels
from phishing.train import models


def synthetic(n=400, seed=0):
    """Phishing hosts carry bait words and hyphens; legit ones are short brand-like names."""
    rng = np.random.default_rng(seed)
    bait = ["secure-login", "verify-account", "paypa1-update", "wallet-confirm"]
    tlds = ["com", "org", "net", "xyz", "top"]
    urls, labels = [], []
    for i in range(n):
        phishing = i % 2
        tld = tlds[rng.integers(len(tlds))]
        if phishing:
            host = f"{bait[rng.integers(len(bait))]}-{rng.integers(1000)}.site{i}.{tld}"
        else:
            host = f"brand{i}.{tld}"
        urls.append(f"https://{host}/")
        labels.append(phishing)
    return extract_many(urls), np.array(labels)


@pytest.fixture(scope="module")
def fitted():
    X, y = synthetic()
    return {name: model.fit(X, y) for name, model in models().items()}


def test_model_set():
    assert set(models()) == {
        "logistic_regression",
        "random_forest",
        "lightgbm",
        "char_ngram_logreg",
    }


def test_every_model_learns_the_synthetic_signal(fitted):
    X, y = synthetic(200, seed=1)
    for name, model in fitted.items():
        scores = model.predict_proba(X)[:, 1]
        assert scores[y == 1].mean() > scores[y == 0].mean() + 0.3, name


@pytest.mark.parametrize(
    "url",
    [
        "",  # nothing at all
        "http://192.168.10.5/login",  # IP host, no TLD
        "https://[2001:db8::1]:8443/",  # IPv6
        "https://xn--pypal-4ve.com",  # punycode, unseen characters for the n-gram model
        "https://a.b.c.d.e.f.g.h.example.zz",  # unseen TLD, many labels
        "https://" + "a" * 250 + ".com",  # very long label
        "https://ÄÖÜ-bank.de",  # non-ASCII
    ],
)
def test_odd_urls_get_a_valid_score(fitted, url):
    X = extract_many([url])
    for name, model in fitted.items():
        score = model.predict_proba(X)[0, 1]
        assert 0.0 <= score <= 1.0, name
        assert np.isfinite(score), name


def test_scoring_is_deterministic(fitted):
    X, _ = synthetic(50, seed=2)
    for name, model in fitted.items():
        np.testing.assert_array_equal(model.predict_proba(X), model.predict_proba(X), name)


def test_training_is_reproducible():
    X, y = synthetic()
    a = models()["lightgbm"].fit(X, y).predict_proba(X)
    b = models()["lightgbm"].fit(X, y).predict_proba(X)
    np.testing.assert_allclose(a, b)


def test_char_model_ignores_numeric_columns():
    # It must see only the hostname text, so changing a numeric feature can't move its score.
    X, y = synthetic()
    model = models()["char_ngram_logreg"].fit(X, y)
    changed = X.assign(n_hyphens=999, entropy=0.0)
    np.testing.assert_allclose(model.predict_proba(X), model.predict_proba(changed))


def test_plot_writes_png(tmp_path, fitted):
    X, y = synthetic(100, seed=3)
    scores = {name: m.predict_proba(X)[:, 1] for name, m in fitted.items()}
    out = tmp_path / "figs" / "roc.png"
    plot_recall_vs_fpr(y, scores, out)
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_plot_rejects_too_many_series(tmp_path):
    y = np.array([0, 1, 0, 1])
    scores = {f"m{i}": np.array([0.1, 0.9, 0.2, 0.8]) for i in range(5)}
    with pytest.raises(ValueError, match="At most"):
        plot_recall_vs_fpr(y, scores, tmp_path / "x.png")


def test_spread_labels_separates_close_values():
    out = spread_labels({"a": 68.4, "b": 68.6, "c": 65.0, "d": 72.7}, min_gap=3.5)
    ordered = sorted(out.values())
    assert all(b - a >= 3.5 - 1e-9 for a, b in zip(ordered, ordered[1:], strict=False))
    assert out["c"] == 65.0  # the lowest label never moves


def test_spread_labels_leaves_far_apart_values_alone():
    ys = {"a": 10.0, "b": 50.0}
    assert spread_labels(ys) == ys
