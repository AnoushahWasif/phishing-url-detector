import json
import logging
import shutil

import pytest
from fastapi.testclient import TestClient

from phishing.api import MAX_URL_LENGTH, RateLimiter, create_app, reasons_for
from phishing.model_store import ModelIntegrityError, export, load_model, sha256
from tests.test_robustness import synthetic_df


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("model")
    export(out, df=synthetic_df())
    return out


@pytest.fixture
def client(model_dir):
    return TestClient(create_app(model_dir))


def score(client, url, **extra):
    return client.post("/score", json={"url": url, **extra})


# --- model integrity


def test_export_writes_matching_manifest(model_dir):
    manifest = json.loads((model_dir / "model.json").read_text())
    assert manifest["sha256"] == sha256(model_dir / "model.joblib")
    assert 0 < manifest["threshold"] <= 1
    assert manifest["model"] == "char_ngram_logreg"


def test_tampered_model_is_refused_before_unpickling(model_dir, tmp_path, monkeypatch):
    bad = tmp_path / "bad"
    shutil.copytree(model_dir, bad)
    with (bad / "model.joblib").open("ab") as f:
        f.write(b"\x00")
    loaded = []
    monkeypatch.setattr("phishing.model_store.joblib.load", lambda p: loaded.append(p))
    with pytest.raises(ModelIntegrityError, match="hash does not match"):
        create_app(bad)
    assert loaded == []  # the pickle was never opened


def test_hash_from_deploy_config_wins_over_manifest(model_dir):
    with pytest.raises(ModelIntegrityError):
        load_model(model_dir, expected_sha256="0" * 64)
    assert load_model(model_dir, expected_sha256=sha256(model_dir / "model.joblib"))


@pytest.mark.parametrize(
    "manifest",
    ['{"threshold": 0.5}', "not json", '{"sha256": "abc", "threshold": 7}', ""],
)
def test_broken_manifest_is_refused(model_dir, tmp_path, manifest):
    bad = tmp_path / "bad"
    shutil.copytree(model_dir, bad)
    (bad / "model.json").write_text(manifest)
    with pytest.raises(ModelIntegrityError):
        load_model(bad)


def test_missing_model_file_is_refused(model_dir, tmp_path):
    bad = tmp_path / "bad"
    shutil.copytree(model_dir, bad)
    (bad / "model.joblib").unlink()
    with pytest.raises(ModelIntegrityError, match="missing"):
        load_model(bad)


# --- scoring


def test_scores_a_url(client):
    r = score(client, "https://secure-login-9.verify3.xyz/account")
    assert r.status_code == 200
    body = r.json()
    assert body["label"] in ("phishing", "legitimate")
    assert 0 <= body["score"] <= 1
    assert body["host"] == "secure-login-9.verify3.xyz"


def test_shortener_is_unknown_not_guessed(client):
    body = score(client, "https://bit.ly/3xYz").json()
    assert body["label"] == "unknown"
    assert body["score"] is None


@pytest.mark.parametrize("url", ["https://github.com/login", "https://accounts.google.com/"])
def test_known_good_domains_are_not_scored(client, url):
    body = score(client, url).json()
    assert body["label"] == "legitimate"
    assert body["score"] is None


@pytest.mark.parametrize(
    "url",
    [
        "https://google.com.evil.xyz/",  # brand as subdomain of an attacker's domain
        "https://someone.github.io/login",  # GitHub Pages: anyone can publish there
        "https://github.com-login.xyz/",
    ],
)
def test_allowlist_cannot_be_borrowed(client, url):
    body = score(client, url).json()
    assert body["score"] is not None


def test_unicode_and_punycode_get_the_same_score(client):
    a = score(client, "https://раураl.com/").json()
    b = score(client, "https://xn--l-7sba6dbr.com/").json()
    assert a["score"] == b["score"]
    assert a["host"] == b["host"] == "xn--l-7sba6dbr.com"


# --- bad input


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<script>x</script>",
        "ftp://example.com/",
        "https://",
        "not a url",
        "",
        "   ",
    ],
)
def test_rejects_non_web_urls(client, url):
    assert score(client, url).status_code == 422


def test_rejects_overlong_url(client):
    url = "https://a.com/" + "x" * MAX_URL_LENGTH
    assert score(client, url).status_code in (413, 422)


def test_rejects_unknown_fields(client):
    assert score(client, "https://a.com", debug=True).status_code == 422


@pytest.mark.parametrize("body", [b"", b"{", b"[]", b'{"url": 5}', b'{"url": null}'])
def test_rejects_malformed_bodies(client, body):
    r = client.post("/score", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 422


def test_large_body_is_refused_before_parsing(client):
    r = client.post("/score", content=b"x" * 5000, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_errors_never_echo_the_url(client):
    secret = "javascript:steal('my-private-token')"
    r = score(client, secret)
    assert r.status_code == 422
    assert "my-private-token" not in r.text


def test_urls_are_not_logged(client, caplog):
    caplog.set_level(logging.DEBUG)
    score(client, "https://private-browsing-history.example/secret-page")
    assert "private-browsing-history" not in caplog.text


# --- operational


def test_security_headers_on_every_response(client):
    for r in (client.get("/health"), score(client, "https://a.com"), score(client, "bad")):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cache-control"] == "no-store"


def test_health_reports_model_and_counts_only(client):
    score(client, "https://bit.ly/x")
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["scored"]["unknown"] >= 1
    assert len(body["model_sha256"]) == 12


def test_rate_limit(model_dir):
    now = [0.0]
    limited = TestClient(create_app(model_dir, rate_limit=3, clock=lambda: now[0]))
    codes = [score(limited, "https://a.com").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    now[0] += 61
    assert score(limited, "https://a.com").status_code == 200


def test_rate_limiter_forgets_old_clients():
    now = [0.0]
    limiter = RateLimiter(limit=1, clock=lambda: now[0])
    for i in range(10_001):
        limiter.allow(f"client-{i}")
    now[0] += 61
    limiter.allow("new")
    assert len(limiter._hits) <= 2


def test_cors_only_for_configured_origin(model_dir):
    origin = "chrome-extension://abcdefghijklmnop"
    app = TestClient(create_app(model_dir, cors_origins=(origin,)))
    ok = app.options("/score", headers={"origin": origin, "access-control-request-method": "POST"})
    other = app.options(
        "/score",
        headers={"origin": "https://evil.example", "access-control-request-method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == origin
    assert "access-control-allow-origin" not in other.headers


def test_reasons_ignore_punycode_hyphens():
    assert not any("hyphens" in r for r in reasons_for("https://xn--pypal-4ve.com"))
    assert any("non-Latin" in r for r in reasons_for("https://xn--pypal-4ve.com"))
