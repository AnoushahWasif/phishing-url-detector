"""Scoring API: POST /score {"url": ...} -> {"score", "label", "reasons"}.

Privacy rule: the URLs people visit are never logged or stored. Only label counts are kept.
"""

import os
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from phishing.data import hostname
from phishing.features import extract, extract_many
from phishing.model_store import load_model
from phishing.split import registered_domain

MAX_URL_LENGTH = 2048
MAX_BODY_BYTES = 4096
SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
    }
)
# The training data has no legitimate pages on these big sites, only abuse of them (all 408
# github.com/github.io rows are phishing), so the model distrusts them. Matched on the
# registered domain: "google.com.evil.xyz" is evil.xyz and still gets scored, and each
# *.github.io site is its own registered domain, so GitHub Pages is never covered by this.
KNOWN_GOOD = frozenset(
    {
        "google.com",
        "youtube.com",
        "github.com",
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "wikipedia.org",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "netflix.com",
        "office.com",
        "dropbox.com",
    }
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def http_url_with_host(cls, url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            raise ValueError("only http and https URLs can be scored")
        if not hostname(url):
            raise ValueError("URL has no host")
        return url


class ScoreResponse(BaseModel):
    host: str
    label: Literal["phishing", "legitimate", "unknown"]
    score: float | None
    threshold: float
    reasons: list[str]


def reasons_for(url: str) -> list[str]:
    """Plain-language signals present in the hostname. They explain, they don't decide."""
    f = extract(url)
    found = []
    if f["is_ip"]:
        found.append("The address is a raw IP, not a domain name")
    if f["has_punycode"]:
        found.append("The domain uses non-Latin characters that can imitate other sites")
    if f["on_free_host"]:
        found.append("Hosted on a free site builder where anyone can get a subdomain")
    # Punycode labels start with "xn--"; those hyphens are encoding, not a signal.
    hyphens = hostname(url).replace("xn--", "").count("-")
    if hyphens >= 3:
        found.append(f"Many hyphens in the host ({hyphens})")
    if f["n_labels"] >= 5:
        found.append(f"Unusually many subdomain levels ({f['n_labels']})")
    if f["host_length"] >= 40:
        found.append(f"Very long host name ({f['host_length']} characters)")
    if f["digit_ratio"] > 0.3:
        found.append("Lots of digits in the host")
    return found


class RateLimiter:
    """Fixed one-minute window per client. In memory, so per process: fine for one container."""

    def __init__(
        self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.monotonic
    ):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        start, count = self._hits.get(key, (now, 0))
        if now - start >= self.window:
            start, count = now, 0
        if count >= self.limit:
            return False
        self._hits[key] = (start, count + 1)
        if len(self._hits) > 10_000:  # forget stale clients so memory can't grow without bound
            self._hits = {k: v for k, v in self._hits.items() if now - v[0] < self.window}
        return True


def _error(status: int, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def create_app(
    model_dir: Path,
    expected_sha256: str | None = None,
    cors_origins: tuple[str, ...] = (),
    rate_limit: int = 60,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    loaded = load_model(model_dir, expected_sha256)  # raises before the app exists if tampered
    limiter = RateLimiter(rate_limit, clock=clock)
    counts: Counter[str] = Counter()

    app = FastAPI(title="Phishing URL scorer", version="0.1.0")
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["POST", "GET"],
            allow_headers=["content-type"],
        )

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method == "POST":
            length = request.headers.get("content-length")
            if length is None:
                response = _error(411, "Content-Length required")
            elif not length.isdigit() or int(length) > MAX_BODY_BYTES:
                response = _error(413, f"Body larger than {MAX_BODY_BYTES} bytes")
            elif not limiter.allow(request.client.host if request.client else "unknown"):
                response = _error(429, "Too many requests", {"Retry-After": "60"})
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the input back. That input is someone's browsing,
        # so only say where the problem is and what it is.
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"error": "Invalid request", "details": details}, status_code=422)

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "model": loaded.manifest["model"],
            "model_sha256": loaded.manifest["sha256"][:12],
            "scored": dict(counts),
        }

    @app.post("/score", response_model=ScoreResponse)
    def score(body: ScoreRequest) -> ScoreResponse:
        host = hostname(body.url)
        if host in SHORTENERS:
            counts["unknown"] += 1
            return ScoreResponse(
                host=host,
                label="unknown",
                score=None,
                threshold=loaded.threshold,
                reasons=["URL shortener: the real destination is hidden until the link is opened"],
            )
        if registered_domain(host) in KNOWN_GOOD:
            counts["legitimate"] += 1
            return ScoreResponse(
                host=host,
                label="legitimate",
                score=None,
                threshold=loaded.threshold,
                reasons=["Well-known domain on the allowlist; not scored by the model"],
            )
        value = float(loaded.model.predict_proba(extract_many([body.url]))[0, 1])
        label = "phishing" if value >= loaded.threshold else "legitimate"
        counts[label] += 1
        return ScoreResponse(
            host=host,
            label=label,
            score=round(value, 4),
            threshold=round(loaded.threshold, 4),
            reasons=reasons_for(body.url),
        )

    return app


def app_from_env() -> FastAPI:
    """Entry point for uvicorn --factory. All settings come from environment variables."""
    origins = tuple(o for o in os.environ.get("PHISHING_CORS_ORIGINS", "").split(",") if o)
    return create_app(
        model_dir=Path(os.environ.get("PHISHING_MODEL_DIR", "models")),
        expected_sha256=os.environ.get("PHISHING_MODEL_SHA256") or None,
        cors_origins=origins,
        rate_limit=int(os.environ.get("PHISHING_RATE_LIMIT", "60")),
    )
