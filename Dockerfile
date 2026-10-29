# Stage 1: install, download the dataset (SHA-256 checked) and train the served model.
FROM python:3.12-slim AS train
# LightGBM needs OpenMP to import. Only training touches it, so the final image goes without.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1  && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.10.9 /uv /bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable
RUN .venv/bin/python -c "from phishing.data import download; download()" \
 && .venv/bin/python -m phishing.export

# Stage 2: only the installed packages and the model. No dataset, no uv, no build tools.
FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home app
WORKDIR /app
COPY --from=train /app/.venv /app/.venv
COPY --from=train /app/models /app/models
ENV PATH=/app/.venv/bin:$PATH \
    PHISHING_MODEL_DIR=/app/models \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["uvicorn", "phishing.api:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
