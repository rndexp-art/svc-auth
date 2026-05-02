# Auth service — FastAPI + SQLite. Runs on port 8001.
#
# Build context is this directory (services/auth) — see compose.fragment.yml.
# We copy app/ + pyproject.toml + uv.lock and let `uv sync` install into the
# system Python (no venv) for a small image.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# `uv` is used by the gateway tooling; here we use it for fast deterministic
# installs from the pinned requirements.txt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.5.11

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt pyproject.toml /app/
RUN uv pip install --system --no-cache -r requirements.txt

# Then the app code.
COPY app/ /app/app/

# Non-root.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin authsvc \
    && mkdir -p /data && chown -R authsvc:authsvc /data /app
USER authsvc

ENV AUTH_DB_PATH=/data/auth.db
EXPOSE 8001

ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--proxy-headers", "--forwarded-allow-ips", "*"]
