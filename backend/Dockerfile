# TraceLayer API image. Multi-stage: dependencies are installed in a builder so the runtime image
# contains no compilers; the app runs as an unprivileged user.
# Supply chain: every dependency is pinned *with its SHA-256* (requirements.lock, exported from uv.lock),
# and pip refuses anything that does not match.
FROM python:3.12.16-slim AS builder
WORKDIR /build
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir --no-deps --prefix=/install .

FROM python:3.12.16-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 tracelayer && mkdir -p /data && chown tracelayer /data
COPY --from=builder /install /usr/local
WORKDIR /srv
COPY --chown=tracelayer:tracelayer app ./app
COPY --chown=tracelayer:tracelayer alembic.ini ./
USER tracelayer
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)" || exit 1
# Migrations run on startup as the owner role (TRACELAYER_MIGRATION_DATABASE_URL); the app then connects as the
# least-privilege runtime role. One worker: background jobs and rate limits are in-process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
