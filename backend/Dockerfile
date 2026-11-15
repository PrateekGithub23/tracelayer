# TraceLayer API image. Multi-stage: dependencies are installed in a builder so the
# runtime image contains no compilers; the app runs as an unprivileged user.
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 tracelayer
COPY --from=builder /install /usr/local
WORKDIR /srv
COPY --chown=tracelayer:tracelayer app ./app
COPY --chown=tracelayer:tracelayer alembic.ini ./
USER tracelayer
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)" || exit 1
# Migrations run on startup (app.main lifespan). One worker: background jobs run in-process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
