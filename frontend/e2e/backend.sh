#!/usr/bin/env bash
# Starts an isolated backend for end-to-end tests: fresh SQLite file, bootstrap admin, fast Argon2.
set -euo pipefail
cd "$(dirname "$0")/../../backend"
DB="$(mktemp -d)/e2e.db"
export TRACELAYER_DATABASE_URL="sqlite:///$DB" TRACELAYER_LLM_MODE=deterministic TRACELAYER_BACKGROUND_JOBS=false \
  TRACELAYER_BOOTSTRAP_ADMIN_EMAIL=chief@e2e.test TRACELAYER_BOOTSTRAP_ADMIN_PASSWORD=Initial-admin-pass-1 \
  TRACELAYER_ARGON2_TIME_COST=1 TRACELAYER_ARGON2_MEMORY_KIB=8192 TRACELAYER_ARGON2_PARALLELISM=1 \
  TRACELAYER_CORS_ORIGINS='["http://localhost:5174"]'
exec .venv/bin/uvicorn app.main:app --port 8010 --log-level warning
