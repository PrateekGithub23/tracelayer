# Common tasks. Everything runs locally; nothing needs a paid service.
.PHONY: setup dev-api dev-ui test lint eval bench up down seed

setup:            ## install backend + frontend dependencies
	cd backend && uv venv -q --python 3.12 .venv && VIRTUAL_ENV=.venv uv pip install -q -e ".[dev]"
	cd frontend && npm ci

dev-api:          ## API on :8000 with SQLite (auto-migrates)
	cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000

dev-ui:           ## UI on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

seed:             ## generate + ingest the scenario into the local SQLite DB and run the pipeline
	cd backend && .venv/bin/tracelayer seed

test:             ## all tests
	cd backend && .venv/bin/pytest
	cd frontend && npm test

lint:             ## lint + type-check
	cd backend && .venv/bin/ruff check app tests && .venv/bin/ruff format --check app tests && .venv/bin/mypy app
	cd frontend && npm run typecheck

eval:             ## adversarial integrity evaluation
	cd backend && .venv/bin/python -m app.evaluation.suite --json ../benchmarks/results/evaluation.json

bench:            ## benchmarks (100k background events, temp SQLite)
	cd backend && .venv/bin/python -m app.benchmarks.runner --events 100000 --json ../benchmarks/results/sqlite-100k.json

up:               ## full stack: Postgres + API + UI on http://localhost:8080
	docker compose up --build -d

down:
	docker compose down
