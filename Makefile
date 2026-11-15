# Common tasks. Everything runs locally; nothing needs a paid service.
.PHONY: setup dev-api dev-ui test lint eval bench up down seed create-admin create-admin-local db-roles e2e \
	demo-snapshot demo-build secrets-scan audit-deps llm-bench

setup:            ## install backend (hash-pinned) + frontend dependencies
	cd backend && uv venv -q --python 3.12 .venv && VIRTUAL_ENV=.venv uv pip install -q -r requirements.lock && VIRTUAL_ENV=.venv uv pip install -q -e ".[dev]"
	cd frontend && npm ci

dev-api:          ## API on :8000 with SQLite (auto-migrates)
	cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000

dev-ui:           ## UI on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

seed:             ## generate + ingest the scenario into the local SQLite DB and run the pipeline
	cd backend && .venv/bin/tracelayer seed

test:             ## all unit/integration tests
	cd backend && .venv/bin/pytest
	cd frontend && npm test

e2e:              ## browser end-to-end tests against an isolated backend (Playwright)
	cd frontend && npx playwright test

lint:             ## lint + type-check
	cd backend && .venv/bin/ruff check app tests && .venv/bin/ruff format --check app tests && .venv/bin/mypy app
	cd frontend && npm run typecheck

eval:             ## adversarial integrity evaluation (all four sets)
	cd backend && .venv/bin/python -m app.evaluation.suite --json ../benchmarks/results/evaluation.json

bench:            ## benchmarks (100k background events, temp SQLite)
	cd backend && .venv/bin/python -m app.benchmarks.runner --events 100000 --json ../benchmarks/results/sqlite-100k.json

llm-bench:        ## local LLM vs deterministic comparison (needs Ollama + llama3.2:3b)
	cd backend && .venv/bin/python -m app.benchmarks.llm_compare --runs 5 --json ../benchmarks/results/llm-vs-deterministic.json

up:               ## full stack: Postgres + API + UI on http://localhost:8080
	docker compose up --build -d

down:
	docker compose down

create-admin:     ## create an administrator in the Docker stack (prompts for the password; never put it on the command line)
	@read -p "Admin email: " email; docker compose exec api python -m app.cli create-user --role admin --email "$$email"

create-admin-local: ## same, for the local SQLite dev setup
	@read -p "Admin email: " email; cd backend && .venv/bin/tracelayer create-user --role admin --email "$$email"

db-roles:         ## add the least-privilege runtime DB role to an existing (pre-v2) database volume
	docker compose exec -T -e TL_APP_PASSWORD=$${TL_APP_PASSWORD:-tracelayer-app-local-only} db sh -s < docker/postgres/10-app-role.sh

demo-snapshot:    ## record the public demo's data from a real backend (optional: OTRF=path/to.zip LLM=1)
	cd backend && .venv/bin/python -m app.demo.build_snapshot --out ../frontend/demo-public/demo-data/snapshot.json $(if $(OTRF),--otrf-file $(OTRF)) $(if $(LLM),--llm)

demo-build:       ## static demo build in frontend/dist-demo (no backend needed)
	cd frontend && npm run build:demo

secrets-scan:     ## scan the working tree and git history for committed secrets (gitleaks)
	gitleaks git --redact --verbose . && gitleaks dir --redact .

audit-deps:       ## known-vulnerability scan of Python and npm dependencies
	cd backend && uvx pip-audit -r requirements.lock --require-hashes --disable-pip
	cd frontend && npm audit --omit=dev
