# Zero-cost verification

TraceLayer must run with **$0 of additional spending**: no paid APIs, cloud billing, hosting, domains, or subscriptions, and no credit card anywhere. This page records what each component is, its licence, and why it costs nothing.

## Stack

| Component | Used for | Licence / terms | Cost | Card needed |
|---|---|---|---|---|
| Python 3.12, FastAPI, Pydantic, SQLAlchemy, Alembic, Uvicorn, httpx | API, models, migrations | PSF / MIT / BSD | Free | No |
| PostgreSQL 16 (Docker image) | Primary database | PostgreSQL licence (BSD-like) | Free | No |
| SQLite | Zero-setup dev DB, tests, benchmarks | Public domain | Free | No |
| React 18, Vite, TypeScript, Tailwind CSS | UI | MIT / Apache-2.0 | Free | No |
| Cytoscape.js, Recharts, TanStack Query, lucide-react | Graph, charts, data fetching, icons | MIT / ISC | Free | No |
| Inter, JetBrains Mono (`@fontsource`) | Fonts, bundled locally (no CDN) | SIL OFL 1.1 | Free | No |
| nginx (Docker image) | Static UI + reverse proxy | BSD-2 | Free | No |
| Ollama | Optional local LLM runtime | MIT | Free, runs on-device | No (no account) |
| Llama 3.2 3B (default model) | Optional local LLM | Llama 3.2 Community Licence (free use, attribution) | Free | No |
| pytest, ruff, mypy, vitest | Quality tooling | MIT / Apache-2.0 | Free | No |
| Docker Desktop | Containers on macOS | Free for personal use, education and small businesses (<250 staff and <$10M revenue) | Free for this use | No |
| GitHub (public repo) + GitHub Actions | Hosting code, CI | Standard runners free for public repositories (GitHub docs) | Free | No |
| **v2 additions** | | | | |
| argon2-cffi | Argon2id password hashing | MIT | Free | No |
| uv | Python lockfile and installs | MIT / Apache-2.0 | Free | No |
| Playwright + Chromium | Browser end-to-end tests | Apache-2.0 | Free | No |
| gitleaks, pip-audit, actionlint | Secret scan, dependency audit, workflow lint | MIT / Apache-2.0 / MIT | Free | No |
| OTRF Security-Datasets | Real (lab) Windows telemetry | MIT, © 2021 Open Threat Research Forge | Free | No |
| GitHub Pages | Hosting the static public demo | Free for public repositories (1 GB site, soft 100 GB/month) | Free | No |
| nginx-unprivileged image | Non-root UI container | BSD-2 | Free | No |

**Alternative to Docker Desktop:** [Colima](https://github.com/abiosoft/colima) (MIT, `brew install colima docker docker-compose`) runs the same Compose file with no licence conditions at all.

## Things deliberately *not* used

| Typical choice | Why it's excluded | What replaces it |
|---|---|---|
| OpenAI / Anthropic / other hosted LLM APIs | Usage-billed; need an API key and payment method. A Claude.ai subscription does **not** include API credits. | Ollama (local) + a deterministic analyst that needs no model at all |
| Managed Postgres, Redis, queues (RDS, Supabase, Upstash…) | Free tiers usually need a card, expire, or sleep | Local PostgreSQL in Compose; in-process thread-pool jobs persisted in a table |
| Hosted full-stack deployment (Render, Fly, Railway, HF Docker Spaces…) | Render's free Postgres is deleted after 30 days with no backups; HF Docker Spaces need a paid plan; others need cards or credits (see DEPLOYMENT.md) | Static, browser-only public demo on GitHub Pages + the full stack locally |
| Elasticsearch / OpenSearch | Heavy (≥2 GB RAM) and unnecessary at this scale | Indexed SQL queries (sub-millisecond p50 at 100k events, see BENCHMARKS.md) |
| Prometheus / Grafana | Two more services for one dashboard | In-process latency percentiles + measured benchmark reports in the DB |
| Commercial threat intel / GeoIP feeds | Paid or need registration | Country codes in the telemetry + a built-in centroid table |

## Verification (2026-11-15)

Every v2 component above was installed and used during development with no account upgrade, trial or
payment method: Ollama via Homebrew, `llama3.2:3b` pulled locally, OTRF archives downloaded from
GitHub, Playwright's Chromium, gitleaks via Homebrew, pip-audit via `uvx`, and actionlint and Postgres
as Docker images. The only planned public artifact (the demo on GitHub Pages) needs a free GitHub
account and a public repository.

## Apple Silicon resource budget (measured on an M4 MacBook Air, 16 GB)

| Process | Typical memory | Notes |
|---|---|---|
| PostgreSQL container | ~50–150 MB | 100k events ≈ 60 MB on disk |
| API container | ~150–250 MB | one Uvicorn worker |
| nginx container | <10 MB | |
| Ollama + `llama3.2:3b` (Q4) | ~2.5–3.5 GB while loaded | ~2 GB download; Metal GPU acceleration when run **natively** (`brew install ollama`) |
| Ollama + `qwen2.5:1.5b` | ~1.5 GB | lighter option for 8 GB machines (Apache-2.0) |

Run Ollama natively, not in Docker: on macOS, Docker containers can't use the GPU, so in-container inference is several times slower. The Compose file includes an `ollama` service behind the opt-in `llm` profile only for machines where a native install isn't possible.

## Graceful degradation

| LLM state | Behaviour |
|---|---|
| Ollama not installed / not running | `auto` mode falls back to the deterministic analyst; the reason is stored and shown |
| Model not pulled | Same, and the UI shows the exact `ollama pull` command |
| Model returns invalid JSON or garbage | Rejected by the schema parser, then the same fallback |
| Model returns valid JSON with hallucinations | Accepted as *output*, then every claim goes through the integrity validator |
| `TRACELAYER_LLM_MODE=deterministic` | No network calls at all |
