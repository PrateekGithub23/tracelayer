# Deployment

**Constraint:** $0 of additional spending, with no credit card, trials or plans that convert to paid.

**Recommendation:** **Option B.** Publish the static, browser-only demo for free (GitHub Pages or
Cloudflare Pages) and run the full application locally with Docker. A public read-only interactive
demo is preferable to a fragile or unsafe free full-stack deployment.

Hosting terms change often. The facts below were read from each provider's **own documentation** on
2026-11-15; re-check them before relying on them.

## Option A: entire stack hosted free (not recommended)

TraceLayer needs FastAPI, a **persistent** PostgreSQL (evidence, audit chain, sessions), file storage
for datasets, and optional LLM inference.

| Provider | Documented free-tier facts | Fit |
|---|---|---|
| Render | Free web services spin down after 15 min idle (~1 min to wake), 750 instance-hours/month, ephemeral filesystem, "might restart a Free web service at any time"; **free Postgres expires 30 days after creation and is then deleted, with no backups**; no persistent disks on free; Render says not to use free instances in production | ✗ An evidence platform whose database is deleted after 30 days, with no backups, contradicts its purpose |
| Hugging Face Spaces | Free CPU Basic (2 vCPU, 16 GB), non-persistent disk; **Docker Spaces require a paid plan** (PRO/Team) | ✗ Not free for this stack |
| Fly.io, Railway, Koyeb, Oracle Cloud | Secondary sources report card requirements, one-off credits or uncertain free tiers; not verified as card-free | ✗ Not used |

No option gives persistent PostgreSQL + an always-available API + LLM at $0 without a card.

## Option B: public static demo + local full application (recommended)

The demo (`frontend/dist-demo`, ~7.4 MB, ~0.7 MB of data gzipped) is the real React app with a
browser-local transport and **real API responses recorded from a real backend** (see FEATURE_GUIDE.md →
Demo). No server code runs anywhere.

| Host | Documented free-tier facts | Notes |
|---|---|---|
| **GitHub Pages** | Site ≤ 1 GB; soft 100 GB/month bandwidth; soft 10 builds/hour (not applied to custom Actions workflows); not for e-commerce, commercial SaaS, or "sensitive transactions such as passwords" | The demo collects nothing and has no login, so it fits the terms. Actions are free for public repositories. |
| **Cloudflare Pages** | Free plan: 20,000 files, 25 MiB per file, 500 builds/month, 100 custom domains per project | A good alternative; a Cloudflare account is required |

### Demo safety properties (tested in `frontend/e2e-demo/`)

- Makes **zero** `/api` requests (asserted on every test).
- No administrative pages; the demo identity is an analyst flagged `is_demo`.
- Changes (case workflow, comments, pins, claim reviews) live only in that browser tab and reset on reload.
- No uploads, no model inference, no credentials: the snapshot is scrubbed and the deploy workflow refuses
  secret-looking content.
- Datasets in the demo are synthetic or MIT-licensed (OTRF), with attribution.

### Publishing (requires your explicit decision; nothing has been published)

1. Review the repository (`make secrets-scan`, already clean), then create a **public** GitHub repository and push.
2. Settings → Pages → Source: **GitHub Actions**.
3. Actions → **deploy-demo** → *Run workflow* (manual only). It builds with the correct base path
   (`https://<user>.github.io/<repo>/`), scans the output for secrets and publishes it.
4. Add the URL to the README and to `VITE_DEMO_URL` if you want the real app's login page to link to it.

To refresh the demo data: `make demo-snapshot OTRF=path/to/otrf.zip LLM=1`, review the diff, commit, and run the workflow.

## Option C: temporarily exposing your laptop (not implemented)

Tunnelling tools (for example Cloudflare Tunnel or Tailscale Funnel) could expose the full stack for a
supervised live demo. **This was not set up**, because it exposes your machine and home network to the
internet. If you ever choose it: only during a supervised session; through nginx on 8080 only (never
PostgreSQL or Ollama); with `TRACELAYER_ENV=production` and Secure cookies over the tunnel's HTTPS;
registration disabled; a dedicated viewer account; synthetic data only; and the tunnel closed
immediately afterwards.

## Comparison

| | A: free full stack | **B: static demo + local app** | C: tunnel to laptop |
|---|---|---|---|
| Monetary cost | $0 but data deleted after 30 days (Render) or paid (HF Docker) | **$0** | $0 |
| Credit card | Varies / unverified | **No** (GitHub) | No |
| Availability | Sleeps, restarts | **Always on (CDN)** | Only while your laptop is on |
| Maintenance | Recreate the database monthly | **Re-run a workflow** | Manual each time |
| Security | Real auth on a fragile host | **No backend to attack** | Exposes your machine |
| Public accessibility | Yes, slow cold start | **Yes, instant** | Temporary |
| Feature completeness | Full, minus the LLM | Read-only demo; full app locally | Full |
| Portfolio value | Medium | **High** (works for anyone, instantly) | Low (not reliably reachable) |
| Data persistence | Lost after 30 days | Demo resets by design; local app persists | Local |
| AI availability | None (no free GPU) | Pre-recorded real LLM output | Live local LLM |

## Running the full application

```bash
cp .env.example .env            # set POSTGRES_PASSWORD and TL_APP_PASSWORD
docker compose up --build -d    # UI on http://localhost:8080
make create-admin               # first administrator
brew install ollama && ollama serve & ollama pull llama3.2:3b   # optional, native for GPU
```

Upgrading a v1 Docker install (preserves data; verified on a real v1 database):

```bash
docker compose exec -T db pg_dump -U tracelayer -Fc tracelayer > backups/pre-v2.dump   # backup first
make db-roles                   # adds the least-privilege runtime role to the existing volume
docker compose up --build -d    # migrations 0002–0005 run as the owner role
make create-admin
```

Production-like deployment behind your own HTTPS reverse proxy:
`docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` (refuses to start without real
secrets and Secure cookies).
