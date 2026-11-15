# LinkedIn carousel

Four 3200×2000 PNGs, in posting order:

| File | What it shows | Source |
|---|---|---|
| `01-dashboard.png` | Security overview of the public demo | Screenshot of the real UI |
| `02-investigation.png` | 7-stage case: ATT&CK stages, telemetry blind spots, entity graph | Screenshot of the real UI |
| `03-evidence-integrity.png` | A contradicted LLM claim with the engine's reasons and the review controls | Screenshot of the real UI |
| `04-evaluation.png` | v3 evaluation results | Chart rendered from `benchmarks/results/*.json` |

The screenshots are unretouched captures of the public demo, which replays responses recorded from the real
backend. The data is synthetic or comes from OTRF lab datasets; the demo identity "Dana (demo analyst)" is
fictional. A title and caption sit outside each screenshot.

Regenerate (the `raw/` captures are git-ignored):

```bash
cd frontend
LINKEDIN=1 GRAPH_LAYOUTS=12 DEMO_URL=https://prateekgithub23.github.io/tracelayer/ \
  npx playwright test -c playwright.demo.config.ts linkedin -g capture
# Inspect raw/02-investigation-layout*.png; the force-directed layout is random. Pick a clear one:
LINKEDIN=1 GRAPH_LAYOUT=1 DEMO_URL=https://prateekgithub23.github.io/tracelayer/ \
  npx playwright test -c playwright.demo.config.ts linkedin -g compose
```

The post text and the video shot list are in [docs/PORTFOLIO.md](../../docs/PORTFOLIO.md).
