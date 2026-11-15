// LinkedIn carousel images, captured from the real demo build (run with LINKEDIN=1; skipped in CI).
//
//   cd frontend && LINKEDIN=1 DEMO_URL=https://<user>.github.io/tracelayer/ \
//     npx playwright test -c playwright.demo.config.ts linkedin
//
// Step 1 ("capture") saves raw 2880x1800 screenshots of the actual UI to portfolio/linkedin/raw/.
// Step 2 ("compose") puts each one in a titled 3200x2000 frame. Image 4 is a chart whose numbers are read
// from benchmarks/results/*.json at render time: nothing is typed in by hand.
// The entity-graph layout is randomised (force-directed), so several real layouts are saved;
// GRAPH_LAYOUT=<n> picks the clearest one for the frame.
import { readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";

test.skip(!process.env.LINKEDIN, "portfolio images only on demand");
test.describe.configure({ mode: "serial" });
test.use({ deviceScaleFactor: 2 });

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const OUT = resolve(ROOT, "portfolio/linkedin");
const RAW = resolve(OUT, "raw");
const LAYOUTS = Number(process.env.GRAPH_LAYOUTS ?? 6);

async function scrollTo(page: Page, y: number) {
  await page.evaluate((top) => window.scrollTo({ top, behavior: "instant" as ScrollBehavior }), Math.max(0, Math.round(y)));
  await page.waitForTimeout(400);
}

test("capture", async ({ page }) => {
  mkdirSync(RAW, { recursive: true });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("./");
  await page.getByRole("button", { name: "Go straight to the dashboard" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
  await page.waitForTimeout(1500); // chart animation
  await page.screenshot({ path: `${RAW}/01-dashboard.png` });

  // The 7-stage case: entity graph with the case's workflow, ATT&CK stages and telemetry blind spots above it.
  await page.getByRole("link", { name: "Investigations" }).click();
  await page.locator("a[href*='/investigations/inv_b70ce']").first().click();
  await expect(page.getByText(/7-stage intrusion/).first()).toBeVisible();
  await page.getByRole("tab", { name: "Entity graph" }).click();
  await page.waitForTimeout(2200);
  for (let i = 0; i < LAYOUTS; i++) {
    const g = (await page.locator("canvas").first().boundingBox())!;
    const y = await page.evaluate(() => window.scrollY);
    await scrollTo(page, y + g.y + g.height + 24 - 900);
    await page.screenshot({ path: `${RAW}/02-investigation-layout${i}.png` });
    await page.getByRole("button", { name: "Re-layout" }).click();
    await page.waitForTimeout(2200);
  }

  // The free-form llama3.2:3b draft: verified claims, a contradicted count and the review controls.
  await page.getByRole("tab", { name: /AI analysis/ }).click();
  await page.getByRole("button", { name: /^ollama · score/ }).click();
  await expect(page.getByText("Alice successfully brute forced admin credentials after 42 failed attempts")).toBeVisible();
  // Crop from the integrity score down to the contradicted claim's Accept/Reject controls (page coordinates).
  await scrollTo(page, 0);
  const top = (await page.getByText("Integrity score").first().boundingBox())!.y - 44;
  const card = page.locator("div", { has: page.getByText("Alice successfully brute forced admin credentials after 42 failed attempts") })
    .filter({ has: page.getByRole("button", { name: "Reject" }) }).last();
  const reject = (await card.getByRole("button", { name: "Reject" }).first().boundingBox())!;
  const height = Math.round(reject.y + reject.height + 30 - top);
  await page.setViewportSize({ width: 1440, height });
  await scrollTo(page, top);
  await page.screenshot({ path: `${RAW}/03-evidence-integrity.png` });
});

// ---------------------------------------------------------------------------------------------------------

const font = (p: string) => readFileSync(resolve(HERE, "../node_modules", p)).toString("base64");
const png = (p: string) => `data:image/png;base64,${readFileSync(p).toString("base64")}`;
const json = (f: string) => JSON.parse(readFileSync(resolve(ROOT, "benchmarks/results", f), "utf8"));
const pct = (x: number, d = 1) => `${(x * 100).toFixed(d)}%`;

const CSS = `
@font-face { font-family: Inter; src: url(data:font/woff2;base64,${font("@fontsource-variable/inter/files/inter-latin-wght-normal.woff2")}) format("woff2"); font-weight: 100 900; }
@font-face { font-family: Mono; src: url(data:font/woff2;base64,${font("@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2")}) format("woff2"); }
:root { --bg: #06080c; --panel: #0d121a; --line: #243041; --text-1: #f1f5f9; --text-2: #a3b0c2; --text-3: #6b7a8f;
        --before: #d95926; --after: #3987e5; }
* { box-sizing: border-box; margin: 0; }
body { width: 1600px; height: 1000px; background: var(--bg); color: var(--text-1); font-family: Inter, system-ui, sans-serif;
       padding: 40px 56px 30px; display: flex; flex-direction: column; gap: 22px; -webkit-font-smoothing: antialiased; }
header { display: flex; align-items: flex-end; justify-content: space-between; gap: 40px; }
.kicker { font: 500 14px Mono, monospace; letter-spacing: .08em; color: #38bdf8; text-transform: uppercase; margin-bottom: 10px; }
h1 { font-size: 33px; font-weight: 640; letter-spacing: -.015em; line-height: 1.15; }
.cap { font-size: 17.5px; line-height: 1.45; color: var(--text-2); margin-top: 8px; max-width: 1180px; }
.count { font: 500 15px Mono, monospace; color: var(--text-3); white-space: nowrap; }
main { flex: 1; min-height: 0; display: flex; justify-content: center; }
.shot { height: 100%; border-radius: 14px; overflow: hidden; border: 1px solid var(--line);
        box-shadow: 0 30px 80px rgba(0,0,0,.55); }
.shot img { height: 100%; width: auto; display: block; }
footer { display: flex; justify-content: space-between; font-size: 13.5px; color: var(--text-3); }
footer b { color: var(--text-2); font-weight: 500; }
`;

function frame(o: { n: number; kicker: string; title: string; caption: string; body: string; source: string; extraCss?: string }) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>${CSS}${o.extraCss ?? ""}</style></head><body>
  <header><div><div class="kicker">${o.kicker}</div><h1>${o.title}</h1><p class="cap">${o.caption}</p></div>
  <div class="count">${o.n} / 4</div></header>
  <main>${o.body}</main>
  <footer><span>${o.source}</span><span><b>TraceLayer</b> · github.com/PrateekGithub23/tracelayer</span></footer></body></html>`;
}

const DEMO_SOURCE = "Unretouched screenshot of the public demo: responses recorded from the real backend · synthetic and OTRF lab data";

function evaluationChart() {
  // 1. Normalisation: v2 parser (any type assigned) vs v3 parser (fully normalised), weighted over all records.
  const norm = json("normalization-v2-vs-v3.json").datasets as Record<string, any>;
  const sets = Object.values(norm);
  const records = sets.reduce((a, d) => a + d.records, 0);
  const v2Typed = sets.reduce((a, d) => a + d.records * (d.otrf_windows.coverage.typed_unassessed ?? 0), 0) / records / 100;
  const v3Full = sets.reduce((a, d) => a + d.records * d["otrf_windows.v3"].coverage.full, 0) / records / 100;
  const fullRange = sets.map((d) => d["otrf_windows.v3"].coverage.full as number);
  // 2. Frozen held-out v3 set: v2 engine baseline vs v3 engine official run.
  const hv2 = json("heldout-v3-baseline-v2-engine.json").metrics;
  const hv3 = json("evaluation-v3.json").sets.heldout_v3;
  // 3-4. Local LLM: free-form vs grounded (same 3 investigations, same model).
  const llm = json("llm-v3-freeform-vs-grounded-idle.json");
  const ff = llm.summary.ollama, gr = llm.summary.grounded;
  const runsPer = llm.environment.runs_per_investigation, nInv = llm.investigations.length;

  // Bars use 72% of the track at full scale, so the value label always fits beside the bar.
  const bar = (label: string, value: number, max: number, text: string, cls: "before" | "after", note = "") => {
    const w = (value / max) * 72;
    return `
    <div class="row"><div class="lab">${label}</div>
      <div><div class="track"><div class="bar ${cls}" style="width:${w}%"></div><div class="val" style="left:calc(${w}% + 14px)">${text}</div></div>
      ${note ? `<div class="note">${note}</div>` : ""}</div></div>`;
  };
  const panel = (title: string, ctx: string, rows: string, foot = "") =>
    `<section><h2>${title}</h2><p class="ctx">${ctx}</p><div class="rows">${rows}</div>${foot ? `<p class="foot">${foot}</p>` : ""}</section>`;

  const body = `<div class="grid">
    ${panel("Windows events fully normalised", `${sets.length} public OTRF lab datasets · ${records.toLocaleString("en-US")} events · higher is better`,
      bar("v2 parser", v2Typed, 1, pct(v2Typed), "before", "assigned any event type") +
      bar("v3 parser", v3Full, 1, pct(v3Full), "after", "fully normalised"),
      `Per dataset: ${Math.min(...fullRange).toFixed(1)}–${Math.max(...fullRange).toFixed(1)}% fully normalised; 0 records rejected.`)}
    ${panel("Claim verification on a frozen held-out set", `${hv3.cases} adversarial and legitimate claims, never used for tuning · single official run · higher is better`,
      bar("v2 engine", hv2.accuracy, 1, pct(hv2.accuracy), "before", `${hv2.false_verification} dangerous false verifications`) +
      bar("v3 engine", hv3.accuracy, 1, pct(hv3.accuracy), "after", `${hv3.false_verification} dangerous false verifications`),
      `Exact six-way verdict match. ${hv3.cases - Math.round(hv3.accuracy * hv3.cases)} of ${hv3.cases} cases still missed by v3, both failing safe.`)}
    ${panel("Unsafe claims in local LLM drafts", `llama3.2:3b on a laptop · ${nInv} investigations × ${runsPer} runs per mode · lower is better`,
      bar("Free-form", ff.unsafe_rate, 1, pct(ff.unsafe_rate), "before", "unsupported or contradicted") +
      bar("Grounded", gr.unsafe_rate, 1, pct(gr.unsafe_rate), "after", "v3 default"),
      `Unsafe claims are blocked from approval in both modes; grounded mode also auto-rejects them.`)}
    ${panel("Fabricated citations per analysis", `Same runs · citations to events that do not exist in the case · lower is better`,
      bar("Free-form", ff.fabricated_citations, 8, ff.fabricated_citations.toFixed(1), "before") +
      bar("Grounded", gr.fabricated_citations, 8, gr.fabricated_citations === 0 ? "0" : gr.fabricated_citations.toFixed(1), "after", "the model cites verified fact ids, not events"),
      `Trade-off: grounded drafts make fewer claims (${gr.claims.toFixed(1)} vs ${ff.claims.toFixed(1)} per analysis).`)}
  </div>`;
  const css = `
    .grid { width: 100%; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    section { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 26px 30px 22px; display: flex; flex-direction: column; }
    h2 { font-size: 21px; font-weight: 600; }
    .ctx { font-size: 14.5px; color: var(--text-2); margin-top: 6px; line-height: 1.4; }
    .rows { display: flex; flex-direction: column; gap: 26px; margin: 34px 0 20px; }
    .row { display: grid; grid-template-columns: 104px 1fr; align-items: start; gap: 16px; }
    .lab { font-size: 16px; color: var(--text-2); line-height: 44px; }
    .track { position: relative; height: 44px; border-left: 1px solid #3a475a; }
    .bar { height: 100%; border-radius: 0 4px 4px 0; }
    .before { background: var(--before); } .after { background: var(--after); }
    .val { position: absolute; top: 50%; transform: translateY(-50%); white-space: nowrap; font: 500 26px Mono, monospace; color: var(--text-1); }
    .note { font-size: 14.5px; color: var(--text-3); margin-top: 7px; }
    .foot { margin-top: auto; font-size: 13.5px; color: var(--text-3); line-height: 1.45; }`;
  return { body, css };
}

test("compose", async ({ page }) => {
  const layout = process.env.GRAPH_LAYOUT ?? "0";
  for (const f of ["01-dashboard.png", `02-investigation-layout${layout}.png`, "03-evidence-integrity.png"])
    expect(existsSync(`${RAW}/${f}`), `run the capture step first (${f})`).toBe(true);
  await page.setViewportSize({ width: 1600, height: 1000 });
  const shot = (f: string) => `<div class="shot"><img src="${png(`${RAW}/${f}`)}"></div>`;
  const frames: [string, string][] = [
    ["01-dashboard.png", frame({ n: 1, kicker: "Security investigation platform",
      title: "From raw Windows telemetry to prioritised investigations",
      caption: "12,993 events from a seeded attack scenario and an OTRF lab dataset, evaluated by 13 ATT&CK-mapped rules and correlated into investigations. Every AI claim made about them is checked against the evidence.",
      body: shot("01-dashboard.png"), source: DEMO_SOURCE })],
    ["02-investigation.png", frame({ n: 2, kicker: "Detection and correlation",
      title: "11 detections across 7 ATT&CK stages, correlated into one case",
      caption: "The entity graph links users, hosts and IP addresses through the events behind each detection; click an edge to open the exact log records. Telemetry gaps are flagged instead of being guessed at.",
      body: shot(`02-investigation-layout${layout}.png`), source: DEMO_SOURCE })],
    ["03-evidence-integrity.png", frame({ n: 3, kicker: "Evidence Integrity Engine",
      title: "The AI blames Alice for 42 failed logins. Its own citations show 1.",
      caption: "The 42 came from one IP spraying several accounts. Every claim from the local model is checked against the events it cites: in this free-form llama3.2:3b draft, 8 were verified, 1 contradicted and 1 unsupported, and approval stays blocked until an analyst decides each unsafe claim.",
      body: shot("03-evidence-integrity.png"), source: DEMO_SOURCE })],
  ];
  const chart = evaluationChart();
  frames.push(["04-evaluation.png", frame({ n: 4, kicker: "Measured, not claimed",
    title: "v3 results: normalisation, verification accuracy, AI safety",
    caption: "Lab and synthetic data on one laptop. These are evaluation results, not production detection or false-positive rates.",
    body: chart.body, extraCss: chart.css,
    source: "Numbers read from benchmarks/results/*.json at render time (normalization-v2-vs-v3, heldout-v3-baseline-v2-engine, evaluation-v3, llm-v3-freeform-vs-grounded-idle)" })]);

  for (const [name, html] of frames) {
    await page.setContent(html, { waitUntil: "load" });
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: `${OUT}/${name}` });
  }
});
