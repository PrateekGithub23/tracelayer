// The public demo must work with no backend, never call /api, keep changes in the tab, and enforce
// the same workflow rules as the server.
import { expect, type Page, test } from "@playwright/test";

const BASE = process.env.VITE_BASE ?? "/";
let offending: string[] = [];
test.beforeEach(async ({ page }) => {
  offending = [];
  // Every request must stay on the demo's own origin and path: no /api, no other host or port (API, Ollama,
  // PostgreSQL), no third-party CDN. Data URLs and blob URLs (downloads) are local to the page.
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.protocol === "data:" || u.protocol === "blob:") return;
    if (u.host !== "localhost:5180" || !u.pathname.startsWith(BASE) || u.pathname.includes("/api/")) offending.push(r.url());
  });
});
test.afterEach(() => expect(offending, "the static demo must only load its own files").toEqual([]));

// Client-side navigation: a full page.goto() reloads the app, which (by design) resets the demo state.
async function go(page: Page, path: string) {
  const full = BASE.replace(/\/$/, "") + path;
  await page.evaluate((p) => { window.history.pushState({}, "", p); window.dispatchEvent(new PopStateEvent("popstate")); }, full);
}

async function enter(page: Page, guided = false) {
  await page.goto("./");
  await page.getByRole("button", { name: guided ? "Start the guided scenario" : "Go straight to the dashboard" }).click();
  await expect(page.getByText("Read-only public demo.")).toBeVisible();
}

test("guided scenario walks through all eight steps with real data", async ({ page }) => {
  await enter(page, true);
  await expect(page.getByRole("heading", { name: "The Suspicious Login That Wasn't Just a Login" })).toBeVisible();
  const titles = ["An ordinary-looking sign-in", "Related authentication activity", "Location and endpoint correlation",
    "Privilege modification", "The AI drafts the investigation", "Every sentence is checked", "The analyst decides", "The final incident report"];
  for (const [i, t] of titles.entries()) {
    await expect(page.getByText(t)).toBeVisible();
    if (i === 0) await expect(page.locator("#main").getByText("203.0.113.45").first()).toBeVisible();  // the brute-force source, not noise
    if (i === 1) await expect(page.getByText(/failed logins/).first()).toBeVisible();
    if (i === 4) { await expect(page.locator("#main").getByText("llama3.2:3b")).toBeVisible(); await expect(page.getByText(/writing freely/)).toBeVisible(); }
    if (i < titles.length - 1) await page.getByRole("button", { name: "Next" }).click();
  }
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Incident report (.md)" }).click();
  expect((await download).suggestedFilename()).toMatch(/^tracelayer-inv_.*\.md$/);
});

test("case workflow follows server rules and resets on reload", async ({ page }) => {
  await enter(page);
  await go(page, "/investigations?view=mine");
  await page.locator("a[href*='/investigations/inv_']").nth(1).click();
  await expect(page.getByText("owner: Dana (demo analyst)")).toBeVisible();
  await page.getByRole("button", { name: "Request review" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Reviewer (must be someone else)").selectOption({ label: "Priya (SOC lead)" });
  await dialog.getByRole("textbox").fill("Sign-in, escalation and exfiltration confirmed");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Awaiting review").first()).toBeVisible();
  // Segregation of duties: the assignee cannot complete their own review.
  await expect(page.getByRole("button", { name: "Approve & resolve" })).toHaveCount(0);
  await page.getByRole("tab", { name: "Activity" }).click();
  await expect(page.getByText("Sign-in, escalation and exfiltration confirmed")).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Go straight to the dashboard" }).click();
  await go(page, "/investigations?view=mine");
  await page.locator("a[href*='/investigations/inv_']").nth(1).click();
  await expect(page.getByText("Investigating").first()).toBeVisible();
});

test("AI claims: approval is blocked until unsafe claims are handled", async ({ page }) => {
  await enter(page);
  await go(page, "/investigations?view=mine");
  await page.locator("a[href*='/investigations/inv_']").nth(1).click();
  await page.getByRole("tab", { name: /AI analysis/ }).click();
  await expect(page.getByText("llama3.2:3b").first()).toBeVisible();
  // Grounded draft (newest): unsafe claims were already rejected by the pipeline, so approval is open.
  await page.getByRole("button", { name: /^ollama-grounded · score/ }).click();
  await expect(page.getByRole("button", { name: "Approve analysis" })).toBeEnabled();
  // Free-form draft: unsafe claims are pending, so the server-side gate (mirrored here) blocks approval.
  await page.getByRole("button", { name: /^ollama · score/ }).click();
  const approve = page.getByRole("button", { name: "Approve analysis" });
  await expect(approve).toBeVisible();
  await expect(approve).toBeDisabled();
  await expect(page.getByText(/unsafe claim\(s\) still need a decision/)).toBeVisible();
  // Accepting an unsafe claim without a justification is refused, exactly as on the server.
  const unsafeCard = page.locator("li", { has: page.getByText(/Unsupported claim|Contradictory finding/) }).first();
  await unsafeCard.getByRole("button", { name: "Accept" }).click();
  await expect(page.getByText("accepting an unsupported/contradictory claim requires a justification note")).toBeVisible();
});

test("validator playground shows the real engine's verdicts on prepared drafts", async ({ page }) => {
  await enter(page);
  await go(page, "/integrity");
  await page.getByRole("tab", { name: "Validation playground" }).click();
  await page.getByRole("button", { name: /Hallucinated draft/ }).click();
  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByText(/Unsupported|unsupported/).first()).toBeVisible();
});

test("administration is not reachable in the demo", async ({ page }) => {
  await enter(page);
  await expect(page.getByRole("link", { name: "Users & settings" })).toHaveCount(0);
  await go(page, "/admin");
  await expect(page.getByText("You don't have access to this page")).toBeVisible();
});


test("deep links and refresh work under the repository sub-path", async ({ page }) => {
  await page.goto("./investigations?view=all");  // a deep link served by the 404.html SPA fallback in production
  await expect(page.getByRole("heading", { name: "Explore the TraceLayer demo" })).toBeVisible();
  await page.getByRole("button", { name: "Go straight to the dashboard" }).click();
  await expect(page.getByText("Read-only public demo.")).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Explore the TraceLayer demo" })).toBeVisible();
});
