// Real browser, real backend. Covers the Phase 2/3 acceptance criteria that unit tests cannot:
// sessions survive reloads, expiry/revocation UX, forced password change, RBAC in the UI, case workflow.
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";

const ADMIN = { email: "chief@e2e.test", initial: "Initial-admin-pass-1", password: "Admin-e2e-passphrase-9" };
const ANALYST = { email: "ana@e2e.test", password: "Analyst-e2e-pass-77" };
const VIEWER = { email: "vic@e2e.test", password: "Viewer-e2e-pass-55" };

async function signIn(page: Page, email: string, password: string, expectSuccess = true) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  // Wait for the login round-trip to finish before the test navigates (a navigation would abort it).
  if (expectSuccess) await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}

async function api(request: APIRequestContext, method: string, path: string, data?: unknown) {
  const me = await (await request.get("/api/auth/me")).json();
  const r = await request.fetch(`/api${path}`, { method, data, headers: { "X-CSRF-Token": me.csrf_token } });
  expect(r.status(), `${method} ${path}: ${await r.text()}`).toBeLessThan(300);
  return r.json();
}

test.describe.serial("TraceLayer v2", () => {
  test("unauthenticated users are sent to the login page", async ({ page }) => {
    await page.goto("/investigations");
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  });

  test("wrong password shows a uniform error", async ({ page }) => {
    await signIn(page, ADMIN.email, "definitely-wrong-pw", false);
    await expect(page.getByRole("alert")).toHaveText("invalid email or password");
    await signIn(page, "nobody@e2e.test", "definitely-wrong-pw", false);
    await expect(page.getByRole("alert")).toHaveText("invalid email or password");
  });

  test("bootstrap admin must change password, then stays signed in across reloads", async ({ page }) => {
    await signIn(page, ADMIN.email, ADMIN.initial);
    await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
    await page.getByLabel("Temporary password").fill(ADMIN.initial);
    await page.getByLabel("New password").fill(ADMIN.password);
    await page.getByRole("button", { name: "Save and continue" }).click();
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    // Nothing secret in JS-readable storage, and the session cookie is HttpOnly.
    expect(await page.evaluate(() => JSON.stringify(localStorage) + document.cookie)).not.toContain("tl_session");
    const cookie = (await page.context().cookies()).find((c) => c.name === "tl_session");
    expect(cookie?.httpOnly).toBe(true);
    await page.reload();
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    await page.goto("/account?tab=sessions");
    await expect(page.getByText("this browser")).toBeVisible();
    await page.getByRole("tab", { name: "My activity" }).click();
    await expect(page.getByText("auth.password_changed")).toBeVisible();
  });

  test("admin seeds data and creates analyst + viewer accounts in the UI", async ({ page }) => {
    await signIn(page, ADMIN.email, ADMIN.password);
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    await api(page.request, "POST", "/synthetic/generate", { seed: 7, background_events: 1500, anchor: "fixed", run_pipeline: true });
    for (const [u, role] of [[ANALYST, "analyst"], [VIEWER, "viewer"]] as const) {
      await page.goto("/admin");
      await page.getByRole("button", { name: "New user" }).click();
      const dialog = page.getByRole("dialog");
      await dialog.getByLabel("Email").fill(u.email);
      await dialog.getByLabel("Role").selectOption(role);
      await dialog.getByLabel("Temporary password").fill(u.password + "-tmp");
      await dialog.getByRole("button", { name: "Create" }).click();
      await expect(page.getByText(u.email)).toBeVisible();
    }
    // Admin can inspect a user's sign-ins and audited actions.
    await page.getByRole("row", { name: /ana@e2e\.test/ }).getByTitle("Sign-in history and activity").click();
    await expect(page.getByRole("dialog").getByText("Recent sign-in attempts")).toBeVisible();
    await page.keyboard.press("Escape");
    // Simulate each user's first login password change through the API (UI flow covered above).
    for (const u of [ANALYST, VIEWER]) {
      const ctx = await page.context().browser()!.newContext({ baseURL: "http://localhost:5174" });
      const r = await ctx.request.post("/api/auth/login", { data: { email: u.email, password: u.password + "-tmp" } });
      expect(r.status(), await r.text()).toBe(200);
      const me = await r.json();
      const pw = await ctx.request.post("/api/auth/password", { data: { current_password: u.password + "-tmp", new_password: u.password }, headers: { "X-CSRF-Token": me.csrf_token } });
      expect(pw.status(), await pw.text()).toBe(200);
      await ctx.close();
    }
  });

  test("analyst works a case: assign, triage with reason, note, activity", async ({ page }) => {
    await signIn(page, ANALYST.email, ANALYST.password);
    await page.goto("/investigations?view=unassigned");
    await page.getByRole("button", { name: "Assign to me" }).first().click();
    await expect(page.getByText("Assigned to you")).toBeVisible();
    await page.goto("/investigations?view=mine");
    await page.locator("a[href^='/investigations/inv_']").nth(1).click();
    await page.getByRole("button", { name: "Mark triaged" }).click();
    await page.getByRole("dialog").getByRole("textbox").fill("Confirmed brute force followed by success");
    await page.getByRole("button", { name: "Confirm" }).click();
    await expect(page.getByText("Case updated")).toBeVisible();
    await page.getByRole("tab", { name: /Notes/ }).click();
    await page.getByPlaceholder("Comment for the team").fill("Checking VPN logs next");
    await page.getByRole("button", { name: "Post" }).click();
    await expect(page.getByText("Checking VPN logs next")).toBeVisible();
    await page.getByRole("tab", { name: "Activity" }).click();
    await expect(page.getByText("Confirmed brute force followed by success")).toBeVisible();
    await expect(page.getByText(": assigned")).toBeVisible();
    await expect(page.getByText("owner: ana")).toBeVisible();
  });

  test("viewer sees cases read-only and cannot reach admin pages", async ({ page }) => {
    await signIn(page, VIEWER.email, VIEWER.password);
    await page.goto("/investigations?view=all");
    await page.locator("a[href^='/investigations/inv_']").nth(1).click();
    await expect(page.getByText("Viewers can read cases but not change them.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Evidence bundle" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Users & settings" })).toHaveCount(0);
    await page.goto("/admin");
    await expect(page.getByText("You don't have access to this page")).toBeVisible();
    // Forging the request the hidden button would have sent is refused by the server.
    const me = await (await page.request.get("/api/auth/me")).json();
    const r = await page.request.post("/api/admin/users", { data: { email: "x@e2e.test", role: "admin", password: "Whatever-long-pw-1" }, headers: { "X-CSRF-Token": me.csrf_token } });
    expect(r.status()).toBe(403);
  });

  test("revoking a session elsewhere shows the signed-out screen", async ({ page, browser }) => {
    await signIn(page, ANALYST.email, ANALYST.password);
    await expect(page.getByRole("navigation", { name: "Main" })).toBeVisible();
    const other = await browser.newContext({ baseURL: "http://localhost:5174" });
    const o = await other.newPage();
    await signIn(o, ANALYST.email, ANALYST.password);
    await o.goto("/account?tab=sessions");
    await o.getByRole("button", { name: "Sign out all others" }).click();
    await expect(o.getByText(/Signed out [1-9][0-9]* other sessions?/)).toBeVisible();
    await page.reload();
    await expect(page.getByRole("heading", { name: "You were signed out" })).toBeVisible();
    await page.getByRole("button", { name: "Sign in again" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await other.close();
  });

  test("logout ends the session", async ({ page }) => {
    await signIn(page, VIEWER.email, VIEWER.password);
    await page.getByRole("button", { name: /viewer/i }).click();
    await page.getByRole("menuitem", { name: "Sign out" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.goto("/");
    await expect(page).toHaveURL(/login/);
  });
});
