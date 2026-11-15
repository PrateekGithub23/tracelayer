// Screenshot capture for UI review and the README (run with SCREENS=1; skipped in CI).
import { test, type Page } from "@playwright/test";

test.skip(!process.env.SCREENS, "screenshots only on demand");
const OUT = process.env.SCREENS_DIR ?? "../docs/screenshots";

const BASE = process.env.VITE_BASE ?? "/";
async function go(page: Page, path: string) {
  path = BASE.replace(/\/$/, "") + path;
  await page.evaluate((p) => { window.history.pushState({}, "", p); window.dispatchEvent(new PopStateEvent("popstate")); }, path);
  await page.waitForTimeout(900);
}

for (const vp of [{ name: "desktop", width: 1440, height: 900 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`screens ${vp.name}`, async ({ page }) => {
    await page.setViewportSize(vp);
    await page.goto("./");
    await page.screenshot({ path: `${OUT}/${vp.name}-landing.png` });
    await page.getByRole("button", { name: "Go straight to the dashboard" }).click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: `${OUT}/${vp.name}-overview.png`, fullPage: vp.name === "desktop" });
    await go(page, "/investigations?view=all");
    await page.screenshot({ path: `${OUT}/${vp.name}-investigations.png` });
    await page.locator("a[href*='/investigations/inv_']").nth(1).click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: `${OUT}/${vp.name}-case.png` });
    await page.getByRole("tab", { name: /AI analysis/ }).click();
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${OUT}/${vp.name}-analysis.png`, fullPage: vp.name === "desktop" });
    await page.getByRole("tab", { name: "Entity graph" }).click();
    await page.waitForTimeout(1800);
    await page.screenshot({ path: `${OUT}/${vp.name}-graph.png` });
    await page.getByRole("tab", { name: /Timeline/ }).click();
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${OUT}/${vp.name}-timeline.png` });
    await page.getByRole("tab", { name: "Activity" }).click();
    await page.waitForTimeout(600);
    await page.screenshot({ path: `${OUT}/${vp.name}-activity.png` });
    for (const [name, path] of [["walkthrough", "/walkthrough"], ["datasets", "/datasets"], ["ai-engine", "/ai"], ["integrity", "/integrity"], ["events", "/events"], ["account", "/account"]]) {
      await go(page, path);
      await page.screenshot({ path: `${OUT}/${vp.name}-${name}.png` });
    }
  });
}
