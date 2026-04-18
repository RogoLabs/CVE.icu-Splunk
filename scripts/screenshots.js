/**
 * Playwright screenshot automation for TA-cveicu dashboards.
 *
 * Usage:
 *   cd scripts
 *   npm install
 *   npx playwright install chromium
 *   npm run screenshots
 *
 * Environment variables:
 *   SPLUNK_URL  - Splunk Web URL (default: http://localhost:18000)
 *   SPLUNK_USER - Splunk username (default: admin)
 *   SPLUNK_PASS - Splunk password (default: testpassword123)
 *   OUTPUT_DIR  - Screenshot output directory (default: ../docs/screenshots)
 */

const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const SPLUNK_URL = process.env.SPLUNK_URL || "http://localhost:18000";
const SPLUNK_USER = process.env.SPLUNK_USER || "admin";
const SPLUNK_PASS = process.env.SPLUNK_PASS || "testpassword123";
const OUTPUT_DIR =
  process.env.OUTPUT_DIR || path.join(__dirname, "..", "docs", "screenshots");

async function login(page) {
  await page.goto(`${SPLUNK_URL}/en-US/account/login`);
  await page.fill('input[name="username"]', SPLUNK_USER);
  await page.fill('input[name="password"]', SPLUNK_PASS);
  await page.click('input[type="submit"]');
  await page.waitForURL("**/en-US/**", { timeout: 30000 });
  // Dismiss any post-login modals/tooltips
  await page.waitForTimeout(2000);
}

async function waitForDashboard(page) {
  // Wait for Splunk 10 Dashboard Studio to render
  try {
    await page.waitForSelector("[data-test]", { timeout: 30000 });
  } catch {
    // Fallback: just wait
  }
  // Give searches time to complete and panels to populate
  await page.waitForTimeout(15000);
}

async function screenshot(page, name) {
  const filepath = path.join(OUTPUT_DIR, `${name}.png`);
  await page.screenshot({ path: filepath, fullPage: true });
  console.log(`  Saved: ${filepath}`);
}

async function dismissModals(page) {
  // Close any Splunk modals, tour prompts, or EULA banners
  const dismissSelectors = [
    'button:has-text("Skip")',
    'button:has-text("Got it")',
    'button:has-text("Close")',
    'button:has-text("Dismiss")',
    ".close-btn",
    '[data-test="close-btn"]',
  ];
  for (const selector of dismissSelectors) {
    try {
      const btn = page.locator(selector).first();
      if (await btn.isVisible({ timeout: 500 })) {
        await btn.click();
        await page.waitForTimeout(500);
      }
    } catch {
      // Ignore — modal not present
    }
  }
}

async function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  console.log(`Logging into Splunk at ${SPLUNK_URL}...`);
  await login(page);
  await dismissModals(page);

  const dashboards = [
    { view: "cve_explorer", name: "cve-explorer", label: "CVE Explorer" },
    { view: "risk_priority", name: "risk-priority", label: "Risk Priority" },
    {
      view: "vulnerability_landscape",
      name: "vulnerability-landscape",
      label: "Vulnerability Landscape",
    },
    {
      view: "operational_health",
      name: "operational-health",
      label: "Operational Health",
    },
  ];

  for (const dash of dashboards) {
    console.log(`\nCapturing ${dash.label}...`);
    await page.goto(`${SPLUNK_URL}/en-US/app/TA-cveicu/${dash.view}`);
    await waitForDashboard(page);
    await dismissModals(page);
    await screenshot(page, dash.name);
  }

  // CVE Explorer with CRITICAL filter
  console.log("\nCapturing CVE Explorer (CRITICAL filter)...");
  await page.goto(`${SPLUNK_URL}/en-US/app/TA-cveicu/cve_explorer`);
  await waitForDashboard(page);
  await dismissModals(page);
  try {
    // Find the Severity dropdown and select CRITICAL
    const severityDropdown = page
      .locator('[data-input-id="input_severity"]')
      .first();
    if (await severityDropdown.isVisible({ timeout: 5000 })) {
      await severityDropdown.click();
      await page.locator("text=Critical").first().click();
      await page.waitForTimeout(8000);
    }
  } catch {
    console.log(
      "  Warning: Could not apply severity filter, using unfiltered view",
    );
  }
  await screenshot(page, "cve-explorer-filtered");

  // Risk Priority with KEV Only filter
  console.log("\nCapturing Risk Priority (KEV Only)...");
  await page.goto(`${SPLUNK_URL}/en-US/app/TA-cveicu/risk_priority`);
  await waitForDashboard(page);
  await dismissModals(page);
  try {
    const kevDropdown = page
      .locator('[data-input-id="input_kev_only"]')
      .first();
    if (await kevDropdown.isVisible({ timeout: 5000 })) {
      await kevDropdown.click();
      await page.locator("text=KEV Only").first().click();
      await page.waitForTimeout(8000);
    }
  } catch {
    console.log("  Warning: Could not apply KEV filter, using unfiltered view");
  }
  await screenshot(page, "risk-priority-kev");

  // Data Inputs page
  console.log("\nCapturing Data Inputs...");
  await page.goto(`${SPLUNK_URL}/en-US/manager/TA-cveicu/datainputstats`);
  await page.waitForTimeout(5000);
  await dismissModals(page);
  await screenshot(page, "data-inputs");

  await browser.close();
  console.log(`\nDone! Screenshots saved to ${OUTPUT_DIR}`);
}

main().catch((err) => {
  console.error("Screenshot capture failed:", err.message);
  process.exit(1);
});
