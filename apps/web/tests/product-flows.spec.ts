import { expect, test } from "@playwright/test";

test("automation and custom-rule controls open working product views", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Audit Solana/i })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No security result yet" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Project risk score" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Findings 0/i })).toBeDisabled();

  await page.getByRole("button", { name: /CI \/ CD/i }).click();
  await expect(page.locator("main")).toHaveAttribute("data-view", "CI / CD");
  await expect(page.getByRole("heading", { name: "Continuous security" })).toBeVisible();

  await page.getByRole("button", { name: /Custom rules/i }).click();
  await expect(page.getByRole("heading", { name: "Custom rule workspace" })).toBeVisible();
  await expect(page.getByText("RBX001").first()).toBeVisible();
});

test("a real imported project produces findings, fixes, and a PDF download", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles("D:/robooxx/examples/vulnerable-anchor");
  await page.getByRole("button", { name: /Start security audit/i }).click();
  await expect(page.getByRole("heading", { name: "Project risk score" })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: /Findings 5/i }).click();
  await page.getByRole("button", { name: "Mark reviewed" }).click();
  await expect(page.getByRole("button", { name: /Reviewed/ })).toBeVisible();
  await page.getByRole("combobox").selectOption("high");
  await expect(page.getByText("Unchecked account accepts substitution").first()).toBeVisible();
  await page.getByRole("button", { name: /Reports/i }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: /Detailed PDF/i }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/robox-.*\.pdf/);
});

test("API recognizes an uploaded Anchor project as a Solana program", async ({ request }) => {
  const response = await request.post("http://127.0.0.1:8080/api/v1/scans", {
    data: {
      project: "anchor-repro",
      source: {
        type: "inline",
        files: [
          { path: "Anchor.toml", content: "[programs.localnet]\nanchor_repro = \"11111111111111111111111111111111\"" },
          { path: "Cargo.toml", content: "[dependencies]\nanchor-lang = \"0.31\"" },
          { path: "programs/repro/src/lib.rs", content: "use anchor_lang::prelude::*;\n#[program]\npub mod anchor_repro { pub fn initialize(_ctx: Context<Initialize>) -> Result<()> { Ok(()) } }\n#[derive(Accounts)]\npub struct Initialize {}" },
        ],
      },
    },
  });

  expect(response.ok()).toBeTruthy();
  const scan = await response.json();
  expect(scan.project_kind).toBe("anchor");
  expect(scan.metrics.instructions).toBeGreaterThan(0);

  const report = await request.get(`http://127.0.0.1:8080/api/v1/scans/${scan.id}/report/markdown`);
  expect(report.ok()).toBeTruthy();
  expect(await report.text()).toContain("**Project type:** Anchor program");

  const pdf = await request.get(`http://127.0.0.1:8080/api/v1/scans/${scan.id}/report/pdf`);
  expect(pdf.ok()).toBeTruthy();
  expect(pdf.headers()["content-type"]).toContain("application/pdf");
  expect((await pdf.body()).subarray(0, 8).toString()).toBe("%PDF-1.4");

  const rules = await request.get("http://127.0.0.1:8080/api/v1/rules");
  expect(rules.ok()).toBeTruthy();
  expect((await rules.json()).length).toBe(11);
});
