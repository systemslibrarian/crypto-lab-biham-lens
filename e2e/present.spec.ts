import { test, expect } from '@playwright/test';
import { boot, scan } from './gate';

for (const width of [1280, 320]) {
  test(`PRESENT every act and recovered fixture accessibility at ${width}`, async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize({ width, height: 900 });
    await boot(page, 'dark');
    await page.locator('#tab-present').click();
    for (let act = 1; act <= 6; act++) {
      await page.locator(`.present-step[data-act="${act}"]`).click();
      await expect(page.locator(`#present-act${act}`)).toBeVisible();
      if (act === 1) await page.locator('#present-act1 summary').click();
      if (act === 4)
        await page.locator('#present-trace details').first().locator('summary').click();
      await scan(page, `PRESENT ${width} act ${act}`);
    }
    await page.locator('#present-run').click();
    await expect(page.locator('#present-progress')).toContainText('running', { timeout: 120_000 });
    await scan(page, `PRESENT ${width} act 6 running`);
    await expect(page.locator('#present-recovery')).toHaveAttribute('data-verdict', 'recovered', {
      timeout: 120_000,
    });
    await scan(page, `PRESENT ${width} recovered`);
  });
}
