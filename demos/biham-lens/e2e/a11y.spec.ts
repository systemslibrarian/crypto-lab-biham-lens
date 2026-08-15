import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * All five tab panels are opened and driven — the differential trace stepped,
 * fully revealed and reset; the live attack run to BOTH verdicts (the weak
 * S-box recovering K4, the strong PRESENT S-box failing to separate the bias
 * from noise); the DDT clicked on an exploitable cell and on a trivial one; the
 * historical timeline advanced through all five steps — with every resulting
 * rendering scanned in both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
