import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page with every <details> expanded,
 * in both dark (default) and light themes.
 *
 * The page paints its way in: `.tab-content` runs `fadeIn 0.3s` (opacity 0 -> 1
 * plus a translate) on load, and `.tab-button` / the themed surfaces carry
 * `transition: all 0.3s ease`, so flipping the theme toggle ramps every colour
 * over 300ms. axe reads *computed* colours at the instant it runs. Scanning
 * without settling first therefore measures half-faded text — e.g. the trace
 * legend at `#3e3e4d on #121223` (1.8:1) partway through the fade, or the tab
 * strip still holding the dark theme's `#9999aa` a frame after the toggle — and
 * reports colour-contrast violations for pixels no user ever sits and reads.
 * That race is why this gate failed intermittently and with a different node set
 * each run. Settled, both themes are clean, so `settle()` below is not masking a
 * real violation: it removes the sampling race so the gate measures the state
 * the page actually rests in.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

/**
 * Drive every in-flight animation and transition to its end state, then wait for
 * the compositor to agree, so axe samples final colours rather than tween frames.
 */
async function settle(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      scroll-behavior:auto!important;
    }`,
  });
  await page.evaluate(async () => {
    await Promise.all(
      document.getAnimations().map((a) => a.finished.catch(() => undefined)),
    );
  });
}

async function scan(page: Page): Promise<void> {
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await openAllDetails(page);
  await scan(page);
});
