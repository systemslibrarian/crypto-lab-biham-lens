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
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.evaluate(async () => {
    await Promise.all(
      document.getAnimations().map((a) => a.finished.catch(() => undefined)),
    );
  });
  await expect(page.locator('h1')).toBeVisible();
}

async function checkGradientContrast(page: Page, selector: string) {
  const ratio = await page.evaluate((sel) => {
    function getLuminance(r: number, g: number, b: number) {
      const a = [r, g, b].map(function (v) {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    const els = document.querySelectorAll(sel);
    if (els.length === 0) return 100;
    let minGlobalRatio = Infinity;

    for (const el of Array.from(els)) {
      const style = window.getComputedStyle(el);
      const textMatch = style.color.match(/\d+/g);
      if (!textMatch) continue;
      const [r1, g1, b1] = textMatch.map(Number);
      const l1 = getLuminance(r1, g1, b1);

      // get nearest parent with a background gradient
      let parent = el;
      let bgStr = '';
      while (parent) {
        bgStr = window.getComputedStyle(parent).backgroundImage;
        if (bgStr && bgStr !== 'none') break;
        parent = parent.parentElement;
      }
      
      if (!bgStr) continue;
      const bgMatches = Array.from(bgStr.matchAll(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/g));
      if (bgMatches.length === 0) continue;

      const bodyBgMatch = window.getComputedStyle(document.body).backgroundColor.match(/\d+/g) || [0,0,0];
      const [br, bg, bb] = bodyBgMatch.map(Number);

      let minRatio = Infinity;
      for (const match of bgMatches) {
        let r2 = parseInt(match[1], 10);
        let g2 = parseInt(match[2], 10);
        let b2 = parseInt(match[3], 10);
        let a = match[4] ? parseFloat(match[4]) : 1;
        
        r2 = Math.round(r2 * a + br * (1 - a));
        g2 = Math.round(g2 * a + bg * (1 - a));
        b2 = Math.round(b2 * a + bb * (1 - a));

        const l2 = getLuminance(r2, g2, b2);
        const lightest = Math.max(l1, l2);
        const darkest = Math.min(l1, l2);
        const cr = (lightest + 0.05) / (darkest + 0.05);
        if (cr < minRatio) minRatio = cr;
      }
      if (minRatio < minGlobalRatio) minGlobalRatio = minRatio;
    }
    return minGlobalRatio;
  }, selector);
  
  if (ratio !== 100) {
    expect(ratio).toBeGreaterThanOrEqual(4.5);
  }
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
  await checkGradientContrast(page, '.insight-callout p, .success-card p, .failure-card p');
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await openAllDetails(page);
  await checkGradientContrast(page, '.insight-callout p, .success-card p, .failure-card p');
  await scan(page);
});
