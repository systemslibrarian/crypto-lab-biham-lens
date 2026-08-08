import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     forced `details.open = true` on a page that has no `<details>`, and its
 *     "gradient contrast check" RETURNED A PASSING 100 whenever it found no
 *     matching element or no parseable `rgb()` in the background. A default
 *     that passes on absence is not an oracle.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and this lab renders almost everything from JS: the trace
 *     pipeline, the S-box grid, the 256-cell DDT, the timeline panels and the
 *     whole attack results section are empty or `display: none` markup until
 *     something is clicked. Four of the five tab panels are hidden at first
 *     paint, so a gate that scans only the untouched page has audited a fifth
 *     of the lab.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * `.tab-content` runs a `fadeIn` keyframe that starts at `opacity: 0`, so the
 * assertion is load-bearing here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. The gate this replaced called
 * `emulateMedia({ reducedMotion: 'reduce' })` inside its settle helper and
 * never checked it took effect, which is indistinguishable from not calling it.
 *
 * The theme is seeded in `localStorage` rather than reached by clicking the
 * toggle, so the light run boots light instead of ramping into it — the old
 * gate clicked the toggle and then had to wait out a 300ms colour transition it
 * could only observe by polling a hardcoded expected colour.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // Everything below is rendered by JS, so an empty shell would otherwise scan
  // clean. Assert the tab strip and the trace pipeline really populated.
  await expect(page.locator('[role="tablist"] [role="tab"]')).toHaveCount(5);
  await expect(page.locator('#tracePipeline .trace-row')).toHaveCount(13);
  await expect(page.locator('#sboxGrid .sbox-cell')).toHaveCount(16);
  await expect(page.locator('#ddtGrid .ddt-cell')).toHaveCount(256);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: the trace rows are a four-column grid with two fixed
 * tracks, the DDT is 16x16, the complexity table is four columns wide, and the
 * bias and sweep charts are 600px canvases.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}





/** Click a tab and wait for its panel to become the shown one. */
async function openTab(page: Page, id: string): Promise<void> {
  await page.locator(`#tab-${id}`).click();
  await expect(page.locator(`#${id}`)).toHaveClass(/\bactive\b/);
  await expect(page.locator(`#${id}`)).toBeVisible();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * All five tabs are opened, because four are `display: none` at first paint.
 * Within them both branches of the attack verdict are reached — the weak S-box
 * recovering K4 (success card) and the strong PRESENT S-box failing to separate
 * the bias from noise (failure card) — because a gate that only ever sees the
 * happy path has not audited the panel a learner most needs to read.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint (trace)`);

  // --- Tab 1: differential trace -----------------------------------------
  // Rows are revealed one stage at a time; un-revealed rows are a faint
  // skeleton, so the fully-revealed pipeline is a different rendering.
  await page.locator('#traceStep').click();
  await page.locator('#traceStep').click();
  await expect(page.locator('#traceStatus')).toContainText('Stage 2 of 12');
  await scan(page, `${theme} / trace stepped twice`);

  // Step onto a permute row: that is the state that draws the wire animation.
  for (let i = 0; i < 4; i++) await page.locator('#traceStep').click();
  await scan(page, `${theme} / trace at a permute stage`);

  await page.locator('#traceShowAll').click();
  await expect(page.locator('#tracePipeline .trace-row.hidden')).toHaveCount(0);
  await scan(page, `${theme} / trace fully revealed`);

  await page.locator('#traceP1').fill('A5');
  await page.locator('#traceP2').fill('5A');
  await scan(page, `${theme} / trace with a different plaintext pair`);

  await page.locator('#traceReset').click();
  await scan(page, `${theme} / trace reset`);

  // --- Tab 2: live attack -------------------------------------------------
  await openTab(page, 'attack');
  await scan(page, `${theme} / attack setup`);

  // K4 is masked until revealed — the revealed value is its own rendering.
  await page.locator('#revealK4').click();
  await expect(page.locator('#hiddenK4')).toContainText('0x');
  await scan(page, `${theme} / subkey revealed`);

  await page.locator('#seedInput').fill('DEADBEEF');
  await page.locator('#applySeed').click();
  await scan(page, `${theme} / seed applied`);

  await page.locator('#deriveDiff').click();
  await expect(page.locator('#characteristicStatus')).not.toBeEmpty();
  await scan(page, `${theme} / characteristic re-derived`);

  // Running with no pairs is a real state a visitor reaches by clicking the
  // buttons in the order they are printed.
  await page.locator('#runAttack').click();
  await expect(page.locator('#attackStatus')).toContainText('collect some pairs');
  await scan(page, `${theme} / attack refused, no pairs`);

  await page.locator('#add100').click();
  await page.locator('#add500').click();
  await page.locator('#add1000').click();
  await expect(page.locator('#pairStatus')).toContainText('1600');
  await scan(page, `${theme} / pairs collected`);

  await page.locator('#runAttack').click();
  await expect(page.locator('#resultsSection')).toBeVisible();
  await expect(page.locator('#successMessage')).toBeVisible();
  await scan(page, `${theme} / attack succeeded (success card)`);

  // The learning-curve sweep draws the second canvas.
  await page.locator('#runSweep').click();
  await expect(page.locator('#attackStatus')).toContainText('Sweep complete');
  await scan(page, `${theme} / learning-curve sweep`);

  await page.locator('#clearPairs').click();
  await expect(page.locator('#pairStatus')).toContainText('0 pairs');
  await scan(page, `${theme} / pairs cleared`);

  // --- Tab 3: S-box analysis ---------------------------------------------
  await openTab(page, 'sbox');
  await scan(page, `${theme} / sbox grid and DDT (weak)`);

  // A high-count DDT cell: the "exploitable" branch, with the CTA button shown.
  // NOT `.first()`: cell 0 is the trivial DIn = 0 -> DOut = 0 entry, whose count
  // is 16 but whose branch reports "trivial case" and HIDES the CTA. Picking it
  // would have scanned the wrong branch while looking right.
  await page.locator('#ddtGrid .ddt-cell.ddt-7-plus').nth(1).click();
  await expect(page.locator('#ddtClickInfo')).toBeVisible();
  await expect(page.locator('#useInAttack')).toBeVisible();
  await scan(page, `${theme} / DDT cell exploitable`);

  // A zero cell: the trivial branch, which hides the CTA and re-colours the note.
  await page.locator('#ddtGrid .ddt-cell.ddt-0').first().click();
  await scan(page, `${theme} / DDT cell not exploitable`);

  await page.locator('#ddtGrid .ddt-cell.ddt-7-plus').nth(1).click();
  await page.locator('#useInAttack').click();
  await scan(page, `${theme} / differential pushed into the attack`);

  // Swap to the strong PRESENT S-box: a different grid, a different DDT and a
  // different assessment verdict.
  await openTab(page, 'sbox');
  await page.locator('#useStrongSbox').click();
  await expect(page.locator('#sboxAssessmentContent')).toContainText('Strong');
  await scan(page, `${theme} / strong S-box analysis`);

  // --- The FAILURE branch of the attack ----------------------------------
  // With the PRESENT S-box the differential no longer separates from noise, so
  // the attack renders its failure card instead of its success card. That is a
  // whole panel the old gate never reached.
  await openTab(page, 'attack');
  await page.locator('#add100').click();
  await page.locator('#runAttack').click();
  await expect(page.locator('#resultsSection')).toBeVisible();
  await scan(page, `${theme} / attack verdict on the strong S-box`);

  await openTab(page, 'sbox');
  await page.locator('#useWeakSbox').click();
  await expect(page.locator('#sboxAssessmentContent')).toContainText('Weak');
  await scan(page, `${theme} / weak S-box restored`);

  // --- Tab 4: historical impact ------------------------------------------
  await openTab(page, 'history');
  await expect(page.locator('#timelineContent')).not.toBeEmpty();
  await scan(page, `${theme} / timeline step 0`);

  for (const step of [1, 2, 3, 4]) {
    await page.locator(`#timelineStep${step}`).click();
    await scan(page, `${theme} / timeline step ${step}`);
  }

  // --- Tab 5: why Serpent survived ---------------------------------------
  await openTab(page, 'serpent');
  await scan(page, `${theme} / serpent`);

  // Both skip links are parked off-screen until focused; the focused rendering
  // is the only one that paints, so it is the only one worth measuring.
  await page.keyboard.press('Tab');
  await scan(page, `${theme} / skip link focused`);
}
