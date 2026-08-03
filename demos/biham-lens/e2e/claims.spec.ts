import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Claims gate.
 *
 * The a11y spec proves the page is reachable. This one proves it is *honest*:
 * every headline verdict, counter and failure path is asserted against a value
 * the page itself computed, not against a string this file hardcodes. Where the
 * page renders the same quantity twice (the DDT grid vs. its strength verdict,
 * the results card vs. the success card, the target-Δ field vs. the prose that
 * explains it), the two renderings are compared to each other — those are the
 * assertions that actually bite.
 *
 * Determinism: the cipher key is fixed (0x5A69) and the plaintext stream comes
 * from a seeded xorshift32. Clicking "Apply" on the seed field resets that
 * stream, so every attack below is reproducible run to run. Tests that depend on
 * an exact bias count reset the seed immediately before collecting.
 */

const K4_FROM_PAGE = /^0x[0-9A-F]{2}$/;

async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#characteristicStatus')).toContainText('Auto-derived on load');
}

async function openAttackTab(page: Page): Promise<void> {
  await page.locator('#tab-attack').click();
  await expect(page.locator('#attack')).toHaveClass(/active/);
}

/** Reveal K₄ and return exactly what the page printed, e.g. "0x69". */
async function revealK4(page: Page): Promise<string> {
  await page.locator('#revealK4').click();
  const k4 = (await page.locator('#hiddenK4').innerText()).trim();
  expect(k4).toMatch(K4_FROM_PAGE);
  return k4;
}

/** Reset the plaintext stream so the following collection is reproducible. */
async function reseed(page: Page): Promise<void> {
  await page.locator('#applySeed').click();
  await expect(page.locator('#attackStatus')).toContainText('Seed reset to 0x12345678');
}

function num(text: string, re: RegExp): number {
  const m = text.match(re);
  expect(m, `expected ${re} in: ${text}`).not.toBeNull();
  return Number(m![1].replace(/,/g, ''));
}

function popcount(n: number): number {
  let c = 0;
  for (let b = 0; b < 8; b++) c += (n >> b) & 1;
  return c;
}

interface TraceRow {
  kind: string;
  label: string;
  diff: number;
  marker: string;
  routing: string;
  hidden: boolean;
}

async function readTrace(page: Page): Promise<TraceRow[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('.trace-row')).map((row) => {
      const cls = row.className;
      const kind = (cls.match(/kind-([a-z-]+)/) ?? ['', ''])[1];
      const diffText = row.querySelector('.diff-value')?.textContent ?? '';
      return {
        kind,
        label: row.querySelector('.stage-label')?.textContent?.trim() ?? '',
        diff: parseInt((diffText.match(/Δ=0x([0-9A-F]{2})/) ?? ['', 'NaN'])[1], 16),
        marker:
          row.querySelector('.diff-preservation-marker')?.textContent?.trim() ??
          row.querySelector('.diff-changed-marker')?.textContent?.trim() ??
          '',
        routing: row.querySelector('.permute-routing-caption')?.textContent?.trim() ?? '',
        hidden: cls.includes('hidden'),
      };
    }),
  );
}

/** The DDT grid as a 16x16 matrix, read back out of the rendered cells. */
async function readDDT(page: Page): Promise<number[][]> {
  const flat = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.ddt-cell')).map((c) => ({
      text: c.textContent ?? '',
      label: c.getAttribute('aria-label') ?? '',
    })),
  );
  expect(flat).toHaveLength(256);
  const matrix: number[][] = [];
  for (let row = 0; row < 16; row++) {
    const cells: number[] = [];
    for (let col = 0; col < 16; col++) {
      const cell = flat[row * 16 + col];
      const shown = cell.text === '·' ? 0 : Number(cell.text);
      // The visible glyph and the screen-reader label must agree.
      const labelled = num(cell.label, /count (\d+)/);
      expect(labelled, `cell ${row},${col} label vs text`).toBe(shown);
      expect(cell.label).toContain(
        `Input diff 0x${row.toString(16).toUpperCase()}, output diff 0x${col
          .toString(16)
          .toUpperCase()}`,
      );
      cells.push(shown);
    }
    matrix.push(cells);
  }
  return matrix;
}

function maxNonTrivial(ddt: number[][]): { value: number; row: number; col: number } {
  let best = { value: -1, row: 0, col: 0 };
  for (let r = 1; r < 16; r++) {
    for (let c = 0; c < 16; c++) {
      if (ddt[r][c] > best.value) best = { value: ddt[r][c], row: r, col: c };
    }
  }
  return best;
}

function ddtCell(page: Page, row: number, col: number): Locator {
  return page.locator('.ddt-cell').nth(row * 16 + col);
}

// ===========================================================================
// 1 · Differential Trace — the page's step-by-step exhibit
// ===========================================================================

test.describe('differential trace', () => {
  test('every XOR-with-key stage leaves the difference untouched', async ({ page }) => {
    await boot(page);
    await page.locator('#traceShowAll').click();

    const rows = await readTrace(page);
    expect(rows.length).toBeGreaterThan(1);

    const xorRows = rows.filter((r) => r.kind === 'xor-key');
    // 4 round keys + the final mixing key.
    expect(xorRows).toHaveLength(5);

    for (let i = 1; i < rows.length; i++) {
      if (rows[i].kind !== 'xor-key') continue;
      // The claim the whole attack rests on: XOR with a constant is transparent
      // to a difference. Assert the numbers, then assert the page says so.
      expect(rows[i].diff, `${rows[i].label} changed the difference`).toBe(rows[i - 1].diff);
      expect(rows[i].marker).toBe('✓ Δ preserved (XOR rule)');
    }
  });

  test('S-box stages are the only place the difference is allowed to change', async ({ page }) => {
    await boot(page);
    await page.locator('#traceShowAll').click();
    const rows = await readTrace(page);

    for (let i = 1; i < rows.length; i++) {
      const changed = rows[i].diff !== rows[i - 1].diff;
      expect(rows[i].marker, `${rows[i].label} marker disagrees with its own numbers`).toBe(
        changed ? '↯ Δ changed' : rows[i].kind === 'xor-key' ? '✓ Δ preserved (XOR rule)' : '= unchanged',
      );
      if (changed) {
        expect(
          ['sbox', 'permute'],
          `${rows[i].label} changed Δ but is not a substitution or permutation stage`,
        ).toContain(rows[i].kind);
      }
    }
    expect(rows.filter((r) => r.kind === 'sbox' && r.marker === '↯ Δ changed').length).toBeGreaterThan(0);
  });

  test('permutation relocates active bits without adding or removing any', async ({ page }) => {
    await boot(page);
    await page.locator('#traceShowAll').click();
    const rows = await readTrace(page);

    const permuteRows = rows.filter((r) => r.kind === 'permute');
    expect(permuteRows).toHaveLength(3); // rounds 1-3; round 4 skips the permutation

    for (let i = 1; i < rows.length; i++) {
      if (rows[i].kind !== 'permute') continue;
      const before = popcount(rows[i - 1].diff);
      const after = popcount(rows[i].diff);
      // The invariant itself, computed from the two rendered Δ values.
      expect(after, `${rows[i].label} changed the active-bit count`).toBe(before);
      // ...and the caption the page draws over the routing diagram, anchored so
      // the "1 byte differs"-style trailing numbers cannot be picked up instead.
      const inCount = num(rows[i].routing, /Bit routing:\s*(\d+)\s+active bits?\s+in/);
      const outCount = num(rows[i].routing, /active bits? in,\s*(\d+)\s+out/);
      expect(inCount).toBe(before);
      expect(outCount).toBe(after);
    }
  });

  test('the trace opens on the plaintext difference the attack tab reports', async ({ page }) => {
    await boot(page);
    await page.locator('#traceShowAll').click();

    const rows = await readTrace(page);
    const plainDiff = (await page.locator('#plainDiff').innerText()).trim();
    // Same quantity, computed and rendered by two different code paths.
    expect(`0x${rows[0].diff.toString(16).toUpperCase().padStart(2, '0')}`).toBe(plainDiff);
    expect(rows[0].kind).toBe('input');

    // Drive it from the trace's own inputs and check both renderings move together.
    await page.locator('#traceP1').fill('0F');
    await page.locator('#traceP2').fill('F0');
    await page.locator('#traceShowAll').click();
    const flipped = await readTrace(page);
    expect(flipped[0].diff).toBe(0xff);
    expect(popcount(flipped[0].diff)).toBe(8);
    await expect(page.locator('#plainDiff')).toHaveText('0xFF');
    await expect(page.locator('#p1')).toHaveValue('0F');
    await expect(page.locator('#p2')).toHaveValue('F0');
  });

  test('the stage counter matches how much of the pipeline is actually revealed', async ({ page }) => {
    await boot(page);
    const status = page.locator('#traceStatus');
    const total = (await readTrace(page)).length;
    expect(total).toBe(13); // input + 4x(XOR-K, S-box) + 3 permutes + final mixing

    const check = async (expectedVisible: number) => {
      const text = await status.innerText();
      expect(num(text, /^Stage (\d+) of/)).toBe(expectedVisible - 1);
      expect(num(text, / of (\d+) /)).toBe(total - 1);
      expect(num(text, /\((\d+)\//)).toBe(expectedVisible);
      expect(num(text, /\/(\d+) visible/)).toBe(total);
      const rows = await readTrace(page);
      expect(rows.filter((r) => !r.hidden)).toHaveLength(expectedVisible);
      // Unrevealed rows are skeletons: border only, no readable content.
      const firstHidden = rows.findIndex((r) => r.hidden);
      if (firstHidden !== -1) {
        expect(
          await page.locator('.trace-row').nth(firstHidden).innerText(),
        ).toBe('');
      }
    };

    await page.locator('#traceReset').click();
    await check(1);
    await page.locator('#traceStep').click();
    await page.locator('#traceStep').click();
    await page.locator('#traceStep').click();
    await check(4);
    await page.locator('#traceShowAll').click();
    await check(total);
    // Stepping past the end must not run off the array.
    await page.locator('#traceStep').click();
    await check(total);
    await page.locator('#traceReset').click();
    await check(1);
  });
});

// ===========================================================================
// S-box Analysis — the DDT and the strength verdict drawn from it
// ===========================================================================

test.describe('S-box analysis', () => {
  test('the DDT is a real distribution: every row accounts for all 16 inputs', async ({ page }) => {
    await boot(page);
    await page.locator('#tab-sbox').click();
    const ddt = await readDDT(page);

    for (let r = 0; r < 16; r++) {
      expect(ddt[r].reduce((a, b) => a + b, 0), `row 0x${r.toString(16)} does not sum to 16`).toBe(16);
      for (const count of ddt[r]) expect(count % 2).toBe(0); // DDT counts are always even
    }
    // Zero input difference can only give zero output difference.
    expect(ddt[0][0]).toBe(16);
    expect(ddt[0].slice(1).every((c) => c === 0)).toBe(true);
  });

  test('the strength verdict matches the peak of the table it is drawn from', async ({ page }) => {
    await boot(page);
    await page.locator('#tab-sbox').click();
    const assessment = page.locator('#sboxAssessmentContent');

    const weakDDT = await readDDT(page);
    const weakPeak = maxNonTrivial(weakDDT);
    // README: "the toy 4-bit S-box in this demo peaks at 8 out of 16 (1/2)".
    expect(weakPeak.value).toBe(8);
    // Cross-path: the grid and the verdict are rendered from two separate
    // computeDDT() calls, so they have to be compared to each other.
    expect(num(await assessment.innerText(), /Max non-trivial DDT entry:\s*(\d+)/)).toBe(weakPeak.value);
    await expect(assessment).toContainText('Weak');
    await expect(assessment).toContainText(
      `≤ ${(weakPeak.value / 16).toFixed(2)} per active S-box`,
    );
    await expect(page.locator('#useWeakSbox')).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#useStrongSbox')).toHaveAttribute('aria-checked', 'false');

    await page.locator('#useStrongSbox').click();
    const strongDDT = await readDDT(page);
    const strongPeak = maxNonTrivial(strongDDT);
    // README: "the PRESENT S-box it can be swapped for peaks at 4 out of 16
    // (1/4), the best a 4-bit permutation can do."
    expect(strongPeak.value).toBe(4);
    expect(num(await assessment.innerText(), /Max non-trivial DDT entry:\s*(\d+)/)).toBe(strongPeak.value);
    await expect(assessment).toContainText('Strong');
    await expect(assessment).toContainText(
      `≤ ${(strongPeak.value / 16).toFixed(2)} per active S-box`,
    );
    await expect(page.locator('#useStrongSbox')).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#activeSboxLabel')).toHaveText('Strong (PRESENT)');

    // Swapping the S-box swapped the cipher: the two tables must differ.
    expect(JSON.stringify(strongDDT)).not.toBe(JSON.stringify(weakDDT));
  });

  test('clicking a cell reports that cell own count and count/16 as a percentage', async ({ page }) => {
    await boot(page);
    await page.locator('#tab-sbox').click();
    const ddt = await readDDT(page);
    const peak = maxNonTrivial(ddt);

    await ddtCell(page, peak.row, peak.col).click();
    const info = page.locator('#ddtClickInfo');
    await expect(info).toBeVisible();
    await expect(page.locator('#ddtInputDiff')).toHaveText(`0x${peak.row.toString(16).toUpperCase()}`);
    await expect(page.locator('#ddtOutputDiff')).toHaveText(`0x${peak.col.toString(16).toUpperCase()}`);
    await expect(page.locator('#ddtCount')).toHaveText(String(peak.value));
    // Exact string equality against the page's own toFixed(1), not toBeCloseTo.
    const pct = `${((peak.value / 16) * 100).toFixed(1)}%`;
    await expect(page.locator('#ddtProb')).toHaveText(pct);
    await expect(page.locator('#ddtExploitable')).toContainText('Exploitable');
    await expect(page.locator('#ddtExploitable')).toContainText(pct);
    await expect(page.locator('#useInAttack')).toBeVisible();

    // The lane exhibit: the clicked nibble differential sits in the low lane,
    // the high lane stays inactive, because K₄ is a byte and the DDT is a nibble.
    const lanes = page.locator('#ddtLanes');
    await expect(lanes).toContainText('Δ=0x0');
    await expect(lanes).toContainText(
      `Δ=0x${peak.row.toString(16).toUpperCase()}→${peak.col.toString(16).toUpperCase()}`,
    );

    // An impossible transition must say so and must not be offered to the attack.
    let zero: { row: number; col: number } | null = null;
    for (let r = 1; r < 16 && !zero; r++) {
      for (let c = 0; c < 16; c++) if (ddt[r][c] === 0) { zero = { row: r, col: c }; break; }
    }
    expect(zero).not.toBeNull();
    await ddtCell(page, zero!.row, zero!.col).click();
    await expect(page.locator('#ddtCount')).toHaveText('0');
    await expect(page.locator('#ddtProb')).toHaveText('0.0%');
    await expect(page.locator('#ddtExploitable')).toHaveText(
      'Impossible differential — this transition never occurs.',
    );
    await expect(page.locator('#useInAttack')).toBeHidden();

    // The zero-input-difference row is the trivial case, not a finding.
    await ddtCell(page, 0, 0).click();
    await expect(page.locator('#ddtCount')).toHaveText('16');
    await expect(page.locator('#ddtProb')).toHaveText('100.0%');
    await expect(page.locator('#ddtExploitable')).toHaveText('Trivial case (zero input difference).');
    await expect(page.locator('#useInAttack')).toBeHidden();

    // A low-but-nonzero entry is usable, just expensive.
    let low: { row: number; col: number } | null = null;
    for (let r = 1; r < 16 && !low; r++) {
      for (let c = 0; c < 16; c++) if (ddt[r][c] > 0 && ddt[r][c] <= 4) { low = { row: r, col: c }; break; }
    }
    expect(low).not.toBeNull();
    await ddtCell(page, low!.row, low!.col).click();
    await expect(page.locator('#ddtExploitable')).toHaveText(
      'Usable but low-probability; the attack needs more pairs.',
    );
  });

  test('"use this differential" hands the clicked cell to the attack unchanged', async ({ page }) => {
    await boot(page);
    await page.locator('#tab-sbox').click();
    const peak = maxNonTrivial(await readDDT(page));

    await ddtCell(page, peak.row, peak.col).click();
    await page.locator('#useInAttack').click();

    await expect(page.locator('#attack')).toHaveClass(/active/);
    const hex2 = (n: number) => n.toString(16).toUpperCase().padStart(2, '0');
    await expect(page.locator('#p1')).toHaveValue('00');
    await expect(page.locator('#p2')).toHaveValue(hex2(peak.row));
    await expect(page.locator('#outDiff')).toHaveValue(hex2(peak.col));
    // The attack tab recomputes Δ from P₁ ⊕ P₂; it must land on the clicked ΔIn.
    await expect(page.locator('#plainDiff')).toHaveText(`0x${hex2(peak.row)}`);
    await expect(page.locator('#characteristicStatus')).toContainText(
      `ΔIn=0x${hex2(peak.row)}, ΔOut=0x${hex2(peak.col)}`,
    );
  });
});

// ===========================================================================
// 2 · Live Attack — the headline verdict, its counters and its failure paths
// ===========================================================================

test.describe('live attack', () => {
  test('a successful run names the key the page itself reveals', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const k4 = await revealK4(page);

    await reseed(page);
    await page.locator('#add500').click();
    await expect(page.locator('#pairStatus')).toHaveText('500 pairs collected. Ready to attack!');
    await page.locator('#runAttack').click();

    await expect(page.locator('#resultsSection')).toBeVisible();
    await expect(page.locator('#successMessage')).toBeVisible();
    await expect(page.locator('#failureMessage')).toBeHidden();
    await expect(page.locator('#successMessage')).toContainText('Key Material Recovered!');

    // Four independent renderings of the same recovered byte, all cross-checked
    // against the K₄ the page printed when we clicked "reveal".
    await expect(page.locator('#recoveredKey')).toHaveText(k4);
    await expect(page.locator('#recoveredKeyText')).toHaveText(k4);
    await expect(page.locator('#actualKey')).toHaveText(k4);
    await expect(page.locator('#attackStatus')).toContainText(`Top candidate: ${k4}.`);
    await expect(page.locator('#correctKeyRank')).toHaveText('1');

    // The verdict has to be earned: the winning bias must sit far above the
    // noise floor the code uses (pairs / 256 ≈ 2 at 500 pairs) and must
    // strictly beat the runner-up, or "rank 1" would be a coin toss.
    const topBias = Number(await page.locator('#topBias').innerText());
    const margin = Number(await page.locator('#biasMargin').innerText());
    expect(topBias).toBeGreaterThan((500 / 256) * 4);
    expect(margin).toBeGreaterThanOrEqual(1);
    expect(margin).toBeLessThanOrEqual(topBias);
  });

  test('the operation counters agree with the pair count and with each other', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    await reseed(page);

    const assertCounters = async () => {
      const pairs = num(await page.locator('#pairStatus').innerText(), /^(\d+) pairs collected/);
      const opCount = num(await page.locator('#opCount').innerText(), /^([\d,]+)$/);
      // 2 partial decryptions per pair, per candidate subkey, over 256 candidates.
      expect(opCount).toBe(pairs * 256 * 2);

      // The complexity table renders the same figure as an equation. Assert the
      // equation actually holds — this is the check that caught it rendering
      // "256 × 500 = 256,000", which is false by a factor of two.
      const cell = (await page.locator('#diffToy').innerText()).trim();
      const m = cell.match(/^(\d+) × (\d+) × (\d+) = ([\d,]+)$/);
      expect(m, `unparseable differential-cost cell: ${cell}`).not.toBeNull();
      const [a, b, c] = [Number(m![1]), Number(m![2]), Number(m![3])];
      const product = Number(m![4].replace(/,/g, ''));
      expect(a * b * c).toBe(product);
      expect(c).toBe(pairs);
      expect(product).toBe(opCount);

      // ...and the status line quotes the same number a third time.
      expect(
        num(await page.locator('#attackStatus').innerText(), /([\d,]+) partial decryptions performed/),
      ).toBe(opCount);
      return pairs;
    };

    await page.locator('#add500').click();
    await page.locator('#runAttack').click();
    expect(await assertCounters()).toBe(500);

    await page.locator('#add1000').click();
    await page.locator('#add100').click();
    await page.locator('#runAttack').click();
    expect(await assertCounters()).toBe(1600);
  });

  test('the pair counter counts down to the 500 it asks for', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const status = page.locator('#pairStatus');
    await expect(status).toHaveText('0 pairs collected. Need 500 more for reliable recovery.');
    await page.locator('#add100').click();
    await expect(status).toHaveText('100 pairs collected. Need 400 more for reliable recovery.');
    await page.locator('#add1000').click();
    await expect(status).toHaveText('1100 pairs collected. Ready to attack!');
    await page.locator('#clearPairs').click();
    await expect(status).toHaveText('0 pairs collected. Need 500 more for reliable recovery.');
    await expect(page.locator('#resultsSection')).toBeHidden();
  });

  test('the same seed reproduces the same attack', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);

    const run = async () => {
      await reseed(page);
      await page.locator('#add500').click();
      await page.locator('#runAttack').click();
      return {
        key: await page.locator('#recoveredKey').innerText(),
        bias: await page.locator('#topBias').innerText(),
        margin: await page.locator('#biasMargin').innerText(),
        rank: await page.locator('#correctKeyRank').innerText(),
      };
    };

    const first = await run();
    const second = await run();
    expect(second).toEqual(first);
  });

  test('the target Δ, its tooltip and its prose all quote one derived peak', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    await page.locator('#deriveDiff').click();

    const status = await page.locator('#characteristicStatus').innerText();
    expect(status).toContain('Sampled 4 000 pairs through 3 rounds');
    const peakHex = status.match(/Peak Δ =\s*0x([0-9A-F]{2})/)![1];
    const pct = num(status, /probability\s*([\d.]+)%/);
    const ratio = num(status, /\(([\d.]+)× the runner-up\)/);

    // Three renderings of one sample: the input value, its tooltip, the prose.
    await expect(page.locator('#outDiff')).toHaveValue(peakHex);
    const title = (await page.locator('#outDiff').getAttribute('title'))!;
    expect(title).toContain(`0x${peakHex} is the peak difference`);
    expect(num(title, /occurring ([\d.]+)% of the time/)).toBe(pct);

    // A "peak" that is not above chance would not be a characteristic at all.
    // Chance for a byte difference is 100/256 ≈ 0.39%.
    expect(pct).toBeGreaterThan((100 / 256) * 4);
    expect(ratio).toBeGreaterThanOrEqual(1);
  });

  test('running with no pairs refuses rather than inventing a verdict', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    await page.locator('#runAttack').click();
    await expect(page.locator('#attackStatus')).toHaveText('Please collect some pairs first.');
    await expect(page.locator('#resultsSection')).toBeHidden();
    await expect(page.locator('#successMessage')).toBeHidden();
  });

  test('an impossible target Δ fails loudly and explains why', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const k4 = await revealK4(page);

    // Δ=0x00 after the last S-box would mean the two ciphertexts decrypt to the
    // same value — impossible for a bijection, so no candidate can ever score.
    await page.locator('#outDiff').fill('00');
    await reseed(page);
    await page.locator('#add500').click();
    await page.locator('#runAttack').click();

    await expect(page.locator('#failureMessage')).toBeVisible();
    await expect(page.locator('#successMessage')).toBeHidden();
    await expect(page.locator('#failureMessage')).toContainText("The bias didn't separate from noise");
    await expect(page.locator('#topBias')).toHaveText('0');

    const recovered = await page.locator('#recoveredKey').innerText();
    expect(recovered).not.toBe(k4);
    const explain = await page.locator('#failureExplain').innerText();
    expect(explain).toContain(`Top candidate ${recovered} ≠ actual K₄ ${k4}`);
    // It has to say *why*, and the rank it quotes must be the rank it displayed.
    expect(num(explain, /\(rank (\d+)\)/)).toBe(
      Number(await page.locator('#correctKeyRank').innerText()),
    );
    expect(num(explain, /\(rank (\d+)\)/)).toBeGreaterThan(1);
    expect(explain).toContain('may be low-probability, or you need more pairs');
    expect(explain).toContain('The chosen differential 0x01→0x00');
  });

  test('too few pairs fails, and the same differential succeeds once given enough', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const k4 = await revealK4(page);

    await reseed(page);
    await page.locator('#add100').click();
    await page.locator('#runAttack').click();
    await expect(page.locator('#failureMessage')).toBeVisible();
    await expect(page.locator('#successMessage')).toBeHidden();
    expect(await page.locator('#recoveredKey').innerText()).not.toBe(k4);
    expect(Number(await page.locator('#correctKeyRank').innerText())).toBeGreaterThan(1);
    await expect(page.locator('#failureExplain')).toContainText('you need more pairs');

    // Identical differential, identical seed, more pairs: the demo's whole
    // learning curve claim in one comparison.
    await reseed(page);
    await page.locator('#add1000').click();
    await page.locator('#runAttack').click();
    await expect(page.locator('#successMessage')).toBeVisible();
    await expect(page.locator('#failureMessage')).toBeHidden();
    await expect(page.locator('#recoveredKey')).toHaveText(k4);
    await expect(page.locator('#correctKeyRank')).toHaveText('1');
  });

  test('the pair-count sweep reports a rank per size and lands on rank 1 at the top', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    await reseed(page);
    await page.locator('#runSweep').click();

    const text = await page.locator('#attackStatus').innerText();
    expect(text).toMatch(/^Sweep complete\. Ranks: /);
    const points = [...text.matchAll(/(\d+)→(\d+)/g)].map((m) => ({
      n: Number(m[1]),
      rank: Number(m[2]),
    }));
    expect(points.map((p) => p.n)).toEqual([50, 100, 200, 500, 1000, 2000]);
    for (const p of points) {
      expect(p.rank, `rank at ${p.n} pairs out of range`).toBeGreaterThanOrEqual(1);
      expect(p.rank).toBeLessThanOrEqual(256);
    }
    // "Rank 1 means the attack worked" — at the largest sample it must.
    expect(points[points.length - 1].rank).toBe(1);
    await expect(page.locator('#resultsSection')).toBeVisible();
  });

  test('changing the chosen difference throws away pairs collected for the old one', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    await reseed(page);
    await page.locator('#add500').click();
    await page.locator('#runAttack').click();
    await expect(page.locator('#successMessage')).toBeVisible();

    await page.locator('#p1').fill('44');
    await expect(page.locator('#plainDiff')).toHaveText('0x07');
    await expect(page.locator('#pairStatus')).toHaveText(
      '0 pairs collected. Need 500 more for reliable recovery.',
    );
    await expect(page.locator('#resultsSection')).toBeHidden();
  });

  test('hardening the S-box costs the attack the key at the same effort', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const k4 = await revealK4(page);
    await expect(page.locator('#activeSboxLabel')).toHaveText('Weak (toy)');
    await expect(page.locator('#masterKeyDisplay')).toHaveText('0x5A69');

    await page.locator('#tab-sbox').click();
    await page.locator('#useStrongSbox').click();
    await openAttackTab(page);
    // Swapping the cipher must invalidate everything collected against the old one.
    await expect(page.locator('#activeSboxLabel')).toHaveText('Strong (PRESENT)');
    await expect(page.locator('#pairStatus')).toHaveText(
      '0 pairs collected. Need 500 more for reliable recovery.',
    );
    await expect(page.locator('#resultsSection')).toBeHidden();
    await expect(page.locator('#attackStatus')).toContainText('S-box swapped to "strong"');
    await expect(page.locator('#hiddenK4')).toHaveText('••'); // re-hidden after the reset

    // Best characteristic the demo can find against PRESENT, then four times the
    // 500 pairs that broke the weak S-box. Deterministic under the fixed seed.
    await reseed(page);
    await page.locator('#deriveDiff').click();
    await reseed(page);
    await page.locator('#add1000').click();
    await page.locator('#add1000').click();
    await page.locator('#runAttack').click();

    await expect(page.locator('#failureMessage')).toBeVisible();
    await expect(page.locator('#successMessage')).toBeHidden();
    expect(await page.locator('#recoveredKey').innerText()).not.toBe(k4);
    expect(Number(await page.locator('#correctKeyRank').innerText())).toBeGreaterThan(1);
    // The bias no longer separates: the winner barely leads the runner-up.
    expect(Number(await page.locator('#biasMargin').innerText())).toBeLessThanOrEqual(2);
  });
});
