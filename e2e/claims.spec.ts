import { reference, referenceKeys, referenceDecrypt } from './present-reference';
import { expect, test, type Locator, type Page } from '@playwright/test';

test.describe('FEAL-4', () => {
  test('computed trace, 20 oracle queries, and verified equivalent-key verdict', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-feal').click();
    const traceRow = page.locator('#fealTrace tbody tr.feal-highlight');
    const computed = (await traceRow.locator('td').nth(3).innerText()).trim();
    expect(computed).toBe('02000000');
    await expect(page.locator('#fealTrace tbody tr').nth(1).locator('td').nth(3)).toHaveText('00000000');
    await expect(page.locator('#fealTraceClaim')).toContainText(`Computed round 2 f output Δ = ${computed}`);
    await expect(page.locator('#fealCipherOutput')).toContainText('D88C4EF31769F53E');
    await page.locator('#fealCollect').click();
    await expect(page.locator('#fealQueried')).toHaveText('20 chosen plaintexts queried');
    await expect(page.locator('#fealStatus')).toContainText('Every A pair computed round 2 f Δ = 02000000');
    await page.locator('#fealEvidence summary').click();
    await expect(page.locator('#fealPairs tbody tr')).toHaveCount(10);
    const aPair = await page.locator('#fealPairs tbody tr').first().locator('td').allInnerTexts();
    expect(aPair[0]).toBe('A');
    expect(BigInt(`0x${aPair[1]}`) ^ BigInt(`0x${aPair[2]}`)).toBe(0x8080000080800000n);
    const bPair = await page.locator('#fealPairs tbody tr').last().locator('td').allInnerTexts();
    expect(bPair[0]).toBe('B');
    expect(BigInt(`0x${bPair[1]}`) ^ BigInt(`0x${bPair[2]}`)).toBe(0x0000000200000002n);
    await expect(page.locator('#fealVerdict')).toBeHidden();
    await page.locator('#fealRun').click();
    await expect(page.locator('#fealFreshCount')).toContainText('64/64 fresh ciphertexts checked', { timeout: 120_000 });
    await expect(page.locator('#fealVerdictText')).toHaveText('decrypts unseen ciphertext');
    await expect(page.locator('#fealEquivalentBadge')).toHaveText('Equivalent key, not the 64-bit master key');
    await expect(page.locator('#fealFreshCount')).toContainText('20 attack queries + 64 later verification queries');
    const freshPlain = (await page.locator('#fealSamplePlaintext').innerText()).trim();
    const freshCipher = (await page.locator('#fealSampleCiphertext').innerText()).trim();
    await expect(page.locator('#fealSampleDecrypted')).toHaveText(freshPlain);
    const observed = await page.locator('#fealPairs tbody tr td:nth-child(2), #fealPairs tbody tr td:nth-child(3)').allInnerTexts();
    expect(observed).not.toContain(freshPlain);
    await page.locator('#fealPlaintext').fill(freshPlain);
    await page.locator('#fealEncrypt').click();
    await expect(page.locator('#fealCipherOutput')).toContainText(`Ciphertext: ${freshCipher}`);
    await expect(page.locator('#fealVerdictText')).toHaveText('decrypts unseen ciphertext');
    await expect(page.locator('#fealFunnel > div')).toHaveCount(4);
    const queried = await page.locator('#fealQueried').innerText();
    expect(queried).toContain('20 chosen plaintexts');
    const ops = await page.locator('#fealOps').innerText();
    const finalOps = Number(ops.match(/[\d,]+/)![0].replace(/,/g, ''));
    const roundOneOps = Number((await page.locator('#fealFunnel small').last().innerText()).match(/[\d,]+/)![0].replace(/,/g, ''));
    expect(finalOps).toBeGreaterThan(roundOneOps); // fresh verification is counted too
    const full = Number((await page.locator('#fealFunnel > div').last().innerText()).match(/([\d,]+) survivors/)![1].replace(/,/g, ''));
    const verified = Number((await page.locator('#fealFreshCount').innerText()).match(/; ([\d,]+) equivalent keys verified/)![1].replace(/,/g, ''));
    expect(verified).toBe(full);
    expect(verified).toBeGreaterThan(0);
  });

  test('invalid input and changed collection settings clear stale state', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-feal').click();
    await page.locator('#fealPlaintext').fill('not hex');
    await page.locator('#fealEncrypt').click();
    await expect(page.locator('#fealCipherStatus')).toContainText('Use exactly 16 hex digits');
    await expect(page.locator('#fealCipherOutput')).toBeEmpty();
    await page.locator('#fealPlaintext').fill('0000000000000000');
    await page.locator('#fealCollect').click();
    await expect(page.locator('#fealQueried')).toContainText('20 chosen plaintexts');
    await page.locator('#fealCountA').fill('5');
    await expect(page.locator('#fealRun')).toBeDisabled();
    await expect(page.locator('#fealQueried')).toContainText('0 chosen plaintexts');
    await expect(page.locator('#fealVerdict')).toBeHidden();
    await expect(page.locator('#fealEvidence')).toBeHidden();
    await page.locator('#fealCollect').click();
    await expect(page.locator('#fealQueried')).toContainText('18 chosen plaintexts');
    await page.locator('#fealKey').fill('bad');
    await expect(page.locator('#fealRun')).toBeDisabled();
    await expect(page.locator('#fealFunnel')).toBeEmpty();
  });

  test('cancel clears progress and marks retained counters incomplete', async ({ page }) => {
    await page.goto('.');
    await page.locator('#tab-feal').click();
    await page.locator('#fealCollect').click();
    await page.locator('#fealRun').click();
    await page.locator('#fealCancel').click();
    await expect(page.locator('#fealStatus')).toContainText('Attack cancelled');
    await expect(page.locator('#fealFunnel')).toBeEmpty();
    await expect(page.locator('#fealVerdict')).toBeHidden();
    await expect(page.locator('#fealOps')).toContainText('incomplete');
  });

  test('a wrong fresh ciphertext rejects the recovered candidates', async ({ page }) => {
    await page.addInitScript(() => {
      const original = Worker.prototype.postMessage;
      Worker.prototype.postMessage = function (message: unknown, transfer?: Transferable[]) {
        const payload = message as { type?: string; ciphertexts?: bigint[] };
        if (payload.type === 'verify-response' && payload.ciphertexts?.length) {
          message = { ...payload, ciphertexts: payload.ciphertexts.map((c, i) => i === 0 ? c ^ 1n : c) };
        }
        return original.call(this, message, transfer ?? []);
      };
    });
    await page.goto('.');
    await page.locator('#tab-feal').click();
    await page.locator('#fealCollect').click();
    await page.locator('#fealRun').click();
    await expect(page.locator('#fealVerdictText')).toHaveText('rejected: wrong on fresh ciphertext', { timeout: 120_000 });
    await expect(page.locator('#fealFreshCount')).toContainText('0 equivalent keys verified');
    await expect(page.locator('#fealEquivalentBadge')).toHaveText('Equivalent key, not the 64-bit master key');
    await expect(page.locator('#fealFreshSample')).toBeHidden();
    await expect(page.locator('#fealRecovered')).toBeEmpty();
  });
});

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
  await expect(page.locator('#characteristicStatus')).toContainText('Attacker view: public S-box and permutation only');
}

async function openAttackTab(page: Page): Promise<void> {
  await page.locator('#tab-attack').click();
  await expect(page.locator('#attack')).toHaveClass(/active/);
  await page.locator('#differentialMode').selectOption('instructor');
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
    await expect(page.locator('#pairStatus')).toContainText('500 sampled pairs;');
    await page.locator('#runAttack').click();

    await expect(page.locator('#resultsSection')).toBeVisible();
    await expect(page.locator('#successMessage')).toBeVisible();
    await expect(page.locator('#failureMessage')).toBeHidden();
    await expect(page.locator('#successMessage')).toContainText('Top candidate matches instructor key');

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
      const pairs = num(await page.locator('#pairStatus').innerText(), /^(\d+) sampled pairs/);
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

  test('the pair counter separates repeated samples from distinct data', async ({ page }) => {
    await boot(page);
    await openAttackTab(page);
    const status = page.locator('#pairStatus');
    await expect(status).toContainText('0 sampled pairs;');
    await page.locator('#add100').click();
    await expect(status).toContainText('100 sampled pairs;');
    await page.locator('#add1000').click();
    await expect(status).toContainText('1100 sampled pairs;');
    await page.locator('#clearPairs').click();
    await expect(status).toContainText('0 sampled pairs;');
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

  test('exact instructor differential sums contributing trails and labels assistance', async ({ page }) => {
    await boot(page); await openAttackTab(page);
    const status = await page.locator('#characteristicStatus').innerText();
    expect(status).toContain('Instructor-assisted');
    expect(status).toContain('all 256 inputs (128 unordered pairs)');
    const endpoint = num(status, /Endpoint count (\d+)\/256/);
    const trail = num(status, /has count (\d+)\/256/);
    expect(trail).toBeLessThanOrEqual(endpoint);
    const peak = status.match(/Target Δ = 0x([0-9A-F]{2})/)![1];
    await expect(page.locator('#outDiff')).toHaveValue(peak);
    await expect(page.locator('#outDiff')).toHaveAttribute('title', /sums all intermediate trails/);
    await page.locator('#differentialMode').selectOption('public');
    await expect(page.locator('#characteristicStatus')).toContainText('not the exact probability for the victim key');
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
    await expect(page.locator('#pairStatus')).toContainText(
      '0 sampled pairs;',
    );
    await expect(page.locator('#resultsSection')).toBeHidden();
  });

  test('S-box changes retire evidence and report the observed rank without a universal recovery claim', async ({ page }) => {
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
    await expect(page.locator('#pairStatus')).toContainText(
      '0 sampled pairs;',
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

    const rank = Number(await page.locator('#correctKeyRank').innerText());
    expect(rank).toBeGreaterThanOrEqual(1); expect(rank).toBeLessThanOrEqual(256);
    const matches = (await page.locator('#recoveredKey').innerText()) === k4;
    await expect(page.locator(matches ? '#successMessage' : '#failureMessage')).toBeVisible();
    await expect(page.locator('#pairStatus')).toContainText('distinct unordered pairs');
  });
});

// FIPS 46-3 Appendix 1, S1-S8. This oracle enumerates the published
// lookup tables directly, independently of the lab's toy SPN and its prose.
const desRows = [
  [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
  [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
  [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
  [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
  [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
  [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
  [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
  [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
];

test('DES comparison uses the independently enumerated nontrivial DDT maximum', async ({ page }) => {
  let maximum = 0;
  for (const box of desRows) {
    expect(box).toHaveLength(64);
    const value = (x: number) => box[(((x >> 5) << 1) | (x & 1)) * 16 + ((x >> 1) & 15)];
    for (let difference = 1; difference < 64; difference++) {
      const counts = Array<number>(16).fill(0);
      for (let x = 0; x < 64; x++) counts[value(x) ^ value(x ^ difference)]++;
      expect(counts.reduce((a, b) => a + b, 0)).toBe(64);
      maximum = Math.max(maximum, ...counts);
    }
  }
  await page.goto('.');
  await page.locator('#tab-serpent').click();
  const cells = page.locator('#serpent .comparison-table tbody tr').first().locator('td');
  await expect(cells.nth(1)).toHaveText(`${maximum} / ${desRows[0].length}`);
});

test.describe('PRESENT', () => {
  test.setTimeout(180_000);
  async function open(page: Page, act = 1) {
    await page.goto('.');
    await page.locator('#tab-present').click();
    await page.locator(`.present-step[data-act="${act}"]`).click();
  }
  async function recover(page: Page) {
    await page.locator('#present-run').click();
    await expect(page.locator('#present-recovery')).toHaveAttribute('data-verdict', 'recovered', {
      timeout: 120_000,
    });
  }
  test('PRESENT rendered trace matches independent published permutation reference', async ({
    page,
  }) => {
    await open(page, 4);
    for (const [p, k] of [
      ['0123456789ABCDEF', '00112233445566778899'],
      ['FEDCBA9876543210', '13579BDF02468ACE1357'],
    ]) {
      await page.locator('#present-key').fill(k);
      await page.locator('#present-plaintext').fill(p);
      await page.locator('#present-compute').click();
      const expected = reference(BigInt('0x' + p), BigInt('0x' + k))
        .toString(16)
        .toUpperCase()
        .padStart(16, '0');
      await expect(page.locator('#present-cipher')).toContainText(`ciphertext ${expected}`);
      await expect(page.locator('#present-trace details')).toHaveCount(31);
    }
    await page.locator('#present-zero').click();
    await expect(page.locator('#present-cipher')).toContainText('5579C1387B228445');
    await page.locator('#present-trace details').last().locator('summary').click();
    await expect(page.locator('#present-trace details').last()).toContainText(
      'After bit permutation',
    );
  });
  for (const [field, n] of [
    ['key', 20],
    ['plaintext', 16],
  ] as const)
    test(`PRESENT bad ${field} length fails closed`, async ({ page }) => {
      await open(page, 4);
      await page.locator('#present-' + field).fill('F');
      await page.locator('#present-compute').click();
      await expect(page.locator('#present-notice')).toContainText(`exactly ${n}`);
      await expect(page.locator('#present-trace')).toBeEmpty();
    });
  test('PRESENT printed keys and DDT recompute independently', async ({ page }) => {
    await open(page, 3);
    const key = await page.locator('#present-key').inputValue(),
      expected = referenceKeys(key);
    const printed = await page
      .locator('#present-keys tbody tr')
      .evaluateAll((rows) => rows.map((r) => r.querySelectorAll('td')[2].textContent));
    expect(printed).toEqual(expected);
    await page.locator('#present-key-next').click();
    await expect(page.locator('#present-key-step')).toContainText(`K2 ${expected[1]}`);
    await page.locator('.present-step[data-act="1"]').click();
    await page.locator('#present-act1 summary').click();
    const table = await page
      .locator('#present-ddt tbody tr')
      .evaluateAll((rows) =>
        rows.map((r) => Array.from(r.querySelectorAll('td'), (n) => Number(n.textContent))),
      );
    expect(Math.max(...table.slice(1).flat())).toBe(4);
    await expect(page.locator('#present-conditions [data-verdict="pass"]')).toHaveCount(7);
    await page.locator('.present-step[data-act="6"]').click();
    await expect(page.locator('#present-k32')).toHaveValue(expected[31]);
  });
  test('PRESENT negative claim retains passing checks and alarm despite full recovery', async ({
    page,
  }) => {
    await open(page, 6);
    const key = await page.locator('#present-key').inputValue();
    await expect(page.locator('#present-fixture-checks [data-check]')).toHaveCount(8);
    await expect(page.locator('#present-fixture-checks [data-verdict="pass"]')).toHaveCount(8);
    await recover(page);
    await expect(page.locator('#present-fixture-checks [data-verdict="pass"]')).toHaveCount(8, {
      timeout: 120_000,
    });
    await expect(page.locator('#present-recovery')).toHaveClass('present-alarm');
    await expect(page.locator('#present-recovery')).toContainText(
      'DESIGN CHECKS PASS — AND ONE ROUND KEY GIVES THE MASTER KEY',
    );
    await expect(page.locator('#present-recovery')).toContainText(
      "PRESENT-80's key schedule does not keep the master key secret from anyone who learns a round key: K32 plus a 2¹⁶ search is the whole 80-bit key. That is why a last-round attack is a full break.",
    );
    await expect(page.locator('#present-progress')).toContainText(
      '65536 candidates tried; 1 survivors',
      { timeout: 120_000 },
    );
    await expect(page.locator('.present-survivor')).toHaveCount(1);
    await expect(page.locator('.present-survivor')).toHaveAttribute('data-key', key.toUpperCase());
    await expect(page.locator('#present-k32')).toHaveValue(referenceKeys(key)[31]);
    const progress = await page.locator('#present-progress').innerText();
    const elapsed = Number(progress.match(/Worker ([\d.]+) s/)![1]);
    test.info().annotations.push({ type: 'worker-seconds', description: String(elapsed) });
  });

  test('PRESENT cancelled unwind marks counters incomplete', async ({ page }) => {
    await open(page, 6);
    await page.locator('#present-run').click();
    await expect(page.locator('#present-progress')).toContainText('running', { timeout: 120_000 });
    await page.locator('#present-cancel').click();
    await expect(page.locator('#present-progress')).toContainText('incomplete', {
      timeout: 120_000,
    });
    await expect(page.locator('.present-survivor')).toHaveCount(0);
    await expect(page.locator('#present-recovery')).not.toHaveAttribute('data-verdict');
    const progress = await page.locator('#present-progress').innerText();
    await page.waitForTimeout(5_000);
    await expect(page.locator('#present-progress')).toHaveText(progress);
    await expect(page.locator('.present-survivor')).toHaveCount(0);
    await expect(page.locator('#present-recovery')).not.toHaveAttribute('data-verdict');
  });

  test('PRESENT mismatched K32 yields zero survivors', async ({ page }) => {
    await open(page, 6);
    await page.locator('#present-zero').click();
    await page.locator('#present-k32').fill('0000000000000000');
    await page.locator('#present-run').click();
    await expect(page.locator('#present-recovery')).toHaveAttribute('data-verdict', 'none', {
      timeout: 120_000,
    });
    await expect(page.locator('#present-recovery')).toHaveClass('present-info');
    await expect(page.locator('#present-recovery')).toContainText(
      'no master key reproduces this pair',
    );
    await expect(page.locator('#present-progress')).toContainText(
      '65536 candidates tried; 0 survivors',
      { timeout: 120_000 },
    );
    await expect(page.locator('.present-survivor')).toHaveCount(0);
  });

  test('PRESENT leaving the tab mid-run terminates the Worker', async ({ page }) => {
    await open(page, 6);
    await page.locator('#present-run').click();
    await expect(page.locator('#present-progress')).toContainText('running', { timeout: 120_000 });
    await page.locator('#tab-feal').click();
    await page.locator('#tab-present').click();
    await expect(page.locator('#present-progress')).toContainText('Left PRESENT', {
      timeout: 120_000,
    });
    await expect(page.locator('#present-progress')).toContainText('incomplete', {
      timeout: 120_000,
    });
    const progress = await page.locator('#present-progress').innerText();
    await page.waitForTimeout(5_000);
    await expect(page.locator('#present-progress')).toHaveText(progress);
    await expect(page.locator('.present-survivor')).toHaveCount(0);
    await expect(page.locator('#present-recovery')).not.toHaveAttribute('data-verdict');
  });

  test('PRESENT key change retires a completed recovery', async ({ page }) => {
    await open(page, 6);
    await recover(page);
    const key = await page.locator('#present-key').inputValue();
    const other = (BigInt('0x' + key) ^ 1n).toString(16).padStart(20, '0');
    await page.locator('#present-key').fill(other);
    await expect(page.locator('#present-recovery')).not.toHaveAttribute('data-verdict');
    await expect(page.locator('#present-recovery')).not.toHaveClass(/present-alarm/);
    await expect(page.locator('.present-survivor')).toHaveCount(0);
    await expect(page.locator('#present-k32')).toBeEmpty();
    await expect(page.locator('#present-pair')).toBeEmpty();
    await expect(page.locator('#present-notice')).toContainText('retired');
  });

  test('PRESENT re-entering the same key is a no-op', async ({ page }) => {
    await open(page, 6);
    await recover(page);
    const verdict = await page.locator('#present-recovery').innerText();
    const survivor = await page.locator('.present-survivor').innerText();
    const key = await page.locator('.present-survivor').getAttribute('data-key');
    const pair = await page.locator('#present-pair').innerText();
    await page.locator('#present-key').dispatchEvent('input');
    await expect(page.locator('#present-recovery')).toHaveAttribute('data-verdict', 'recovered', {
      timeout: 120_000,
    });
    await expect(page.locator('#present-recovery')).toHaveText(verdict);
    await expect(page.locator('.present-survivor')).toHaveCount(1);
    await expect(page.locator('.present-survivor')).toHaveText(survivor);
    await expect(page.locator('.present-survivor')).toHaveAttribute('data-key', key!);
    await expect(page.locator('#present-pair')).toHaveText(pair);
  });

  test('PRESENT bad K32 length fails closed', async ({ page }) => {
    await open(page, 6);
    await page.locator('#present-k32').fill('0');
    await page.locator('#present-run').click();
    await expect(page.locator('#present-notice')).toContainText('exactly 16', { timeout: 120_000 });
    await expect(page.locator('.present-survivor')).toHaveCount(0);
    await expect(page.locator('#present-recovery')).not.toHaveAttribute('data-verdict');
  });

  test('PRESENT invariant 3 Worker receives only K32 and the known pair', async ({ page }) => {
    await page.addInitScript(() => {
      const messages: unknown[] = [];
      (window as unknown as { presentMessages: unknown[] }).presentMessages = messages;
      const original = Worker.prototype.postMessage;
      Worker.prototype.postMessage = function (message: unknown, transfer?: Transferable[]) {
        messages.push(structuredClone(message));
        return original.call(this, message, transfer ?? []);
      };
    });
    await open(page, 6);
    const key = await page.locator('#present-key').inputValue();
    await recover(page);
    const messages = await page.evaluate((masterKey) => {
      const posted = (window as unknown as { presentMessages: Record<string, unknown>[] })
        .presentMessages;
      const hasMasterKey = (value: unknown): boolean => {
        if (typeof value === 'bigint') return value === BigInt('0x' + masterKey);
        if (typeof value === 'string') return value.toUpperCase() === masterKey.toUpperCase();
        return (
          value !== null && typeof value === 'object' && Object.values(value).some(hasMasterKey)
        );
      };
      return posted.map((message) => ({
        keys: Object.keys(message),
        pairKeys: Object.keys(message.pair as object),
        hasMasterKey: hasMasterKey(message),
      }));
    }, key);
    expect(messages).toHaveLength(1);
    for (const message of messages) {
      expect(message.keys).toEqual(['k32', 'pair']);
      expect(message.pairKeys).toEqual(['plaintext', 'ciphertext']);
      expect(message.hasMasterKey).toBe(false);
    }
  });

  test('PRESENT highlighted wires map S-box 1 with bit 63 on the left', async ({ page }) => {
    await open(page, 2);
    await page.locator('#present-box').fill('1');
    const svg = page.locator('#present-wires svg');
    await expect(svg).toHaveAttribute('aria-label', /bit 63 on the left and bit 0 on the right/);
    await expect(svg).toContainText('input bit (before pLayer)');
    await expect(svg).toContainText('output bit (after pLayer)');
    expect(await svg.locator('text').allTextContents()).toEqual([
      'input bit (before pLayer)',
      'output bit (after pLayer)',
      '63',
      '0',
      '63',
      '0',
    ]);
    const lines = await svg.locator('line[stroke-width="3"]').evaluateAll((nodes) =>
      nodes.map((node) => ({
        x1: Number(node.getAttribute('x1')),
        x2: Number(node.getAttribute('x2')),
        y1: Number(node.getAttribute('y1')),
        y2: Number(node.getAttribute('y2')),
      })),
    );
    expect(lines).toHaveLength(4);
    expect(lines.map((line) => [63 - (line.x1 - 10) / 10, 63 - (line.x2 - 10) / 10])).toEqual([
      [4, 1],
      [5, 17],
      [6, 33],
      [7, 49],
    ]);
    for (const line of lines) expect(line.y1).toBeLessThan(line.y2);
  });

  test('PRESENT all four printed Appendix I vectors recompute independently', async ({ page }) => {
    await open(page, 4);
    const rows = page.locator('#present-vectors .present-vector');
    await expect(rows).toHaveCount(4);
    const inputs: string[][] = [];
    for (const row of await rows.all()) {
      const text = await row.innerText();
      const parsed = text.match(
        /^Plaintext ([0-9A-F]{16}); key ([0-9A-F]{20}); computed ciphertext ([0-9A-F]{16}); decrypt-back ([0-9A-F]{16});/,
      );
      expect(parsed).not.toBeNull();
      const [, plaintext, key, ciphertext, decrypted] = parsed!;
      inputs.push([plaintext, key]);
      const expected = reference(BigInt('0x' + plaintext), BigInt('0x' + key));
      expect(BigInt('0x' + ciphertext)).toBe(expected);
      expect(decrypted).toBe(plaintext);
      expect(BigInt('0x' + decrypted)).toBe(referenceDecrypt(BigInt('0x' + ciphertext), key));
      expect(reference(BigInt('0x' + decrypted), BigInt('0x' + key))).toBe(
        BigInt('0x' + ciphertext),
      );
      await expect(row).toHaveAttribute('data-verdict', 'pass');
      await expect(row).toContainText('✓ matches CHES 2007 Appendix I');
    }
    expect(inputs).toEqual([
      ['0'.repeat(16), '0'.repeat(20)],
      ['0'.repeat(16), 'F'.repeat(20)],
      ['F'.repeat(16), '0'.repeat(20)],
      ['F'.repeat(16), 'F'.repeat(20)],
    ]);
  });
});
