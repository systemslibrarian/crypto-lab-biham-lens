# Extension brief — `crypto-lab-biham-lens` (PRESENT)

**2026-10-21. Extension to a live lab; no new repository.** Written against
`crypto-lab-biham-lens` at `70678f29a894` and `audits/_MASTER-TEMPLATE.md` (catalog
`88f75e7edc6f`). Template §5 applies: "Extend, never restructure." Save this file at the repo
root as `brief-extension-present.md`, and write your handoff to
`extension-handoff-present.md`.

Source of the gap: Paar & Pelzl, *Understanding Cryptography* (1st ed., 2010), §3.7.3. That
covers the PRESENT S-box (Table 3.14), the bit permutation (Table 3.15 and P(i) = 16i mod 63)
and the 80-bit key schedule, all checked against the book's text. It is also the draft gap
check's rank 4 (`draft/understanding-cryptography-2e`). Paul planned PRESENT as a fold-in
rather than a new lab on 2026-09-28; this brief is that fold-in.

**Verdict: extension — one new tab, "4 · PRESENT", after "3 · FEAL-4".**

## What the lab has now

Read at `70678f29a894`:

- **Six tabs** (`index.html:152–157`): 1 · Differential Trace, 2 · Live Attack, 3 · FEAL-4,
  S-box Analysis, Historical Impact, Why Serpent Survived.
  - Panels start at `index.html:162`.
  - `switchTab` is at `src/main.ts:204`, and `initFealTab()` is wired at `src/main.ts:64`.
  - **The FEAL tab is the precedent to copy**: `src/feal-tab.ts`, with its engine in
    `src/crypto/feal/` and a Worker in `feal/worker.ts`. It puts a real published cipher beside
    the toy, with its own engine module.
- **PRESENT's S-box is already the toy's "strong" option.**
  - `src/crypto/sbox.ts:22–25` holds a module-private `SBOX_STRONG` = `C 5 6 B 9 0 A D 3 E F 8 4
    7 1 2`, labelled "PRESENT cipher S-box".
  - It is reachable through the exported `setSbox('strong')` (`:46`) and `getSbox()` (`:83`),
    with a toggle on the S-box tab (`#useStrongSbox`).
  - The same table is used by **Return Path** (`src/crypto/sbox.ts:27`) and **Matsui Line**
    (`src/crypto/sbox.ts`).
  - At this commit none of the three implements the PRESENT *cipher*. The catalog records
    PRESENT for this lab as **comment-only**: catalog `index.html:5585`,
    `data-comment-only="… PRESENT@src/crypto/sbox.ts:20 …"`.
- **Tests:**
  - Unit tests run with `node --import tsx --test src/**/*.test.ts` (node:test, **not**
    Vitest) and live in `src/__tests__/`. The e2e specs are `a11y.spec.ts`, `claims.spec.ts`
    and `gate.ts`.
  - `e2e/gate.ts:123` asserts **6** tabs, and the FEAL scan states run at `gate.ts:407–420`.
  - `claims.spec.ts:742` shows that with the strong S-box the toy attack fails at 2,000 pairs.
  - **There is no `scripts/` directory and no mutation script.**
- **Non-text contrast:** `e2e/nontext-baseline.ts` is a shrink-only to-do list with five
  `button#tab-*.tab-button.active` entries at 1.05:1.
  - **`#tab-feal` is absent only because of `src/style.css:209`**, which reads
    `.tab-button[data-tab="feal"].active { background-color: transparent; }`. That removes the
    active fill, so the oracle skips the element. It is a dodge, not a fix.
  - **Do not copy it for `#tab-present`.** Instead, give `.tab-button` a ≥ 3:1 boundary. The
    lab has no `--control-border` token yet; add one that aliases `--border-strong`
    (`style.css:29`, `#71719f`), as AES Modes did.
  - Then delete the five baseline entries **and** FEAL's override, which the baseline's own
    rules require once the findings are gone.
  - If that is more than this extension can carry, **stop and ask Paul**. Never add an entry.
- **README sections:** What It Is, When to Use It, Live Demo (with `### FEAL-4 extension` at
  `README.md:24`), What Can Go Wrong, Real-World Usage, How to Run Locally, Related Demos, and
  Reduced-round ChaCha context. **There is no Build & Verify section.**

**Overlap check:** grep the sibling clones for `\bPRESENT\b` (case-sensitive). At brief time
the hits were S-box tables, their tests, UI labels and citations in biham-lens, return-path and
matsui-line, plus unrelated all-caps comments ("…IS PRESENT FIRST") in several `e2e/gate.ts`
files. No hit implemented the cipher. Report what you find, with commits.

## What to add — the PRESENT tab

**Plain-language intro.** "The 'strong' S-box you can switch on in the S-box tab was not
invented for this toy. It is the only S-box of PRESENT, a real 64-bit block cipher built for
RFID tags and other tiny chips, and standardised in ISO/IEC 29192-2. PRESENT uses that one
4-bit box sixteen times per round, a bit shuffle instead of any arithmetic, and 31 rounds. This
tab runs the real cipher and shows why one small S-box is enough."

**Six short acts, each computed live:**

1. **Same box, full size.**
   - The PRESENT S-box table, with an equality check against the toy's strong box, computed
     via `setSbox('strong')` and `getSbox()`, then restoring the previous selection.
   - The paper's conditions 1–3 (CHES 2007 §4.3), checked exhaustively:
     - (1) every DDT entry with a **non-zero** input difference is ≤ 4;
     - (2) the 16 single-bit→single-bit DDT cells are all 0;
     - (3) |S^W_b(a)| ≤ 8 for all non-zero a and b.
   - **Do not claim condition 4.** See *Open question*.
2. **The bit shuffle.**
   - Draw 64 wires from bit i to P(i), with P(i) = 16i mod 63 for i < 63 and P(63) = 63.
     Check it against the published table: Paar Table 3.15, and the uncaptioned pLayer table
     in CHES 2007 §3.
   - **Predict:** "where does bit 5 go?" The answer is 17.
   - Two exhaustive checks, which are the paper's §5.1 observations:
     - each S-box's four **input** bits come from four distinct S-boxes (Observation 1);
     - each S-box's four **output** bits enter four distinct S-boxes (Observation 3).
3. **Key schedule.** Step the 80-bit register:
   - round key Kᵢ is its leftmost 64 bits;
   - rotate left by 61;
   - apply the S-box to the leftmost nibble;
   - XOR the round counter into k₁₉…k₁₅.

   Show K1, K2 and K32 for the published keys.
4. **Encrypt.** Run the four published vectors (CHES 2007 Appendix I) with a 31-round trace:
   round key, sBoxLayer and pLayer per row, then K32 after round 31. Each round collapses, and
   rows show 16 nibbles rather than 64 bits.
5. **Why one 4-bit box is enough.**
   - Run a chosen plaintext difference through real rounds and count the **observed** active
     S-boxes per round, labelled "observed for this pair".
   - Beside it, cite the paper's **Theorem 1** without re-proving it: "any five-round
     differential characteristic of PRESENT has a minimum of 10 active S-boxes" (§5.1, proved
     in Appendix III). Connect it to the ingredients acts 1–2 checked: condition 2, and
     Observations 1 and 3.
   - Then the paper's arithmetic, computed on screen: 25 rounds give at least 50 active
     S-boxes, each at most 4/16 = 2⁻², so any 25-round characteristic has probability ≤ 2⁻¹⁰⁰.
   - The page may add, **labelled as its own remark rather than the paper's**, that 2⁻¹⁰⁰ is far
     below 1/2⁶⁴, the reciprocal of the number of possible plaintexts.
   - Contrast this with tab 2, where the same S-box on 4 rounds of an 8-bit toy already resisted
     2,000 pairs. Link to that behaviour rather than duplicating it.
6. **One round key is (almost) the whole key** — the §4.1d fixture. The framing is "Suppose a
   last-round attack like tab 2's had recovered K32."
   - **The key source is the tab's own key field** (the act-4 key). The main thread derives
     K32 and one known plaintext/ciphertext pair from it, and says in plain text that it did
     so. **The Worker receives only K32 and the pair, never the key**, just as FEAL's Worker
     receives observations only.
   - The Worker works from the fact that the register at round 32 is K32 plus 16 unknown bits.
     For each of the 2¹⁶ guesses, it unwinds 31 updates (each one is invertible: rotate, an
     S-box bijection, an XOR with the counter) and tests the candidate against the pair. It
     returns the survivors with a live counter.
   - Only after that does the main thread compare each survivor with the key field.
   - In the brief-time reference, and in the reviewer's independent one, **exactly one**
     candidate survived, and it was the key.

## SECURITY / CORRECTNESS INVARIANTS

1. **The engine is separate, as with FEAL.** `src/crypto/present/` never imports the toy SPN or
   `sbox.ts`. The engine keeps its own S-box table, and a test compares it with the toy's via
   `setSbox('strong')` / `getSbox()`.
2. **Bit numbering is explicit.** The state is b₆₃…b₀ and nibble wᵢ = b₄ᵢ₊₃…b₄ᵢ, as in the
   paper and in Paar §3.7.3. One helper converts to hex.
3. **Act 6 never attacks PRESENT and never ships the key to the Worker.** It is labelled as a
   consequence of the key schedule, given a round key.
4. **PRESENT-80 only.** The paper's Appendix I has test vectors for 80-bit keys only, and
   ISO/IEC 29192-2 is paywalled, so don't ship an unvectored key size.
5. **Act 5's observed counts are never presented as a bound**, and Theorem 1 is always the
   paper's, never the page's.
6. **Number representation:** the 80-bit register exceeds `Number`. Use BigInt for the
   displayed trace if you like, but measure the act-6 Worker loop in the built bundle on CI
   Chromium. If it exceeds about 10 s, switch the hot path to two `Uint32` halves plus a 16-bit
   word, or to byte tables. The brief author's Python reference took about 26 s with naive bit
   loops; the reviewer's byte-table version took 4–8 s.

## ARCHITECTURE

- `src/crypto/present/present.ts`: `sBoxLayer`, `pLayer`, `keySchedule80` (returns the
  register per round), `encrypt80`, `decrypt80`, `trace80`.
- `src/crypto/present/analysis.ts`: `ddt` (non-zero input differences only), `walsh`,
  `conditions123`, `pLayerSpread`.
- `src/crypto/present/unwind.ts`: `unwind(register, fromRound)`, and
  `recoverFromK32(k32, pair, onProgress)`.
- `src/crypto/present/worker.ts`, for act 6.
- `src/present-tab.ts` (`initPresentTab()`), wired right after `initFealTab()` at
  `src/main.ts:64`.
  - To stop the Worker when the learner leaves the tab, attach click/keydown listeners to the
    other `.tab-button`s **from `present-tab.ts`**.
  - Touch nothing else in `main.ts`, and don't edit `switchTab`.
- `index.html`: add a tab button with `data-tab="present"` after FEAL's, and its
  `role="tabpanel"`.
- `src/__tests__/present.test.ts`.
- `scripts/check-present-mutations.mjs`, plus `mutation-evidence-present.json`, following
  `crypto-lab-aes-modes/scripts/check-ofb-mutations.mjs` in shape. **Swap that script's Vitest
  unit command for this lab's `node --import tsx --test …`.**
- `// [extension] point` markers: in `present.ts` for PRESENT-128 (blocked on a published
  vector), and in `analysis.ts` for a characteristic search.

## UI

- An act stepper inside the tab, with the toy-to-PRESENT bridge sentence at the top.
- Act 2's wire diagram is SVG with a text alternative listing P(i), plus a "highlight one
  S-box" control.
- Act 6 has "Run the 2¹⁶ unwind", a Cancel button, and counters for candidates tried and
  survivors.
- Predict prompts on act 2 and on act 6 ("how many master keys survive one known pair?").
- Stacks below 640px. At 320px the 64-wire diagram collapses to an S-box-group view with an
  equivalent table.

## VISUAL SEMANTICS

- A match with the published vectors reads OK: icon plus "matches CHES 2007 Appendix I".
- The condition checks read OK. Condition 4 is not shown.
- **Act 6's recovery is ALARM and the §4.1d dual verdict:**
  - `data-verdict="recovered"` with an alarm class;
  - text: **`DESIGN CHECKS PASS — AND ONE ROUND KEY GIVES THE MASTER KEY`**.
- Act 5's bound arithmetic is neutral and factual, and the observed counts carry a distinct
  "observed" label.
- Never use colour alone.

## EDGE CASES

- A key that is not 20 hex characters, or a plaintext that is not 16, is refused, naming the
  length found.
- If act 6 is cancelled, the counters are marked "incomplete", as FEAL's are.
- If the learner edits K32 so it no longer matches the key field, there are zero survivors,
  reported honestly as "no master key reproduces this pair". That is not an error.
- Leaving the tab mid-run terminates the Worker (see ARCHITECTURE).
- Changing the key retires the trace, the K-rows and act 6's result, and says so. Re-entering
  the same key is a no-op.

## Open question (for Paul, not for the page)

The CHES 2007 paper's S-box **condition 4** reads: "for all a ∈ F₂⁴ and all non-zero b ∈ F₂⁴ such
that wt(a) = wt(b) = 1 it holds that S^W_b(a) = ±4".

The brief author and an independent reviewer each computed the published S-box's
single-bit Walsh coefficients exhaustively. Rows a = 1, 2, 4, 8 come out as [0,0,0,0],
[0,4,−4,4], [0,−4,−4,−4] and [0,4,0,−4], so **8 of the 16 are 0**. Bit reversal, transposition and
the inverse S-box all leave the zeros in place. **The condition as printed does not hold.**

What does hold is |S^W_b(a)| ≤ 4 for single-bit masks, which is plausibly the intended reading
and the bound the paper's linear argument needs.

So the page must not claim "= ±4". If you show anything, show the computed 4×4 table and the
check "|S^W_b(a)| ≤ 4 for single-bit a, b", labelled as **this lab's reading**, not the paper's
wording.

## Acceptance checks

**Published vectors (unit).** These are CHES 2007 Appendix I values, checked against the paper.
Decrypt each one back as well.

| Plaintext | Key | Ciphertext |
|---|---|---|
| 0000000000000000 | 00000000000000000000 | 5579C1387B228445 |
| 0000000000000000 | FFFFFFFFFFFFFFFFFFFF | E72C46C0F5945049 |
| FFFFFFFFFFFFFFFF | 00000000000000000000 | A112FFC72F68417B |
| FFFFFFFFFFFFFFFF | FFFFFFFFFFFFFFFFFFFF | 3333DCD3213210D2 |

**Brief-time cross-check values.** These are NOT published vectors. Both the brief author's
reference and the reviewer's independent one, each reproducing all four vectors above, give
these values. Label them as cross-checks in the test. They exist because the published set
uses only all-zero and all-one patterns.

| Check | Value |
|---|---|
| pt 0123456789ABCDEF, key 00112233445566778899 | 1A6D783F0C184F4D |
| pt FEDCBA9876543210, key 0123456789ABCDEF0123 | CB7D344F360DE3B1 |
| key 0: K1, K2, K32 | 0000000000000000, C000000000000000, 6DAB31744F41D700 |
| key FF…FF: K1, K2, K32 | FFFFFFFFFFFFFFFF, 2FFFFFFFFFFFFFFF, FE7A548FB60EB167 |
| key 0, pt 0: state after round 1's pLayer | FFFFFFFF00000000 |
| P(5), P(62), P(63) | 17, 47, 63 |

**Exhaustive facts (unit):**

- the max DDT entry over non-zero input differences is 4;
- all 16 single-bit→single-bit cells are 0;
- the max |S^W_b(a)| over non-zero a and b is 8;
- the engine's S-box equals the toy's strong box;
- the formula for P matches the table at all 64 positions;
- Observations 1 and 3 hold for all 16 S-boxes;
- 50 × log₂(4/16) = −100.

**Act 6 (unit):**

- Use **three fixed master keys whose round-32 register has its low 16 bits (the part the
  search guesses) ≥ 0x8000**. Choose them explicitly, not from a random seed, so a half-range
  search is guaranteed to miss all three. Brief-time candidates:

  | Key | Round-32 low 16 bits |
  |---|---|
  | 00112233445566778899 | d41a |
  | FEDCBA98765432100123 | 948e |
  | 13579BDF02468ACE1357 | b403 |

  Re-derive these with your engine before relying on them.
- For each, `recoverFromK32` tries exactly 2¹⁶ candidates and returns exactly one survivor,
  equal to the key.
- `unwind` inverts `keySchedule80` across all 32 rounds.

**Claims (`e2e/claims.spec.ts`, §4.1b).** Re-derive each one by a different route.

- Act 4: parse the printed plaintext, key and ciphertext, then recompute in `page.evaluate`
  with a **table-driven** pLayer (the published table hard-coded in the test), not the
  source's formula.
- Act 3: recompute K2 from the printed K1 register in the test.
- Act 6:
  - the "tried" counter ends at 65,536;
  - **exactly one survivor, equal to the key in the tab's key field**;
  - that key, run through the test's own key schedule, reproduces the printed K32;
  - the survivor count equals the number of drawn rows;
  - `data-verdict="recovered"` and the alarm class are both present.
- Retirement, and the no-op guard on key changes.

**§4.1c mutations.** Break the mechanism, never a flag. Each kill meets the four §4.1c rules.

1. pLayer computes `i·16 mod 64` → all four published vectors fail.
2. The key-register rotation is 19 left instead of 61 → the vectors fail.
3. The round counter is XORed at bit 16 instead of bit 15 → the vectors fail.
4. The S-box layer covers only 15 nibbles → the vectors fail.
5. `unwind` skips undoing the S-box step → act 6 finds zero survivors, so the "exactly one
   survivor, equal to the key" claim and the §4.1d test fail.
6. Act 6 tries only 2¹⁵ candidates → both the 65,536-counter claim and the unit test with the
   ≥ 0x8000 keys fail.
7. `ddt` includes the zero input difference when taking the maximum → condition 1 reports 16
   and fails, and the claims test that recomputes the non-zero-row maximum from the printed
   table fails.
8. The act-6 verdict element gets the neutral class and `data-verdict` → the class/verdict
   assertion fails.
9. Delete the act-6 negative-claim sentence → §4.1d assertion 3 fails.

**§4.1d negative claim:** *"PRESENT-80's key schedule does not keep the master key secret from
anyone who learns a round key: K32 plus a 2¹⁶ search is the whole 80-bit key. That is why a
last-round attack is a full break."*

- Optionally add: "AES-128's key schedule can be inverted from any round key with no search at
  all." Keep this clause **only** if you also add a unit test that inverts FIPS 197
  KeyExpansion from Appendix A.1's w[40..43] back to the key. Glass Box already runs an
  `invertKeySchedule` (`crypto-lab-glass-box/src/lab.worker.ts:346`), so link it.
- **Fixture:** act 6, after the run. Every check the tab renders reports success:
  - the published vectors ✓;
  - conditions 1–3 ✓;
  - Observations 1 and 3 ✓;
  - the trace decrypts back ✓.

  **And the property is violated:** the master key is recovered.
- Assert all three §4.1d points. Breaking a condition check inside the fixture must fail
  assertion 2, and deleting the sentence must fail assertion 3.

**Gate (§4.1a):** `e2e/gate.ts:123` goes from 6 tabs to 7. Add the PRESENT scans **after
`gate.ts:420`** in FEAL's shape:

- the trace state;
- act 6 running;
- act 6 complete.

Assert structure only. Also scan every new state at 320px.

**Fail-closed paths.** Give each a NAMED test:

- bad key length;
- bad plaintext length;
- a cancelled unwind;
- a mismatched K32 that yields zero survivors;
- leaving the tab mid-run;
- a key change retiring the result.

## README and card follow-up

- **What It Is:** one sentence saying the toy's strong S-box is PRESENT's and that the PRESENT
  tab runs the real cipher.
- **Live Demo:** add `### PRESENT extension`, mirroring the FEAL subsection: what runs, what is
  real, and what is only cited (Theorem 1).
- **Build & Verify:** the README has none. Add one per template §5, listing the four vectors
  with their source and the labelled cross-checks.
- **Catalog handoff (do not edit `../crypto-lab`):**
  - proposed chip `PRESENT-80`, which matches the existing `tools/catalog-vocab.js` PRESENT
    term (`chipRe` accepts `PRESENT-80`);
  - PRESENT moves from comment-only to implemented for this lab in the derived files;
  - concept-coverage placement is for the catalog pass to judge;
  - in a later pass, link Return Path's and Matsui Line's "strong S-box" labels to this tab;
  - **one citation defect seen in a sibling:** `crypto-lab-matsui-line/src/crypto/sbox.test.ts:10`
    and its `README.md:86` cite the S-box as CHES 2007 "Table 1", but the paper's Table 1 is
    "Area requirement of present". Report it; don't fix it here.

## Do not touch

The toy SPN, its attack and seed handling, the FEAL engine and Worker, the existing S-box toggle
and its claims, the Historical and Serpent tabs, and the header. **FEAL's `style.css:209`
override is the one exception**: remove it only as part of the `--control-border` fix above.

## Sources

Each was checked by the brief author and re-checked by an independent reviewer.

- A. Bogdanov, L. R. Knudsen, G. Leander, C. Paar, A. Poschmann, M. J. B. Robshaw, Y. Seurin and
  C. Vikkelsoe, "PRESENT: An Ultra-Lightweight Block Cipher", CHES 2007, LNCS 4727,
  doi:10.1007/978-3-540-74735-2_31 (author copy at iacr.org/archive/ches2007). Sections used:
  - §3: the pLayer table and the key schedule;
  - §4.3: conditions 1–4;
  - §5.1: Theorem 1 and Observations 1 and 3;
  - Appendix I: the 80-bit vectors;
  - Appendix II: the 128-bit schedule, which this extension does not build.
- The ISO/IEC 29192-2:2019 abstract (iso.org/standard/78477), which specifies PRESENT (64-bit
  block, 80- or 128-bit key), CLEFIA and LEA.
- Paar & Pelzl, *Understanding Cryptography* (1st ed., 2010), §3.7.3: Tables 3.14 and 3.15, and
  the key-schedule text. Teaching context only; reproduce no text or figures.
