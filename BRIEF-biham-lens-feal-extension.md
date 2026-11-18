# Extension brief — `crypto-lab-biham-lens`: FEAL-4 (differential attack on a published cipher)

**2026-10-06. Brief only; the repository exists, this panel does not.** Written against
`audits/_MASTER-TEMPLATE.md` — §0 principles through §6 deploy apply unchanged.
Source of the gap: CrypTool 2 component FEAL (`CrypPlugins/FEAL/`) — the idea only.

**Verdict: extension of Biham Lens, but a separate engine inside it.** The lesson is the step
from a cipher built to be broken (the 8-bit toy SPN) to one that was proposed for real use and
broken with the same idea. Biham Lens owns the vocabulary that step needs (difference, XOR-key
stage leaves Δ unchanged, characteristic, last-round peel). Nothing in its crypto code can be
reused for FEAL, though — see "Engine decision". A grep of the cloned repo (`demos/biham-lens/`
`src`, `e2e`, `index.html`, `README.md`) and of the hub's `CATALOG.md`, `README.md` and
`concept-coverage.md` for `FEAL` returned nothing; the builder should re-check before shipping.

```
EXTENSION BRIEF
- Repo:        crypto-lab-biham-lens (existing; app lives in demos/biham-lens/)
- Panel name:  "3 · FEAL-4" (new tab after "2 · Live Attack"; proposed id `feal`)
- One-liner:   Runs the same chosen-plaintext differential idea against FEAL-4, a published
               1987 cipher: a difference that survives two rounds with probability 1 lets
               20 chosen plaintexts peel four rounds and decrypt fresh ciphertexts.
- Concept:     The toy SPN was not a strawman. A real Feistel cipher whose round function
               turns one input difference into one output difference every time falls to
               the same peel-the-last-round logic, with a handful of chosen plaintexts.
- In scope:    FEAL-4 encryption with its published key schedule; round-by-round difference
               trace for a chosen pair; the classroom round-peeling differential attack
               (rounds 4, 3, 2, then 1 by consistency) in a Web Worker; candidate funnel and
               F-evaluation counter; verification on fresh ciphertexts; master-key note
- Non-goals:   inverting the key schedule to the 64-bit master key (Murphy 1990 does that —
               cited, not built); FEAL-8/FEAL-N/FEAL-NX; Biham–Shamir's paper-exact attack;
               linear / known-plaintext attacks on FEAL (Matsui–Yamagishi — link out);
               any generic multi-cipher attack framework
- Level:       Advanced
```

## Why this panel exists

- **What the learner gains.** The toy SPN's attack ranks 256 guesses by a statistical bias.
  FEAL-4's round function `f` maps input difference `0x80800000` to output difference
  `0x02000000` for every input (I checked 200 000 random inputs against a FEAL `f` prototype:
  zero failures). A probability-1 differential turns counting into filtering: each wrong key
  guess is eliminated outright, so a few pairs suffice.
- **What existing source already covers** (read in full: every file under `src/crypto/`,
  `src/main.ts`, both `src/__tests__/` files, `e2e/claims.spec.ts`):
  - `src/crypto/spn.ts:encrypt` / `encryptRounds` / `traceEncryption` — 8-bit block, 16-bit
    master key, `generateKey` rotates out five 8-bit subkeys; the trace types
    (`TraceStageKind = 'input'|'xor-key'|'sbox'|'permute'`) are SPN-specific.
  - `src/crypto/attack.ts:attackLastRound` — loops `candidateKey < 256`, calls
    `invertBothNibbles` from `./sbox.js`, uses a `pairs.length / 256` noise floor, and returns
    bias counts. `collectPairs` draws plaintexts with `nextInt(256)` and calls `spn.ts:encrypt`.
    `performAttack` reads `key.subkeys[4]`. `deriveCharacteristic` calls `encryptRounds(…, 3)`.
  - `src/crypto/characteristic.ts` imports `getSbox`, `applyBothNibbles`, `permute` directly.
  - `src/crypto/sbox.ts:setSbox` mutates module-global `SBOX`/`SBOX_INV` read by all of the above.
  - `src/crypto/rng.ts:seed` / `nextU32` — a module-global xorshift32 stream.
  - `src/main.ts` (1156 lines) holds all tab wiring (`setupEventListeners`, `switchTab`), the
    verdict rendering (`showAttackResults`) and the op counter (`updateOpCounter`).
- **The experiment.** Collect 20 chosen plaintexts (two structured sets), run the peel, and
  decrypt ciphertexts of plaintexts the attack never saw. Then show the survivors per round
  shrink from 2³² to a handful, and the F-evaluation count that bought it.
- **What it establishes / does not.** It establishes that four-round FEAL with this round
  function is broken with 20 chosen plaintexts and seconds of computation (measured, below).
  It does **not** recover the 64-bit master key, does not reproduce Murphy's or Biham–Shamir's
  exact procedures, and says nothing about FEAL-8 or later FEAL-NX at the data counts shown.

## Engine decision (state this in the PR description)

**Keep the engines separate.** `attack.ts` is not a generic engine: it imports the SPN's
`encrypt`, `encryptRounds`, `invertBothNibbles` and `SPNKey`, and its shape (enumerate 256
candidates, count a bias, compare to a /256 noise floor) does not fit FEAL's attack (a 2³²
subkey space searched as 2¹⁶ inner bytes then 2¹⁶ outer bytes, filtered by exact equality,
over four dependent rounds). A shared `Cipher`/`Attack` interface would need SPN-ish methods
FEAL lacks or FEAL-ish ones the SPN lacks, plus de-globalising `sbox.ts:setSbox`. That refactor
touches every existing claims test for no learner-visible gain.
- **New files:** `src/crypto/feal/feal.ts` (`fealF`, `fealFk`, `keySchedule`, `encrypt4`,
  `decrypt4`, `traceFeal4`), `src/crypto/feal/attack.ts` (`collectStructures`,
  `recoverRoundKey`, `peelRound`, `solveRound1`, `verifyEquivalentKey`),
  `src/crypto/feal/worker.ts`, `src/feal-tab.ts` (render + wiring), `src/__tests__/feal.test.ts`.
- **Shared:** nothing from `src/crypto/`. The worker seeds its own xorshift copy, so a FEAL
  run never advances `rng.ts`'s stream. `main.ts` gains one tab button, `switchTab` case, init call.
- **Cost:** about 4 new modules plus a tab; duplicated (not shared) verdict/counter UI. Accept it.

## Scope — inside the new tab

1. **The cipher.** Learner enters a 64-bit key (hex, default fixed) and plaintext; the page
   runs `feal.ts:encrypt4` with the published key schedule (12 × 16-bit subkeys from
   `keySchedule`) and shows ciphertext and decrypt round-trip. One line names the step from
   the SPN: 64-bit block, Feistel structure, `f` built from addition mod 256 and rotation.
2. **Difference trace.** For a pair with Δ = `8080000080800000`, `traceFeal4` shows per-round
   (L, R) differences; the round-1 and round-2 `f` output Δ is computed, not asserted, and
   the page highlights that it equals `02000000` for this pair and for every pair collected.
3. **The attack (Worker).** "Collect" makes set A: N_A pairs with Δ = `8080000080800000`;
   set B: N_B pairs with Δ = `0000000200000002`. "Run" peels round 4 (from set A), round 3
   (set A), round 2 (set B), then solves round 1 plus the two whitening combinations from 8
   collected plaintext/ciphertext values. A funnel shows survivors per stage; a counter shows
   F evaluations and chosen plaintexts actually queried. Cancel button; progress messages.
4. **Verification and honesty card.** Each surviving candidate decrypts 64 fresh ciphertexts
   (plaintexts generated after the attack ends). The verdict reads "decrypts unseen
   ciphertext" only if all 64 match. The card says: *this recovers an equivalent key
   (round-key material + whitening combinations), not the 64-bit master key; it attacks the
   rounds as if the subkeys were independent and never uses the key schedule. Murphy (1990)
   goes further and recovers the master key.* It reports how many equivalent keys verified.

## Acceptance criteria (testable)

Measured with a C port of the attack against FEAL-4 with the published key schedule
(`scratchpad/feal/c/f4.c`, random keys, seeds 1/3/5/7):
- **Data:** 20 chosen plaintexts (N_A = 6 pairs, N_B = 4 pairs). Chosen, not known.
- **Success:** every surviving full candidate is checked; ≥ 1 candidate decrypts 64 fresh
  ciphertexts correctly. Observed 4/4 runs; 256 verified equivalent keys each time.
- **Work:** 2.3 × 10⁸ to 1.6 × 10⁹ F evaluations per run (≤ 6 s in C). The browser build must
  report its own count; budget a Worker and a seed-pinned e2e run, not a main-thread loop.
- **Below 20:** with 12 chosen plaintexts (4 + 2 pairs) runs took 6 × 10⁹–2.2 × 10¹⁰ F evals
  and one of five exceeded 200 s; expose N_A/N_B but warn when below 6/4.
- **Recovered material:** round-4/3/2/1 32-bit `f`-key vectors plus two 32-bit whitening
  combinations — enough to decrypt. **Not** the master key. The UI must say so (panel 4).

## Security / correctness invariants
1. No verdict without verification: "key recovered" renders only after the 64-ciphertext check.
2. The key is per-session, in memory. The attack never reads it: `feal/attack.ts` takes an
   `encryptOracle(p) => c` function, not a key (enforce by module boundary and a unit test).
3. A cancelled or failed run clears the funnel and verdict; stale results never stay rendered.
4. Changing the key or N_A/N_B discards collected pairs (mirror the existing SPN-tab rule).

## Keeping it real
Hand-rolled TypeScript (the cipher is ~60 lines). No library needed. KATs:
- FEAL-8 and FEAL-4, key `0123456789ABCDEF`, P = 0: a port of CrypTool 2's FEAL gives
  `CEEF2C86F2490752` (FEAL-8) and `D88C4EF31769F53E` (FEAL-4). The FEAL-8 value should match the
  designers' published vector [unverified — check against Miyaguchi's FEAL-8 specification]; the
  FEAL-4 value is cross-implementation only — label it so in the test.
- Multi-block KAT rule: no primary multi-block FEAL vector found. Add a 4-block ECB vector
  cross-checked against an independent implementation (CrypTool 2) and label it as such.
- `f` property test: `fealF(x) ^ fealF(x ^ 0x80800000) === 0x02000000` for 10 000 seeded x.

## Visual semantics
Funnel neutral while running; verified = ok colour + "decrypts unseen ciphertext"; failed
verification = alarm colour + "rejected: wrong on fresh ciphertext". The "equivalent key, not
master key" badge is text, never colour alone.

## Edge cases
Non-hex or wrong-length key/plaintext → refuse, no encryption. N_A < 2 or N_B < 1 → refuse to
run. Zero survivors at any stage → "attack failed at round r" with the stage named, never a key.
Worker error or cancel → idle state, counters retained but marked "incomplete".

## Tests
- **Unit** (`src/__tests__/feal.test.ts`): KATs; round-trip; `f` property; seeded 6+4-pair
  attack verifies 64/64; `feal/attack.ts` never imports `keySchedule` or a key. Note: this repo runs `node --import tsx --test`, not Vitest
  (`package.json:scripts.test`); follow the repo or migrate in a separate PR — do not mix.
- **e2e/claims.spec.ts** (new `describe('FEAL-4')`): trace's round-1 Δ equals `02000000` as the
  page computes it; the chosen-plaintext counter equals 2·(N_A+N_B); verdict appears only after
  the 64/64 line; the master-key badge is present whenever a verdict is.
- **§4.1c mutations:** flip one bit of the `0x80800000` constant → verdict must not render;
  skip verification → test fails; drop the master-key badge → test fails; report counter as
  N_A+N_B → test fails.
- **§4.1d wrong belief:** "the attack found FEAL's key." Refuting test: the page's recovered
  output is not the 64-bit master key, and the badge saying so is present and asserted.

## Extension seams
`// [extension] point` in `feal.ts:encrypt4` (N rounds, e.g. FEAL-8) and in
`attack.ts:solveRound1` (key-schedule inversion to the master key, Murphy-style).

## Links out (confirmed in CATALOG.md)
- **Matsui Line** — linear cryptanalysis (Algorithm 2) on a toy SPN. It does not implement
  FEAL; link it for the known-plaintext counterpart and name Matsui–Yamagishi 1992 as the
  known-plaintext attack on FEAL-4.
- **Feistel Forge** — real DES round by round (FEAL's Feistel shape); **Return Path** — impossible
  differentials and boomerangs on the same toy SPN.

## Citations
- A. Shimizu, S. Miyaguchi, "Fast Data Encipherment Algorithm FEAL," EUROCRYPT '87, Springer
  1988, pp. 267–280 (per Wikipedia's reference list) [LNCS volume 304: unverified — check].
- S. Murphy, "The Cryptanalysis of FEAL-4 with 20 Chosen Plaintexts," J. Cryptology 2(3):
  145–154, 1990, DOI 10.1007/BF00190801. Content verified from the author PDF (Royal Holloway
  repository): "at most twenty chosen plaintexts", recovers the key K via the key schedule,
  "up to ten hours" on a Sun 3. Volume/pages from Wikipedia's reference list [check].
- E. Biham, A. Shamir, "Differential Cryptanalysis of Feal and N-Hash," EUROCRYPT '91,
  LNCS 547, pp. 1–16, DOI 10.1007/3-540-46416-6_1 (verified on Springer). Its FEAL-4
  chosen-plaintext count and work factor: [unverified — check].
- M. Matsui, A. Yamagishi, "A New Method for Known Plaintext Attack of FEAL Cipher,"
  EUROCRYPT '92, pp. 81–91, DOI 10.1007/3-540-47555-9_7 (verified via Crossref).
- Classroom variant: B. Minaud, ENS "Introduction à la cryptologie" 2018–19, TD 5 and its
  correction (di.ens.fr/~bminaud/cours/2018/) — FEAL-4 with independent subkeys, Δ
  (80800000, 00000000) → (80800000, 02000000) after two rounds, 8 chosen plaintexts, 2³⁵ F
  evaluations. The brief's attack follows this structure but runs on the real key schedule.
