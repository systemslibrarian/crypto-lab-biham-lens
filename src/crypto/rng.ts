/**
 * Seeded PRNG (xorshift32) for reproducible attack runs.
 *
 * The differential attack involves a Monte Carlo step (sampling random
 * plaintexts), and reproducibility matters for teaching: instructors need
 * to point at specific bias counts and bar heights without "well, it was
 * different on my screen" being a confound.
 */

let state = 0x12345678;

export function seed(value: number): void {
  // xorshift gets stuck at 0; nudge if so.
  state = (value | 0) || 0x12345678;
}

export function getSeed(): number {
  return state >>> 0;
}

/** Next uint32 from the stream. */
export function nextU32(): number {
  let x = state | 0;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  state = x | 0;
  return state >>> 0;
}

/** Random integer in [0, max). */
export function nextInt(max: number): number {
  return nextU32() % max;
}
