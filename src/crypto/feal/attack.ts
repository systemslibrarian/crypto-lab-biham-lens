import { fealF, join, split } from './feal.js';

export interface Observation { plaintext: bigint; ciphertext: bigint }
export interface ChosenPair { first: Observation; second: Observation }
export interface Structures { a: ChosenPair[]; b: ChosenPair[]; queried: number }
export interface EquivalentKey { rounds: [number, number, number, number]; whiteningLeft: number; whiteningRight: number }
export interface FunnelStage { round: number; survivors: number; fEvaluations: number }
export interface AttackReport { stages: FunnelStage[]; candidates: EquivalentKey[]; fEvaluations: number; queried: number }
export type EncryptOracle = (plaintext: bigint) => bigint;
export const DIFFERENCE_A = 0x8080000080800000n;
export const DIFFERENCE_B = 0x0000000200000002n;
export const DELTA = 0x80800000;
export const GAMMA = 0x02000000;

export function seededWords(seed: number): () => number {
  // Xorshift's all-zero state is absorbing. Map only that seed to a distinct,
  // documented nonzero state; 00000000 must not silently reuse the default.
  let state = seed >>> 0 || 0x6d2b79f5;
  return () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return state >>> 0;
  };
}

/** Only oracle access crosses this boundary; no master key or schedule is imported. */
export function collectStructures(oracle: EncryptOracle, countA = 6, countB = 4, seed = 0x12345678): Structures {
  if (!Number.isInteger(countA) || !Number.isInteger(countB) || countA < 2 || countB < 1) throw new Error('Need at least 2 A pairs and 1 B pair.');
  const next = seededWords(seed);
  const collect = (count: number, difference: bigint): ChosenPair[] => Array.from({ length: count }, () => {
    const p = join(next(), next());
    const q = p ^ difference;
    return { first: { plaintext: p, ciphertext: oracle(p) }, second: { plaintext: q, ciphertext: oracle(q) } };
  });
  return { a: collect(countA, DIFFERENCE_A), b: collect(countB, DIFFERENCE_B), queried: 2 * (countA + countB) };
}

export interface FeistelState { left: number; right: number; plaintext: bigint }
export interface StatePair { first: FeistelState; second: FeistelState }
export function fromCiphertext(pair: ChosenPair): StatePair {
  const make = (ob: Observation): FeistelState => {
    const [c0, c1] = split(ob.ciphertext);
    return { left: (c0 ^ c1) >>> 0, right: c0, plaintext: ob.plaintext };
  };
  return { first: make(pair.first), second: make(pair.second) };
}
export function peelRound(pair: StatePair, key: number, stats?: SearchStats): StatePair {
  const peel = ({ left, right, plaintext }: FeistelState): FeistelState => ({
    left: (right ^ fealF(left ^ key)) >>> 0, right: left, plaintext,
  });
  if (stats) stats.fEvaluations += 2;
  return { first: peel(pair.first), second: peel(pair.second) };
}

export interface SearchStats { fEvaluations: number }
/**
 * Search the 32-bit f-key as two 16-bit problems: inner XOR bytes determine
 * output bytes 1/2; surviving inner bytes permit separate 8-bit searches for
 * output bytes 0 and 3. Every counted evaluation calls the actual FEAL f.
 */
export function recoverRoundKey(pairs: StatePair[], expectedPreviousLeftDifference: number, stats: SearchStats): number[] {
  if (!pairs.length) return [];
  const x = pairs.map(({ first, second }) => [first.left, second.left, (first.right ^ second.right ^ expectedPreviousLeftDifference) >>> 0] as const);
  const matches = (key: number, mask: number): boolean => {
    for (const [a, b, target] of x) {
      const actual = fealF(a ^ key) ^ fealF(b ^ key);
      stats.fEvaluations += 2;
      if (((actual ^ target) & mask) !== 0) return false;
    }
    return true;
  };
  const result: number[] = [];
  for (let innerA = 0; innerA < 256; innerA++) {
    for (let innerB = 0; innerB < 256; innerB++) {
      const base = ((innerA << 16) | (innerB << 8)) >>> 0;
      if (!matches(base, 0x00ffff00)) continue;
      const highs: number[] = [], lows: number[] = [];
      for (let high = 0; high < 256; high++) {
        const key = ((high << 24) | ((innerA ^ high) << 16) | (innerB << 8)) >>> 0;
        if (matches(key, 0xff000000)) highs.push(high);
      }
      for (let low = 0; low < 256; low++) {
        const key = ((innerA << 16) | ((innerB ^ low) << 8) | low) >>> 0;
        if (matches(key, 0x000000ff)) lows.push(low);
      }
      for (const high of highs) for (const low of lows) {
        result.push(((high << 24) | ((innerA ^ high) << 16) | ((innerB ^ low) << 8) | low) >>> 0);
      }
    }
  }
  return result;
}

export function solveRound1(pairs: StatePair[], rounds234: [number, number, number], stats: SearchStats): EquivalentKey[] {
  const observations = pairs.flatMap((p) => [p.first, p.second]);
  if (observations.length < 2) return [];
  const anchor = observations[0];
  const whiteningXor = (anchor.left ^ Number(anchor.plaintext >> 32n) ^ Number(anchor.plaintext & 0xffffffffn)) >>> 0;
  if (!observations.every((ob) => ((ob.left ^ Number(ob.plaintext >> 32n) ^ Number(ob.plaintext & 0xffffffffn)) >>> 0) === whiteningXor)) return [];
  const compare: StatePair[] = observations.slice(1).map((ob) => ({
    first: { left: anchor.left, right: (anchor.right ^ Number(anchor.plaintext >> 32n)) >>> 0, plaintext: anchor.plaintext },
    second: { left: ob.left, right: (ob.right ^ Number(ob.plaintext >> 32n)) >>> 0, plaintext: ob.plaintext },
  }));
  // [extension] point: schedule inversion could turn equivalent material into a master key.
  return recoverRoundKey(compare, 0, stats).map((key0) => {
    stats.fEvaluations++;
    const whiteningLeft = (anchor.right ^ fealF(anchor.left ^ key0) ^ Number(anchor.plaintext >> 32n)) >>> 0;
    return { rounds: [key0, rounds234[0], rounds234[1], rounds234[2]], whiteningLeft, whiteningRight: (whiteningLeft ^ whiteningXor) >>> 0 };
  });
}

export function decryptEquivalent(ciphertext: bigint, key: EquivalentKey, stats?: SearchStats): bigint {
  const [c0, c1] = split(ciphertext);
  let left = (c0 ^ c1) >>> 0, right = c0;
  for (let r = 3; r >= 0; r--) {
    [left, right] = [(right ^ fealF(left ^ key.rounds[r])) >>> 0, left];
    if (stats) stats.fEvaluations++;
  }
  return join((left ^ key.whiteningLeft) >>> 0, (right ^ left ^ key.whiteningRight) >>> 0);
}

export function verifyEquivalentKey(key: EquivalentKey, fresh: Observation[], stats?: SearchStats): boolean {
  if (fresh.length !== 64) return false;
  let matches = true;
  for (const { plaintext, ciphertext } of fresh) {
    if (decryptEquivalent(ciphertext, key, stats) !== plaintext) matches = false;
  }
  return matches;
}

export interface AttackOptions { onProgress?: (stage: FunnelStage) => void; cancelled?: () => boolean; yieldControl?: () => Promise<void> }
export async function attackStructures(structures: Structures, options: AttackOptions = {}): Promise<AttackReport> {
  const stats: SearchStats = { fEvaluations: 0 };
  const stages: FunnelStage[] = [];
  const emit = (round: number, survivors: number) => { const stage = { round, survivors, fEvaluations: stats.fEvaluations }; stages.push(stage); options.onProgress?.(stage); };
  let ticks = 0;
  const check = async () => { if (options.yieldControl && (++ticks & 15) === 0) await options.yieldControl(); if (options.cancelled?.()) throw new Error('Attack cancelled'); };
  const a = structures.a.map(fromCiphertext), b = structures.b.map(fromCiphertext);
  const fourth = recoverRoundKey(a, GAMMA, stats);
  emit(4, fourth.length);
  if (!fourth.length) throw new Error('Attack failed at round 4');
  const three: Array<{ keys: [number, number]; a: StatePair[]; b: StatePair[] }> = [];
  for (const k4 of fourth) {
    await check();
    const a3 = a.map((pair) => peelRound(pair, k4, stats));
    const b3 = b.map((pair) => peelRound(pair, k4, stats));
    for (const k3 of recoverRoundKey(a3, DELTA, stats)) three.push({ keys: [k3, k4], a: a3, b: b3 });
  }
  emit(3, three.length);
  if (!three.length) throw new Error('Attack failed at round 3');
  const two: Array<{ keys: [number, number, number]; a: StatePair[]; b: StatePair[] }> = [];
  for (const item of three) {
    await check();
    const b2 = item.b.map((pair) => peelRound(pair, item.keys[0], stats));
    for (const k2 of recoverRoundKey(b2, 0, stats)) two.push({ keys: [k2, ...item.keys], a: item.a.map((pair) => peelRound(pair, item.keys[0], stats)), b: b2 });
  }
  emit(2, two.length);
  if (!two.length) throw new Error('Attack failed at round 2');
  const candidates: EquivalentKey[] = [];
  for (const item of two) {
    await check();
    const all = [...item.a, ...item.b].map((pair) => peelRound(pair, item.keys[0], stats));
    candidates.push(...solveRound1(all, item.keys, stats));
  }
  emit(1, candidates.length);
  if (!candidates.length) throw new Error('Attack failed at round 1');
  return { stages, candidates, fEvaluations: stats.fEvaluations, queried: structures.queried };
}
