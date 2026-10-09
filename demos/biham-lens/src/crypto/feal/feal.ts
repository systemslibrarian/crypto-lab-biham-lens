/** FEAL-4, byte order and key schedule matched to CrypTool 2 FEAL_Algorithms.cs. */
export type FealBlock = bigint;
export interface FealTraceRow { round: number; left: number; right: number; deltaLeft: number; deltaRight: number; fDelta: number | null }
const MASK = 0xffffffffn;
const word = (x: bigint): number => Number(x & MASK) >>> 0;
export const split = (x: FealBlock): [number, number] => [word(x >> 32n), word(x)];
export const join = (left: number, right: number): FealBlock => (BigInt(left >>> 0) << 32n) | BigInt(right >>> 0);
export const hex32 = (x: number): string => (x >>> 0).toString(16).toUpperCase().padStart(8, '0');
export const hex64 = (x: bigint): string => x.toString(16).toUpperCase().padStart(16, '0');
export function parseHex64(value: string): bigint | null { return /^[0-9a-fA-F]{16}$/.test(value) ? BigInt(`0x${value}`) : null; }

const s = (a: number, b: number, carry: number): number => {
  const n = (a + b + carry) & 255;
  return ((n << 2) | (n >>> 6)) & 255;
};

export function fealF(x: number): number {
  const a = x >>> 24, b = (x >>> 16) & 255, c = (x >>> 8) & 255, d = x & 255;
  const y1 = s(a ^ b, c ^ d, 1);
  const y2 = s(c ^ d, y1, 0);
  return ((s(a, y1, 0) << 24) | (y1 << 16) | (y2 << 8) | s(d, y2, 1)) >>> 0;
}

export function fealFk(alpha: number, beta: number): number {
  const a = alpha >>> 24, b = (alpha >>> 16) & 255, c = (alpha >>> 8) & 255, d = alpha & 255;
  const e = beta >>> 24, f = (beta >>> 16) & 255, g = (beta >>> 8) & 255, h = beta & 255;
  const y1 = s(a ^ b, (c ^ d) ^ e, 1);
  const y2 = s(c ^ d, y1 ^ f, 0);
  return ((s(a, y1 ^ g, 0) << 24) | (y1 << 16) | (y2 << 8) | s(d, y2 ^ h, 1)) >>> 0;
}

/** Twelve 16-bit subkeys, in published K0..K11 order. */
export function keySchedule(masterKey: bigint): number[] {
  let [a, b] = split(masterKey);
  let d = 0;
  const keys: number[] = [];
  for (let r = 0; r < 6; r++) {
    const next = fealFk(a, b ^ d);
    keys.push(next >>> 16, next & 0xffff);
    d = a; a = b; b = next;
  }
  return keys;
}

export function roundKey(subkeys: number[], r: number): number {
  return ((subkeys[r] >>> 8) << 16) | ((subkeys[r] & 255) << 8);
}
const whitening = (k: number[], i: number): number => ((k[i] << 16) | k[i + 1]) >>> 0;

export function encrypt4(plaintext: FealBlock, masterKey: bigint): FealBlock {
  const k = keySchedule(masterKey);
  let [l, r] = split(plaintext);
  l ^= whitening(k, 4);
  r ^= whitening(k, 6) ^ l;
  // [extension] point: an N-round variant needs its own subkey/whitening layout.
  for (let i = 0; i < 4; i++) [l, r] = [r, (l ^ fealF(r ^ roundKey(k, i))) >>> 0];
  return join((r ^ whitening(k, 8)) >>> 0, (l ^ r ^ whitening(k, 10)) >>> 0);
}

export function decrypt4(ciphertext: FealBlock, masterKey: bigint): FealBlock {
  const k = keySchedule(masterKey);
  const [c0, c1] = split(ciphertext);
  let r = (c0 ^ whitening(k, 8)) >>> 0;
  let l = (c1 ^ whitening(k, 10) ^ r) >>> 0;
  for (let i = 3; i >= 0; i--) [l, r] = [(r ^ fealF(l ^ roundKey(k, i))) >>> 0, l];
  r ^= l;
  return join((l ^ whitening(k, 4)) >>> 0, (r ^ whitening(k, 6)) >>> 0);
}

export function traceFeal4(first: bigint, second: bigint, masterKey: bigint): FealTraceRow[] {
  const k = keySchedule(masterKey);
  const [p0, q0] = split(first), [p1, q1] = split(second);
  let l0 = (p0 ^ whitening(k, 4)) >>> 0, l1 = (p1 ^ whitening(k, 4)) >>> 0;
  let r0 = (q0 ^ whitening(k, 6) ^ l0) >>> 0, r1 = (q1 ^ whitening(k, 6) ^ l1) >>> 0;
  const rows: FealTraceRow[] = [{ round: 0, left: l0, right: r0, deltaLeft: l0 ^ l1, deltaRight: r0 ^ r1, fDelta: null }];
  for (let i = 0; i < 4; i++) {
    const f0 = fealF(r0 ^ roundKey(k, i)), f1 = fealF(r1 ^ roundKey(k, i));
    [l0, r0] = [r0, (l0 ^ f0) >>> 0];
    [l1, r1] = [r1, (l1 ^ f1) >>> 0];
    rows.push({ round: i + 1, left: l0, right: r0, deltaLeft: l0 ^ l1, deltaRight: r0 ^ r1, fDelta: f0 ^ f1 });
  }
  return rows;
}
