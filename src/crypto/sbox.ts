/**
 * S-box implementation for differential cryptanalysis demo
 *
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 *
 * Two named S-boxes are provided so users can FEEL why S-box choice matters:
 *   - 'weak'   : the toy S-box used in textbook examples, max DDT = 8
 *   - 'strong' : the PRESENT S-box (Bogdanov et al. 2007), max DDT = 4
 *
 * Swapping at runtime updates SBOX/SBOX_INV consulted by every other module.
 */

// Toy textbook S-box (Heys' tutorial / Stinson's "Cryptography" 3rd ed).
// Max DDT entry = 8 — highly exploitable.
const SBOX_WEAK: ReadonlyArray<number> = [
  0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
];

// PRESENT cipher S-box. Max DDT entry = 4 — the smallest possible for a
// 4-bit permutation, which is why PRESENT chose it.
const SBOX_STRONG: ReadonlyArray<number> = [
  0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

export type SboxName = 'weak' | 'strong';

const SBOXES: Record<SboxName, ReadonlyArray<number>> = {
  weak: SBOX_WEAK,
  strong: SBOX_STRONG,
};

let activeName: SboxName = 'weak';
let SBOX: number[] = [...SBOX_WEAK];
let SBOX_INV: number[] = computeSboxInverse(SBOX);

function computeSboxInverse(sbox: number[]): number[] {
  const inverse: number[] = new Array(16).fill(0);
  for (let i = 0; i < 16; i++) {
    inverse[sbox[i]] = i;
  }
  return inverse;
}

/** Switch the cipher's active S-box. Returns the new active name. */
export function setSbox(name: SboxName): SboxName {
  activeName = name;
  SBOX = [...SBOXES[name]];
  SBOX_INV = computeSboxInverse(SBOX);
  return activeName;
}

export function getActiveSboxName(): SboxName {
  return activeName;
}

export function sboxApply(nibble: number): number {
  if (nibble < 0 || nibble > 15) {
    throw new Error(`Invalid nibble: ${nibble}. Must be in range 0-15.`);
  }
  return SBOX[nibble];
}

export function sboxInvert(nibble: number): number {
  if (nibble < 0 || nibble > 15) {
    throw new Error(`Invalid nibble: ${nibble}. Must be in range 0-15.`);
  }
  return SBOX_INV[nibble];
}

export function applyBothNibbles(byte: number): number {
  const highNibble = (byte >> 4) & 0xF;
  const lowNibble = byte & 0xF;
  return (SBOX[highNibble] << 4) | SBOX[lowNibble];
}

export function invertBothNibbles(byte: number): number {
  const highNibble = (byte >> 4) & 0xF;
  const lowNibble = byte & 0xF;
  return (SBOX_INV[highNibble] << 4) | SBOX_INV[lowNibble];
}

export function getSbox(): ReadonlyArray<number> {
  return SBOX;
}

export function getSboxInverse(): ReadonlyArray<number> {
  return SBOX_INV;
}
