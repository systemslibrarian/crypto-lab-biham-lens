/**
 * S-box implementation for differential cryptanalysis demo
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * This module implements a 4-bit S-box for the toy SPN cipher.
 * The S-box is the source of non-linearity in the cipher.
 */

// 4-bit S-box: input (0-15) → output (0-15)
// Input:  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// Output: E  4  D  1  2  F  B  8  3  A  6  C  5  9  0  7
const SBOX: number[] = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7];

// Compute inverse S-box
function computeSboxInverse(sbox: number[]): number[] {
  const inverse: number[] = new Array(16).fill(0);
  for (let i = 0; i < 16; i++) {
    inverse[sbox[i]] = i;
  }
  return inverse;
}

const SBOX_INV: number[] = computeSboxInverse(SBOX);

/**
 * Apply S-box to a single 4-bit nibble
 * @param nibble Value from 0-15
 * @returns S-box output (0-15)
 */
export function sboxApply(nibble: number): number {
  if (nibble < 0 || nibble > 15) {
    throw new Error(`Invalid nibble: ${nibble}. Must be in range 0-15.`);
  }
  return SBOX[nibble];
}

/**
 * Apply inverse S-box to a single 4-bit nibble
 * @param nibble Value from 0-15
 * @returns Inverse S-box output (0-15)
 */
export function sboxInvert(nibble: number): number {
  if (nibble < 0 || nibble > 15) {
    throw new Error(`Invalid nibble: ${nibble}. Must be in range 0-15.`);
  }
  return SBOX_INV[nibble];
}

/**
 * Apply S-box to both 4-bit nibbles of an 8-bit byte
 * High nibble (bits 4-7) and low nibble (bits 0-3)
 * @param byte 8-bit value
 * @returns Result with S-box applied to both nibbles
 */
export function applyBothNibbles(byte: number): number {
  const highNibble = (byte >> 4) & 0xF;
  const lowNibble = byte & 0xF;
  const sboxHigh = sboxApply(highNibble);
  const sboxLow = sboxApply(lowNibble);
  return (sboxHigh << 4) | sboxLow;
}

/**
 * Apply inverse S-box to both 4-bit nibbles of an 8-bit byte
 * @param byte 8-bit value
 * @returns Result with inverse S-box applied to both nibbles
 */
export function invertBothNibbles(byte: number): number {
  const highNibble = (byte >> 4) & 0xF;
  const lowNibble = byte & 0xF;
  const invHigh = sboxInvert(highNibble);
  const invLow = sboxInvert(lowNibble);
  return (invHigh << 4) | invLow;
}

/**
 * Get the S-box lookup table (read-only)
 */
export function getSbox(): ReadonlyArray<number> {
  return SBOX;
}

/**
 * Get the inverse S-box lookup table (read-only)
 */
export function getSboxInverse(): ReadonlyArray<number> {
  return SBOX_INV;
}
