/**
 * Bit permutation for the toy SPN cipher
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * This permutation provides diffusion across the cipher.
 * Bit positions [7,6,5,4,3,2,1,0] → [7,3,6,2,5,1,4,0]
 * PERMUTATION[i] = j means input bit i goes to output position j
 */

// Bit permutation matrix
// PERMUTATION[i] = j means bit at position i in the input
// is placed at position j in the output
const PERMUTATION: number[] = [7, 3, 6, 2, 5, 1, 4, 0];

// Compute inverse permutation
function computeInversePermutation(perm: number[]): number[] {
  const inverse: number[] = new Array(perm.length).fill(0);
  for (let i = 0; i < perm.length; i++) {
    inverse[perm[i]] = i;
  }
  return inverse;
}

const PERMUTATION_INV: number[] = computeInversePermutation(PERMUTATION);

/**
 * Apply permutation to an 8-bit value
 * @param byte Input byte
 * @returns Permuted byte
 */
export function permute(byte: number): number {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    // Extract bit i from input
    const bit = (byte >> i) & 1;
    // Place it at position PERMUTATION[i] in output
    result |= bit << PERMUTATION[i];
  }
  return result;
}

/**
 * Apply inverse permutation to an 8-bit value
 * @param byte Input byte
 * @returns Inverse permuted byte
 */
export function permuteInverse(byte: number): number {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    // Extract bit i from input
    const bit = (byte >> i) & 1;
    // Place it at position PERMUTATION_INV[i] in output
    result |= bit << PERMUTATION_INV[i];
  }
  return result;
}

/**
 * Get the permutation matrix (read-only)
 */
export function getPermutation(): ReadonlyArray<number> {
  return PERMUTATION;
}

/**
 * Get the inverse permutation matrix (read-only)
 */
export function getPermutationInverse(): ReadonlyArray<number> {
  return PERMUTATION_INV;
}
