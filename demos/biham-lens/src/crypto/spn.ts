/**
 * 4-round SPN (Substitution-Permutation Network) toy cipher
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * This simplified SPN cipher operates on 8-bit blocks with:
 * - 4-bit S-box (applied twice per byte)
 * - Bit-level permutation for diffusion
 * - 4 rounds with subkeys
 */

import { applyBothNibbles, invertBothNibbles } from './sbox.js';
import { permute, permuteInverse } from './permutation.js';

/**
 * SPN key structure
 */
export interface SPNKey {
  masterKey: number;    // 16-bit master key
  subkeys: number[];    // 4 subkeys of 8 bits each (one per round)
}

/**
 * Generate subkeys from master key using a simple key schedule
 * @param masterKey 16-bit master key
 * @returns SPNKey with 4 subkeys
 */
export function generateKey(masterKey: number): SPNKey {
  const subkeys: number[] = [];
  let key = masterKey & 0xFFFF;

  // Generate 4 subkeys by rotating and XORing
  for (let i = 0; i < 4; i++) {
    // Extract 8 bits from the rotated key
    subkeys.push((key >> (i * 4)) & 0xFF);
    // Rotate key left by 4 bits
    key = ((key << 4) | (key >> 12)) & 0xFFFF;
  }

  return { masterKey, subkeys };
}

/**
 * One round of the SPN cipher (encryption)
 * @param state Current state (8-bit)
 * @param subkey Round subkey (8-bit)
 * @param isLastRound If true, skip permutation
 * @returns State after round
 */
function roundEncrypt(state: number, subkey: number, isLastRound: boolean): number {
  // Step 1: XOR with round subkey
  let result = state ^ subkey;

  // Step 2: Apply S-box to both nibbles
  result = applyBothNibbles(result);

  // Step 3: Apply permutation (skip in last round)
  if (!isLastRound) {
    result = permute(result);
  }

  return result & 0xFF;
}

/**
 * One round of the SPN cipher (decryption)
 * @param state Current state (8-bit)
 * @param subkey Round subkey (8-bit)
 * @param isFirstRound If true, skip permutation inverse
 * @returns State after round
 */
function roundDecrypt(state: number, subkey: number, isFirstRound: boolean): number {
  // Step 1: Apply inverse permutation (skip in first round - which is the last encryption round)
  let result = state;
  if (!isFirstRound) {
    result = permuteInverse(result);
  }

  // Step 2: Apply inverse S-box to both nibbles
  result = invertBothNibbles(result);

  // Step 3: XOR with round subkey
  result = result ^ subkey;

  return result & 0xFF;
}

/**
 * Encrypt a plaintext block using the SPN cipher
 * @param plaintext 8-bit plaintext block
 * @param key SPN key object
 * @returns 8-bit ciphertext block
 */
export function encrypt(plaintext: number, key: SPNKey): number {
  let state = plaintext & 0xFF;

  // Execute 4 rounds
  for (let round = 0; round < 4; round++) {
    const isLastRound = round === 3;
    state = roundEncrypt(state, key.subkeys[round], isLastRound);
  }

  return state & 0xFF;
}

/**
 * Decrypt a ciphertext block using the SPN cipher
 * @param ciphertext 8-bit ciphertext block
 * @param key SPN key object
 * @returns 8-bit plaintext block
 */
export function decrypt(ciphertext: number, key: SPNKey): number {
  let state = ciphertext & 0xFF;

  // Execute 4 rounds in reverse order
  for (let round = 3; round >= 0; round--) {
    const isFirstRound = round === 3;
    state = roundDecrypt(state, key.subkeys[round], isFirstRound);
  }

  return state & 0xFF;
}

/**
 * Encrypt using only the first N rounds
 * Used for partial encryption in differential attacks
 * @param plaintext 8-bit plaintext block
 * @param key SPN key object
 * @param rounds Number of rounds to execute (1-4)
 * @returns State after N rounds
 */
export function encryptRounds(plaintext: number, key: SPNKey, rounds: number): number {
  if (rounds < 1 || rounds > 4) {
    throw new Error('Rounds must be between 1 and 4');
  }

  let state = plaintext & 0xFF;

  for (let round = 0; round < rounds; round++) {
    const isLastRound = round === rounds - 1;
    state = roundEncrypt(state, key.subkeys[round], isLastRound);
  }

  return state & 0xFF;
}

/**
 * Decrypt using only the last N rounds
 * Used for partial decryption in attacks (from the end backwards)
 * @param ciphertext 8-bit ciphertext block
 * @param key SPN key object
 * @param rounds Number of rounds to execute from the end (1-4)
 * @returns State after N rounds of decryption
 */
export function decryptRounds(ciphertext: number, key: SPNKey, rounds: number): number {
  if (rounds < 1 || rounds > 4) {
    throw new Error('Rounds must be between 1 and 4');
  }

  let state = ciphertext & 0xFF;

  for (let round = 4 - 1; round >= 4 - rounds; round--) {
    const isFirstRound = round === 3;
    state = roundDecrypt(state, key.subkeys[round], isFirstRound);
  }

  return state & 0xFF;
}
