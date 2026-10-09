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

  // Generate 5 subkeys by rotating
  for (let i = 0; i < 5; i++) {
    // Extract lower 8 bits
    subkeys.push(key & 0xFF);
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

  // Final key mixing
  state = (state ^ key.subkeys[4]) & 0xFF;

  return state;
}

/**
 * Decrypt a ciphertext block using the SPN cipher
 * @param ciphertext 8-bit ciphertext block
 * @param key SPN key object
 * @returns 8-bit plaintext block
 */
export function decrypt(ciphertext: number, key: SPNKey): number {
  let state = ciphertext & 0xFF;

  // Undo final key mixing
  state = (state ^ key.subkeys[4]) & 0xFF;

  // Execute 4 rounds in reverse order
  for (let round = 3; round >= 0; round--) {
    const isFirstRound = round === 3;
    state = roundDecrypt(state, key.subkeys[round], isFirstRound);
  }

  return state;
}

/**
 * Per-stage trace for the Differential Trace tab.
 *
 * Each entry is one observable step in the cipher pipeline, with the two
 * concrete states *and* their XOR difference. The whole point is to make
 * visible that the XOR-K stages leave the difference unchanged — that is
 * the foundation of differential cryptanalysis.
 */
export type TraceStageKind = 'input' | 'xor-key' | 'sbox' | 'permute';

export interface TraceStage {
  kind: TraceStageKind;
  label: string;
  round: number;          // 1..4 for round-internal stages, 0 for input
  state1: number;
  state2: number;
  diff: number;
}

export function traceEncryption(p1: number, p2: number, key: SPNKey): TraceStage[] {
  const stages: TraceStage[] = [];
  let s1 = p1 & 0xFF;
  let s2 = p2 & 0xFF;

  stages.push({
    kind: 'input',
    label: 'Plaintext',
    round: 0,
    state1: s1,
    state2: s2,
    diff: (s1 ^ s2) & 0xFF,
  });

  for (let round = 0; round < 4; round++) {
    const subkey = key.subkeys[round];
    const isLastRound = round === 3;

    // Stage 1: XOR with subkey — diff unchanged.
    s1 = (s1 ^ subkey) & 0xFF;
    s2 = (s2 ^ subkey) & 0xFF;
    stages.push({
      kind: 'xor-key',
      label: `Round ${round + 1}: XOR K${round + 1}`,
      round: round + 1,
      state1: s1,
      state2: s2,
      diff: (s1 ^ s2) & 0xFF,
    });

    // Stage 2: S-box — diff may change.
    s1 = applyBothNibbles(s1);
    s2 = applyBothNibbles(s2);
    stages.push({
      kind: 'sbox',
      label: `Round ${round + 1}: S-box`,
      round: round + 1,
      state1: s1,
      state2: s2,
      diff: (s1 ^ s2) & 0xFF,
    });

    // Stage 3: permutation (skipped in last round).
    if (!isLastRound) {
      s1 = permute(s1);
      s2 = permute(s2);
      stages.push({
        kind: 'permute',
        label: `Round ${round + 1}: Permute`,
        round: round + 1,
        state1: s1,
        state2: s2,
        diff: (s1 ^ s2) & 0xFF,
      });
    }
  }

  // Final Key XOR
  s1 = (s1 ^ key.subkeys[4]) & 0xFF;
  s2 = (s2 ^ key.subkeys[4]) & 0xFF;
  stages.push({
    kind: 'xor-key',
    label: `Round 5: Final Key Mixing`,
    round: 5,
    state1: s1,
    state2: s2,
    diff: (s1 ^ s2) & 0xFF,
  });

  return stages;
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
    const isLastRound = round === 3;
    state = roundEncrypt(state, key.subkeys[round], isLastRound);
  }

  if (rounds === 4) {
    state = (state ^ key.subkeys[4]) & 0xFF;
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

  if (rounds === 4) {
    state = (state ^ key.subkeys[4]) & 0xFF;
  }

  for (let round = 4 - 1; round >= 4 - rounds; round--) {
    const isFirstRound = round === 3;
    state = roundDecrypt(state, key.subkeys[round], isFirstRound);
  }

  return state & 0xFF;
}
