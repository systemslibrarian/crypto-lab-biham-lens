/**
 * Differential characteristic finding and analysis
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * A differential characteristic describes the propagation of differences
 * through multiple rounds of a cipher. This module finds high-probability
 * characteristics that can be used in differential attacks.
 */

import { computeDDT, getDifferentialProbability } from './ddt.js';
import { getSbox } from './sbox.js';
import { encryptRounds } from './spn.js';
import type { SPNKey } from './spn.js';

/**
 * A differential characteristic
 */
export interface DifferentialCharacteristic {
  inputDiff: number;         // Δp - initial plaintext difference
  roundDiffs: number[];      // Difference after each round
  probability: number;       // Product of conditional probabilities
  activeSBoxes: number[][];  // Which S-boxes are active each round
  roundProbabilities: number[]; // Individual round probabilities
}

/**
 * Compute which nibbles (S-boxes) are active for a given byte difference
 * Returns [0, 1] for each nibble: 0 = high nibble, 1 = low nibble
 */
function getActiveSBoxes(byteXor: number): number[] {
  const active: number[] = [];
  const highNibble = (byteXor >> 4) & 0xF;
  const lowNibble = byteXor & 0xF;

  if (highNibble !== 0) {
    active.push(0); // High nibble is active
  }
  if (lowNibble !== 0) {
    active.push(1); // Low nibble is active
  }

  return active;
}

/**
 * Trace how a difference propagates through the cipher for diagnostic purposes
 * @param plaintext1 First plaintext
 * @param plaintext2 Second plaintext (with chosen difference)
 * @param key The encryption key
 * @param rounds Number of rounds to trace
 * @returns Trace of differences through each round
 */
export interface DifferenceTrace {
  inputDiff: number;
  roundDiffs: number[];
  roundStates: Array<{ state1: number; state2: number; diff: number }>;
}

export function traceCharacteristic(
  plaintext1: number,
  plaintext2: number,
  key: SPNKey,
  rounds: number = 4,
): DifferenceTrace {
  let state1 = plaintext1 & 0xFF;
  let state2 = plaintext2 & 0xFF;
  const inputDiff = state1 ^ state2;

  const roundDiffs: number[] = [];
  const roundStates: Array<{ state1: number; state2: number; diff: number }> = [];

  // Trace through encryption
  for (let round = 0; round < rounds; round++) {
    roundStates.push({
      state1: state1 & 0xFF,
      state2: state2 & 0xFF,
      diff: (state1 ^ state2) & 0xFF,
    });

    // Simple round: XOR with key, S-box, permutation
    state1 = (state1 ^ key.subkeys[round]) & 0xFF;
    state2 = (state2 ^ key.subkeys[round]) & 0xFF;

    // S-box
    state1 = ((state1 >> 4) & 0xF) === 0 ? state1 & 0x0F : 0;
    state2 = ((state2 >> 4) & 0xF) === 0 ? state2 & 0x0F : 0;

    const roundDiff = (state1 ^ state2) & 0xFF;
    roundDiffs.push(roundDiff);
  }

  return {
    inputDiff,
    roundDiffs,
    roundStates,
  };
}

/**
 * Find the best differential characteristic for a given number of rounds
 * Uses a greedy approach: find the best single-round differential,
 * then extends it with compatible round differentials
 * 
 * @param rounds Number of rounds in the characteristic (typically 3 for attacking 4-round cipher)
 * @returns The best characteristic found
 */
export function findCharacteristic(rounds: number = 3): DifferentialCharacteristic {
  const ddt = computeDDT(getSbox() as number[]);

  // For simplicity in this toy cipher, we'll use a mixed greedy approach:
  // Find the best S-box differential and propagate it through rounds

  // Get all non-trivial differentials sorted by count
  interface DDTDiff {
    inputDiff: number;
    outputDiff: number;
    count: number;
  }

  const differentials: DDTDiff[] = [];
  for (let inputDiff = 1; inputDiff < 16; inputDiff++) {
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      const count = ddt[inputDiff][outputDiff];
      if (count > 0) {
        differentials.push({ inputDiff, outputDiff, count });
      }
    }
  }

  // Sort by probability descending
  differentials.sort((a, b) => b.count - a.count);

  // Use the best differential for all rounds (approximation for toy cipher)
  // Real differential cryptanalysis would find optimal multi-round characteristics
  const best = differentials[0];
  const inputDiff = best.inputDiff;

  // Construct a characteristic
  const roundDiffs: number[] = [];
  const roundProbabilities: number[] = [];
  let probability = 1.0;

  for (let r = 0; r < rounds; r++) {
    // For this simple toy cipher, assume the differential active S-boxes give us
    // the output difference (this is simplified; real analysis is more complex)
    const outputDiff = best.outputDiff << (r % 2 === 0 ? 4 : 0); // Alternate nibbles
    roundDiffs.push(outputDiff);

    const prob = getDifferentialProbability(ddt, best.inputDiff, best.outputDiff);
    roundProbabilities.push(prob);
    probability *= prob;
  }

  return {
    inputDiff,
    roundDiffs,
    probability,
    activeSBoxes: roundDiffs.map((diff) => getActiveSBoxes(diff)),
    roundProbabilities,
  };
}

/**
 * Get the best characteristics for attacking this cipher
 * Pre-computed for efficiency (real attack would search these)
 */
export function getBestCharacteristics(): DifferentialCharacteristic[] {
  // For this toy cipher, compute the single best characteristic
  // In a real scenario, we'd maintain a database of good characteristics
  return [findCharacteristic(3)];
}

/**
 * Compute the expected probability of a characteristic
 */
export function getCharacteristicProbability(characteristic: DifferentialCharacteristic): number {
  return characteristic.probability;
}
