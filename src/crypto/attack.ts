import { permute } from './permutation.js';
/**
 * Differential cryptanalysis attack engine
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * This implements the last-round attack that recovers the final round's subkey.
 * The attack uses the peel-last-round technique: guess the last round key,
 * partially decrypt both ciphertexts, and check if the differential holds.
 */

import { applyBothNibbles, invertBothNibbles } from './sbox.js';
import { encrypt, encryptRounds } from './spn.js';
import type { SPNKey } from './spn.js';
import { nextInt } from './rng.js';

/**
 * Result of attacking with a candidate key
 */
export interface AttackResult {
  candidateKey: number;  // 0-255 - guessed last round subkey
  biasCount: number;     // How many pairs matched the expected output diff
  probability: number;   // biasCount / totalPairs
  ratio: number;         // biasCount / expectedRandomCount
}

/**
 * Attack statistics for the full key recovery
 */
export interface AttackStats {
  totalPairs: number;
  expectedRandomCount: number;
  results: AttackResult[];
  correctKeyRank: number; // Rank of the correct key (1st is best)
  correctKeyBias: number;
}

/**
 * Collect encrypted plaintext pairs with a specific chosen difference
 * @param key The secret key
 * @param inputDiff Chosen plaintext difference
 * @param count Number of pairs to collect
 * @returns Array of ciphertext pairs
 */
export function collectPairs(
  key: SPNKey,
  inputDiff: number,
  count: number,
): Array<{ c1: number; c2: number }> {
  const pairs: Array<{ c1: number; c2: number }> = [];

  for (let i = 0; i < count; i++) {
    // Choose random plaintext from the seeded stream so runs are reproducible.
    const p1 = nextInt(256);
    const p2 = (p1 ^ inputDiff) & 0xFF;

    // Encrypt both
    const c1 = encrypt(p1, key);
    const c2 = encrypt(p2, key);

    pairs.push({ c1, c2 });
  }

  return pairs;
}

/**
 * Attack the last round by guessing the subkey
 * 
 * For each candidate subkey k (0-255):
 * 1. Partially decrypt c1 by XORing with k and inverting S-box
 * 2. Partially decrypt c2 by XORing with k and inverting S-box
 * 3. Check if (decrypted_c1 ⊕ decrypted_c2) equals expectedDiff
 * 4. Count matches (bias)
 * 
 * @param pairs Ciphertext pairs collected with chosen plaintext difference
 * @param expectedOutputDiff Expected difference before the last S-box
 * @returns Array of results for all 256 candidate keys, sorted by bias
 */
export function attackLastRound(
  pairs: Array<{ c1: number; c2: number }>,
  expectedOutputDiff: number,
): AttackResult[] {
  const results: AttackResult[] = [];
  // The target difference is a full BYTE, not a nibble, so at a wrong key guess
  // the partially-decrypted difference lands on it about 1 time in 256 — not 1
  // in 16. Measured on this cipher: 500 pairs gives a wrong-key mean of ~2-3
  // hits, i.e. ~500/256, against ~25 hits for the correct key. Using /16 here
  // would put the noise floor (31) ABOVE the real signal (25).
  const expectedRandomCount = pairs.length / 256;

  // Try all 256 possible values for the last round subkey
  for (let candidateKey = 0; candidateKey < 256; candidateKey++) {
    let biasCount = 0;

    // Test this candidate against all pairs
    for (const pair of pairs) {
      const c1 = pair.c1;
      const c2 = pair.c2;

      // Partially decrypt: XOR with candidate key
      const partial1 = c1 ^ candidateKey;
      const partial2 = c2 ^ candidateKey;

      // Invert S-box to get value before last S-box
      const inverted1 = invertBothNibbles(partial1);
      const inverted2 = invertBothNibbles(partial2);

      // Compute difference
      const diff = inverted1 ^ inverted2;

      // Check if matches expected difference
      if (diff === expectedOutputDiff) {
        biasCount++;
      }
    }

    results.push({
      candidateKey,
      biasCount,
      probability: biasCount / pairs.length,
      ratio: biasCount / expectedRandomCount,
    });
  }

  // Sort by bias count descending
  results.sort((a, b) => b.biasCount - a.biasCount);

  return results;
}

/**
 * Identify the recovered key from attack results
 * @param results Attack results sorted by bias
 * @returns The recovered subkey (candidate with highest bias)
 */
export function identifyCorrectKey(results: AttackResult[]): number {
  if (results.length === 0) {
    throw new Error('No results to analyze');
  }
  return results[0].candidateKey;
}

/**
 * Get rank of the correct key in the results
 * @param results Attack results sorted by bias
 * @param correctKey The known correct key
 * @returns Rank (1 = best, 256 = worst)
 */
export function getKeyRank(results: AttackResult[], correctKey: number): number {
  for (let i = 0; i < results.length; i++) {
    if (results[i].candidateKey === correctKey) {
      return i + 1;
    }
  }
  return -1; // Not found
}

/**
 * Perform a complete attack
 * @param key Known key (for testing/evaluation)
 * @param inputDiff Chosen plaintext difference
 * @param expectedOutputDiff Expected output difference for evaluation
 * @param pairCount Number of pairs to use
 * @returns Statistics of the attack
 */
export function performAttack(
  key: SPNKey,
  inputDiff: number,
  expectedOutputDiff: number,
  pairCount: number,
): AttackStats {
  // Collect pairs
  const pairs = collectPairs(key, inputDiff, pairCount);

  // Attack
  const results = attackLastRound(pairs, expectedOutputDiff);

  // Analyze
  const correctKeyRank = getKeyRank(results, key.subkeys[4]); // Final mixing key

  return {
    totalPairs: pairCount,
    expectedRandomCount: pairCount / 256,
    results,
    correctKeyRank,
    correctKeyBias: results.find(r => r.candidateKey === key.subkeys[4])!.biasCount,
  };
}

/** Exact fixed-key endpoint differential, for instructor inspection only.
 * A characteristic fixes every intermediate difference; an endpoint sums trails.
 */
export interface CharacteristicSample {
  outputDiff: number;
  count: number;
  probability: number;
}

export function deriveCharacteristic(key: SPNKey, inputDiff: number, _samples = 256): CharacteristicSample[] {
  const histogram = new Array<number>(256).fill(0);
  for (let p = 0; p < 256; p++) {
    histogram[encryptRounds(p, key, 3) ^ encryptRounds(p ^ inputDiff, key, 3)]++;
  }
  return histogram.map((count, outputDiff) => ({ outputDiff, count, probability: count / 256 }))
    .sort((a, b) => b.count - a.count);
}

/** Public S-box/permutation preprocessing. No victim key or oracle input.
 * Independent uniform round-input model; not a fixed-key probability theorem.
 */
export function publicDifferentialModel(inputDiff: number): CharacteristicSample[] {
  const transitions = Array.from({ length: 256 }, (_, delta) => {
    const counts = new Array<number>(256).fill(0);
    for (let x = 0; x < 256; x++) counts[permute(applyBothNibbles(x) ^ applyBothNibbles(x ^ delta))]++;
    return counts;
  });
  let distribution = new Array<number>(256).fill(0);
  distribution[inputDiff] = 1;
  for (let round = 0; round < 3; round++) {
    const next = new Array<number>(256).fill(0);
    distribution.forEach((p, delta) => {
      if (p) transitions[delta].forEach((count, out) => { next[out] += p * count / 256; });
    });
    distribution = next;
  }
  return distribution.map((probability, outputDiff) => ({ outputDiff, probability, count: probability * 256 }))
    .sort((a, b) => b.probability - a.probability);
}

export function exactTrails(key: SPNKey, inputDiff: number) {
  const counts = new Map<string, number>();
  for (let p = 0; p < 256; p++) {
    const path = [inputDiff, ...[1, 2, 3].map(round => encryptRounds(p, key, round) ^ encryptRounds(p ^ inputDiff, key, round))];
    const id = path.join(',');
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return [...counts].map(([id, count]) => ({ differences: id.split(',').map(Number), count }))
    .sort((a, b) => b.count - a.count);
}

export function distinctPairCount(pairs: Array<{ c1: number; c2: number }>): number {
  return new Set(pairs.map(({c1, c2}) => Math.min(c1, c2) * 256 + Math.max(c1, c2))).size;
}

/**
 * Simulate multiple attacks to measure success rate
 * @param key Known key
 * @param inputDiff Chosen plaintext difference
 * @param expectedOutputDiff Expected output difference
 * @param pairCount Pairs per attack
 * @param trials Number of trials
 * @returns Statistics across trials
 */
export function evaluateAttack(
  key: SPNKey,
  inputDiff: number,
  expectedOutputDiff: number,
  pairCount: number,
  trials: number = 10,
): {
  successRate: number;
  averageRank: number;
  minRank: number;
  maxRank: number;
} {
  let successCount = 0;
  let totalRank = 0;
  let minRank = 256;
  let maxRank = 0;

  for (let trial = 0; trial < trials; trial++) {
    const stats = performAttack(key, inputDiff, expectedOutputDiff, pairCount);
    const rank = stats.correctKeyRank;

    if (rank === 1) {
      successCount++;
    }
    totalRank += rank;
    minRank = Math.min(minRank, rank);
    maxRank = Math.max(maxRank, rank);
  }

  return {
    successRate: successCount / trials,
    averageRank: totalRank / trials,
    minRank,
    maxRank,
  };
}
