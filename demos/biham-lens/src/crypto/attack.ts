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

import { invertBothNibbles } from './sbox.js';
import { encrypt } from './spn.js';
import type { SPNKey } from './spn.js';

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
    // Choose random plaintext
    const p1 = Math.floor(Math.random() * 256);
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
  const expectedRandomCount = (pairs.length / 16) * 1; // Random: each nibble has ~1/16 chance

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
  const correctKeyRank = getKeyRank(results, key.subkeys[3]); // Last round key

  return {
    totalPairs: pairCount,
    expectedRandomCount: (pairCount / 16) * 1,
    results,
    correctKeyRank,
    correctKeyBias: results[0].biasCount, // Get bias of best candidate
  };
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
