/**
 * Difference Distribution Table (DDT) computation
 * 
 * Based on "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 * 
 * The DDT is a fundamental table in differential cryptanalysis.
 * DDT[Δx][Δy] = number of input pairs (x, x⊕Δx) that produce output difference Δy
 * when passed through an S-box.
 */

/**
 * Entry in the Difference Distribution Table
 */
export interface DDTEntry {
  inputDiff: number;     // Input difference (0-15)
  outputDiff: number;    // Output difference (0-15)
  count: number;         // How many input pairs produce this output diff
  probability: number;   // count / 16
}

/**
 * Compute the full Difference Distribution Table for an S-box
 * 
 * Mathematical definition:
 * DDT[Δx][Δy] = |{x ∈ [0,15] : S(x) ⊕ S(x ⊕ Δx) = Δy}|
 * 
 * @param sbox The S-box (typically SBOX from sbox.ts)
 * @returns 16×16 matrix where ddt[inputDiff][outputDiff] = count
 */
export function computeDDT(sbox: number[]): number[][] {
  const ddt: number[][] = Array(16)
    .fill(null)
    .map(() => Array(16).fill(0));

  // For each input difference
  for (let inputDiff = 0; inputDiff < 16; inputDiff++) {
    // For each possible input value
    for (let x = 0; x < 16; x++) {
      // Compute the pair value
      const xPrime = x ^ inputDiff;

      // Get S-box outputs
      const sx = sbox[x];
      const sxPrime = sbox[xPrime];

      // Compute output difference
      const outputDiff = sx ^ sxPrime;

      // Increment the count
      ddt[inputDiff][outputDiff]++;
    }
  }

  return ddt;
}

/**
 * Get probability of a differential from the DDT
 * @param ddt The Difference Distribution Table
 * @param inputDiff Input difference (0-15)
 * @param outputDiff Output difference (0-15)
 * @returns count / 16 (the probability)
 */
export function getDifferentialProbability(ddt: number[][], inputDiff: number, outputDiff: number): number {
  const count = ddt[inputDiff][outputDiff];
  return count / 16;
}

/**
 * Find the most probable non-trivial differential in the DDT
 * (excluding the case where input difference is 0)
 * @param ddt The Difference Distribution Table
 * @returns The highest-probability non-trivial entry
 */
export function findBestDifferential(ddt: number[][]): DDTEntry {
  let bestEntry: DDTEntry = {
    inputDiff: 0,
    outputDiff: 0,
    count: 0,
    probability: 0,
  };

  for (let inputDiff = 1; inputDiff < 16; inputDiff++) {
    // Skip trivial input difference
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      const count = ddt[inputDiff][outputDiff];
      if (count > bestEntry.count) {
        bestEntry = {
          inputDiff,
          outputDiff,
          count,
          probability: count / 16,
        };
      }
    }
  }

  return bestEntry;
}

/**
 * Get the maximum non-trivial DDT entry (for S-box strength analysis)
 * @param ddt The Difference Distribution Table
 * @returns Maximum count value excluding ddt[0][*]
 */
export function getMaxDDTEntry(ddt: number[][]): number {
  let max = 0;
  for (let i = 1; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      max = Math.max(max, ddt[i][j]);
    }
  }
  return max;
}

/**
 * Verify DDT properties (for testing and validation)
 */
export interface DDTProperties {
  trivialCasesCorrect: boolean;      // ddt[0][0] === 16, ddt[0][y] === 0 for y ≠ 0
  rowSumsCorrect: boolean;           // Every row sums to 16
  maxDDTValue: number;               // Maximum non-trivial entry
  isWeak: boolean;                   // True if max DDT > 4 (weak S-box)
}

/**
 * Verify and analyze DDT properties
 * @param ddt The Difference Distribution Table
 * @returns Properties of the DDT
 */
export function verifyDDTProperties(ddt: number[][]): DDTProperties {
  let trivialCasesCorrect = true;
  let rowSumsCorrect = true;
  let maxDDTValue = 0;

  // Check trivial cases
  if (ddt[0][0] !== 16) {
    trivialCasesCorrect = false;
  }
  for (let y = 1; y < 16; y++) {
    if (ddt[0][y] !== 0) {
      trivialCasesCorrect = false;
    }
  }

  // Check row sums and find max
  for (let i = 0; i < 16; i++) {
    let rowSum = 0;
    for (let j = 0; j < 16; j++) {
      rowSum += ddt[i][j];
      if (i > 0) {
        // Exclude trivial row
        maxDDTValue = Math.max(maxDDTValue, ddt[i][j]);
      }
    }
    if (rowSum !== 16) {
      rowSumsCorrect = false;
    }
  }

  return {
    trivialCasesCorrect,
    rowSumsCorrect,
    maxDDTValue,
    isWeak: maxDDTValue > 4,
  };
}

/**
 * Get all differentials with a specific probability from the DDT
 * @param ddt The Difference Distribution Table
 * @param count Target count (0-16)
 * @returns Array of differentials with that exact count
 */
export function getDifferentialsWithCount(ddt: number[][], count: number): DDTEntry[] {
  const result: DDTEntry[] = [];

  for (let inputDiff = 0; inputDiff < 16; inputDiff++) {
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      if (ddt[inputDiff][outputDiff] === count) {
        result.push({
          inputDiff,
          outputDiff,
          count,
          probability: count / 16,
        });
      }
    }
  }

  return result;
}
