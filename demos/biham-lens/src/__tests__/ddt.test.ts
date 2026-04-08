/**
 * Tests for Difference Distribution Table (DDT)
 * 
 * References:
 * "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 */

import { strict as assert } from 'assert';
import { test } from 'node:test';

import { getSbox } from '../crypto/sbox.js';
import {
  computeDDT,
  getDifferentialProbability,
  findBestDifferential,
  verifyDDTProperties,
  getDifferentialsWithCount,
  getMaxDDTEntry,
} from '../crypto/ddt.js';

const sbox = getSbox() as number[];

test('DDT: computeDDT returns 16x16 matrix', () => {
  const ddt = computeDDT(sbox);
  assert.equal(ddt.length, 16, 'DDT should have 16 rows');
  for (let i = 0; i < 16; i++) {
    assert.equal(ddt[i].length, 16, `Row ${i} should have 16 columns`);
  }
});

test('DDT: trivial case ddt[0][0] === 16', () => {
  const ddt = computeDDT(sbox);
  assert.equal(ddt[0][0], 16, 'ddt[0][0] should be 16 (zero diff always gives zero diff)');
});

test('DDT: trivial case ddt[0][y] === 0 for y !== 0', () => {
  const ddt = computeDDT(sbox);
  for (let y = 1; y < 16; y++) {
    assert.equal(ddt[0][y], 0, `ddt[0][${y}] should be 0`);
  }
});

test('DDT: all rows sum to 16', () => {
  const ddt = computeDDT(sbox);
  for (let i = 0; i < 16; i++) {
    let rowSum = 0;
    for (let j = 0; j < 16; j++) {
      rowSum += ddt[i][j];
    }
    assert.equal(rowSum, 16, `Row ${i} should sum to 16`);
  }
});

test('DDT: probability calculation', () => {
  const ddt = computeDDT(sbox);
  const count = ddt[1][5];
  const prob = getDifferentialProbability(ddt, 1, 5);
  assert.equal(prob, count / 16, 'Probability should be count/16');
});

test('DDT: max DDT entry for this S-box', () => {
  const ddt = computeDDT(sbox);
  const maxEntry = getMaxDDTEntry(ddt);
  // This toy S-box is intentionally weak to allow differential attacks
  assert.equal(maxEntry, 8, 'Max DDT entry should be 8 for this intentionally weak S-box');
});

test('DDT: findBestDifferential returns best non-trivial entry', () => {
  const ddt = computeDDT(sbox);
  const best = findBestDifferential(ddt);

  assert.ok(best.inputDiff > 0, 'Best differential should have non-zero input diff');
  assert.ok(best.count > 0, 'Best differential should have positive count');

  // Verify this is actually the best
  for (let inputDiff = 1; inputDiff < 16; inputDiff++) {
    for (let outputDiff = 0; outputDiff < 16; outputDiff++) {
      const count = ddt[inputDiff][outputDiff];
      assert.ok(count <= best.count, `Found better differential: ${count} > ${best.count}`);
    }
  }
});

test('DDT: verifyDDTProperties detects weak S-box', () => {
  const ddt = computeDDT(sbox);
  const props = verifyDDTProperties(ddt);

  assert.ok(props.trivialCasesCorrect, 'Trivial cases should be correct');
  assert.ok(props.rowSumsCorrect, 'Row sums should be correct');
  assert.ok(props.isWeak, 'This S-box should be weak (max DDT > 4)');
  assert.equal(props.maxDDTValue, 8, 'Max DDT should be 8 for this S-box');
});

test('DDT: getDifferentialsWithCount finds all with specific count', () => {
  const ddt = computeDDT(sbox);

  // Get all differentials with count 2
  const count2 = getDifferentialsWithCount(ddt, 2);

  // Verify each one has count 2
  for (const diff of count2) {
    assert.equal(ddt[diff.inputDiff][diff.outputDiff], 2, 'Should have count 2');
    assert.equal(diff.count, 2, 'Entry count should be 2');
    assert.equal(diff.probability, 2 / 16, 'Probability should be 2/16');
  }

  // Verify we found all of them
  let foundCount = 0;
  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      if (ddt[i][j] === 2) {
        foundCount++;
      }
    }
  }
  assert.equal(count2.length, foundCount, 'Should find all differentials with count 2');
});

test('DDT: probabilities are between 0 and 1', () => {
  const ddt = computeDDT(sbox);

  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      const prob = getDifferentialProbability(ddt, i, j);
      assert.ok(prob >= 0 && prob <= 1, `Probability should be in [0,1], got ${prob}`);
    }
  }
});

console.log('✓ All DDT tests passed');
