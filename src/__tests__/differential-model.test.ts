import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { deriveCharacteristic, exactTrails, publicDifferentialModel, distinctPairCount, collectPairs } from '../crypto/attack';
import { generateKey } from '../crypto/spn';

describe('differentials and trails', () => {
  it('sums exact trail counts into each endpoint and counts all inputs', () => {
    for (const master of [0, 0x5a69, 0xffff]) {
      const key = generateKey(master), endpoints = deriveCharacteristic(key, 1), trails = exactTrails(key, 1);
      assert.equal(endpoints.reduce((n, x) => n + x.count, 0), 256);
      for (const end of endpoints) assert.equal(trails.filter(t => t.differences[3] === end.outputDiff).reduce((n, t) => n + t.count, 0), end.count);
    }
  });
  it('public model is normalized, accepts no key and handles zero difference', () => {
    assert.ok(Math.abs(publicDifferentialModel(1).reduce((n, x) => n + x.probability, 0) - 1) < 1e-12);
    assert.deepEqual(publicDifferentialModel(0)[0], { outputDiff: 0, probability: 1, count: 256 });
  });
  it('does not turn repeated observations into fresh data', () => {
    assert.equal(distinctPairCount([{c1: 1, c2: 2}, {c1: 2, c2: 1}, {c1: 1, c2: 2}]), 1);
    assert.ok(distinctPairCount(collectPairs(generateKey(0x5a69), 1, 4000)) <= 128);
  });
});
