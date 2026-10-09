import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { collectStructures, attackStructures, decryptEquivalent, DIFFERENCE_A, fromCiphertext, GAMMA, recoverRoundKey, seededWords, verifyEquivalentKey } from '../crypto/feal/attack.js';
import { decrypt4, encrypt4, fealF, fealFk, hex64, join, keySchedule, split } from '../crypto/feal/feal.js';

const KEY = 0x0123456789ABCDEFn;

test('FEAL-4 known answer and four-block ECB cross-check against an independent byte port', () => {
  const vectors = [
    ['0000000000000000', 'D88C4EF31769F53E'], // CrypTool 2 cross-implementation value
    ['0001020304050607', '8FC143FBDB4D5527'],
    ['FEDCBA9876543210', 'C4BF068C15B12B30'],
    ['FFFFFFFFFFFFFFFF', '8C26393071CE33DD'],
  ];
  for (const [plain, cipher] of vectors) {
    assert.equal(hex64(encrypt4(BigInt(`0x${plain}`), KEY)), cipher);
    assert.equal(hex64(decrypt4(BigInt(`0x${cipher}`), KEY)), plain);
  }
  assert.equal(keySchedule(KEY).length, 12);
});

test('CrypTool FEAL-8 KAT checks the shared f and fk primitives', () => {
  // Test-only eight-round wrapper; FEAL-8 is outside the shipped panel.
  let [a, b] = split(KEY), d = 0;
  const subkeys: number[] = [];
  for (let i = 0; i < 8; i++) {
    const next = fealFk(a, b ^ d);
    subkeys.push(next >>> 16, next & 65535);
    d = a; a = b; b = next;
  }
  const w = (i: number) => ((subkeys[i] << 16) | subkeys[i + 1]) >>> 0;
  let left = w(8), right = (w(10) ^ left) >>> 0;
  for (let i = 0; i < 8; i++) {
    const key = ((subkeys[i] >>> 8) << 16) | ((subkeys[i] & 255) << 8);
    [left, right] = [right, (left ^ fealF(right ^ key)) >>> 0];
  }
  assert.equal(hex64(join((right ^ w(12)) >>> 0, (left ^ right ^ w(14)) >>> 0)), 'CEEF2C86F2490752');
});

test('probability-one f difference on 10,000 seeded inputs', () => {
  const next = seededWords(0x91e10da5);
  for (let i = 0; i < 10_000; i++) {
    const x = next();
    assert.equal((fealF(x) ^ fealF(x ^ 0x80800000)) >>> 0, GAMMA);
  }
});

test('zero seed remains deterministic and distinct from the default seed', () => {
  const zeroA = seededWords(0), zeroB = seededWords(0), regular = seededWords(0x12345678);
  assert.equal(zeroA(), zeroB());
  assert.notEqual(seededWords(0)(), regular());
});

test('flipping one bit of the characteristic eliminates the round-4 survivors', () => {
  const structures = collectStructures((p) => encrypt4(p, KEY));
  assert.equal(recoverRoundKey(structures.a.map(fromCiphertext), GAMMA ^ 1, { fEvaluations: 0 }).length, 0);
});

test('oracle-only 20-plaintext attack recovers material that decrypts 64 unseen blocks', async () => {
  let calls = 0;
  const structures = collectStructures((p) => { calls++; return encrypt4(p, KEY); }, 6, 4, 0x12345678);
  assert.equal(calls, 20);
  assert.equal(structures.queried, 20);
  assert.equal(structures.a[0].first.plaintext ^ structures.a[0].second.plaintext, DIFFERENCE_A);
  const report = await attackStructures(structures);
  assert.deepEqual(report.stages.map((s) => s.round), [4, 3, 2, 1]);
  assert.ok(report.stages.every((s) => s.survivors > 0));
  assert.ok(report.fEvaluations > 0);
  const next = seededWords(0xa5a5a5a5);
  const fresh = Array.from({ length: 64 }, () => { const plaintext = join(next(), next()); return { plaintext, ciphertext: encrypt4(plaintext, KEY) }; });
  const seen = new Set([...structures.a, ...structures.b].flatMap((pair) => [pair.first.plaintext, pair.second.plaintext]));
  assert.ok(fresh.every((sample) => !seen.has(sample.plaintext)));
  const verified = report.candidates.filter((candidate) => verifyEquivalentKey(candidate, fresh));
  assert.ok(verified.length >= 1);
  assert.equal(verified.length, report.candidates.length); // every full survivor was checked
  assert.equal(decryptEquivalent(fresh[0].ciphertext, verified[0]), fresh[0].plaintext);
  assert.equal(verifyEquivalentKey(verified[0], fresh.slice(0, 63)), false);
  const altered = fresh.map((sample, i) => i === 0 ? { ...sample, ciphertext: sample.ciphertext ^ 1n } : sample);
  const verificationWork = { fEvaluations: 0 };
  assert.equal(verifyEquivalentKey(verified[0], altered, verificationWork), false);
  assert.equal(verificationWork.fEvaluations, 64 * 4); // all fresh blocks are checked, even after a mismatch
});

test('attack module has no master-key or schedule dependency', () => {
  const source = readFileSync(new URL('../crypto/feal/attack.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /keySchedule|masterKey|encrypt4|decrypt4/);
});
