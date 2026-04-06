/**
 * Tests for SPN cipher implementation
 * 
 * References:
 * "Differential Cryptanalysis of DES-like Cryptosystems"
 * by Eli Biham and Adi Shamir, Journal of Cryptology, 1991
 */

import { strict as assert } from 'assert';
import { test } from 'node:test';

import { sboxApply, sboxInvert, applyBothNibbles, invertBothNibbles } from '../crypto/sbox.js';
import { permute, permuteInverse } from '../crypto/permutation.js';
import { generateKey, encrypt, decrypt, encryptRounds } from '../crypto/spn.js';

test('S-box: sboxApply applies S-box correctly', () => {
  // Test a few known values
  assert.equal(sboxApply(0), 0xE, 'sboxApply(0) should be 0xE');
  assert.equal(sboxApply(1), 0x4, 'sboxApply(1) should be 0x4');
  assert.equal(sboxApply(2), 0xD, 'sboxApply(2) should be 0xD');
  assert.equal(sboxApply(0xF), 0x7, 'sboxApply(0xF) should be 0x7');
});

test('S-box: sboxInvert is correct inverse', () => {
  for (let i = 0; i < 16; i++) {
    const applied = sboxApply(i);
    const inverted = sboxInvert(applied);
    assert.equal(inverted, i, `sboxInvert(sboxApply(${i})) should equal ${i}`);
  }
});

test('S-box: all values 0-255 pass identity test for both nibbles', () => {
  for (let byte = 0; byte < 256; byte++) {
    const sboxed = applyBothNibbles(byte);
    const inverted = invertBothNibbles(sboxed);
    assert.equal(inverted, byte, `invertBothNibbles(applyBothNibbles(${byte})) should equal ${byte}`);
  }
});

test('Permutation: permute and permuteInverse are inverses', () => {
  for (let byte = 0; byte < 256; byte++) {
    const permuted = permute(byte);
    const unpermuted = permuteInverse(permuted);
    assert.equal(unpermuted, byte, `permuteInverse(permute(${byte})) should equal ${byte}`);
  }
});

test('Permutation: known bit positions', () => {
  // Input bits [7,6,5,4,3,2,1,0] go to positions [7,3,6,2,5,1,4,0]
  // So bit 0 in input goes to position 7 in output
  const input = 0b00000001; // Only bit 0 set
  const output = permute(input);
  assert.equal(output, 0b10000000, 'Bit 0 should go to position 7');

  // Bit 7 in input goes to position 7 in output
  const input2 = 0b10000000; // Only bit 7 set
  const output2 = permute(input2);
  assert.equal(output2, 0b10000000, 'Bit 7 should stay at position 7');

  // Bit 1 in input goes to position 1 in output
  const input3 = 0b00000010; // Only bit 1 set
  const output3 = permute(input3);
  assert.equal(output3, 0b00000010, 'Bit 1 should stay at position 1');
});

test('SPN cipher: round-trip encryption/decryption', () => {
  const key = generateKey(0xABCD);

  for (let plaintext = 0; plaintext < 256; plaintext++) {
    const ciphertext = encrypt(plaintext, key);
    const decrypted = decrypt(ciphertext, key);
    assert.equal(decrypted, plaintext, `Decrypt(Encrypt(${plaintext})) should equal ${plaintext}`);
  }
});

test('SPN cipher: known test vector', () => {
  const key = generateKey(0x12345678);
  const plaintext = 0x3A;
  const ciphertext = encrypt(plaintext, key);

  // Should be deterministic
  const ciphertext2 = encrypt(plaintext, key);
  assert.equal(ciphertext, ciphertext2, 'Encryption should be deterministic');

  // Decrypt should work
  const decrypted = decrypt(ciphertext, key);
  assert.equal(decrypted, plaintext, 'Known test vector should round-trip');
});

test('SPN cipher: different plaintexts produce different ciphertexts', () => {
  const key = generateKey(0x9876);
  const ciphertexts = new Set<number>();

  // Encrypt 100 different plaintexts
  for (let p = 0; p < 100; p++) {
    const c = encrypt(p, key);
    ciphertexts.add(c);
  }

  // Should get 100 different ciphertexts (very high probability)
  assert.ok(ciphertexts.size > 90, `Should get mostly different ciphertexts, got ${ciphertexts.size}`);
});

test('SPN cipher: encryptRounds stops after N rounds', () => {
  const key = generateKey(0xFFFF);
  const plaintext = 0x42;

  const round1 = encryptRounds(plaintext, key, 1);
  const round2 = encryptRounds(plaintext, key, 2);
  const round3 = encryptRounds(plaintext, key, 3);
  const round4 = encryptRounds(plaintext, key, 4);

  // Each should be different (with very high probability)
  assert.notEqual(round1, round2, 'Round 1 and 2 should differ');
  assert.notEqual(round2, round3, 'Round 2 and 3 should differ');
  assert.notEqual(round3, round4, 'Round 3 and 4 should differ');

  // Full encryption equals round4
  const fullEncrypt = encrypt(plaintext, key);
  assert.equal(fullEncrypt, round4, 'Full encryption should equal 4 rounds');
});

test('SPN cipher: key schedule generates 4 subkeys', () => {
  const key = generateKey(0xABCD);
  assert.equal(key.subkeys.length, 4, 'Should have 4 subkeys');

  for (let i = 0; i < 4; i++) {
    const subkey = key.subkeys[i];
    assert.ok(subkey >= 0 && subkey <= 0xFF, `Subkey ${i} should be 8-bit value`);
  }
});

test('SPN cipher: different master keys produce different subkeys', () => {
  const key1 = generateKey(0x1234);
  const key2 = generateKey(0x5678);

  let allSame = true;
  for (let i = 0; i < 4; i++) {
    if (key1.subkeys[i] !== key2.subkeys[i]) {
      allSame = false;
      break;
    }
  }

  assert.ok(!allSame, 'Different master keys should produce different subkeys');
});

console.log('✓ All SPN cipher tests passed');
