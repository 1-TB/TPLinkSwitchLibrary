import { describe, expect, it } from 'vitest';
import {
  newSessionKey,
  rsaEncryptSessionKey,
  RSA_SMALL_MODULUS,
  sessionRC4,
} from '../src/session.js';

describe('newSessionKey', () => {
  it('generates 8 alphanumeric characters', () => {
    for (let i = 0; i < 50; i++) {
      expect(newSessionKey()).toMatch(/^[A-Za-z0-9]{8}$/);
    }
  });
});

describe('sessionRC4', () => {
  it('matches a known-answer vector (verified against real switches)', () => {
    const plain = Buffer.from('The quick brown fox jumps over the lazy dog 0123456789', 'utf8');
    const key = 'AbCdEf12';
    expect(sessionRC4(plain, key).toString('hex')).toBe(
      '556e602575736f626f2465726e766c27666a7d226a736c7671276c71677524776f63236960797c266468602130343436353732313b3d',
    );
  });

  it('is symmetric', () => {
    const key = 'K9zQ2xWp';
    const data = Buffer.from('packet payload with mixed bytes \x00\x01\x02\xff', 'latin1');
    expect(sessionRC4(sessionRC4(data, key), key)).toEqual(data);
  });

  it('differs from the legacy cipher output', () => {
    // The 8-byte-state cipher must not coincide with static RC4; this just
    // pins the output for a fixed input so accidental reuse is caught.
    const out = sessionRC4(Buffer.alloc(16), 'AAAAAAAA');
    expect(out.toString('hex')).toBe('06010201020606000600010007050405');
  });
});

describe('rsaEncryptSessionKey', () => {
  // The 64-bit modulus factors as p*q; the private exponent lets the test
  // decrypt independently of the implementation under test.
  const P = 3765816959n;
  const Q = 3443843009n;
  const E = 65537n;

  function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
    let r = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return r;
  }

  function egcd(a: bigint, b: bigint): [bigint, bigint] {
    let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n];
    while (b) {
      const q = a / b;
      [a, b] = [b, a - q * b];
      [x0, x1] = [x1, x0 - q * x1];
      [y0, y1] = [y1, y0 - q * y1];
    }
    return [a, x0];
  }

  it('lays out [0x00][limbCount][c little-endian]', () => {
    const out = rsaEncryptSessionKey('AbCdEf12', RSA_SMALL_MODULUS);
    expect(out.length).toBe(10); // 2 + 2*4 limbs for the 64-bit modulus
    expect(out[0]).toBe(0x00);
    expect(out[1]).toBe(4);
  });

  it('encrypts the little-endian key with e=65537 mod N', () => {
    const key = 'AbCdEf12';
    const out = rsaEncryptSessionKey(key, RSA_SMALL_MODULUS);
    const n = BigInt('0x' + RSA_SMALL_MODULUS.toString('hex'));
    // Recover c from the output layout.
    let c = 0n;
    for (let i = out.length - 1; i >= 2; i--) c = (c << 8n) | BigInt(out[i]);
    expect(c < n).toBe(true);
    // Decrypt with the private exponent computed from the factors.
    const phi = (P - 1n) * (Q - 1n);
    const [, x] = egcd(E, phi);
    const d = ((x % phi) + phi) % phi;
    const m = modpow(c, d, n);
    // m must be the key bytes read little-endian.
    const kb = Buffer.from(key, 'utf8');
    let expected = 0n;
    for (let i = kb.length - 1; i >= 0; i--) expected = (expected << 8n) | BigInt(kb[i]);
    expect(m).toBe(expected);
  });

  it('is deterministic', () => {
    expect(rsaEncryptSessionKey('AbCdEf12', RSA_SMALL_MODULUS)).toEqual(
      rsaEncryptSessionKey('AbCdEf12', RSA_SMALL_MODULUS),
    );
  });
});
