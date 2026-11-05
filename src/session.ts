// RSA session-key exchange (TLV 528) and session RC4 cipher.
// Ported from markpash/tplink-easysmart go/escp/crypto.go + keys.go, verified
// live against TL-SG108E v6 and TL-SG1024DE v7.

import { randomBytes } from 'node:crypto';

export const RSA_SMALL_MODULUS = Buffer.from('B3FAB9D6646D4EBF', 'hex');
export const RSA_BIG_MODULUS = Buffer.from(
  'E5DDBB5F41342937AA6DB4E4ABE145251A9131B2983BC9CA3FF6E228C5C54DA460A232EAE97D5C9012E7D11669EB7003F6A65264F116294BD6C7897C62D2937DC5EB0D3F044251BA40F4E24E411C5F6C7B669594034B2288F72F161052344C18F94A33FB90ACF9B1D9BA984733A2D760DBD7C5BA8C87ACA281197E7BE7CC1A1D',
  'hex',
);
/** Reply error code acknowledging the RSA session key. */
export const RSA_OK = 4098;

const SESSION_KEY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Random 8-character alphanumeric session key, same shape as the official utility. */
export function newSessionKey(): string {
  const b = randomBytes(8);
  let out = '';
  for (const byte of b) out += SESSION_KEY_ALPHABET[byte % SESSION_KEY_ALPHABET.length];
  return out;
}

/**
 * Session transport cipher: RC4 over an 8-byte S-box keyed by the session key.
 * Applied to the whole packet after the RSA handshake (TLV 528) succeeds.
 */
export function sessionRC4(data: Buffer, key: string): Buffer {
  const n = 8;
  const s = Array.from({ length: n }, (_, i) => i);
  const kb = Buffer.from(key, 'utf8');
  let j = 0;
  for (let i = 0; i < n; i++) {
    j = (j + s[i] + kb[i % kb.length]) % n;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = Buffer.alloc(data.length);
  let i = 0;
  let jj = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) % n;
    jj = (jj + s[i]) % n;
    [s[i], s[jj]] = [s[jj], s[i]];
    out[k] = data[k] ^ s[(s[i] + s[jj]) % n];
  }
  return out;
}

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

/**
 * RSA-encrypt the session key for the TLV 528 handshake.
 * m = key bytes read little-endian, c = m^65537 mod N,
 * output = [0x00][limbCount][c little-endian, limbCount*2 bytes].
 */
export function rsaEncryptSessionKey(key: string, modulus: Buffer): Buffer {
  const kb = Buffer.from(key, 'utf8');
  let m = 0n;
  for (let i = kb.length - 1; i >= 0; i--) m = (m << 8n) | BigInt(kb[i]);
  const n = BigInt('0x' + modulus.toString('hex'));
  const c = modpow(m, 65537n, n);
  const limbs = modulus.length / 2;
  const out = Buffer.alloc(2 + 2 * limbs);
  out[0] = 0x00;
  out[1] = limbs;
  let cb = c;
  for (let i = 0; i < 2 * limbs; i++) {
    out[2 + i] = Number(cb & 0xffn);
    cb >>= 8n;
  }
  return out;
}
