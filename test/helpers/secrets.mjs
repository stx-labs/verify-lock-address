import { sha256 } from '@noble/hashes/sha2.js';
import { createBase58check } from '@scure/base';
import { bytesToHex, hexToBytes } from '@stacks/common';
import { addressFromVersionHash, addressToString, privateKeyToPublic } from '@stacks/transactions';

const b58check = createBase58check(sha256);

const SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff);
const wif = (version, compressed) => b58check.encode(Uint8Array.from([version, ...SECRET, ...(compressed ? [0x01] : [])]));

const CHAIN_CODE = Uint8Array.from({ length: 32 }, (_, i) => (i * 53 + 7) & 0xff);
const PARENT_FINGERPRINT = [0x48, 0x61, 0x15, 0x87];
const HARDENED_2 = [0x80, 0x00, 0x00, 0x02];
const be32 = n => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const serialize = (version, key) =>
  b58check.encode(Uint8Array.from([...be32(version), 4, ...PARENT_FINGERPRINT, ...HARDENED_2, ...CHAIN_CODE, ...key]));
const extendedPrivate = version => serialize(version, [0x00, ...SECRET]);
const extendedPublic = version => serialize(version, hexToBytes(privateKeyToPublic(`${bytesToHex(SECRET)}01`)));

export const PRIVATE_KEYS = {
  'WIF mainnet compressed': wif(0x80, true),
  'WIF mainnet uncompressed': wif(0x80, false),
  'WIF testnet compressed': wif(0xef, true),
  'WIF testnet uncompressed': wif(0xef, false),
  xprv: extendedPrivate(0x0488ade4),
  tprv: extendedPrivate(0x04358394),
  zprv: extendedPrivate(0x04b2430c),
  'Stacks hex private key': `${bytesToHex(SECRET)}01`,
  'bare 64-hex secret': bytesToHex(SECRET),
};

export const AMBIGUOUS_PUBKEY = '022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01';

const fullwidth = text => text.replace(/[\x21-\x7e]/g, ch => String.fromCharCode(ch.charCodeAt(0) + 0xfee0));
const every = (text, n, sep) => text.match(new RegExp(`.{1,${n}}`, 'g')).join(sep);

export function obfuscations(key) {
  return {
    'zero-width split': every(key, 9, '​'),
    'word-joiner split': every(key, 11, '⁠'),
    'soft-hyphen split': every(key, 7, '­'),
    'BOM inside': `${key.slice(0, 5)}﻿${key.slice(5)}`,
    'hyphen split': every(key, 8, '-'),
    'dot and colon split': every(key, 6, '.').replace(/\./g, (m, i) => (i % 2 ? ':' : '.')),
    'full width (NFKC)': fullwidth(key),
    'full width and zero-width': every(fullwidth(key), 10, '‌'),
  };
}

export const XPUB = extendedPublic(0x0488b21e);
export const TPUB = extendedPublic(0x043587cf);
export const ZPUB = extendedPublic(0x04b24746);

const HASH = 'a46ff88886c2ef9762d970b4d2c63678835bd39d';
export const STX = Object.fromEntries([22, 20, 26, 21].map(v => [v, addressToString(addressFromVersionHash(v, HASH))]));
export const SP = STX[22];

export const PK = '030347be500a8b2707a00e7576c0c527a247cddc6e8363ee51147b8e43b590baa9';
export const PK_NO_ZERO = '0259dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e';
export const PK_C = '03cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26';

export const JUNK = 'zzKLc95jJhHgGfF4xXprvtprv9cK5L';

export function embeddings(key) {
  if (/^[0-9a-f]+$/.test(key)) {
    return {
      bare: key,
      quoted: `"${key}"`,
      'single-quoted': `'${key}'`,
      padded: `   ${key}\n`,
      '0x prefix': `0x${key}`,
      'upper case': key.toUpperCase(),
      descriptor: `wsh(multi(2,${key},${PK}))`,
      json: JSON.stringify({ wallet: 'x', key }),
      'url query': `https://example.invalid/import?k=${key}&net=main`,
      ...obfuscations(key),
    };
  }
  const inDescriptor = key.length === 111
    ? `wsh(multi(2,[d34db33f/48'/0'/0'/2']${key}/0/*,${XPUB}/0/*))`
    : `wsh(multi(2,${key},${PK}))`;
  return {
    bare: key,
    quoted: `"${key}"`,
    'single-quoted': `'${key}'`,
    'padded': `   ${key}\n`,
    'contract principal': `${SP}.${key}`,
    'glued to a principal': `${SP}${key}`,
    descriptor: inDescriptor,
    'descriptor with checksum': `${inDescriptor}#abcdefgh`,
    json: JSON.stringify({ wallet: 'x', key }),
    'url query': `https://example.invalid/import?k=${key}&net=main`,
    'base58 junk around': `${JUNK}${key}${JUNK}`,
    'base58 junk before': `${JUNK}${key}`,
    'base58 junk after': `${key}${JUNK}`,
    ...obfuscations(key),
  };
}
