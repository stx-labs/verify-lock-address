import './helpers/offline.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  assertNoPrivateKey,
  classifySecret,
  containsAmbiguousKey,
  containsPrivateKey,
  MAX_DESCRIPTOR_LENGTH,
  MAX_FIELD_LENGTH,
  PRIVATE_KEY_ERROR,
  privateKeyError,
  screenFields,
  tooLongError,
} from '../web/src/secrets.ts';
import { AMBIGUOUS_PUBKEY, embeddings, PK, PK_C, PK_NO_ZERO, PRIVATE_KEYS, SP, STX, TPUB, XPUB, ZPUB } from './helpers/secrets.mjs';
import { DESCRIPTOR, LOCK_ADDRESS, VAULT } from './helpers/stub-api.mjs';

test('every private-key embedding is detected', () => {
  for (const [kind, key] of Object.entries(PRIVATE_KEYS)) {
    for (const [where, text] of Object.entries(embeddings(key))) {
      assert.equal(containsPrivateKey(text), true, `${kind} ${where}`);
      assert.throws(() => assertNoPrivateKey('', text), e => e.message === PRIVATE_KEY_ERROR, `${kind} ${where}`);
    }
  }
});

test('a key spread over several values or nested arrays is detected', () => {
  assert.equal(containsPrivateKey(['', [PK, [PRIVATE_KEYS.xprv]]]), true);
  assert.throws(() => assertNoPrivateKey(SP, null, undefined, [PK, PRIVATE_KEYS['WIF testnet compressed']]), /private key/);
});

test('public material is never mistaken for a private key', () => {
  const reference = JSON.parse(readFileSync(new URL('./fixtures/bitcoinerlab-multisig.json', import.meta.url), 'utf8'));
  const publics = {
    xpub: XPUB,
    tpub: TPUB,
    zpub: ZPUB,
    'fixture descriptor': DESCRIPTOR,
    'descriptor with origins': `wsh(sortedmulti(2,[48611587/48'/1'/0'/2']${TPUB}/0/*,[deadbeef/48'/0'/0'/2']${XPUB}/0/*))#8ahpc9a3`,
    'pubkey 02/03': PK,
    'pubkey whose x has no zero': PK_NO_ZERO,
    'pubkey starting with c run': PK_C,
    SP: STX[22],
    SM: STX[20],
    ST: STX[26],
    SN: STX[21],
    'contract principal': `${SP}.pox-5`,
    bc1: VAULT,
    'bc1 lock': LOCK_ADDRESS,
    'bc1 upper': LOCK_ADDRESS.toUpperCase(),
    tb1: 'tb1q2t8hc5ssw5evn22w9ptvuhuux8k39nqn735hqz9yhqr4ttltl5nq757ymr',
    bcrt1: 'bcrt1qy088v00xhafqjm5pulh2py67nwjg7g3l9aglsjytz7cp80m9lafqqkcdvw',
    taproot: 'bc1p3fkam9r2qjqs3k26mhxka9ag9lastgvfy4axucx8ua6tcvh4lwvsuqn3gd',
    p2sh: '37Rf1c6VoRDVNBXVuiiqLZdLehvksYa4Ye',
    'fixture keys': reference.keys.join(','),
    'fixture witness scripts': Object.values(reference.witnessScripts).join(''),
    'many xpubs glued': `${XPUB}${TPUB}${ZPUB}${XPUB}`,
  };
  for (const [what, text] of Object.entries(publics)) {
    assert.equal(containsPrivateKey(text), false, what);
    assert.doesNotThrow(() => assertNoPrivateKey(text), what);
  }
});

test('bare 64-hex values and 66-hex values ending in 01 that cannot be public keys are refused outright', () => {
  for (const text of [PK_C.slice(2), `0x${PK_C.slice(2)}`, `${'0b'.repeat(32)}01`, `04${'ab'.repeat(31)}01`, `${'ff'.repeat(32)}01`]) {
    assert.equal(classifySecret(text), 'private', text);
    for (const keyField of [false, true]) {
      assert.deepEqual(screenFields([{ label: 'key #1', value: text, keyField }]), { label: 'key #1', error: privateKeyError('key #1') }, text);
    }
  }
  for (const text of [`0020${PK_C.slice(2)}`, `5120${PK_C.slice(2)}`, PK_C.slice(2, 64), `${PK_C}`]) {
    assert.notEqual(classifySecret(text), 'private', text);
  }
});

test('a raw hex key with stray hex characters glued to it is still refused', () => {
  const key = PK_C.slice(2);
  for (const text of [`0020${key.slice(4)}01`, `5120${key.slice(4)}01`, `0020${key}a`, `a${key}`, `${key}f`, `ab${key}`, `a${key}01`, `ab${key}cd`, `abc${key}de`, `1${key}`.toUpperCase(), `note: 9${key}`]) {
    assert.equal(classifySecret(text), 'private', text);
    for (const keyField of [false, true]) {
      assert.deepEqual(screenFields([{ label: 'f', value: text, keyField }]), { label: 'f', error: privateKeyError('f') }, text);
    }
  }
  for (const text of [`0020${key}`, `5120${key}`.toUpperCase(), PK, PK_C, PK_NO_ZERO, `${PK},${PK_C}`]) {
    assert.equal(classifySecret(text), null, text);
  }
});

test('a 66-hex value starting 02/03 and ending 01 is ambiguous: allowed only in a key field, refused everywhere else', () => {
  assert.equal(classifySecret(AMBIGUOUS_PUBKEY), 'ambiguous');
  assert.equal(containsAmbiguousKey(AMBIGUOUS_PUBKEY), true);
  assert.equal(containsPrivateKey(AMBIGUOUS_PUBKEY), false);
  for (const text of [AMBIGUOUS_PUBKEY, `0x${AMBIGUOUS_PUBKEY}`, AMBIGUOUS_PUBKEY.toUpperCase(), `${AMBIGUOUS_PUBKEY.slice(0, 20)}\u200b${AMBIGUOUS_PUBKEY.slice(20)}`]) {
    assert.equal(screenFields([{ label: 'key #2', value: text, keyField: true }]), null, text);
    for (const label of ['vault address', 'expected address', 'staker principal', 'unlock height override']) {
      assert.deepEqual(screenFields([{ label, value: text }]), { label, error: privateKeyError(label) }, `${label}: ${text}`);
    }
  }
  for (const pub of [PK, PK_C, PK_NO_ZERO]) {
    assert.equal(classifySecret(pub), null, pub);
    assert.equal(screenFields([{ label: 'key #1', value: pub, keyField: true }]), null, pub);
  }
});

test('obfuscated keys are found in every kind of field, key fields included', () => {
  for (const [kind, key] of Object.entries(PRIVATE_KEYS)) {
    for (const [where, text] of Object.entries(embeddings(key))) {
      for (const keyField of [false, true]) {
        const found = screenFields([{ label: 'f', value: text, keyField, max: 4096 }]);
        assert.deepEqual(found, { label: 'f', error: privateKeyError('f') }, `${kind} ${where} keyField=${keyField}`);
      }
    }
  }
});

test('a near-miss key with a broken checksum is not flagged, so the checksum is what decides', () => {
  const key = PRIVATE_KEYS['WIF mainnet compressed'];
  const flipped = key.slice(0, 20) + (key[20] === 'a' ? 'b' : 'a') + key.slice(21);
  assert.equal(containsPrivateKey(flipped), false);
});

test('scanning a long base58 paste stays fast', () => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let seed = 7;
  const junk = Array.from({ length: 20_000 }, () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return alphabet[seed % alphabet.length];
  }).join('');
  const started = Date.now();
  assert.equal(containsPrivateKey(junk), false);
  assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  assert.equal(containsPrivateKey(`${junk}${PRIVATE_KEYS.tprv}${junk}`), true);
});

test('a key split by whitespace or line wrapping is still detected', () => {
  for (const key of Object.values(PRIVATE_KEYS)) {
    for (const sep of ['\n', ' ', '\r\n', '\t  ']) {
      assert.equal(containsPrivateKey(`${key.slice(0, 17)}${sep}${key.slice(17)}`), true, sep);
      assert.equal(containsPrivateKey(`prefix ${key.slice(0, 9)}${sep}${key.slice(9, 40)}${sep}${key.slice(40)} suffix`), true);
    }
  }
});

test('screenFields names the field and bounds the work by length', () => {
  assert.equal(screenFields([{ label: 'expected address', value: LOCK_ADDRESS }]), null);
  assert.deepEqual(screenFields([{ label: 'vault address', value: `x ${PRIVATE_KEYS.xprv}` }]), {
    label: 'vault address',
    error: privateKeyError('vault address'),
  });
  const started = Date.now();
  const found = screenFields([{ label: 'expected address', value: 'K'.repeat(1_000_000) }]);
  assert.ok(Date.now() - started < 200, `took ${Date.now() - started} ms`);
  assert.deepEqual(found, { label: 'expected address', error: tooLongError('expected address', MAX_FIELD_LENGTH) });
  assert.equal(screenFields([{ label: 'descriptor', value: 'K'.repeat(MAX_DESCRIPTOR_LENGTH), max: MAX_DESCRIPTOR_LENGTH }]), null);
  assert.throws(() => assertNoPrivateKey('K'.repeat(MAX_DESCRIPTOR_LENGTH + 1)), /longer than 16384 characters/);
});

test('scanning the largest accepted value of worst-case characters stays quick', () => {
  for (const ch of ['K', '5', 'x']) {
    const started = Date.now();
    assert.equal(containsPrivateKey(ch.repeat(MAX_DESCRIPTOR_LENGTH)), false);
    assert.ok(Date.now() - started < 3000, `${ch}: ${Date.now() - started} ms`);
  }
});
