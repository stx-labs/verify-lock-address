import './helpers/offline.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

import { readFileSync } from 'node:fs';

import { sha256 } from '@noble/hashes/sha2.js';
import { createBase58check } from '@scure/base';
import { HDKey } from '@scure/bip32';
import { bytesToHex } from '@stacks/common';

import { descriptorChecksum, MAX_MULTISIG_KEYS, parseMultisigDescriptor } from '../web/src/descriptor.ts';
import {
  buildMultisigUnlockScript,
  buildStakerUnlockBytes,
  checkVault,
  MAX_UNLOCK_BYTES,
  pickWalletAddresses,
} from '../web/src/lock.ts';
import { describeUnlockScript } from '../web/src/script-view.ts';
import { AMBIGUOUS_KEY_ERROR, containsPrivateKey, PRIVATE_KEY_ERROR } from '../web/src/secrets.ts';

const XPUB_A =
  'xpub6BuKrNqTrGfsy8VAAdUW2KCxbHywuSKjg7hZuAXERXDv7GfuxUgUWdVRKNsgujcwdjEHCjaXWouPKi1m5gMgdWX8JpRcyMkrSxPe4Da3Lx8';
const XPUB_B =
  'xpub6C4MQD2bVDTfdnVe5AYKB6gE7BE4yQeKBRgukQ4Hi3phDB5fCYKEAdViQ2n7kZQ1t728QV4wKGgiR5qGigjNNrm5DCGWYUZDRVNWYb8ZWGK';
const TPUB_A =
  'tpubDCGxNcf9ZYdLEvg1cpTbEEYKvR5btppoDkHsFiaNmRyorZLd2hXZf5AFZQxUSEaBRdmBpK6Q3ujS1tWNUYCvWwyRNRAvetR62uz3pGeDYq2';
const TPUB_B =
  'tpubDCRyvSrHCVR7uagVXMXQP21bSJKixo9Nj4HD6x7S3xaaxTkNGmAKK5AYe4ruH4MFg1Z324aorNWm7GKt7YacGJDNGo1pE1DT1SxvJXM9ppX';

const PK_A = '030347be500a8b2707a00e7576c0c527a247cddc6e8363ee51147b8e43b590baa9';
const PK_B = '0347b913aed4ee088b6fea3e9537836a1c8f1b72111cf010af5589d93f3a433f02';
const PK_C = '02e815a71c4214535e1a9b1cffb5798142fd3197e5ccc7cf7b124716ade78ec974';

const DESC_A = `wsh(sortedmulti(2,${XPUB_A}/0/0,${XPUB_B}/0/0))`;
const VAULT_A = 'bc1q2t8hc5ssw5evn22w9ptvuhuux8k39nqn735hqz9yhqr4ttltl5nqfugtpv';
const WITNESS_A = `5221${PK_A}21${PK_B}52ae`;

const DESC_B = `wsh(multi(2,${PK_B},${PK_A},${PK_C}))#3wv0784k`;
const VAULT_B = 'bc1q2g4pgfy5vcaywpjkqa3u3vhxa73nwelhk6wm3fm0pfhaag4mlcvspmj4ue';
const WITNESS_B = `5221${PK_B}21${PK_A}21${PK_C}53ae`;

const DESC_C =
  `wsh(sortedmulti(2,[48611587/48'/1'/0'/2']${TPUB_A}/0/*,[deadbeef/48'/1'/0'/2']${TPUB_B}/0/*))#8ahpc9a3`;
const VAULT_C = 'tb1q2t8hc5ssw5evn22w9ptvuhuux8k39nqn735hqz9yhqr4ttltl5nq757ymr';

const unlockFrom = parsed =>
  buildStakerUnlockBytes({ mode: 'multi', keys: parsed.keys, threshold: parsed.threshold, sorted: parsed.sorted });

test('the BIP-380 checksum matches the reference implementation', () => {
  assert.equal(descriptorChecksum(DESC_A), 'st2fmzu6');
  assert.equal(descriptorChecksum(DESC_B.split('#')[0]), '3wv0784k');
  assert.equal(descriptorChecksum(DESC_C.split('#')[0]), '8ahpc9a3');
});

test("Leather's xpub sortedmulti descriptor reproduces its vault", () => {
  const parsed = parseMultisigDescriptor(DESC_A);
  assert.deepEqual(parsed.keys, [PK_A, PK_B]);
  assert.equal(parsed.threshold, 2);
  assert.equal(parsed.sorted, true);
  assert.equal(parsed.network, 'mainnet');
  assert.deepEqual(parsed.notes, []);

  const { unlockBytes } = unlockFrom(parsed);
  assert.equal(bytesToHex(unlockBytes), WITNESS_A);
  assert.equal(checkVault(unlockBytes, VAULT_A, 'bc').status, 'pass');
});

test('plain multi keeps the descriptor order, and the other order is caught', () => {
  const parsed = parseMultisigDescriptor(DESC_B);
  assert.deepEqual(parsed.keys, [PK_B, PK_A, PK_C]);
  assert.equal(parsed.sorted, false);
  assert.equal(parsed.network, null, 'raw keys say nothing about the chain');

  const { unlockBytes, altUnlockBytes } = unlockFrom(parsed);
  assert.equal(bytesToHex(unlockBytes), WITNESS_B);
  assert.equal(checkVault(unlockBytes, VAULT_B, 'bc').status, 'pass');

  const sorted = buildStakerUnlockBytes({ mode: 'multi', keys: parsed.keys, threshold: 2, sorted: true });
  const v = checkVault(sorted.unlockBytes, VAULT_B, 'bc', sorted.altUnlockBytes);
  assert.equal(v.status, 'fail');
  assert.equal(v.reason, 'other-order');
  assert.ok(altUnlockBytes);
});

test('tpub keys with origins and a wildcard derive at index 0', () => {
  const parsed = parseMultisigDescriptor(DESC_C);
  assert.deepEqual(parsed.keys, [PK_A, PK_B], 'same key material as the xpub fixture');
  assert.equal(parsed.network, 'testnet');
  assert.equal(parsed.notes.length, 1);
  assert.match(parsed.notes[0], /index 0/);
  assert.equal(checkVault(unlockFrom(parsed).unlockBytes, VAULT_C, 'tb').status, 'pass');
});

test('a vault address from another chain is called out as such', () => {
  const { unlockBytes } = unlockFrom(parseMultisigDescriptor(DESC_A));
  const v = checkVault(unlockBytes, VAULT_C, 'bc');
  assert.equal(v.status, 'fail');
  assert.equal(v.reason, 'wrong-network');
});

test('whitespace and case in the pasted text are tolerated', () => {
  const parsed = parseMultisigDescriptor(`  wsh(multi(1,\n  ${PK_A.toUpperCase()}))  `);
  assert.deepEqual(parsed.keys, [PK_A]);
});

test('the descriptors that would build the wrong script are refused', () => {
  const refuse = (d, re) => assert.throws(() => parseMultisigDescriptor(d), re);

  refuse('', /Paste a wsh/);
  refuse(`${DESC_A}#aaaaaaaa`, e => /checksum does not match/.test(e.message) && !e.message.includes('aaaaaaaa'));
  refuse(`${DESC_A}#a#b`, /more than one #/);
  refuse(`sh(wsh(multi(1,${PK_A})))`, /Only wsh\(multi/);
  refuse(`wsh(pk(${PK_A}))`, /Only wsh\(multi/);
  refuse(
    `wsh(and_v(v:or_i(after(900000),and_v(v:hash160(${'00'.repeat(20)}),pk(${PK_C}))),sortedmulti(2,${PK_A},${PK_B})))`,
    /timelocked or hash-locked/
  );
  refuse(
    `wsh(and_v(v:or_i(after(900000),and_v(v:sha256(${'00'.repeat(32)}),pk(${PK_C}))),sortedmulti(2,${PK_A},${PK_B})))`,
    e => e.message === PRIVATE_KEY_ERROR
  );
  refuse(`wsh(multi(3,${PK_A},${PK_B}))`, /threshold 3 is more than the 2/);
  refuse(`wsh(multi(0,${PK_A}))`, /threshold is not a whole number of 1 or more/);
  for (const written of ['0x1', '+1', '1.0', '01.', 'Infinity', '']) {
    refuse(`wsh(multi(${written},${PK_A}))`, /threshold is not a whole number of 1 or more/);
  }
  refuse(`wsh(multi(1e0,${PK_A}))`, e => e.message === PRIVATE_KEY_ERROR, 'hex threshold glued to the key is a key with stray hex to the scanner');
  assert.equal(parseMultisigDescriptor(`wsh(multi(01,${PK_A}))`).threshold, 1, 'plain digits, as Bitcoin Core parses them');
  refuse(`wsh(multi(1,${Array(21).fill(PK_A).join(',')}))`, /between 1 and 20 keys, the descriptor has 21/);
  refuse(`wsh(multi(1,04${'11'.repeat(64)}))`, e => e.message === PRIVATE_KEY_ERROR, 'a 65-byte uncompressed key is free hex to the scanner, refused before the parser names it');
  refuse(`wsh(multi(1,${XPUB_A}/0h/0))`, /hardened step/);
  refuse(`wsh(multi(1,${XPUB_A}/<0;1>/*))`, /Multipath/);
  refuse(`wsh(multi(2,${XPUB_A}/0/0,${TPUB_B}/0/0))`, /mixes mainnet \(xpub\) and testnet \(tpub\)/);
  refuse(`wsh(multi(1,zpub${XPUB_A.slice(4)}/0/0))`, /Key #1 in the descriptor is a SLIP-132 extended key/);
  refuse(`wsh(multi(1,xprv${XPUB_A.slice(4)}/0/0))`, /private key/);
  refuse('wsh(multi(1,nonsense))', /Key #1 in the descriptor is not a public key/);
});

test('an off-curve multisig key is refused like a single-sig one', () => {
  assert.throws(
    () => buildStakerUnlockBytes({ mode: 'multi', keys: [PK_A, `02${'00'.repeat(32)}`], threshold: 1, sorted: true }),
    /not a valid secp256k1 point/
  );
});

test('a Leather policy-account reply yields the vault, not a missing key', () => {
  const p = pickWalletAddresses([{ symbol: 'BTC', type: 'p2wsh', address: VAULT_A, descriptor: DESC_A }]);
  assert.deepEqual(p.vault, { address: VAULT_A, descriptor: DESC_A });
  assert.deepEqual(p.missing, ['stx'], 'the vault stands in for the Bitcoin key');
  assert.equal(p.btcPublicKey, '');
  assert.equal(p.networkGuess, 'mainnet');

  const single = pickWalletAddresses([{ symbol: 'BTC', type: 'p2wpkh', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: PK_A }]);
  assert.equal(single.vault, null);
});

const SEED = new Uint8Array(32).fill(7);
const extendedPrivate = version => HDKey.fromMasterSeed(SEED, { private: version, public: 0x0488b21e }).privateExtendedKey;
const EXTENDED_PRIVATE = {
  xprv: 0x0488ade4,
  yprv: 0x049d7878,
  zprv: 0x04b2430c,
  Yprv: 0x0295b005,
  Zprv: 0x02aa7a99,
  tprv: 0x04358394,
  uprv: 0x044a4e28,
  vprv: 0x045f18bc,
  Uprv: 0x024285b5,
  Vprv: 0x02575048,
};

const b58check = createBase58check(sha256);
const wif = (version, compressed) =>
  b58check.encode(Uint8Array.from([version, ...new Uint8Array(32).fill(0x11), ...(compressed ? [0x01] : [])]));
const WIFS = {
  '5': wif(0x80, false),
  K: wif(0x80, true),
  L: b58check.encode(Uint8Array.from([0x80, ...new Uint8Array(32).fill(0xcc), 0x01])),
  '9': wif(0xef, false),
  c: wif(0xef, true),
};

function assertRefusedWithoutEcho(fn, secret) {
  assert.throws(fn, e => {
    assert.equal(e.message, PRIVATE_KEY_ERROR);
    for (let i = 0; i + 5 <= secret.length; i += 1) {
      assert.ok(!e.message.includes(secret.slice(i, i + 5)), 'no part of the key is echoed');
    }
    return true;
  });
}

test('every extended private key flavour is recognised and refused without echo', () => {
  for (const [prefix, version] of Object.entries(EXTENDED_PRIVATE)) {
    const key = extendedPrivate(version);
    assert.ok(key.startsWith(prefix), `${prefix} encodes as ${key.slice(0, 4)}`);
    assert.equal(containsPrivateKey(key), true, prefix);

    assertRefusedWithoutEcho(() => parseMultisigDescriptor(`wsh(multi(1,${key}/0/0))`), key);
    assertRefusedWithoutEcho(() => parseMultisigDescriptor(`wsh(multi(1,[deadbeef/48'/0'/0'/2']${key}/0/*))`), key);
    assertRefusedWithoutEcho(() => parseMultisigDescriptor(`wsh(multi(1,${key}/0/0))#aaaaaaaa`), key);
    assertRefusedWithoutEcho(() => buildStakerUnlockBytes({ mode: 'single', pubkey: key }), key);
    assertRefusedWithoutEcho(
      () => buildStakerUnlockBytes({ mode: 'multi', keys: [PK_A, key], threshold: 1, sorted: true }),
      key
    );
  }
});

test('WIF private keys are recognised and refused without echo', () => {
  for (const [lead, key] of Object.entries(WIFS)) {
    assert.ok(key.startsWith(lead), `${lead} encodes as ${key[0]}`);
    assert.equal(key.length, lead === '5' || lead === '9' ? 51 : 52);
    assert.equal(containsPrivateKey(key), true, lead);

    assertRefusedWithoutEcho(() => parseMultisigDescriptor(`wsh(multi(2,${PK_A},${key}))`), key);
    assertRefusedWithoutEcho(() => buildStakerUnlockBytes({ mode: 'single', pubkey: ` ${key} ` }), key);
    assertRefusedWithoutEcho(
      () => buildStakerUnlockBytes({ mode: 'multi', keys: [key, PK_B], threshold: 1, sorted: true }),
      key
    );
  }
});

test('public keys and descriptors are not mistaken for private keys', () => {
  for (const pub of [PK_A, XPUB_A, TPUB_A, `zpub${XPUB_A.slice(4)}`, VAULT_A, 'SP2TC7YMDH77T5GP41W6JZK3Q7AJ10ZJ36ZQNGQ79']) {
    assert.equal(containsPrivateKey(pub), false, pub);
  }
  assert.equal(containsPrivateKey(DESC_A), false);
  assert.equal(containsPrivateKey(DESC_C), false);
});

test('an invalid key is named by position, never echoed', () => {
  const junk = 'deadbeefcafe0123456789';
  assert.throws(
    () => buildStakerUnlockBytes({ mode: 'multi', keys: [PK_A, junk], threshold: 1, sorted: true }),
    e => e.message === 'Key #2 is not a 33-byte compressed public key.'
  );
  assert.throws(
    () => parseMultisigDescriptor(`wsh(multi(1,${PK_A},z${junk}))`),
    e => /Key #2 in the descriptor/.test(e.message) && !e.message.includes('deadbeef')
  );
  assert.throws(
    () => parseMultisigDescriptor(`wsh(multi(1,${PK_A},${junk}))`),
    e => e.message === PRIVATE_KEY_ERROR,
    'hex junk glued to a key is a key with stray hex to the scanner, refused before the parser names it'
  );
});

const REFERENCE = JSON.parse(readFileSync(new URL('./fixtures/bitcoinerlab-multisig.json', import.meta.url), 'utf8'));

test('17 to 20 key multisigs build byte for byte what the staking app compiles', () => {
  assert.equal(MAX_MULTISIG_KEYS, 20);
  for (const [policy, witness] of Object.entries(REFERENCE.witnessScripts)) {
    const [m, n] = policy.split('-of-').map(Number);
    const keys = REFERENCE.keys.slice(0, n);
    assert.equal(bytesToHex(buildMultisigUnlockScript(keys, m)), witness, policy);

    const parsed = parseMultisigDescriptor(`wsh(multi(${m},${keys.join(',')}))`);
    assert.deepEqual(parsed.keys, keys);
    assert.equal(parsed.threshold, m);

    const tail = describeUnlockScript(buildMultisigUnlockScript(keys, m));
    assert.equal(tail.label, policy);
    assert.equal(tail.keys.length, n);
  }
  assert.match(REFERENCE.witnessScripts['17-of-17'], /^0111/);
  assert.match(REFERENCE.witnessScripts['20-of-20'], /0114ae$/);
});

test('a 17-key vault builds staker-unlock-bytes; a 20-key one is refused for size like the staking app does', () => {
  const k17 = REFERENCE.keys.slice(0, 17);
  assert.ok(k17.some(k => /^0[23][0-9a-f]{62}01$/.test(k)), 'the fixture holds a real public key shaped like a Stacks private key');
  assert.throws(() => buildStakerUnlockBytes({ mode: 'multi', keys: k17, threshold: 17, sorted: false }), e => e.message === AMBIGUOUS_KEY_ERROR);
  const built = buildStakerUnlockBytes({ mode: 'multi', keys: k17, threshold: 17, sorted: false, confirmAmbiguous: true });
  assert.equal(bytesToHex(built.unlockBytes), REFERENCE.witnessScripts['17-of-17']);
  assert.ok(built.unlockBytes.length <= MAX_UNLOCK_BYTES);

  const k20 = REFERENCE.keys.slice(0, 20);
  const parsed = parseMultisigDescriptor(`wsh(multi(2,${k20.join(',')}))`);
  assert.equal(parsed.keys.length, 20, 'a 20-key descriptor parses');
  assert.throws(
    () => buildStakerUnlockBytes({ mode: 'multi', keys: parsed.keys, threshold: 2, sorted: false, confirmAmbiguous: true }),
    /2-of-20 multisig script is 684 bytes; pox-5 accepts at most 683/
  );
  assert.throws(
    () => buildStakerUnlockBytes({ mode: 'multi', keys: [...k20, PK_A], threshold: 2, sorted: false }),
    /at most 20 keys/
  );
});

const SPACED = `wsh(multi(2, ${PK_A}, ${PK_B}))`;

test('the checksum covers the descriptor exactly as written, spaces included', () => {
  assert.equal(descriptorChecksum(SPACED), '729lpcg2', 'matches @bitcoinerlab/descriptors');

  const parsed = parseMultisigDescriptor(`  ${SPACED}#729lpcg2 `);
  assert.deepEqual(parsed.keys, [PK_A, PK_B]);
  assert.equal(parsed.threshold, 2);

  const strippedSum = descriptorChecksum(SPACED.replace(/\s+/g, ''));
  assert.notEqual(strippedSum, '729lpcg2');
  assert.throws(() => parseMultisigDescriptor(`${SPACED}#${strippedSum}`), /checksum does not match/);
  assert.deepEqual(parseMultisigDescriptor(`${SPACED.replace(/\s+/g, '')}#${strippedSum}`).keys, [PK_A, PK_B]);
});

test('derivation steps outside the unhardened range get the page’s own message, never the library’s or the typed value', () => {
  for (const step of ['2147483648', '4294967295', '4294967296', '99999999999']) {
    assert.throws(
      () => parseMultisigDescriptor(`wsh(multi(1,${XPUB_A}/${step}))`),
      e => /^Key #1 in the descriptor has a derivation step/.test(e.message) && !e.message.includes(step),
      step
    );
  }
  assert.deepEqual(parseMultisigDescriptor(`wsh(multi(1,${XPUB_A}/2147483647))`).keys.length, 1);
});

test('a private key wrapped across lines inside a descriptor is still called a private key', () => {
  for (const key of [WIFS.K, WIFS.c, extendedPrivate(EXTENDED_PRIVATE.xprv)]) {
    for (const sep of ['\n', ' ', '\r\n  ', '\t']) {
      const wrapped = `${key.slice(0, 20)}${sep}${key.slice(20)}`;
      assertRefusedWithoutEcho(() => parseMultisigDescriptor(`wsh(multi(1,${wrapped},${PK_A}))`), key);
    }
  }
});

test('a descriptor longer than any real one is refused before it is scanned', () => {
  assert.throws(() => parseMultisigDescriptor(`wsh(multi(1,${'K'.repeat(20000)}))`), /descriptor field is longer than 16384 characters/);
});
