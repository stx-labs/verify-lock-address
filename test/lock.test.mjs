import assert from 'node:assert/strict';
import test from 'node:test';

import { buildUnlockScript } from '@stacks/bitcoin-staking';
import { bytesToHex, hexToBytes } from '@stacks/common';

import {
  buildMultisigUnlockScript,
  outputScriptToAddress,
  sortKeysBip67,
  verify,
  wshOutputScript,
} from '../docs/src/lock.js';
import { annotate, describeUnlockScript, disassemble, tokenText } from '../docs/src/script-view.js';

// The worked example from the lock-address validation doc: a 1-of-2 multisig on
// bond 106, private-1. Every published intermediate value is pinned here.
const KEY1 = '032bfc45f5dec5ba404da7ca12d3120dd67350bd72607eec3990bbb31611b454a0';
const KEY2 = '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4';
const STX = 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M';
const UNLOCK_HEX = `5121${KEY1}21${KEY2}52ae`;
const EARLY = '21032853a683729ff79dc33bce675d83892cf0bad4fc15462225de42d7b88ed89292ac';
const OUTPUT = '002023ce763de6bf52096e81e7eea0935e9ba48f223f2f51f8488b17b013bf65ff52';
const ADDRESS = 'bcrt1qy088v00xhafqjm5pulh2py67nwjg7g3l9aglsjytz7cp80m9lafqqkcdvw';

test('multisig unlock script matches the documented 1-of-2 tail', () => {
  assert.equal(bytesToHex(buildMultisigUnlockScript([KEY1, KEY2], 1)), UNLOCK_HEX);
});

test('multisig builder rejects bad thresholds and malformed keys', () => {
  assert.throws(() => buildMultisigUnlockScript([KEY1, KEY2], 3), /threshold 3 is out of range/);
  assert.throws(() => buildMultisigUnlockScript([KEY1, KEY2], 0), /out of range/);
  assert.throws(() => buildMultisigUnlockScript(['04' + KEY1.slice(2)], 1), /start with 02 or 03/);
  assert.throws(() => buildMultisigUnlockScript(['02ab'], 1), /33-byte compressed key/);
});

test('BIP-67 sorts keys lexicographically', () => {
  assert.deepEqual(sortKeysBip67([KEY2, KEY1]), [KEY1, KEY2]);
  // Key order changes the script, and therefore the address.
  assert.notEqual(
    bytesToHex(buildMultisigUnlockScript([KEY2, KEY1], 1)),
    bytesToHex(buildMultisigUnlockScript([KEY1, KEY2], 1))
  );
});

test('describeUnlockScript reads back a multisig tail', () => {
  const d = describeUnlockScript(hexToBytes(UNLOCK_HEX));
  assert.equal(d.kind, 'multisig');
  assert.equal(d.label, '1-of-2');
  assert.equal(d.threshold, 1);
  assert.equal(d.total, 2);
  assert.deepEqual(d.keys, [KEY1, KEY2]);
  assert.equal(d.verify, false);
});

test('describeUnlockScript reads back a single-sig tail', () => {
  const d = describeUnlockScript(buildUnlockScript(KEY1));
  assert.equal(d.kind, 'single');
  assert.equal(d.label, 'single key');
  assert.deepEqual(d.keys, [KEY1]);
});

test('describeUnlockScript flags a VERIFY tail', () => {
  // OP_CHECKSIGVERIFY consumes the boolean the shared OP_VERIFY needs.
  const d = describeUnlockScript(hexToBytes(`21${KEY1}ad`));
  assert.equal(d.kind, 'single');
  assert.equal(d.verify, true);
});

test('disassembly is lossless over the whole lock script', () => {
  const script = hexToBytes(`63025212b16782012088a820${'11'.repeat(32)}88${EARLY}6869${UNLOCK_HEX}`);
  const tokens = disassemble(script);
  const consumed = tokens.reduce((n, t) => {
    if (t.kind === 'push') return n + t.pushHex.length / 2 + t.len;
    return n + 1;
  }, 0);
  assert.equal(consumed, script.length, 'every byte accounted for');
  assert.equal(tokens[0].text, 'OP_IF');
  assert.equal(tokenText(tokens[1]), '4690', 'CLTV height decodes as a ScriptNum');
  assert.equal(tokens[2].text, 'OP_CHECKLOCKTIMEVERIFY');
});

test('a truncated push is surfaced, not thrown', () => {
  const tokens = disassemble(hexToBytes('6321032bfc45'));
  assert.equal(tokens[0].text, 'OP_IF');
  assert.equal(tokens[1].kind, 'bad');
});

test('annotations name the keys by whose they are', () => {
  const early = annotate(disassemble(hexToBytes(EARLY)), 'early');
  assert.match(early[0].cmt, /not yours/);

  const staker = annotate(disassemble(hexToBytes(UNLOCK_HEX)), 'staker', { threshold: 1 });
  assert.match(staker[1].cmt, /your key #1/);
  assert.match(staker[2].cmt, /your key #2/);
  assert.match(staker[0].cmt, /threshold — 1 signature required/);
  assert.match(staker[4].cmt, /m of n/);
});

test('P2WSH address derivation is HRP-driven', () => {
  assert.equal(outputScriptToAddress(OUTPUT, 'bcrt'), ADDRESS);
  assert.ok(outputScriptToAddress(OUTPUT, 'bc').startsWith('bc1q'));
  assert.throws(() => outputScriptToAddress('0020ab', 'bc'), /not a P2WSH output script/);
});

// Live cross-check against private-1. Skipped when the API is unreachable so the
// pure tests still run offline.
test('bond 106 on private-1 reproduces the documented address', async t => {
  const reachable = await fetch('https://api.private-1.hiro.so/v2/pox', { signal: AbortSignal.timeout(8000) })
    .then(r => r.ok)
    .catch(() => false);
  if (!reachable) return t.skip('private-1 API unreachable');

  const result = await verify({
    network: 'private-1',
    bondIndex: 106,
    stxAddress: STX,
    unlockBytes: hexToBytes(UNLOCK_HEX),
    expected: ADDRESS,
  });

  assert.equal(result.earlyUnlockBytes, EARLY);
  assert.equal(result.derivedHeight, 4690);
  assert.equal(result.unlockHeight, 4690);
  assert.equal(result.sdkScript, OUTPUT);
  assert.equal(result.contractScript, OUTPUT);
  assert.equal(result.agree, true);
  assert.equal(result.address, ADDRESS);
  assert.equal(result.comparison.match, true);
  assert.equal(result.tail.label, '1-of-2');
  assert.equal(wshOutputScript(result.lockScript), OUTPUT);

  // The three segments must tile the script exactly — the viewer's offsets depend on it.
  const early = hexToBytes(result.earlyUnlockBytes);
  const headLen = result.lockScript.length - result.unlockBytes.length - 2 - early.length;
  assert.ok(headLen > 0);
  assert.equal(bytesToHex(result.lockScript.slice(headLen, headLen + early.length)), result.earlyUnlockBytes);
  assert.equal(bytesToHex(result.lockScript.slice(headLen + early.length, headLen + early.length + 2)), '6869');
  assert.equal(bytesToHex(result.lockScript.slice(headLen + early.length + 2)), UNLOCK_HEX);
});

test('buildStakerUnlockBytes covers all three input shapes', async () => {
  const { buildStakerUnlockBytes } = await import('../docs/src/lock.js');

  const single = buildStakerUnlockBytes({ mode: 'single', pubkey: KEY1 });
  assert.equal(bytesToHex(single.unlockBytes), `21${KEY1}ac`);
  assert.equal(single.altUnlockBytes, null);

  const multi = buildStakerUnlockBytes({ mode: 'multi', keys: [KEY1, KEY2], threshold: '1', sorted: false });
  assert.equal(bytesToHex(multi.unlockBytes), UNLOCK_HEX);
  assert.equal(multi.altLabel, 'BIP-67 sorted');

  // Sorted and unsorted differ here only if the entered order is not already sorted.
  const reversed = buildStakerUnlockBytes({ mode: 'multi', keys: [KEY2, KEY1], threshold: '1', sorted: true });
  assert.equal(bytesToHex(reversed.unlockBytes), UNLOCK_HEX, 'sorted mode normalises the order');
  assert.equal(bytesToHex(reversed.altUnlockBytes), `5121${KEY2}21${KEY1}52ae`);

  const raw = buildStakerUnlockBytes({ mode: 'raw', rawHex: `0x${UNLOCK_HEX.toUpperCase()}` });
  assert.equal(bytesToHex(raw.unlockBytes), UNLOCK_HEX, '0x prefix and case are tolerated');
});

test('buildStakerUnlockBytes rejects the inputs that would cost money', async () => {
  const { buildStakerUnlockBytes } = await import('../docs/src/lock.js');

  assert.throws(() => buildStakerUnlockBytes({ mode: 'single', pubkey: '' }), /Enter the 33-byte/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'single', pubkey: 'deadbeef' }), /66 hex characters/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'multi', keys: [] }), /Add the public keys/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'multi', keys: [KEY1, KEY1], threshold: '1' }), /appears twice/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'multi', keys: [KEY1], threshold: '2' }), /between 1 and 1/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'raw', rawHex: '' }), /Paste the staker-unlock-bytes/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'raw', rawHex: 'abc' }), /even-length hex/);
  assert.throws(() => buildStakerUnlockBytes({ mode: 'raw', rawHex: 'zzzz' }), /even-length hex/);

  // An off-curve x-coordinate still yields a fundable address whose OP_CHECKSIG
  // can never be satisfied, so the SDK's curve check has to stay in the path.
  assert.throws(
    () => buildStakerUnlockBytes({ mode: 'single', pubkey: `02${'00'.repeat(32)}` }),
    /not a valid secp256k1 point/
  );
});

// The reply shapes Leather actually produces. A BTC-only one is normal, and for a
// multisig staker the principal is the vault's — which the extension cannot know.
const BTC_ONLY = [
  {
    symbol: 'BTC',
    type: 'p2wpkh',
    address: 'bcrt1qvz04jt55sy7a4e9fg447gm2zlmnjck3dhdw5gf',
    publicKey: '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4',
    derivationPath: "m/84'/1'/0'/0/0",
    fingerprint: '48611587',
  },
  {
    symbol: 'BTC',
    type: 'p2tr',
    address: 'bcrt1p3fkam9r2qjqs3k26mhxka9ag9lastgvfy4axucx8ua6tcvh4lwvsuqn3gd',
    publicKey: '029d0db5f341fc661d3f1a1adfd1157b299067922fe04bde8910dfbd3a161540ad',
    tweakedPublicKey: '9d0db5f341fc661d3f1a1adfd1157b299067922fe04bde8910dfbd3a161540ad',
    derivationPath: "m/86'/1'/0'/0/0",
    fingerprint: '48611587',
  },
];

test('a BTC-only reply fills the key and reports the missing principal', async () => {
  const { pickWalletAddresses } = await import('../docs/src/lock.js');
  const p = pickWalletAddresses(BTC_ONLY);

  assert.equal(p.stxAddress, '');
  assert.equal(p.btcPublicKey, KEY2, 'the p2wpkh key wins over the taproot one');
  assert.equal(p.btcAddress, 'bcrt1qvz04jt55sy7a4e9fg447gm2zlmnjck3dhdw5gf');
  assert.equal(p.btcType, 'p2wpkh');
  assert.equal(p.taprootOnly, false);
  assert.deepEqual(p.missing, ['stx']);
  // With no principal to read, the Bitcoin HRP still identifies the chain.
  assert.equal(p.networkGuess, 'private-1');
});

test('an STX-only reply fills the principal and reports the missing key', async () => {
  const { pickWalletAddresses } = await import('../docs/src/lock.js');
  const p = pickWalletAddresses([{ symbol: 'STX', address: STX }]);

  assert.equal(p.stxAddress, STX);
  assert.equal(p.btcPublicKey, '');
  assert.deepEqual(p.missing, ['btc']);
  assert.equal(p.networkGuess, 'private-1');
});

test('a full reply fills both and reads the network off the principal', async () => {
  const { pickWalletAddresses } = await import('../docs/src/lock.js');

  const regtest = pickWalletAddresses([{ symbol: 'STX', address: STX }, ...BTC_ONLY]);
  assert.equal(regtest.stxAddress, STX);
  assert.equal(regtest.btcPublicKey, KEY2);
  assert.deepEqual(regtest.missing, []);
  assert.equal(regtest.networkGuess, 'private-1');

  const main = pickWalletAddresses([
    { symbol: 'STX', address: 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7' },
    { symbol: 'BTC', type: 'p2wpkh', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: KEY1 },
  ]);
  assert.equal(main.networkGuess, 'mainnet');
});

test('a taproot-only reply is flagged rather than silently used', async () => {
  const { pickWalletAddresses } = await import('../docs/src/lock.js');
  const p = pickWalletAddresses([BTC_ONLY[1]]);

  assert.equal(p.taprootOnly, true);
  assert.equal(p.btcPublicKey, BTC_ONLY[1].publicKey, 'still offered, but marked');
  assert.deepEqual(p.missing, ['stx'], 'the key is present; only the principal is not');
});

test('pickWalletAddresses survives junk and older reply shapes', async () => {
  const { pickWalletAddresses } = await import('../docs/src/lock.js');

  assert.deepEqual(pickWalletAddresses([]).missing, ['stx', 'btc']);
  assert.deepEqual(pickWalletAddresses(undefined).missing, ['stx', 'btc']);
  assert.deepEqual(pickWalletAddresses([null, 'nope', 42]).missing, ['stx', 'btc']);
  assert.equal(pickWalletAddresses([]).networkGuess, null);

  // No `symbol` field: entries are identified by the shape of the address.
  const legacy = pickWalletAddresses([
    { address: STX },
    { address: 'bcrt1qvz04jt55sy7a4e9fg447gm2zlmnjck3dhdw5gf', publicKey: KEY1 },
  ]);
  assert.equal(legacy.stxAddress, STX);
  assert.equal(legacy.btcPublicKey, KEY1);
});
