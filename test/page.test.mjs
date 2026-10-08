import { live } from './helpers/offline.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test, { before } from 'node:test';

import { bech32 } from '@scure/base';
import { hexToBytes } from '@stacks/common';
import { JSDOM } from 'jsdom';

import { NETWORKS } from '../web/src/lock.ts';
import { deadlineError, isTransient, reachable, skipOnTransient } from './helpers/live.mjs';
import { AMBIGUOUS_PUBKEY, embeddings, PRIVATE_KEYS } from './helpers/secrets.mjs';
import {
  ALLOWLISTED,
  BOND_2_EARLY,
  BOND_2_HEIGHT,
  DESCRIPTOR,
  LOCK_ADDRESS as MULTI_LOCK_ADDRESS,
  NOT_LISTED,
  VAULT,
  contractLockupOutputScript,
  stubApi,
} from './helpers/stub-api.mjs';

const root = new URL('../', import.meta.url);
const path = rel => fileURLToPath(new URL(rel, root));

const KEY1 = '032bfc45f5dec5ba404da7ca12d3120dd67350bd72607eec3990bbb31611b454a0';
const KEY2 = '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4';
const STX = 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M';
const ADDRESS = 'bcrt1qy088v00xhafqjm5pulh2py67nwjg7g3l9aglsjytz7cp80m9lafqqkcdvw';

const LIVE_PAGE_TIMEOUT_MS = 45_000;

const pageError = (message, name, code) =>
  Object.assign(new Error(message), { name: name || 'Error', cause: code ? Object.assign(new Error(code), { code }) : undefined });

let bundle;

before(() => {
  execFileSync('npm', ['run', 'build:test'], { cwd: path('.'), stdio: 'pipe' });
  bundle = readFileSync(path('.tmp/app.iife.js'), 'utf8');
});

function loadPage() {
  const html = readFileSync(path('web/index.html'), 'utf8').replace(
    '<script type="module" src="app.js"></script>',
    ''
  );
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    beforeParse(w) {
      w.matchMedia = () => ({ matches: false, addEventListener() {} });
    },
  });
  const { window } = dom;
  window.fetch = (...args) => fetch(...args);
  window.HTMLElement.prototype.scrollIntoView = () => {};
  const errors = [];
  window.addEventListener('error', e => errors.push(e.error ?? e.message));
  window.eval(bundle);
  return { window, doc: window.document, errors };
}

const click = (doc, id) => doc.getElementById(id).dispatchEvent(new doc.defaultView.Event('click', { bubbles: true }));

function setValue(doc, id, value) {
  const el = doc.getElementById(id);
  el.value = value;
  el.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
}

const checksText = doc => doc.getElementById('checks').textContent.replace(/\s+/g, ' ');

test('the page boots without errors, offering the single-key flow', () => {
  const { doc, errors } = loadPage();
  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('results').hidden, true);
  assert.equal(doc.getElementById('netBadgeText').textContent, 'private-1');
  assert.equal(doc.getElementById('paneSingle').hidden, false, 'single key is the default');
  assert.equal(doc.getElementById('paneMulti').hidden, true);
  assert.equal(doc.querySelectorAll('#keyList input').length, 2, 'multisig starts with two empty key rows');

  for (const gone of ['paneRaw', 'rawHex']) {
    assert.equal(doc.getElementById(gone), null, `#${gone} should no longer be in the page`);
  }
});

test('the network selector drives the badge and the placeholder', () => {
  const { doc } = loadPage();
  const sel = doc.getElementById('network');
  sel.value = 'mainnet';
  sel.dispatchEvent(new doc.defaultView.Event('change', { bubbles: true }));

  assert.equal(doc.getElementById('netBadgeText').textContent, 'mainnet');
  assert.match(doc.getElementById('netBadge').className, /badge-main/);
  assert.match(doc.getElementById('expected').placeholder, /^bc1…/);
});

test('form validation refuses to run on incomplete input', () => {
  const { doc } = loadPage();
  click(doc, 'verifyBtn');
  assert.equal(doc.getElementById('formErr').hidden, false);
  assert.match(doc.getElementById('formErr').textContent, /bond index/);

  setValue(doc, 'bondIndex', '106');
  click(doc, 'verifyBtn');
  assert.match(doc.getElementById('formErr').textContent, /Stacks address/);

  setValue(doc, 'stxAddress', STX);
  setValue(doc, 'pubkey', 'not-a-key');
  click(doc, 'verifyBtn');
  assert.match(doc.getElementById('formErr').textContent, /66 hex characters/);
});

test('a mainnet address on private-1 is caught before anything is funded', () => {
  const { doc } = loadPage();
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7');
  setValue(doc, 'pubkey', KEY1);
  assert.equal(doc.getElementById('formErr').hidden, true);
});

test('a full verification renders end to end', async t => {
  if (!(await reachable(t, `${NETWORKS['private-1'].api}/v2/pox`))) return;

  const { verify } = await import('../web/src/lock.ts');
  const { buildUnlockScript } = await import('@stacks/bitcoin-staking');
  const ran = await skipOnTransient(t, () => live(async () => {
    const expected = await verify({
      network: 'private-1',
      bondIndex: 106,
      stxAddress: STX,
      unlockBytes: buildUnlockScript(KEY1),
    });

    const page = loadPage();
    const { doc } = page;
    setValue(doc, 'bondIndex', '106');
    setValue(doc, 'stxAddress', STX);
    setValue(doc, 'pubkey', KEY1);
    setValue(doc, 'expected', expected.address);
    click(doc, 'verifyBtn');

    const deadline = Date.now() + LIVE_PAGE_TIMEOUT_MS;
    while (Date.now() < deadline && doc.getElementById('results').hidden && doc.getElementById('formErr').hidden) {
      await new Promise(r => setTimeout(r, 100));
    }
    if (doc.getElementById('results').hidden && doc.getElementById('formErr').hidden) {
      throw deadlineError(LIVE_PAGE_TIMEOUT_MS);
    }
    const formErr = doc.getElementById('formErr');
    if (!formErr.hidden) throw pageError(formErr.textContent, formErr.dataset.errorName, formErr.dataset.errorCode);
    return { ...page, expected };
  }));
  if (!ran) return;
  const { doc, errors, expected } = ran;
  assert.equal(expected.agree, true);

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').textContent);
  assert.equal(doc.getElementById('results').hidden, false);
  assert.equal(doc.getElementById('addrText').textContent, expected.address);
  assert.ok(expected.address.startsWith('bcrt1q'));
  assert.equal(doc.getElementById('verdictMark').textContent, '✓');
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Match — this is the address to fund');
  assert.match(checksText(doc), /The SDK and pox-5 derive the same output script/);
  assert.match(checksText(doc), /The address you supplied matches/);
  assert.equal(doc.getElementById('tPolicy').textContent, 'single key');
  assert.equal(doc.getElementById('tHeight').textContent, '4690');
  assert.match(doc.getElementById('asmOut').textContent, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(doc.getElementById('asmOut').textContent, /your key #1/);
  assert.match(doc.getElementById('asmOut').textContent, /final authorisation — one signature/);
  assert.equal(doc.getElementById('paneLoading').hidden, true);
  assert.equal(doc.getElementById('verifyBtn').disabled, false);

  click(doc, 'toggleHex');
  assert.equal(doc.getElementById('rawHexOut').hidden, false);
  assert.match(doc.getElementById('rawHexOut').textContent, /^63/);
});

function withLeather(window, addresses) {
  const seen = [];
  window.LeatherProvider = {
    request: async (method, params) => {
      assert.equal(method, 'getAddresses');
      seen.push(params);
      return { jsonrpc: '2.0', id: 'test', result: { addresses } };
    },
  };
  return seen;
}

const settle = () => new Promise(r => setTimeout(r, 20));

const BTC_ONLY = [
  {
    symbol: 'BTC',
    type: 'p2wpkh',
    address: 'bcrt1qvz04jt55sy7a4e9fg447gm2zlmnjck3dhdw5gf',
    publicKey: KEY2,
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

test('a BTC-only wallet reply connects and says what is still needed', async () => {
  const { doc, window, errors } = loadPage();
  withLeather(window, BTC_ONLY);

  click(doc, 'connectBtn');
  await settle();

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true, 'a partial reply is not an error');
  assert.equal(doc.getElementById('pubkey').value, KEY2, 'the p2wpkh key is filled in');
  assert.equal(doc.getElementById('stxAddress').value, '', 'the principal stays empty and typeable');
  assert.ok(!doc.getElementById('stxAddress').className.includes('prefilled'));

  const note = doc.getElementById('walletNote');
  assert.equal(note.hidden, false);
  assert.match(note.textContent, /no Stacks address/);
  assert.match(note.textContent, /the Stacks principal the staking app will register with/);
  assert.match(note.textContent, /single-key SP… \(mainnet\) \/ ST… \(private-1\) address/);
  assert.match(note.textContent, /multisig vault has no Stacks principal/);
  assert.doesNotMatch(note.textContent, /SM…\/SN…/);
  assert.doesNotMatch(note.textContent, /no Bitcoin public key/);

  assert.equal(doc.getElementById('network').value, 'private-1');
  assert.equal(doc.getElementById('walletBadge').hidden, false);
  assert.equal(doc.getElementById('connectBtn').hidden, true);

  window.fetch = stubApi({ network: 'private-1', bonds: [106] }).fetch;
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', STX);
  await runVerify(doc);
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').textContent);
});

test('an STX-only wallet reply connects and asks for the key', async () => {
  const { doc, window, errors } = loadPage();
  withLeather(window, [{ symbol: 'STX', address: STX }]);

  click(doc, 'connectBtn');
  await settle();

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true);
  assert.equal(doc.getElementById('stxAddress').value, STX);
  assert.equal(doc.getElementById('pubkey').value, '');
  assert.match(doc.getElementById('walletNote').textContent, /no Bitcoin public key/);
  assert.match(doc.getElementById('walletNote').textContent, /paste the compressed key/i);
  assert.equal(doc.getElementById('network').value, 'private-1');
});

test('a complete reply fills both and shows no notice', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [{ symbol: 'STX', address: STX }, ...BTC_ONLY]);

  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('stxAddress').value, STX);
  assert.equal(doc.getElementById('pubkey').value, KEY2);
  assert.equal(doc.getElementById('walletNote').hidden, true, 'nothing missing, nothing to say');
});

test('a mainnet reply flips the network selector', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [
    { symbol: 'STX', address: 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7' },
    { symbol: 'BTC', type: 'p2wpkh', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: KEY1 },
  ]);

  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('network').value, 'mainnet');
  assert.equal(doc.getElementById('netBadgeText').textContent, 'mainnet');
});

test('an empty wallet reply is the one case that is an error', async () => {
  const { doc, window } = loadPage();
  withLeather(window, []);

  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('formErr').hidden, false);
  assert.match(doc.getElementById('formErr').textContent, /neither a Stacks address nor a Bitcoin public key/);
  assert.equal(doc.getElementById('connectBtn').hidden, false, 'still connectable after a failure');
  assert.equal(doc.getElementById('connectBtn').disabled, false);
});

test('no extension at all gives an actionable message', async () => {
  const { doc } = loadPage();
  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('formErr').hidden, false);
  assert.match(doc.getElementById('formErr').textContent, /Leather was not detected/);
});

test('disconnect clears the fields and the notice', async () => {
  const { doc, window } = loadPage();
  withLeather(window, BTC_ONLY);

  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('walletNote').hidden, false);

  click(doc, 'disconnectBtn');
  assert.equal(doc.getElementById('pubkey').value, '');
  assert.equal(doc.getElementById('walletNote').hidden, true);
  assert.equal(doc.getElementById('walletBadge').hidden, true);
  assert.equal(doc.getElementById('connectBtn').hidden, false);
});

const lockAddress = (staker, pubkey) => {
  const output = contractLockupOutputScript({
    staker,
    unlockHeight: BOND_2_HEIGHT,
    stakerUnlockHex: `21${pubkey}ac`,
    earlyUnlockHex: BOND_2_EARLY,
  });
  return bech32.encode('bc', [0, ...bech32.toWords(hexToBytes(output.slice(4)))]);
};

const LOCK_ADDRESS = lockAddress(ALLOWLISTED, KEY1);

const VAULT_KEYS = [
  '030347be500a8b2707a00e7576c0c527a247cddc6e8363ee51147b8e43b590baa9',
  '0347b913aed4ee088b6fea3e9537836a1c8f1b72111cf010af5589d93f3a433f02',
];
const STRANGER = '02e815a71c4214535e1a9b1cffb5798142fd3197e5ccc7cf7b124716ade78ec974';

const POLICY_REPLY = [{ symbol: 'BTC', type: 'p2wsh', address: VAULT, descriptor: DESCRIPTOR }];

const keyInputs = doc => Array.from(doc.querySelectorAll('#keyList input'));

async function runVerify(doc) {
  click(doc, 'verifyBtn');
  for (let i = 0; i < 100 && doc.getElementById('results').hidden && doc.getElementById('formErr').hidden; i += 1) {
    await new Promise(r => setTimeout(r, 20));
  }
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').textContent);
  assert.equal(doc.getElementById('results').hidden, false);
}

test('a Leather account fills the single key and verifies', async () => {
  const { doc, window, errors } = loadPage();
  withLeather(window, [
    { symbol: 'STX', address: ALLOWLISTED },
    { symbol: 'BTC', type: 'p2wpkh', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: KEY1 },
  ]);
  window.fetch = stubApi().fetch;

  click(doc, 'connectBtn');
  await settle();

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true);
  assert.equal(doc.getElementById('stxAddress').value, ALLOWLISTED);
  assert.equal(doc.getElementById('pubkey').value, KEY1);
  assert.ok(['stxAddress', 'pubkey'].every(id => doc.getElementById(id).classList.contains('prefilled')));
  assert.equal(doc.getElementById('network').value, 'mainnet', 'the Stacks address decides the chain');
  assert.equal(doc.getElementById('walletNote').hidden, true);

  setValue(doc, 'bondIndex', '2');
  await runVerify(doc);

  assert.notEqual(doc.getElementById('addrText').textContent, LOCK_ADDRESS, 'withheld until the wallet destination is pasted');
  assert.ok(!doc.body.textContent.includes(LOCK_ADDRESS));
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Not compared — paste the destination from your wallet');
  assert.equal(doc.getElementById('tPolicy').textContent, 'single key');
  assert.equal(doc.getElementById('tHeight').textContent, String(BOND_2_HEIGHT));
  assert.equal(doc.getElementById('tHeightSrc').textContent, 'computeBondUnlockHeight');
  assert.equal(doc.getElementById('verdictMark').textContent, '!', 'consistent, but not compared');
  assert.match(checksText(doc), /The SDK and pox-5 derive the same output script/);
  assert.match(checksText(doc), /No address supplied to compare against/);

  setValue(doc, 'expected', LOCK_ADDRESS);
  await runVerify(doc);
  assert.equal(doc.getElementById('addrText').textContent, LOCK_ADDRESS);
  assert.equal(doc.getElementById('verdictMark').textContent, '✓');
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Match — this is the address to fund');
  assert.match(checksText(doc), /The address you supplied matches/);
});

test('a Leather policy account fills the multisig from its descriptor and verifies', async () => {
  const { doc, window, errors } = loadPage();
  const seen = withLeather(window, POLICY_REPLY);
  window.fetch = stubApi().fetch;

  click(doc, 'connectBtn');
  await settle();

  assert.deepEqual(errors, []);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].allowPolicyAccounts, true, 'asks Leather to include policy accounts');
  assert.equal(doc.getElementById('formErr').hidden, true);
  assert.equal(doc.getElementById('paneMulti').hidden, false, 'switches to multisig on its own');
  assert.equal(doc.getElementById('paneSingle').hidden, true);
  assert.deepEqual(keyInputs(doc).map(i => i.value), VAULT_KEYS);
  assert.ok(keyInputs(doc).every(i => i.classList.contains('prefilled')));
  assert.equal(doc.getElementById('threshold').value, '2');
  assert.equal(doc.getElementById('sortKeys').checked, true);
  assert.equal(doc.getElementById('vaultAddress').value, VAULT);
  assert.match(doc.getElementById('vaultInfo').textContent, /2-of-2 sortedmulti/);
  assert.equal(doc.getElementById('network').value, 'mainnet', 'the vault address decides the chain');
  assert.match(doc.getElementById('walletNote').textContent, /no Stacks address/);
  assert.doesNotMatch(doc.getElementById('walletNote').textContent, /no Bitcoin public key/);

  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await runVerify(doc);

  assert.notEqual(doc.getElementById('addrText').textContent, MULTI_LOCK_ADDRESS, 'withheld until the wallet destination is pasted');
  assert.ok(!doc.body.textContent.includes(MULTI_LOCK_ADDRESS));
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Not compared — paste the destination from your wallet');
  assert.equal(doc.getElementById('tPolicy').textContent, '2-of-2');
  assert.equal(doc.getElementById('tHeightSrc').textContent, 'computeBondUnlockHeight');
  assert.equal(doc.getElementById('verdictMark').textContent, '!', 'consistent, pending the manual checks');
  assert.match(checksText(doc), /These keys and this threshold reproduce your vault address/);

  setValue(doc, 'expected', MULTI_LOCK_ADDRESS);
  await runVerify(doc);
  assert.equal(doc.getElementById('addrText').textContent, MULTI_LOCK_ADDRESS);
  assert.equal(doc.getElementById('verdictMark').textContent, '✓');
});

test('keys entered by hand verify the same as the wallet-filled ones', async () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi().fetch;
  doc.getElementById('network').value = 'mainnet';

  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  assert.equal(doc.getElementById('paneMulti').hidden, false);

  const [a, b] = keyInputs(doc);
  a.value = VAULT_KEYS[1];
  b.value = VAULT_KEYS[0];
  a.dispatchEvent(new window.Event('input', { bubbles: true }));
  setValue(doc, 'threshold', '2');
  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await runVerify(doc);

  setValue(doc, 'expected', MULTI_LOCK_ADDRESS);
  await runVerify(doc);
  assert.equal(doc.getElementById('addrText').textContent, MULTI_LOCK_ADDRESS);
  assert.match(checksText(doc), /Vault address not supplied — this page cannot tie the keys to your wallet/);
  assert.equal(doc.getElementById('verdictMark').textContent, '!', 'a multisig without its vault is not verified');
  assert.equal(doc.getElementById('verdictTitle').textContent, 'Not verified — copy your vault address from your wallet');
  assert.ok(!doc.body.textContent.includes(VAULT), 'the derived vault is not printed for pasting back');

  click(doc, 'addKeyBtn');
  assert.equal(keyInputs(doc).length, 3);
  for (const btn of doc.querySelectorAll('#keyList button')) btn.dispatchEvent(new window.Event('click', { bubbles: true }));
  assert.equal(keyInputs(doc).length, 1);
  assert.equal(doc.querySelector('#keyList button').disabled, true);
});

test('a pasted descriptor fills the keys, and a bad one says why', async () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi({ network: 'private-1' }).fetch;
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));

  setValue(doc, 'descriptor', DESCRIPTOR.replace('sortedmulti(2', 'sortedmulti(3'));
  click(doc, 'useDescriptorBtn');
  assert.equal(doc.getElementById('descriptorNote').hidden, false);
  assert.match(doc.getElementById('descriptorNote').textContent, /threshold 3 is more than the 2/);

  setValue(doc, 'descriptor', DESCRIPTOR);
  click(doc, 'useDescriptorBtn');
  assert.deepEqual(keyInputs(doc).map(i => i.value), VAULT_KEYS);
  assert.equal(doc.getElementById('threshold').value, '2');
  assert.match(doc.getElementById('descriptorNote').textContent, /Filled 2 keys, threshold 2, sorted/);

  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await runVerify(doc);
  assert.match(doc.getElementById('verdictSub').textContent, /mainnet \(xpub\) keys, but the network selected is private-1/);
});

test('changing a wallet-supplied key fails the vault check', async () => {
  const { doc, window } = loadPage();
  withLeather(window, POLICY_REPLY);
  window.fetch = stubApi().fetch;
  click(doc, 'connectBtn');
  await settle();

  const [first] = keyInputs(doc);
  first.value = STRANGER;
  first.dispatchEvent(new window.Event('input', { bubbles: true }));
  assert.ok(!first.classList.contains('prefilled'));
  assert.match(doc.getElementById('vaultInfo').textContent, /You changed what Leather supplied/);

  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await runVerify(doc);

  assert.equal(doc.getElementById('verdictMark').textContent, '✕');
  assert.equal(doc.getElementById('verdictTitle').textContent, 'The keys do not reproduce your vault');
  assert.match(checksText(doc), /The keys do not reproduce your vault address — do not fund this address/);
});

test('flipping the key order is diagnosed as such', async () => {
  const { doc, window } = loadPage();
  withLeather(window, POLICY_REPLY);
  window.fetch = stubApi().fetch;
  click(doc, 'connectBtn');
  await settle();

  const [a, b] = keyInputs(doc);
  [a.value, b.value] = [b.value, a.value];
  a.dispatchEvent(new window.Event('input', { bubbles: true }));
  doc.getElementById('sortKeys').checked = false;
  doc.getElementById('sortKeys').dispatchEvent(new window.Event('change', { bubbles: true }));

  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await runVerify(doc);
  assert.match(checksText(doc), /The other key order would match your vault/);
});

test('an unreadable wallet descriptor keeps the vault and asks for the keys', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [{ ...POLICY_REPLY[0], descriptor: 'wsh(pk(nonsense))' }]);
  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('formErr').hidden, true, 'still connected');
  assert.equal(doc.getElementById('paneMulti').hidden, false);
  assert.equal(doc.getElementById('vaultAddress').value, VAULT);
  assert.deepEqual(keyInputs(doc).map(i => i.value), ['', '']);
  assert.match(doc.getElementById('walletNote').textContent, /descriptor could not be read/);
});

test('disconnecting drops the wallet vault and returns to single key', async () => {
  const { doc, window } = loadPage();
  withLeather(window, POLICY_REPLY);
  click(doc, 'connectBtn');
  await settle();

  click(doc, 'disconnectBtn');
  assert.equal(doc.getElementById('paneSingle').hidden, false);
  assert.equal(doc.getElementById('paneMulti').hidden, true);
  assert.equal(doc.getElementById('vaultAddress').value, '');
  assert.equal(doc.getElementById('vaultInfo').hidden, true);
  assert.deepEqual(keyInputs(doc).map(i => i.value), ['', '']);
});

test('disconnecting drops what the wallet supplied and keeps what the staker typed', async () => {
  const { doc, window } = loadPage();
  withLeather(window, POLICY_REPLY);
  click(doc, 'connectBtn');
  await settle();

  const sort = doc.getElementById('sortKeys');
  for (const checked of [false, true]) {
    sort.checked = checked;
    sort.dispatchEvent(new window.Event('change', { bubbles: true }));
  }
  const [first] = keyInputs(doc);
  first.value = STRANGER;
  first.dispatchEvent(new window.Event('input', { bubbles: true }));

  click(doc, 'disconnectBtn');
  assert.equal(doc.getElementById('paneMulti').hidden, false, 'a typed key keeps the multisig open');
  assert.deepEqual(keyInputs(doc).map(i => i.value), [STRANGER], 'the typed key stays, the wallet key goes');
  assert.equal(doc.getElementById('vaultAddress').value, '', 'the wallet-supplied vault goes');
  assert.equal(doc.getElementById('threshold').value, '2');
  assert.equal(doc.getElementById('vaultInfo').hidden, true);

  const typed = loadPage();
  withLeather(typed.window, POLICY_REPLY);
  click(typed.doc, 'connectBtn');
  await settle();
  setValue(typed.doc, 'vaultAddress', VAULT);
  setValue(typed.doc, 'stxAddress', ALLOWLISTED);
  click(typed.doc, 'disconnectBtn');
  assert.equal(typed.doc.getElementById('vaultAddress').value, VAULT, 'a vault address typed over the wallet one stays');
  assert.equal(typed.doc.getElementById('stxAddress').value, ALLOWLISTED, 'a typed principal stays');
});

test('a descriptor fill survives connecting and disconnecting a single-key wallet, and a wallet vault resets its note', async () => {
  const { doc, window } = loadPage();
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  setValue(doc, 'descriptor', DESCRIPTOR);
  click(doc, 'useDescriptorBtn');
  assert.deepEqual(keyInputs(doc).map(i => i.value), VAULT_KEYS);

  withLeather(window, [{ symbol: 'STX', address: STX }, ...BTC_ONLY]);
  click(doc, 'connectBtn');
  await settle();
  click(doc, 'disconnectBtn');
  assert.deepEqual(keyInputs(doc).map(i => i.value), VAULT_KEYS, 'descriptor-filled keys are not the wallet’s to take back');
  assert.equal(doc.getElementById('pubkey').value, '', 'the wallet-filled key goes');

  withLeather(window, POLICY_REPLY);
  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('descriptorNote').hidden, true, 'a wallet vault replaces the descriptor fill and its note');
});

test('disconnecting drops the vault of an account whose descriptor could not be read', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [{ ...POLICY_REPLY[0], descriptor: 'wsh(pk(nonsense))' }]);
  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('vaultAddress').value, VAULT);

  click(doc, 'disconnectBtn');
  assert.equal(doc.getElementById('vaultAddress').value, '');
  assert.equal(doc.getElementById('paneSingle').hidden, false);
});

test('a single-sig connect after a policy account verifies the new key, not the old vault', async () => {
  const { doc, window } = loadPage();
  withLeather(window, POLICY_REPLY);
  click(doc, 'connectBtn');
  await settle();
  const sort = doc.getElementById('sortKeys');
  for (const checked of [false, true]) {
    sort.checked = checked;
    sort.dispatchEvent(new window.Event('change', { bubbles: true }));
  }
  click(doc, 'disconnectBtn');

  withLeather(window, [{ symbol: 'STX', address: STX }, ...BTC_ONLY]);
  window.fetch = stubApi({ network: 'private-1', bonds: [106] }).fetch;
  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('paneSingle').hidden, false, 'single-sig mode');
  assert.equal(doc.getElementById('paneMulti').hidden, true);
  assert.equal(doc.getElementById('pubkey').value, KEY2);
  assert.equal(doc.getElementById('vaultAddress').value, '');

  setValue(doc, 'bondIndex', '106');
  await runVerify(doc);
  assert.equal(doc.getElementById('tPolicy').textContent, 'single key');
  assert.doesNotMatch(checksText(doc), /vault address/);
});

test('a single-sig connect switches out of a multisig the staker typed, and keeps their keys', async () => {
  const { doc, window } = loadPage();
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  const [a, b] = keyInputs(doc);
  a.value = VAULT_KEYS[0];
  b.value = VAULT_KEYS[1];
  a.dispatchEvent(new window.Event('input', { bubbles: true }));

  withLeather(window, [{ symbol: 'STX', address: STX }, ...BTC_ONLY]);
  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('paneSingle').hidden, false);

  click(doc, 'disconnectBtn');
  assert.deepEqual(keyInputs(doc).map(i => i.value), VAULT_KEYS);
});

test('a wallet reply with a BTC key but no address connects without crashing', async () => {
  const { doc, window, errors } = loadPage();
  withLeather(window, [{ symbol: 'BTC', type: 'p2wpkh', publicKey: KEY2 }]);
  click(doc, 'connectBtn');
  await settle();

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').textContent);
  assert.equal(doc.getElementById('pubkey').value, KEY2);
  assert.equal(doc.getElementById('walletBadge').hidden, false);
  assert.equal(doc.getElementById('walletBadgeText').textContent, `${KEY2.slice(0, 6)}…${KEY2.slice(-4)}`);
  assert.equal(doc.getElementById('connectBtn').textContent, 'Connect Leather');
  assert.equal(doc.getElementById('disconnectBtn').hidden, false);

  click(doc, 'disconnectBtn');
  withLeather(window, [{ symbol: 'STX' }, { symbol: 'BTC', type: 'p2wpkh', publicKey: KEY1, address: '' }]);
  click(doc, 'connectBtn');
  await settle();
  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('pubkey').value, KEY1);
});

test("the descriptor's network warning lasts only while one of its keys is still there", async () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi({ network: 'private-1' }).fetch;
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  setValue(doc, 'descriptor', DESCRIPTOR);
  click(doc, 'useDescriptorBtn');
  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);

  const [a, b] = keyInputs(doc);
  a.value = KEY1;
  a.dispatchEvent(new window.Event('input', { bubbles: true }));
  await runVerify(doc);
  assert.match(doc.getElementById('verdictSub').textContent, /mainnet \(xpub\) keys/, 'one descriptor key remains');

  b.value = KEY2;
  b.dispatchEvent(new window.Event('input', { bubbles: true }));
  await runVerify(doc);
  assert.doesNotMatch(doc.getElementById('verdictSub').textContent, /xpub/, 'every descriptor key replaced by hand');
});

test('a private key pasted into a key field is refused without being echoed', () => {
  const wif = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617';
  const { doc, window } = loadPage();
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', STX);
  setValue(doc, 'pubkey', wif);
  click(doc, 'verifyBtn');
  const err = doc.getElementById('formErr');
  assert.equal(err.hidden, false);
  assert.match(err.textContent, /looks like a private key/);
  assert.ok(!err.textContent.includes(wif.slice(0, 6)) && !err.textContent.includes(wif.slice(-6)));

  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  const [first] = keyInputs(doc);
  first.value = wif;
  first.dispatchEvent(new window.Event('input', { bubbles: true }));
  click(doc, 'verifyBtn');
  assert.match(err.textContent, /looks like a private key/);
  assert.ok(!err.textContent.includes(wif.slice(0, 6)));
});

function fillForm(doc, window, mode = 'single') {
  doc.getElementById('network').value = 'mainnet';
  doc.getElementById('network').dispatchEvent(new window.Event('change', { bubbles: true }));
  doc.querySelector(`#modeSeg [data-mode="${mode}"]`).dispatchEvent(new window.Event('click', { bubbles: true }));
  const [a, b] = keyInputs(doc);
  a.value = VAULT_KEYS[0];
  b.value = VAULT_KEYS[1];
  setValue(doc, 'threshold', '2');
  setValue(doc, 'bondIndex', '2');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  setValue(doc, 'pubkey', KEY1);
  setValue(doc, 'vaultAddress', VAULT);
  setValue(doc, 'expected', mode === 'multi' ? MULTI_LOCK_ADDRESS : LOCK_ADDRESS);
  setValue(doc, 'descriptor', DESCRIPTOR);
}

function put(doc, field, value) {
  if (field === 'key row') {
    const [first] = keyInputs(doc);
    first.value = value;
    first.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
  } else {
    setValue(doc, field, value);
  }
}

const fieldEl = (doc, field) => (field === 'key row' ? keyInputs(doc)[0] : doc.getElementById(field));

test('a pasted expected address cannot inject markup into the checks', async () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi().fetch;
  fillForm(doc, window);
  setValue(doc, 'expected', `${LOCK_ADDRESS}   <img id="pwned" src="x" onerror="document.title='pwned'">`);
  await runVerify(doc);

  assert.equal(doc.querySelector('#results img'), null);
  assert.equal(doc.getElementById('pwned'), null);
  assert.match(checksText(doc), /not a Bitcoin address or output script/);
  assert.doesNotMatch(doc.body.textContent, /pwned/, 'unreadable input is not echoed at all');
  assert.equal(doc.getElementById('verdictMark').textContent, '✕');
});

test('a private key in the vault, expected or staker field is refused without being echoed', async () => {
  const wif = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617';
  for (const field of ['vaultAddress', 'expected', 'stxAddress']) {
    const { doc, window } = loadPage();
    withLeather(window, POLICY_REPLY);
    const { fetch, calls } = stubApi();
    window.fetch = fetch;
    click(doc, 'connectBtn');
    await settle();

    setValue(doc, 'bondIndex', '2');
    setValue(doc, 'stxAddress', ALLOWLISTED);
    setValue(doc, field, wif);
    click(doc, 'verifyBtn');
    await settle();

    const err = doc.getElementById('formErr');
    assert.equal(err.hidden, false, field);
    assert.match(err.textContent, /looks like a private key/, field);
    assert.ok(!err.textContent.includes(wif.slice(0, 6)) && !err.textContent.includes(wif.slice(-6)), field);
    assert.equal(doc.getElementById('results').hidden, true, `${field}: nothing rendered`);
    assert.deepEqual(calls, [], `${field}: nothing sent`);
  }
});

test('a staker principal that is not one is refused without echoing it', () => {
  const { doc } = loadPage();
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', 'not-a-principal-xyz');
  setValue(doc, 'pubkey', KEY1);
  click(doc, 'verifyBtn');
  const err = doc.getElementById('formErr');
  assert.match(err.textContent, /does not look like a Stacks address/);
  assert.ok(!err.textContent.includes('not-a-principal-xyz'));
});

const SCREENED = {
  bondIndex: 'bond index',
  stxAddress: 'staker principal',
  'key row': 'key #1',
  threshold: 'threshold',
  vaultAddress: 'vault address',
  expected: 'expected address',
  heightOverride: 'unlock height override',
};

async function sweepKeys(field, mode, expectRefusal) {
  const { doc, window } = loadPage();
  const stub = stubApi();
  window.fetch = stub.fetch;
  fillForm(doc, window, mode);
  const baseline = doc.body.textContent;

  for (const [kind, key] of Object.entries(PRIVATE_KEYS)) {
    const fragments = Array.from({ length: key.length - 5 }, (_, i) => key.slice(i, i + 6)).filter(f => !baseline.includes(f));
    for (const [where, text] of Object.entries(embeddings(key))) {
      fillForm(doc, window, mode);
      put(doc, field, text);
      stub.requests.length = 0;
      const label = `${kind} ${where} in ${field} (${mode})`;
      const held = fieldEl(doc, field).value;

      click(doc, 'verifyBtn');
      await settle();
      click(doc, 'useDescriptorBtn');

      const sent = stub.requests.map(r => `${r.url} ${r.body}`).join('\n');
      assert.equal(fragments.find(f => sent.includes(f)), undefined, `${label}: part of the key was sent`);
      const page = doc.body.textContent;
      assert.equal(fragments.find(f => page.includes(f)), undefined, `${label}: part of the key is on the page`);
      expectRefusal({ doc, stub, label, held, key });
    }
  }
}

test('a private key in any active field, in any wrapping, is refused by name and never reaches the page or the network', async () => {
  const control = loadPage();
  const controlStub = stubApi();
  control.window.fetch = controlStub.fetch;
  fillForm(control.doc, control.window, 'multi');
  await runVerify(control.doc);
  assert.ok(controlStub.calls.length > 0, 'the filled form does verify when no key is present');
  assert.equal(control.doc.getElementById('verdictMark').textContent, '✓');

  const refused = name => ({ doc, stub, label, held }) => {
    assert.notEqual(held, '', `${label}: the field kept the text, so it was screened`);
    assert.deepEqual(stub.requests, [], `${label}: nothing sent`);
    const err = doc.getElementById('formErr');
    assert.equal(err.hidden, false, label);
    assert.equal(err.textContent, `The ${name} field holds what looks like a private key. Never paste one anywhere — nothing was sent, but clear it from that field. Use the public key (02… / 03…) or the xpub / tpub form instead.`, label);
    assert.equal(doc.getElementById('results').hidden, true, `${label}: nothing rendered`);
  };

  for (const [field, name] of Object.entries(SCREENED)) await sweepKeys(field, 'multi', refused(name));
  await sweepKeys('pubkey', 'single', refused('Bitcoin public key'));
  await sweepKeys('descriptor', 'multi', ({ doc, label }) => {
    assert.match(doc.getElementById('descriptorNote').textContent, /^The descriptor field holds what looks like a private key/, label);
  });
});

test('fields the current mode does not read are not screened or sent', async () => {
  const { doc, window } = loadPage();
  const stub = stubApi();
  window.fetch = stub.fetch;
  fillForm(doc, window, 'single');
  setValue(doc, 'descriptor', `wsh(multi(1,${PRIVATE_KEYS.xprv}/0/0))`);
  setValue(doc, 'vaultAddress', PRIVATE_KEYS['WIF mainnet compressed']);
  put(doc, 'key row', PRIVATE_KEYS['WIF testnet compressed']);
  await runVerify(doc);
  assert.ok(stub.calls.length > 0, 'single key verifies with junk left in the hidden multisig fields');

  const multi = loadPage();
  fillForm(multi.doc, multi.window, 'multi');
  setValue(multi.doc, 'pubkey', PRIVATE_KEYS['WIF mainnet compressed']);
  click(multi.doc, 'useDescriptorBtn');
  assert.match(multi.doc.getElementById('descriptorNote').textContent, /^Filled 2 keys/);
});

test('up to 20 key rows can be added', () => {
  const { doc, window } = loadPage();
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  for (let i = 0; i < 25; i += 1) click(doc, 'addKeyBtn');
  assert.equal(keyInputs(doc).length, 20);
  for (const id of ['threshold', 'bondIndex', 'heightOverride']) {
    assert.equal(doc.getElementById(id).type, 'text', `${id}: a text input keeps a pasted secret so it can be screened`);
    assert.equal(doc.getElementById(id).getAttribute('inputmode'), 'numeric', id);
  }
});

test('the vault field is required in multisig mode and says why', () => {
  const { doc, window } = loadPage();
  assert.match(doc.querySelector('label[for="vaultAddress"]').textContent, /required for a multisig/);
  doc.querySelector('#modeSeg [data-mode="multi"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  assert.equal(doc.getElementById('vaultAddress').required, true);
  doc.querySelector('#modeSeg [data-mode="single"]').dispatchEvent(new window.Event('click', { bubbles: true }));
  assert.equal(doc.getElementById('vaultAddress').required, false);
});

test('the refused field gets focus', () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi().fetch;
  fillForm(doc, window);
  setValue(doc, 'expected', `"${PRIVATE_KEYS.tprv}"`);
  click(doc, 'verifyBtn');
  assert.equal(doc.activeElement, doc.getElementById('expected'));
});

test('a very long paste is refused by field name before any scan', () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi().fetch;
  fillForm(doc, window, 'multi');
  setValue(doc, 'expected', 'K'.repeat(1_000_000));
  const started = Date.now();
  click(doc, 'verifyBtn');
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started} ms`);
  assert.match(doc.getElementById('formErr').textContent, /^The expected address field is longer than 1024 characters/);

  setValue(doc, 'expected', MULTI_LOCK_ADDRESS);
  setValue(doc, 'descriptor', 'K'.repeat(1_000_000));
  click(doc, 'useDescriptorBtn');
  assert.match(doc.getElementById('descriptorNote').textContent, /^The descriptor field is longer than 16384 characters/);
});

test('any change to the inputs, mode, network or wallet clears a shown result', async () => {
  const changes = {
    input: (doc) => setValue(doc, 'stxAddress', NOT_LISTED),
    network: (doc, window) => {
      doc.getElementById('network').value = 'private-1';
      doc.getElementById('network').dispatchEvent(new window.Event('change', { bubbles: true }));
    },
    mode: (doc, window) => doc.querySelector('#modeSeg [data-mode="single"]').dispatchEvent(new window.Event('click', { bubbles: true })),
    sort: (doc, window) => {
      doc.getElementById('sortKeys').checked = false;
      doc.getElementById('sortKeys').dispatchEvent(new window.Event('change', { bubbles: true }));
    },
    'remove key': (doc, window) => {
      click(doc, 'addKeyBtn');
      doc.querySelector('#keyList .keyrow:last-child button').dispatchEvent(new window.Event('click', { bubbles: true }));
    },
    connect: async (doc, window) => {
      withLeather(window, [{ symbol: 'STX', address: STX }, ...BTC_ONLY]);
      click(doc, 'connectBtn');
      await settle();
    },
    disconnect: (doc) => click(doc, 'disconnectBtn'),
  };
  for (const [what, change] of Object.entries(changes)) {
    const { doc, window } = loadPage();
    window.fetch = stubApi().fetch;
    fillForm(doc, window, 'multi');
    await runVerify(doc);
    assert.equal(doc.getElementById('verdictMark').textContent, '✓', what);
    await change(doc, window);
    assert.equal(doc.getElementById('results').hidden, true, `${what} clears the result`);
  }
});

test('a result that arrives after the inputs changed is discarded', async () => {
  const { doc, window } = loadPage();
  const stub = stubApi();
  let release;
  const gate = new Promise(r => {
    release = r;
  });
  window.fetch = async (url, init) => {
    await gate;
    return stub.fetch(url, init);
  };
  fillForm(doc, window);
  click(doc, 'verifyBtn');
  await settle();
  setValue(doc, 'stxAddress', NOT_LISTED);
  release();
  await new Promise(r => setTimeout(r, 300));
  assert.equal(doc.getElementById('results').hidden, true);
  assert.equal(doc.getElementById('formErr').hidden, true);
  assert.equal(doc.getElementById('verifyBtn').disabled, false);
});

test('whole numbers are read only as plain digits, and nothing else', async () => {
  for (const [bond, override] of [['2', ''], ['02', '994700'], [' 2 ', ' 0994700 ']]) {
    const { doc, window } = loadPage();
    const calls = stubApi();
    window.fetch = calls.fetch;
    fillForm(doc, window);
    setValue(doc, 'bondIndex', bond);
    setValue(doc, 'heightOverride', override);
    await runVerify(doc);
    assert.equal(doc.getElementById('tBond').textContent, '2', bond);
    assert.equal(doc.getElementById('tHeight').textContent, '994700', override);
  }
  const { doc, window } = loadPage();
  fillForm(doc, window);
  for (const bond of ['2.0', '1.00000000000000001', '2e0', '+2', '0x2', '0b10', '-1', 'Infinity', '2 3', '9007199254740993']) {
    setValue(doc, 'bondIndex', bond);
    click(doc, 'verifyBtn');
    assert.match(doc.getElementById('formErr').textContent, /The bond index must be a whole number, 0 or above/, bond);
  }
  setValue(doc, 'bondIndex', '2');
  for (const override of ['0', '994700.0', '9947e2']) {
    setValue(doc, 'heightOverride', override);
    click(doc, 'verifyBtn');
    assert.match(doc.getElementById('formErr').textContent, /The unlock height override must be a whole number, 1 or above/, override);
  }
});

test("Leather's own rejection reason is shown, and a cancel says so", async () => {
  for (const [rejection, shown] of [
    [{ jsonrpc: '2.0', id: '1', error: { code: 4001, message: 'User rejected request' } }, 'You cancelled the request in Leather.'],
    [{ jsonrpc: '2.0', id: '1', error: { code: -32603, message: 'Wallet is locked' } }, 'Wallet is locked'],
    ['plain string reason', 'plain string reason'],
    [{}, 'Something went wrong.'],
  ]) {
    const { doc, window } = loadPage();
    window.LeatherProvider = { request: async () => Promise.reject(rejection) };
    click(doc, 'connectBtn');
    await settle();
    assert.equal(doc.getElementById('formErr').textContent, shown);
  }
});

test('the copy button always returns to its own label', async () => {
  const { doc, window } = loadPage();
  Object.defineProperty(window.navigator, 'clipboard', { value: { writeText: async () => {} }, configurable: true });
  window.fetch = stubApi().fetch;
  fillForm(doc, window);
  await runVerify(doc);
  const btn = doc.querySelector('[data-copy="addrText"]');
  const label = btn.textContent;
  btn.dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise(r => setTimeout(r, 500));
  btn.dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise(r => setTimeout(r, 1600));
  assert.equal(btn.textContent, label);
  assert.equal(btn.classList.contains('copied'), false);
  await new Promise(r => setTimeout(r, 600));
  assert.equal(btn.textContent, label);
});

test('a failure keeps its error name and code on the page, so a transient one can be told apart', async () => {
  const { doc, window } = loadPage();
  window.fetch = stubApi({ fail: { 'get-protocol-bond': 'network' } }).fetch;
  fillForm(doc, window);
  click(doc, 'verifyBtn');
  for (let i = 0; i < 100 && doc.getElementById('formErr').hidden; i += 1) await settle();
  assert.equal(doc.getElementById('formErr').dataset.errorCode, 'ECONNRESET');
  assert.equal(isTransient(pageError('x', doc.getElementById('formErr').dataset.errorName, 'ECONNRESET')), true);
});

test('changing the inputs cancels a running verification: its requests abort and Verify is usable at once', async () => {
  const stages = [
    { hang: ['pox', 'get-protocol-bond'], hung: /\/v2\/pox$|get-protocol-bond/ },
    { hang: ['construct-lockup-output-script'], hung: /construct-lockup-output-script/ },
  ];
  for (const { hang, hung } of stages) {
    const { doc, window } = loadPage();
    const stub = stubApi({ hang });
    window.fetch = stub.fetch;
    fillForm(doc, window);
    click(doc, 'verifyBtn');
    await settle();
    assert.equal(doc.getElementById('verifyBtn').disabled, true, 'running');
    assert.equal(doc.getElementById('paneLoading').hidden, false);

    setValue(doc, 'expected', '');
    assert.equal(doc.getElementById('verifyBtn').disabled, false, 'usable again without waiting for the reads');
    assert.equal(doc.getElementById('paneLoading').hidden, true);
    await settle();
    const inFlight = stub.requests.filter(r => hung.test(r.url));
    assert.equal(inFlight.length, hang.length, `${hang}: every hung read was sent`);
    assert.ok(inFlight.every(r => r.signal.aborted), `${hang}: the superseded reads were aborted`);
    assert.equal(doc.getElementById('formErr').hidden, true, 'a cancelled run shows no error');
    assert.equal(doc.getElementById('results').hidden, true);

    window.fetch = stubApi().fetch;
    setValue(doc, 'expected', LOCK_ADDRESS);
    await runVerify(doc);
    assert.equal(doc.getElementById('verdictMark').textContent, '✓', 'the next run is not affected');
  }
});

test('a typed key shaped like a Stacks private key is held back until the staker confirms it is public', async () => {
  const setKey = (doc, mode, value) => {
    if (mode === 'single') return setValue(doc, 'pubkey', value);
    const row = keyInputs(doc)[1];
    row.value = value;
    row.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
  };
  const keyField = (doc, mode) => (mode === 'single' ? doc.getElementById('pubkey') : keyInputs(doc)[1]);

  for (const mode of ['single', 'multi']) {
    const { doc, window } = loadPage();
    const stub = stubApi();
    window.fetch = stub.fetch;
    fillForm(doc, window, mode);
    setValue(doc, 'expected', '');
    setKey(doc, mode, AMBIGUOUS_PUBKEY);

    click(doc, 'verifyBtn');
    await settle();
    const err = doc.getElementById('formErr');
    assert.equal(err.hidden, false, mode);
    assert.match(err.textContent, /exactly what a Stacks private key looks like/);
    assert.ok(!doc.body.textContent.replace(doc.getElementById(mode === 'single' ? 'pubkey' : 'keyList').textContent, '').includes(AMBIGUOUS_PUBKEY.slice(10, 40)), `${mode}: not shown`);
    assert.deepEqual(stub.requests, [], `${mode}: nothing sent`);
    assert.equal(doc.getElementById('confirmPubkeysBox').hidden, false);
    assert.equal(doc.activeElement, keyField(doc, mode), `${mode}: the key field holding the ambiguous key is focused`);

    doc.getElementById('confirmPubkeys').checked = true;
    doc.getElementById('confirmPubkeys').dispatchEvent(new window.Event('change', { bubbles: true }));
    await runVerify(doc);
    assert.ok(stub.requests.length > 0, `${mode}: sent once confirmed`);

    setKey(doc, mode, `${AMBIGUOUS_PUBKEY} `);
    assert.equal(doc.getElementById('confirmPubkeys').checked, false, `${mode}: editing a key unticks the confirmation`);
    assert.equal(doc.getElementById('confirmPubkeysBox').hidden, true);
    stub.requests.length = 0;
    click(doc, 'verifyBtn');
    await settle();
    assert.deepEqual(stub.requests, [], `${mode}: asked again after an edit`);
  }
});

test('a key Leather supplies as a public key needs no confirmation, even when it ends in 01', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [{ symbol: 'STX', address: ALLOWLISTED }, { symbol: 'BTC', type: 'p2wpkh', address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', publicKey: AMBIGUOUS_PUBKEY }]);
  const stub = stubApi();
  window.fetch = stub.fetch;
  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('pubkey').value, AMBIGUOUS_PUBKEY);
  setValue(doc, 'bondIndex', '2');
  await runVerify(doc);
  assert.equal(doc.getElementById('confirmPubkeysBox').hidden, true);
  assert.equal(doc.getElementById('tPolicy').textContent, 'single key');

  setValue(doc, 'pubkey', ` ${AMBIGUOUS_PUBKEY}`);
  stub.requests.length = 0;
  click(doc, 'verifyBtn');
  await settle();
  assert.deepEqual(stub.requests, [], 'after an edit the key is no longer the one Leather filled in');
  assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/);

  click(doc, 'disconnectBtn');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  setValue(doc, 'pubkey', AMBIGUOUS_PUBKEY);
  stub.requests.length = 0;
  click(doc, 'verifyBtn');
  await settle();
  assert.deepEqual(stub.requests, [], 'after disconnect the same key is no longer trusted');
  assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/);
});

test('a raw key typed into a descriptor is not trusted for being in a descriptor', async () => {
  const { doc, window } = loadPage();
  const stub = stubApi();
  window.fetch = stub.fetch;
  fillForm(doc, window, 'multi');
  setValue(doc, 'descriptor', `wsh(multi(1,${AMBIGUOUS_PUBKEY},${VAULT_KEYS[0]}))`);
  click(doc, 'useDescriptorBtn');
  assert.deepEqual(keyInputs(doc).map(i => i.value), [AMBIGUOUS_PUBKEY, VAULT_KEYS[0]]);
  stub.requests.length = 0;
  click(doc, 'verifyBtn');
  await settle();
  assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/);
  assert.deepEqual(stub.requests, []);
});

const [XPUB_A, XPUB_B] = DESCRIPTOR.match(/xpub[1-9A-HJ-NP-Za-km-z]+/g);
const AMBIGUOUS_DERIVED = '03c000bec4a37a8e36509d13631039f3b511d83277c1b07f4aee6c79b869dab801';
const AMBIGUOUS_XPUB_DESCRIPTOR = `wsh(sortedmulti(2,${XPUB_A}/0/267,${XPUB_B}/0/0,${XPUB_A}/0/0))`;

test('a key derived from an xpub in a descriptor needs no confirmation, until something could have replaced it', async () => {
  const refusedUntilConfirmed = async (doc, stub, why) => {
    stub.requests.length = 0;
    click(doc, 'verifyBtn');
    await settle();
    assert.deepEqual(stub.requests, [], `${why}: nothing sent`);
    assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/, why);
    assert.equal(doc.getElementById('confirmPubkeysBox').hidden, false, why);
  };
  const trustedAgain = async (doc, stub, why) => {
    stub.requests.length = 0;
    await runVerify(doc);
    assert.ok(stub.requests.length > 0, `${why}: sent`);
    assert.equal(doc.getElementById('confirmPubkeysBox').hidden, true, why);
  };
  const fillFromDescriptor = doc => {
    setValue(doc, 'descriptor', AMBIGUOUS_XPUB_DESCRIPTOR);
    click(doc, 'useDescriptorBtn');
    assert.deepEqual(keyInputs(doc).map(i => i.value), [AMBIGUOUS_DERIVED, VAULT_KEYS[1], VAULT_KEYS[0]]);
  };
  const switchMode = (doc, mode) => doc.querySelector(`#modeSeg [data-mode="${mode}"]`).dispatchEvent(new doc.defaultView.Event('click', { bubbles: true }));

  const { doc, window } = loadPage();
  const stub = stubApi();
  window.fetch = stub.fetch;
  fillForm(doc, window, 'multi');
  setValue(doc, 'expected', '');

  fillFromDescriptor(doc);
  await trustedAgain(doc, stub, 'derived from the descriptor');

  put(doc, 'key row', `${AMBIGUOUS_DERIVED} `);
  await refusedUntilConfirmed(doc, stub, 'a row edit');

  fillFromDescriptor(doc);
  await trustedAgain(doc, stub, 'filled again');
  doc.querySelectorAll('#keyList button')[2].dispatchEvent(new window.Event('click', { bubbles: true }));
  await refusedUntilConfirmed(doc, stub, 'a removed row');

  fillFromDescriptor(doc);
  switchMode(doc, 'single');
  switchMode(doc, 'multi');
  await refusedUntilConfirmed(doc, stub, 'a mode switch');

  fillFromDescriptor(doc);
  withLeather(window, [{ symbol: 'STX', address: ALLOWLISTED }]);
  click(doc, 'connectBtn');
  await settle();
  assert.equal(doc.getElementById('paneMulti').hidden, false, 'a wallet without a vault leaves the mode alone');
  assert.deepEqual(keyInputs(doc).map(i => i.value), [AMBIGUOUS_DERIVED, VAULT_KEYS[1], VAULT_KEYS[0]], 'and the descriptor keys in place');
  await refusedUntilConfirmed(doc, stub, 'a wallet connect');

  fillFromDescriptor(doc);
  await trustedAgain(doc, stub, 'filled again while connected');
  click(doc, 'disconnectBtn');
  setValue(doc, 'stxAddress', ALLOWLISTED);
  await refusedUntilConfirmed(doc, stub, 'a wallet disconnect');

  setValue(doc, 'descriptor', `wsh(sortedmulti(2,${AMBIGUOUS_DERIVED},${XPUB_B}/0/0))`);
  click(doc, 'useDescriptorBtn');
  await refusedUntilConfirmed(doc, stub, 'the same key written raw in a descriptor');
});

test('a Leather policy account whose descriptor derives such a key needs no confirmation either', async () => {
  const { doc, window } = loadPage();
  withLeather(window, [{ symbol: 'STX', address: ALLOWLISTED }, { symbol: 'BTC', type: 'p2wsh', address: VAULT, descriptor: AMBIGUOUS_XPUB_DESCRIPTOR }]);
  const stub = stubApi();
  window.fetch = stub.fetch;
  click(doc, 'connectBtn');
  await settle();
  assert.deepEqual(keyInputs(doc).map(i => i.value), [AMBIGUOUS_DERIVED, VAULT_KEYS[1], VAULT_KEYS[0]]);
  setValue(doc, 'bondIndex', '2');
  await runVerify(doc);
  assert.ok(stub.requests.length > 0);
  assert.equal(doc.getElementById('confirmPubkeysBox').hidden, true);

  put(doc, 'key row', ` ${AMBIGUOUS_DERIVED}`);
  stub.requests.length = 0;
  click(doc, 'verifyBtn');
  await settle();
  assert.deepEqual(stub.requests, [], 'after an edit the key is no longer the one Leather filled in');
  assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/);
});

const AMBIGUOUS_2 = '037777777777777777777777777777777777777777777777777777777777777301';

test('the public-key confirmation covers only the exact keys it was given; every change to them asks again', async () => {
  const tick = doc => {
    const box = doc.getElementById('confirmPubkeys');
    box.checked = true;
    box.dispatchEvent(new doc.defaultView.Event('change', { bubbles: true }));
  };
  const switchMode = (doc, mode) => doc.querySelector(`#modeSeg [data-mode="${mode}"]`).dispatchEvent(new doc.defaultView.Event('click', { bubbles: true }));
  const setRows = (doc, keys) => {
    while (keyInputs(doc).length < keys.length) click(doc, 'addKeyBtn');
    keys.forEach((k, i) => {
      keyInputs(doc)[i].value = k;
    });
    keyInputs(doc)[0].dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
  };
  const transitions = {
    'none (control)': { mode: 'single', act: () => {} },
    'edit to another such key': { mode: 'single', act: doc => setValue(doc, 'pubkey', AMBIGUOUS_2) },
    'value replaced without an input event (autofill, an extension)': {
      mode: 'single',
      act: doc => {
        doc.getElementById('pubkey').value = AMBIGUOUS_2;
      },
    },
    'row replaced without an input event': {
      mode: 'multi',
      act: doc => {
        keyInputs(doc)[0].value = AMBIGUOUS_2;
      },
    },
    'descriptor fill with another such key': {
      mode: 'multi',
      act: doc => {
        setValue(doc, 'descriptor', `wsh(multi(1,${AMBIGUOUS_2},${VAULT_KEYS[0]}))`);
        click(doc, 'useDescriptorBtn');
      },
    },
    'descriptor fill with the same keys': {
      mode: 'multi',
      act: doc => {
        setValue(doc, 'descriptor', `wsh(multi(1,${AMBIGUOUS_PUBKEY},${VAULT_KEYS[0]}))`);
        click(doc, 'useDescriptorBtn');
      },
    },
    'mode switch to multisig': { mode: 'single', act: doc => switchMode(doc, 'multi') },
    'mode switch and back': { mode: 'multi', act: doc => (switchMode(doc, 'single'), switchMode(doc, 'multi')) },
    'add a row': { mode: 'multi', act: doc => click(doc, 'addKeyBtn') },
    'remove a row': {
      mode: 'multi',
      rows: [AMBIGUOUS_PUBKEY, VAULT_KEYS[0], VAULT_KEYS[1]],
      act: doc => doc.querySelectorAll('#keyList button')[2].dispatchEvent(new doc.defaultView.Event('click', { bubbles: true })),
    },
    'network change and back': {
      mode: 'single',
      act: doc => {
        for (const net of ['private-1', 'mainnet']) {
          doc.getElementById('network').value = net;
          doc.getElementById('network').dispatchEvent(new doc.defaultView.Event('change', { bubbles: true }));
        }
      },
    },
    'wallet connect': { mode: 'single', act: async (doc, window) => (withLeather(window, [{ symbol: 'STX', address: ALLOWLISTED }]), click(doc, 'connectBtn'), await settle()) },
    'wallet disconnect': { mode: 'single', before: async (doc, window) => (withLeather(window, [{ symbol: 'STX', address: ALLOWLISTED }]), click(doc, 'connectBtn'), await settle()), act: doc => click(doc, 'disconnectBtn') },
  };

  for (const [name, { mode, rows, act, before }] of Object.entries(transitions)) {
    const { doc, window } = loadPage();
    const stub = stubApi();
    window.fetch = stub.fetch;
    fillForm(doc, window, mode);
    setValue(doc, 'expected', '');
    if (before) await before(doc, window);
    setValue(doc, 'stxAddress', ALLOWLISTED);
    setValue(doc, 'pubkey', AMBIGUOUS_PUBKEY);
    setRows(doc, rows ?? [AMBIGUOUS_PUBKEY, VAULT_KEYS[0]]);
    tick(doc);
    await act(doc, window);
    stub.requests.length = 0;
    click(doc, 'verifyBtn');
    await settle();
    await settle();

    const sent = stub.requests.map(r => `${r.url} ${r.body}`).join('\n');
    const shown = doc.body.textContent;
    if (name === 'none (control)') {
      assert.ok(stub.requests.length > 0, 'a confirmed key is sent');
      continue;
    }
    assert.deepEqual(stub.requests, [], `${name}: nothing sent`);
    for (const key of [AMBIGUOUS_PUBKEY, AMBIGUOUS_2]) {
      assert.ok(!sent.includes(key.slice(4, 40)), `${name}: key sent`);
      assert.ok(!shown.includes(key.slice(4, 40)), `${name}: key rendered`);
    }
    assert.match(doc.getElementById('formErr').textContent, /exactly what a Stacks private key looks like/, name);
    assert.equal(doc.getElementById('results').hidden, true, name);
    assert.equal(doc.getElementById('confirmPubkeys').checked, false, `${name}: stale tick cleared`);
    assert.equal(doc.getElementById('confirmPubkeysBox').hidden, false, `${name}: asked again`);
  }
});
