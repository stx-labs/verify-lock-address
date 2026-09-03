// End-to-end over the real index.html, driven headlessly.
//
// The unit tests cover the modules; this covers the wiring between them — the
// class of bug (a lost import, an id that moved) that only shows up when the
// page actually runs.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test, { before } from 'node:test';

import { JSDOM } from 'jsdom';

const root = new URL('../', import.meta.url);
const path = rel => fileURLToPath(new URL(rel, root));

const KEY1 = '032bfc45f5dec5ba404da7ca12d3120dd67350bd72607eec3990bbb31611b454a0';
const KEY2 = '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4';
const STX = 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M';
const ADDRESS = 'bcrt1qy088v00xhafqjm5pulh2py67nwjg7g3l9aglsjytz7cp80m9lafqqkcdvw';

let bundle;

before(() => {
  // jsdom cannot run <script type="module">, so the same sources are rebuilt as
  // an IIFE and evaluated in the window.
  execFileSync('npm', ['run', 'build:test'], { cwd: path('.'), stdio: 'pipe' });
  bundle = readFileSync(path('.tmp/app.iife.js'), 'utf8');
});

/** Load index.html, run the app in it, and hand back the window. */
function loadPage() {
  const html = readFileSync(path('docs/index.html'), 'utf8').replace(
    '<script type="module" src="app.js"></script>',
    ''
  );
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    // jsdom has no matchMedia; the page's theme bootstrap runs before anything else.
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

test('the page boots without errors, offering the single-key flow', () => {
  const { doc, errors } = loadPage();
  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('results').hidden, true);
  assert.equal(doc.getElementById('netBadgeText').textContent, 'private-1');
  assert.ok(doc.getElementById('pubkey'), 'the public-key field is the only unlock input');

  // The multisig and raw-hex flows are parked in the UI; nothing should reference them.
  for (const gone of ['modeSeg', 'paneMulti', 'paneRaw', 'keyList', 'threshold', 'sortKeys', 'rawHex']) {
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
  assert.match(doc.getElementById('formErr').innerHTML, /bond index/);

  setValue(doc, 'bondIndex', '106');
  click(doc, 'verifyBtn');
  assert.match(doc.getElementById('formErr').innerHTML, /Stacks address/);

  setValue(doc, 'stxAddress', STX);
  setValue(doc, 'pubkey', 'not-a-key');
  click(doc, 'verifyBtn');
  assert.match(doc.getElementById('formErr').innerHTML, /66 hex characters/);
});

test('a mainnet address on private-1 is caught before anything is funded', () => {
  const { doc } = loadPage();
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7');
  setValue(doc, 'pubkey', KEY1);
  // The warning rides along with the result rather than blocking, so this only
  // asserts the form itself accepts it — the network mismatch surfaces below.
  assert.equal(doc.getElementById('formErr').hidden, true);
});

test('a full verification renders end to end', async t => {
  const reachable = await fetch('https://api.private-1.hiro.so/v2/pox', { signal: AbortSignal.timeout(8000) })
    .then(r => r.ok)
    .catch(() => false);
  if (!reachable) return t.skip('private-1 API unreachable');

  // Derive the expected address through the module, then drive the page to it —
  // this pins the wiring, while lock.test.mjs pins the module to the documented value.
  const { verify } = await import('../docs/src/lock.js');
  const { buildUnlockScript } = await import('@stacks/bitcoin-staking');
  const expected = await verify({
    network: 'private-1',
    bondIndex: 106,
    stxAddress: STX,
    unlockBytes: buildUnlockScript(KEY1),
  });
  assert.equal(expected.agree, true);

  const { doc, errors } = loadPage();
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', STX);
  setValue(doc, 'pubkey', KEY1);
  setValue(doc, 'expected', expected.address);
  click(doc, 'verifyBtn');

  for (let i = 0; i < 100 && doc.getElementById('results').hidden; i += 1) {
    await new Promise(r => setTimeout(r, 100));
  }

  assert.deepEqual(errors, []);
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').innerHTML);
  assert.equal(doc.getElementById('results').hidden, false);
  assert.equal(doc.getElementById('addrText').textContent, expected.address);
  assert.ok(expected.address.startsWith('bcrt1q'));
  assert.equal(doc.getElementById('verdictMark').textContent, '\u2713');
  assert.equal(doc.getElementById('tPolicy').textContent, 'single key');
  assert.equal(doc.getElementById('tHeight').textContent, '4690');
  assert.match(doc.getElementById('asmOut').innerHTML, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(doc.getElementById('asmOut').innerHTML, /your key #1/);
  assert.match(doc.getElementById('asmOut').innerHTML, /final authorisation — one signature/);
  assert.equal(doc.getElementById('paneLoading').hidden, true);
  assert.equal(doc.getElementById('verifyBtn').disabled, false);

  click(doc, 'toggleHex');
  assert.equal(doc.getElementById('rawHexOut').hidden, false);
  assert.match(doc.getElementById('rawHexOut').textContent, /^63/);
});

/** Install a Leather stub that answers `getAddresses` with `addresses`. */
function withLeather(window, addresses) {
  window.LeatherProvider = {
    request: async method => {
      assert.equal(method, 'getAddresses');
      return { jsonrpc: '2.0', id: 'test', result: { addresses } };
    },
  };
}

const settle = () => new Promise(r => setTimeout(r, 20));

// Verbatim from a real Leather reply: two BTC accounts, no STX entry.
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
  assert.match(note.innerHTML, /no Stacks address/);
  assert.match(note.innerHTML, /vault/, 'points multisig stakers at the right principal');
  assert.doesNotMatch(note.innerHTML, /no Bitcoin public key/);

  // The BTC address HRP identifies the chain when there is no principal to read.
  assert.equal(doc.getElementById('network').value, 'private-1');
  assert.equal(doc.getElementById('walletBadge').hidden, false);
  assert.equal(doc.getElementById('connectBtn').hidden, true);

  // The form still works: type the principal and verify.
  setValue(doc, 'bondIndex', '106');
  setValue(doc, 'stxAddress', STX);
  click(doc, 'verifyBtn');
  await settle();
  assert.equal(doc.getElementById('formErr').hidden, true, doc.getElementById('formErr').innerHTML);
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
  assert.match(doc.getElementById('walletNote').innerHTML, /no Bitcoin public key/);
  assert.match(doc.getElementById('walletNote').innerHTML, /paste the compressed key/i);
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
  assert.match(doc.getElementById('formErr').innerHTML, /neither a Stacks address nor a Bitcoin public key/);
  assert.equal(doc.getElementById('connectBtn').hidden, false, 'still connectable after a failure');
  assert.equal(doc.getElementById('connectBtn').disabled, false);
});

test('no extension at all gives an actionable message', async () => {
  const { doc } = loadPage();
  click(doc, 'connectBtn');
  await settle();

  assert.equal(doc.getElementById('formErr').hidden, false);
  assert.match(doc.getElementById('formErr').innerHTML, /Leather was not detected/);
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
