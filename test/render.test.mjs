import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildLockScript } from '@stacks/bitcoin-staking';
import { bytesToHex, hexToBytes } from '@stacks/common';

import { NETWORKS, outputScriptToAddress, wshOutputScript } from '../web/src/lock.js';
import { describeUnlockScript } from '../web/src/script-view.js';

const root = new URL('../', import.meta.url);
const html = readFileSync(fileURLToPath(new URL('web/index.html', root)), 'utf8');
const ids = new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g), m => m[1]));

const KEY1 = '032bfc45f5dec5ba404da7ca12d3120dd67350bd72607eec3990bbb31611b454a0';
const KEY2 = '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4';
const UNLOCK_HEX = `5121${KEY1}21${KEY2}52ae`;
const EARLY = '21032853a683729ff79dc33bce675d83892cf0bad4fc15462225de42d7b88ed89292ac';

test('every element the code reaches for exists in index.html', () => {
  for (const file of ['app.js', 'render.js']) {
    const src = readFileSync(fileURLToPath(new URL(`web/src/${file}`, root)), 'utf8');
    for (const [, id] of src.matchAll(/\$\('([^']+)'\)/g)) {
      assert.ok(ids.has(id), `${file} reads #${id}, which index.html does not define`);
    }
  }
});

test('index.html loads the built bundle and the vendored tokens', () => {
  assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  assert.match(html, /assets\/tokens\.css/);
  // The bundle is committed alongside the page: GitHub Pages serves static files only.
  assert.ok(readFileSync(fileURLToPath(new URL('web/app.js', root)), 'utf8').length > 1000);
});

/** Minimal DOM: enough for the render path, and loud about anything unexpected. */
function stubDom() {
  const nodes = new Map();
  const make = id => ({
    id,
    _html: '',
    textContent: '',
    className: '',
    hidden: true,
    get innerHTML() {
      return this._html;
    },
    set innerHTML(v) {
      this._html = v;
    },
    scrollIntoView() {},
  });
  globalThis.document = {
    getElementById(id) {
      assert.ok(ids.has(id), `render reached for #${id}, absent from index.html`);
      if (!nodes.has(id)) nodes.set(id, make(id));
      return nodes.get(id);
    },
  };
  return nodes;
}

/** A verify() result built offline — no API, but the same shape and real script bytes. */
function fakeResult(overrides = {}) {
  const unlockBytes = hexToBytes(UNLOCK_HEX);
  const lockScript = buildLockScript({
    stxAddress: 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M',
    unlockHeight: 4690,
    unlockBytes,
    earlyUnlockBytes: EARLY,
  });
  const script = wshOutputScript(lockScript);
  return {
    net: NETWORKS['private-1'],
    tail: describeUnlockScript(unlockBytes),
    unlockBytes,
    earlyUnlockBytes: EARLY,
    derivedHeight: 4690,
    unlockHeight: 4690,
    heightOverridden: false,
    lockScript,
    sdkScript: script,
    contractScript: script,
    agree: true,
    address: outputScriptToAddress(script, 'bcrt'),
    alternate: null,
    comparison: { supplied: outputScriptToAddress(script, 'bcrt'), match: true },
    notes: [],
    bondIndex: 106,
    stxAddress: 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M',
    ...overrides,
  };
}

test('a passing result renders the address, the script and the checks', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  const result = fakeResult();
  renderResult(result);

  assert.equal(nodes.get('addrText').textContent, result.address);
  assert.equal(nodes.get('verdictMark').textContent, '✓');
  assert.match(nodes.get('verdictTitle').textContent, /Match/);
  assert.equal(nodes.get('verdict').className, 'verdict ok');
  assert.equal(nodes.get('results').hidden, false);
  assert.equal(nodes.get('tPolicy').textContent, '1-of-2');
  assert.equal(nodes.get('tHeight').textContent, '4690');
  assert.equal(nodes.get('tSize').textContent, String(result.lockScript.length));

  const asm = nodes.get('asmOut').innerHTML;
  assert.match(asm, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(asm, /OP_CHECKMULTISIG/);
  assert.match(asm, /your key #1/);
  assert.match(asm, /your key #2/);
  assert.match(asm, /not yours/, 'the bond key must be labelled as not the staker&#39;s');
  assert.match(asm, /early-unlock-bytes/);
  assert.match(asm, /staker-unlock-bytes/);
  assert.ok(asm.includes(KEY1) && asm.includes(KEY2), 'both keys shown in full for comparison');
  assert.match(asm, /t-key/);
  assert.match(asm, /t-flow/);

  // The tinted hex must reassemble into exactly the script.
  const raw = nodes.get('rawHexOut').innerHTML.replace(/<[^>]+>/g, '');
  assert.equal(raw, bytesToHex(result.lockScript));

  const checks = nodes.get('checks').innerHTML;
  assert.match(checks, /SDK and pox-5 derive the same output script/);
  assert.match(checks, /These keys are yours/);
  assert.match(checks, /1-of-N policy means any single one/, 'the 1-of-2 sweep warning must fire');
});

test('a mismatch renders as a failure, not a pass', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  renderResult(fakeResult({ comparison: { supplied: 'bcrt1qwrong', match: false } }));

  assert.equal(nodes.get('verdictMark').textContent, '✕');
  assert.equal(nodes.get('verdict').className, 'verdict err');
  assert.match(nodes.get('verdictTitle').textContent, /does not match/);
  assert.match(nodes.get('verdictSub').innerHTML, /Do not fund/);
  assert.match(nodes.get('checks').innerHTML, /does NOT match/);
});

test('SDK/contract disagreement is reported as a failure', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  renderResult(fakeResult({ agree: false, contractScript: `0020${'ff'.repeat(32)}`, comparison: null }));

  assert.equal(nodes.get('verdict').className, 'verdict err');
  assert.match(nodes.get('verdictTitle').textContent, /SDK and the contract disagree/);
});

test('with no address supplied the verdict stays provisional', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  renderResult(fakeResult({ comparison: null }));

  assert.equal(nodes.get('verdict').className, 'verdict warn');
  assert.match(nodes.get('verdictTitle').textContent, /now check the keys are yours/);
  assert.match(nodes.get('checks').innerHTML, /No address supplied/);
});

test('the alternate key order is offered when it differs', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  renderResult(fakeResult({ alternate: { label: 'BIP-67 sorted', address: 'bcrt1qalternate' } }));

  assert.match(nodes.get('verdictSub').innerHTML, /BIP-67 sorted/);
  assert.match(nodes.get('verdictSub').innerHTML, /bcrt1qalternate/);
});

test('a single-sig result renders its own vocabulary', async () => {
  const nodes = stubDom();
  const { renderResult } = await import('../web/src/render.js');
  const unlockBytes = hexToBytes(`21${KEY1}ac`);
  const lockScript = buildLockScript({
    stxAddress: 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M',
    unlockHeight: 4690,
    unlockBytes,
    earlyUnlockBytes: EARLY,
  });
  const script = wshOutputScript(lockScript);
  renderResult(
    fakeResult({
      tail: describeUnlockScript(unlockBytes),
      unlockBytes,
      lockScript,
      sdkScript: script,
      contractScript: script,
      address: outputScriptToAddress(script, 'bcrt'),
      comparison: null,
    })
  );

  assert.equal(nodes.get('tPolicy').textContent, 'single key');
  assert.match(nodes.get('asmOut').innerHTML, /final authorisation — one signature/);
  assert.doesNotMatch(nodes.get('checks').innerHTML, /1-of-N policy/);
});

test('mainnet renders bc1 addresses', () => {
  const result = fakeResult();
  assert.ok(outputScriptToAddress(result.contractScript, NETWORKS.mainnet.hrp).startsWith('bc1q'));
  assert.ok(outputScriptToAddress(result.contractScript, NETWORKS['private-1'].hrp).startsWith('bcrt1q'));
});
