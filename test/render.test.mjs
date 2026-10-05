import './helpers/offline.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { buildLockScript } from '@stacks/bitcoin-staking';
import { bytesToHex, hexToBytes } from '@stacks/common';
import { JSDOM } from 'jsdom';

import { p2wshScript } from '../web/src/address.ts';
import { NETWORKS, outputScriptToAddress } from '../web/src/lock.ts';
import { describeUnlockScript } from '../web/src/script-view.ts';
import { computeVerdict, deriveChecks, REQUIRED_CHECKS } from '../web/src/verdict.ts';

const root = new URL('../', import.meta.url);
const html = readFileSync(fileURLToPath(new URL('web/index.html', root)), 'utf8');
const ids = new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g), m => m[1]));

const KEY1 = '032bfc45f5dec5ba404da7ca12d3120dd67350bd72607eec3990bbb31611b454a0';
const KEY2 = '039236b5534c437a2bf0b59963d57771c3f88687b4b3f90b35703dce4acd3879f4';
const UNLOCK_HEX = `5121${KEY1}21${KEY2}52ae`;
const EARLY = '21032853a683729ff79dc33bce675d83892cf0bad4fc15462225de42d7b88ed89292ac';
const STX = 'SN275N04VCDVG27KQSESEKD6X06PS3HH634SNH41M';

const { renderResult } = await import('../web/src/render.ts');

test('every element the code reaches for exists in index.html', () => {
  for (const file of ['app.ts', 'render.ts']) {
    const src = readFileSync(fileURLToPath(new URL(`web/src/${file}`, root)), 'utf8');
    for (const [, id] of src.matchAll(/\$\('([^']+)'\)/g)) {
      assert.ok(ids.has(id), `${file} reads #${id}, which index.html does not define`);
    }
  }
});

test('index.html loads the built bundle and the vendored tokens', () => {
  assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  assert.match(html, /assets\/tokens\.css/);
  assert.ok(readFileSync(fileURLToPath(new URL('web/app.js', root)), 'utf8').length > 1000);
});

function page() {
  const dom = new JSDOM(html.replace('<script type="module" src="app.js"></script>', ''), {
    beforeParse(w) {
      w.matchMedia = () => ({ matches: false, addEventListener() {} });
    },
  });
  dom.window.HTMLElement.prototype.scrollIntoView = () => {};
  globalThis.document = dom.window.document;
  const doc = dom.window.document;
  const text = id => doc.getElementById(id).textContent.replace(/\s+/g, ' ').trim();
  return { doc, window: dom.window, text, el: id => doc.getElementById(id) };
}

function fakeResult(overrides = {}) {
  const unlockBytes = hexToBytes(UNLOCK_HEX);
  const lockScript = buildLockScript({ stxAddress: STX, unlockHeight: 4690, unlockBytes, earlyUnlockBytes: EARLY });
  const script = p2wshScript(lockScript);
  const address = outputScriptToAddress(script, 'bcrt');
  const result = {
    net: NETWORKS['private-1'],
    mode: 'multi',
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
    address,
    comparison: { match: true, reason: 'match', display: address },
    notes: [],
    bondIndex: 106,
    stxAddress: STX,
    ...overrides,
  };
  if (!('checks' in overrides)) result.checks = deriveChecks(result);
  return result;
}

test('a passing result renders the address, the script and the checks', () => {
  const { el, text } = page();
  const result = fakeResult();
  renderResult(result);

  assert.equal(text('addrText'), result.address);
  assert.equal(text('verdictMark'), '✓');
  assert.match(text('verdictTitle'), /Match/);
  assert.equal(el('verdict').className, 'verdict ok');
  assert.equal(el('results').hidden, false);
  assert.equal(text('tPolicy'), '1-of-2');
  assert.equal(text('tHeight'), '4690');
  assert.equal(text('tSize'), String(result.lockScript.length));

  const asm = text('asmOut');
  assert.match(asm, /OP_CHECKLOCKTIMEVERIFY/);
  assert.match(asm, /OP_CHECKMULTISIG/);
  assert.match(asm, /your key #1/);
  assert.match(asm, /your key #2/);
  assert.match(asm, /not yours/, "the bond key must be labelled as not the staker's");
  assert.match(asm, /early-unlock-bytes/);
  assert.match(asm, /staker-unlock-bytes/);
  assert.ok(asm.includes(KEY1) && asm.includes(KEY2), 'both keys shown in full for comparison');
  assert.ok(el('asmOut').querySelector('.t-key'));
  assert.ok(el('asmOut').querySelector('.t-flow'));

  assert.equal(el('rawHexOut').textContent, bytesToHex(result.lockScript));
  assert.equal(el('rawHexOut').querySelectorAll('span').length, 4);

  const checks = text('checks');
  assert.match(checks, /SDK and pox-5 derive the same output script/);
  assert.match(checks, /These keys are yours/);
  assert.match(checks, /1-of-N policy means any single one/, 'the 1-of-2 sweep warning must fire');
});

test('a mismatch renders as a failure, not a pass', () => {
  const { el, text } = page();
  renderResult(fakeResult({ comparison: { match: false, reason: 'mismatch', display: 'bcrt1qwrong' } }));

  assert.equal(text('verdictMark'), '✕');
  assert.equal(el('verdict').className, 'verdict err');
  assert.match(text('verdictTitle'), /does not match/);
  assert.match(text('verdictSub'), /Do not fund/);
  assert.match(text('checks'), /does NOT match/);
  assert.match(text('checks'), /Supplied: bcrt1qwrong/);
});

test('SDK/contract disagreement is reported as a failure', () => {
  const { el, text } = page();
  renderResult(fakeResult({ agree: false, contractScript: `0020${'ff'.repeat(32)}`, comparison: null }));

  assert.equal(el('verdict').className, 'verdict err');
  assert.match(text('verdictTitle'), /SDK and the contract disagree/);
});

test('with no address supplied the verdict stays provisional', () => {
  const { el, text } = page();
  renderResult(fakeResult({ comparison: null }));

  assert.equal(el('verdict').className, 'verdict warn');
  assert.equal(text('verdictTitle'), 'Not compared — paste the destination from your wallet');
  assert.match(text('checks'), /No address supplied/);
});

test('the address for the other key order is never printed', () => {
  const { text, doc } = page();
  const otherOrder = outputScriptToAddress(p2wshScript(buildLockScript({
    stxAddress: STX,
    unlockHeight: 4690,
    unlockBytes: hexToBytes(`5121${KEY2}21${KEY1}52ae`),
    earlyUnlockBytes: EARLY,
  })), 'bcrt');
  for (const comparison of [null, { match: false, reason: 'mismatch', display: 'bcrt1qsupplied' }]) {
    renderResult(fakeResult({ comparison }));
    assert.ok(!doc.body.textContent.includes(otherOrder), `${comparison?.reason}`);
    assert.doesNotMatch(text('verdictSub'), /With the keys|the address would be/);
  }
});

test("a derived height names the SDK's computation as its source", () => {
  const { el, text } = page();
  renderResult(fakeResult());

  assert.equal(text('verdictMark'), '✓');
  assert.equal(text('tHeightSrc'), 'computeBondUnlockHeight');
  assert.ok(el('derivRows').textContent.includes('4690  (computeBondUnlockHeight)'));
});

test('an override is described as one, against the derived height', () => {
  const { el, text } = page();
  renderResult(fakeResult({ unlockHeight: 4800, heightOverridden: true }));

  assert.ok(el('derivRows').textContent.includes('4800  (overridden — computeBondUnlockHeight gives 4690)'));
  assert.equal(text('tHeightSrc'), 'overridden · derived 4690');
});

test('the checklist intro lists the checks without claiming any of them ran', () => {
  assert.doesNotMatch(html, /first three are checked here/);
  const intro = html.match(/<h2 class="pane-title">Before you approve<\/h2>\s*<p class="pane-sub">([\s\S]*?)<\/p>/)[1].replace(/\s+/g, ' ');
  for (const part of [/output script/, /unlock tail/, /address you pasted/, /last two/]) {
    assert.match(intro, part);
  }
  assert.doesNotMatch(intro, /runs here|checked here|were run|ran here/);
  assert.match(intro, /could not be run/);
});

test('a single-sig result renders its own vocabulary', () => {
  const { text } = page();
  const unlockBytes = hexToBytes(`21${KEY1}ac`);
  const lockScript = buildLockScript({ stxAddress: STX, unlockHeight: 4690, unlockBytes, earlyUnlockBytes: EARLY });
  const script = p2wshScript(lockScript);
  renderResult(
    fakeResult({
      mode: 'single',
      tail: describeUnlockScript(unlockBytes),
      unlockBytes,
      lockScript,
      sdkScript: script,
      contractScript: script,
      address: outputScriptToAddress(script, 'bcrt'),
      comparison: null,
    })
  );

  assert.equal(text('tPolicy'), 'single key');
  assert.match(text('asmOut'), /final authorisation — one signature/);
  assert.doesNotMatch(text('checks'), /1-of-N policy/);
});

test('mainnet renders bc1 addresses', () => {
  const result = fakeResult();
  assert.ok(outputScriptToAddress(result.contractScript, NETWORKS.mainnet.hrp).startsWith('bc1q'));
  assert.ok(outputScriptToAddress(result.contractScript, NETWORKS['private-1'].hrp).startsWith('bcrt1q'));
});

test('with no expected address the lock address and output script are withheld', () => {
  const { text, doc } = page();
  const result = fakeResult({ comparison: null });
  renderResult(result);
  assert.doesNotMatch(doc.body.textContent, new RegExp(result.address));
  assert.doesNotMatch(doc.body.textContent, new RegExp(result.contractScript));
  assert.match(text('addrText'), /Paste the destination from your wallet/);
  assert.equal(doc.querySelector('[data-copy="addrText"]').hidden, true);

  renderResult(fakeResult());
  assert.equal(text('addrText'), result.address);
  assert.equal(doc.querySelector('[data-copy="addrText"]').hidden, false);

  renderResult(fakeResult({ comparison: { match: false, reason: 'unreadable', display: null } }));
  assert.doesNotMatch(text('checks'), new RegExp(`computed ${result.address}`), 'junk input does not unlock the address');
  renderResult(fakeResult({ comparison: { match: false, reason: 'mismatch', display: 'bcrt1qtheirs' } }));
  assert.match(text('checks'), new RegExp(`This page computed ${result.address}`));
});

const PAYLOAD = n => `<img src=x onerror=globalThis.__pwn=1>"><svg onload=globalThis.__pwn=1>M${n}Z`;

function leaves(value, path = []) {
  if (typeof value === 'string' || typeof value === 'number') return [path];
  if (!value || typeof value !== 'object' || value instanceof Uint8Array) return [];
  return Object.entries(value).flatMap(([k, v]) => leaves(v, [...path, k]));
}

function setPath(target, path, value) {
  const copy = Array.isArray(target) ? [...target] : { ...target };
  if (path.length === 1) copy[path[0]] = value;
  else copy[path[0]] = setPath(target[path[0]], path.slice(1), value);
  return copy;
}

const SCENARIOS = {
  mismatch: () =>
    fakeResult({
      notes: ['a note'],
      comparison: { match: false, reason: 'mismatch', display: 'bcrt1qsupplied' },
    }),
  overridden: () => fakeResult({ heightOverridden: true }),
  match: () => fakeResult({ notes: ['a note'] }),
};

const NOT_RENDERED = new Map([
  [/^mode$/, 'selects the required checks'],
  [/^comparison\.reason$/, 'enum read by deriveChecks'],
  [/^tail\.(kind|threshold|total)$/, 'drives the tail check and the 1-of-N sentence'],
  [/^net\.(badge|boot|prefixes\.\d+|stacks\..+)$/, 'network constants used by the form and the reads, not the result'],
]);

const notRenderedReason = path => [...NOT_RENDERED].find(([re]) => re.test(path))?.[1];

const ACTIVE = 'img, svg, script, iframe, object, embed';

test('every string and number a result carries is rendered as text, and never as markup', () => {
  const rendered = new Set();
  const seen = new Set();
  let n = 0;
  for (const [name, make] of Object.entries(SCENARIOS)) {
    const base = make();
    for (const path of leaves(base).filter(p => p[0] !== 'checks')) {
      const key = path.join('.');
      seen.add(key);
      n += 1;
      const payload = PAYLOAD(n);
      const result = setPath(base, path, payload);
      result.checks = deriveChecks(result);
      const { doc, window } = page();
      const baseline = doc.querySelectorAll(ACTIVE).length;
      renderResult(result);
      assert.equal(doc.querySelectorAll(ACTIVE).length, baseline, `${name} ${key}: markup was parsed`);
      assert.equal(window.__pwn, undefined, `${name} ${key}`);
      if (doc.body.textContent.includes(payload)) rendered.add(key);
    }
  }
  const missing = [...seen].filter(key => !rendered.has(key) && !notRenderedReason(key));
  assert.deepEqual(missing, [], 'every field is rendered as text in some scenario, or listed with the reason it is not');
  for (const key of ['notes.0', 'comparison.display', 'stxAddress', 'tail.label', 'tail.keys.0']) {
    assert.ok(rendered.has(key), `${key} reaches the page as text`);
  }
});

test('a poisoned check list never renders markup or a pass', () => {
  for (const path of leaves(fakeResult().checks)) {
    const { doc, window, text } = page();
    const baseline = doc.querySelectorAll(ACTIVE).length;
    const base = fakeResult();
    renderResult({ ...base, checks: setPath(base.checks, path, PAYLOAD(0)) });
    assert.equal(doc.querySelectorAll(ACTIVE).length, baseline, path.join('.'));
    assert.equal(window.__pwn, undefined);
    if (path[1] === 'status' || path[1] === 'id') assert.notEqual(text('verdictMark'), '✓', path.join('.'));
  }
});

test('the verdict is ✓ only when every required check passes (table over each mode and check)', () => {
  for (const [mode, required] of Object.entries(REQUIRED_CHECKS)) {
    const allPass = required.map(id => ({ id, status: 'pass', reason: 'ok' }));
    assert.equal(computeVerdict({ mode, checks: allPass }).state, 'match', `${mode}: all pass`);

    for (const id of required) {
      const with_ = status => allPass.map(c => (c.id === id ? { ...c, status } : c));
      assert.equal(computeVerdict({ mode, checks: with_('unknown') }).state, 'unverified', `${mode} ${id} unknown`);
      assert.equal(computeVerdict({ mode, checks: with_('fail') }).state, 'fail', `${mode} ${id} fail`);
      assert.equal(computeVerdict({ mode, checks: with_('PASS') }).state, 'unverified', `${mode} ${id} unknown status word`);
      assert.equal(computeVerdict({ mode, checks: allPass.filter(c => c.id !== id) }).state, 'unverified', `${mode} ${id} missing`);
      assert.equal(
        computeVerdict({ mode, checks: [...allPass, { id, status: 'unknown' }] }).state,
        'unverified',
        `${mode} ${id} duplicated as unknown`
      );
    }
    assert.equal(computeVerdict({ mode, checks: [...allPass, { id: 'extra', status: 'fail' }] }).state, 'fail', 'any fail fails');
    assert.equal(computeVerdict({ mode, checks: [...allPass, { id: 'extra', status: 'unknown' }] }).state, 'unverified');
  }
  assert.equal(computeVerdict({ mode: 'single', checks: REQUIRED_CHECKS.single.map(id => ({ id, status: 'pass' })) }).state, 'match');
  assert.equal(computeVerdict({ mode: 'other', checks: REQUIRED_CHECKS.multi.map(id => ({ id, status: 'pass' })) }).state, 'unverified');
  assert.equal(computeVerdict({ checks: [] }).state, 'unverified');
  assert.equal(computeVerdict(undefined).state, 'unverified');
});

test('the rendered banner, title and mark follow the single verdict for each required check', () => {
  for (const mode of ['single', 'multi']) {
    for (const id of REQUIRED_CHECKS[mode]) {
      for (const [status, mark, cls] of [
        ['unknown', '!', 'verdict warn'],
        ['fail', '✕', 'verdict err'],
        [null, '!', 'verdict warn'],
      ]) {
        const { el, text } = page();
        const base = fakeResult(mode === 'single' ? { mode } : {});
        const checks = status ? base.checks.map(c => (c.id === id ? { ...c, status } : c)) : base.checks.filter(c => c.id !== id);
        renderResult({ ...base, checks });
        assert.equal(text('verdictMark'), mark, `${mode} ${id} ${status}`);
        assert.equal(el('verdict').className, cls, `${mode} ${id} ${status}`);
        assert.doesNotMatch(text('verdictTitle'), /^Match/, `${mode} ${id} ${status}`);
      }
    }
  }
});

test('no computed address or script reaches the page unless a decoded wallet value was compared; the other key order never does', () => {
  const base = fakeResult();
  const altBytes = hexToBytes(`5121${KEY2}21${KEY1}52ae`);
  const otherOrder = outputScriptToAddress(
    p2wshScript(buildLockScript({ stxAddress: STX, unlockHeight: 4690, unlockBytes: altBytes, earlyUnlockBytes: EARLY })),
    'bcrt'
  );
  const strangerScript = `0020${'cd'.repeat(32)}`;
  const computed = [base.address, base.sdkScript, base.contractScript, strangerScript, outputScriptToAddress(strangerScript, 'bcrt')];

  const comparisons = {
    none: null,
    unreadable: { match: false, reason: 'unreadable', display: null },
    'mixed-case': { match: false, reason: 'mixed-case', display: null },
    'unknown reason with a display': { match: false, reason: 'brand-new', display: 'bcrt1qsupplied' },
    'mismatch without a display': { match: false, reason: 'mismatch', display: null },
    'wrong-network': { match: false, reason: 'wrong-network', display: 'bc1qsupplied' },
    mismatch: { match: false, reason: 'mismatch', display: 'bcrt1qsupplied' },
    match: { match: true, reason: 'match', display: base.address },
  };
  const variants = {
    agree: {},
    disagree: { agree: false, contractScript: strangerScript },
  };

  const { doc } = page();
  let states = 0;
  for (const [cName, comparison] of Object.entries(comparisons)) {
    for (const [xName, extra] of Object.entries(variants)) {
      const label = `comparison ${cName}, ${xName}`;
      const result = fakeResult({ comparison, ...extra });
      renderResult(result);
      states += 1;
      const text = doc.body.textContent;
      const allowed = ['match', 'mismatch', 'wrong-network'].includes(comparison?.reason) && Boolean(comparison?.display);
      for (const value of computed) {
        if (!allowed) assert.ok(!text.includes(value), `${label}: ${value} shown`);
      }
      if (allowed) assert.equal(doc.getElementById('addrText').textContent, result.address, label);
      assert.equal(doc.querySelector('[data-copy="addrText"]')?.hidden ?? !allowed, !allowed, `${label}: copy button`);
      assert.ok(!text.includes(otherOrder), `${label}: other order ${otherOrder}`);
    }
  }
  assert.equal(states, 8 * 2);
});

test('every check is required: a result where any one is unread is not ✓, in either mode', () => {
  const pinned = {
    single: ['script', 'expected', 'tail'],
    multi: ['script', 'expected', 'tail'],
  };
  for (const [mode, ids] of Object.entries(pinned)) {
    assert.deepEqual([...REQUIRED_CHECKS[mode]].sort(), [...ids].sort(), mode);
    const base = fakeResult({ mode });
    assert.deepEqual(base.checks.map(c => c.id).sort(), [...ids].sort(), `${mode}: deriveChecks emits each pinned check`);
    for (const id of ids) {
      const checks = base.checks.map(c => (c.id === id ? { ...c, status: 'unknown', reason: 'unread' } : { ...c, status: 'pass' }));
      assert.equal(computeVerdict({ mode, checks }).state, 'unverified', `${mode} ${id}`);
      assert.equal(computeVerdict({ mode, checks: checks.filter(c => c.id !== id) }).state, 'unverified', `${mode} without ${id}`);
    }
  }
  for (const [field, value] of [['agree', null], ['comparison', null], ['tail', null]]) {
    assert.notEqual(computeVerdict(fakeResult({ [field]: value })).state, 'match', field);
  }
});
