import { guardFetch, live, takeAttempts } from './helpers/offline.mjs';
import assert from 'node:assert/strict';
import test, { afterEach } from 'node:test';

import { buildUnlockScript } from '@stacks/bitcoin-staking';
import { Cl } from '@stacks/transactions';

import {
  buildStakerUnlockBytes,
  NETWORKS,
  INPUT_LABELS,
  isStacksPrincipal,
  verify,
} from '../web/src/lock.ts';
import { computeVerdict } from '../web/src/verdict.ts';
import { AMBIGUOUS_KEY_ERROR, privateKeyError } from '../web/src/secrets.ts';
import { embeddings, PRIVATE_KEYS } from './helpers/secrets.mjs';
import {
  ALLOWLISTED,
  BOND_2_EARLY,
  BOND_2_HEIGHT,
  BOND_2_TUPLE,
  LOCK_ADDRESS,
  LOCK_OUTPUT,
  NOT_LISTED,
  VAULT,
  stubApi as makeStub,
  takeViolations,
} from './helpers/stub-api.mjs';
import { deadlineError, isTransient, reachable, skipOnTransient, throwIfTransientGap } from './helpers/live.mjs';

const VAULT_KEYS = [
  '030347be500a8b2707a00e7576c0c527a247cddc6e8363ee51147b8e43b590baa9',
  '0347b913aed4ee088b6fea3e9537836a1c8f1b72111cf010af5589d93f3a433f02',
];

const vaultInput = () => ({ mode: 'multi', ...buildStakerUnlockBytes({ mode: 'multi', keys: VAULT_KEYS, threshold: 2, sorted: true }) });

const passing = (overrides = {}) => ({
  network: 'mainnet',
  bondIndex: 2,
  stxAddress: ALLOWLISTED,
  ...vaultInput(),
  expected: LOCK_ADDRESS,
  ...overrides,
});

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function stubApi(opts) {
  const stub = makeStub(opts);
  globalThis.fetch = stub.fetch;
  stub.calls.requests = stub.requests;
  return stub.calls;
}

const checkOf = (r, id) => r.checks.find(c => c.id === id);

test('bond 2: a staker with the vault keys and the matching address is a match', async () => {
  stubApi();
  const r = await verify(passing());

  assert.deepEqual(r.notes, []);
  assert.equal(r.agree, true);
  assert.equal(r.unlockHeight, BOND_2_HEIGHT);
  assert.equal(r.earlyUnlockBytes, BOND_2_EARLY);
  assert.equal(r.contractScript, LOCK_OUTPUT);
  assert.equal(r.address, LOCK_ADDRESS);
  assert.equal(r.tail.label, '2-of-2');
  assert.equal(r.mode, 'multi');
  assert.ok(r.checks.every(c => c.status === 'pass'), JSON.stringify(r.checks));
  assert.equal(computeVerdict(r).state, 'match');
});

test('verify refuses a private key in any text it is handed, before any request and without echoing it', async () => {
  for (const [kind, key] of Object.entries(PRIVATE_KEYS)) {
    for (const [where, text] of Object.entries(embeddings(key))) {
      for (const field of ['expected', 'stxAddress']) {
        const calls = stubApi();
        await assert.rejects(verify(passing({ [field]: text })), e => {
          assert.equal(e.message, privateKeyError(INPUT_LABELS[field]), `${kind} ${where} in ${field}`);
          assert.ok(!e.message.includes(key.slice(0, 6)) && !e.message.includes(key.slice(-6)));
          return true;
        });
        assert.deepEqual(calls.requests, [], `${kind} ${where} in ${field}: nothing sent, /v2/pox included`);
      }
    }
  }
});

test('verify refuses a staker principal that is not one, before any request', async () => {
  for (const stxAddress of [`${ALLOWLISTED}.`, `${ALLOWLISTED}.a.b`, 'SP2TC7YMDH77T5GP41W6JZK3Q7AJ10ZJ36ZQNGQ7X', 'not-a-principal', `${ALLOWLISTED}.${'a'.repeat(41)}`]) {
    const calls = stubApi();
    await assert.rejects(verify(passing({ stxAddress })), /not a valid Stacks address/);
    assert.deepEqual(calls.requests, [], stxAddress);
  }
  stubApi();
  assert.equal((await verify(passing({ stxAddress: `${ALLOWLISTED}.my-vault_1` }))).stxAddress, `${ALLOWLISTED}.my-vault_1`);
});

test('every bond and staker read is asked once about the bond index and principal being verified', async () => {
  const expectedArgs = bondIndex => ({
    'get-protocol-bond': [String(bondIndex)],
  });

  for (const bondIndex of [3, 106]) {
    for (const staker of [ALLOWLISTED, NOT_LISTED]) {
      const stub = makeStub({ bonds: [bondIndex] });
      globalThis.fetch = stub.fetch;
      await verify({ network: 'mainnet', bondIndex, stxAddress: staker, ...vaultInput() });

      for (const [fn, args] of Object.entries(expectedArgs(bondIndex))) {
        const seen = stub.calls.filter(c => c.fn === fn);
        assert.equal(seen.length, 1, `${fn} is read once`);
        assert.deepEqual(seen[0].args, args, `${fn} for bond ${bondIndex} and ${staker}`);
      }
      const lockup = stub.calls.filter(c => c.fn === 'construct-lockup-output-script');
      assert.equal(lockup.length, 1);
      assert.equal(lockup[0].args[0], staker, 'construct-lockup-output-script for the same principal');
      assert.equal(stub.requests.filter(r => r.url.endsWith('/v2/pox')).length, 1, '/v2/pox is read once');
      assert.equal(stub.requests.length, 3, 'one /v2/pox and two pox-5 reads per verification');
      assert.ok(stub.requests.every(r => r.signal && typeof r.signal.aborted === 'boolean'), 'every request carries an abort signal');
    }
  }
});

test('an override replaces the derived height and is described as an override', async () => {
  stubApi();
  const above = await verify(passing({ heightOverride: BOND_2_HEIGHT + 20 }));
  assert.equal(above.unlockHeight, BOND_2_HEIGHT + 20);
  assert.equal(above.derivedHeight, BOND_2_HEIGHT);
  assert.equal(above.heightOverridden, true);

  const same = await verify(passing({ heightOverride: BOND_2_HEIGHT }));
  assert.equal(same.heightOverridden, false, 'overriding with the derived height is no override');

  for (const heightOverride of [0, -1, 1.5, 2 ** 60, NaN]) {
    await assert.rejects(verify(passing({ heightOverride })), /override must be a whole number/);
  }
});

test('the expected address is compared as a script: either bech32 case, hex, or a stated reason it cannot match', async () => {
  const cases = [
    [LOCK_ADDRESS, true, 'match'],
    [LOCK_ADDRESS.toUpperCase(), true, 'match'],
    [LOCK_OUTPUT, true, 'match'],
    [`0x${LOCK_OUTPUT.toUpperCase()}`, true, 'match'],
    [`  ${LOCK_ADDRESS}\n`, true, 'match'],
    [`bc1Q${LOCK_ADDRESS.slice(4)}`, false, 'mixed-case'],
    ['bcrt1qs4vfn4jc7va3lspxfw2ukxnwa9lj9024hf3t29p9g3j7r2ah9tqqsz8dyc', false, 'unreadable'],
    [VAULT, false, 'mismatch'],
    ['tb1q2t8hc5ssw5evn22w9ptvuhuux8k39nqn735hqz9yhqr4ttltl5nq757ymr', false, 'wrong-network'],
    ['hello <b>world</b>', false, 'unreadable'],
  ];
  for (const [expected, match, reason] of cases) {
    stubApi();
    const r = await verify(passing({ expected }));
    assert.equal(r.comparison.match, match, expected);
    assert.equal(r.comparison.reason, reason, expected);
    assert.equal(computeVerdict(r).state, match ? 'match' : 'fail', expected);
    if (reason === 'unreadable') assert.equal(r.comparison.display, null, 'unreadable input is never echoed');
  }
  stubApi();
  const none = await verify(passing({ expected: null }));
  assert.equal(none.comparison, null);
  assert.equal(checkOf(none, 'expected').status, 'unknown');
  assert.equal(computeVerdict(none).state, 'unverified');
});

test('the bond and lockup-script reads accept only their exact type; anything else fails the verification', async () => {
  const bond = {
    ok: Cl.ok(Cl.some(BOND_2_TUPLE)),
    'bare tuple': BOND_2_TUPLE,
    err: Cl.error(Cl.uint(1)),
    'missing field': Cl.some(Cl.tuple({ 'early-unlock-bytes': Cl.bufferFromHex(BOND_2_EARLY) })),
    'wrong field type': Cl.some(Cl.tuple({ ...BOND_2_TUPLE.value, 'early-unlock-bytes': Cl.stringAscii(BOND_2_EARLY) })),
  };
  for (const [shape, cv] of Object.entries(bond)) {
    stubApi({ replies: { 'get-protocol-bond': cv } });
    await assert.rejects(verify(passing()), /get-protocol-bond returned a value of an unexpected shape/, shape);
  }

  const lockup = {
    bare: Cl.bufferFromHex(LOCK_OUTPUT),
    some: Cl.some(Cl.ok(Cl.bufferFromHex(LOCK_OUTPUT))),
    err: Cl.error(Cl.uint(1)),
    none: Cl.none(),
    'ok uint': Cl.ok(Cl.uint(1)),
  };
  for (const [shape, cv] of Object.entries(lockup)) {
    stubApi({ replies: { 'construct-lockup-output-script': cv } });
    await assert.rejects(verify(passing()), /construct-lockup-output-script returned a value of an unexpected shape/, shape);
  }

  stubApi({ replies: { 'construct-lockup-output-script': Cl.ok(Cl.bufferFromHex(`0014${'11'.repeat(20)}`)) } });
  await assert.rejects(verify(passing()), /not a P2WSH output script/);
});

test('unusable /v2/pox cycle parameters fail the verification instead of deriving from them', async () => {
  for (const pox of [
    { reward_cycle_length: '2100<b>' },
    { reward_cycle_length: 0 },
    { prepare_cycle_length: -1 },
    { prepare_cycle_length: 1.5 },
    { first_burnchain_block_height: 2 ** 60 },
    { first_burnchain_block_height: null },
  ]) {
    stubApi({ pox });
    await assert.rejects(verify(passing()), /\/v2\/pox returned cycle parameters this page cannot use/, JSON.stringify(pox));
  }
});

function within(ms, promise) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`verify() was still pending after ${ms} ms`)), ms);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

test('a read that never answers is aborted with a message naming it, and the verification fails', async () => {
  for (const abortAs of ['reason', 'plain']) {
    for (const fn of ['get-protocol-bond', 'pox', 'construct-lockup-output-script']) {
      const calls = stubApi({ hang: [fn], abortAs });
      const name = fn === 'pox' ? '/v2/pox' : fn;
      await assert.rejects(within(2000, verify(passing(), () => {}, { timeoutMs: 50 })), e => {
        assert.equal(e.name, 'TimeoutError');
        assert.equal(e.message, `${name} did not answer within 0.1 s`);
        return true;
      });
      assert.ok(calls.requests.filter(q => q.url.endsWith(fn === 'pox' ? '/v2/pox' : `/${fn}`)).every(q => q.signal.aborted), fn);
    }
  }
});

test('every request is bounded without AbortSignal.timeout, and its timer is cleared once it answers', async () => {
  const saved = AbortSignal.timeout;
  delete AbortSignal.timeout;
  try {
    assert.equal(typeof AbortSignal.timeout, 'undefined');
    const calls = stubApi();
    const r = await verify(passing());
    assert.equal(computeVerdict(r).state, 'match');
    assert.ok(calls.requests.every(q => q.signal && q.signal.aborted === false), 'answered reads are never aborted later');
    stubApi({ hang: ['construct-lockup-output-script'] });
    await assert.rejects(within(2000, verify(passing(), () => {}, { timeoutMs: 50 })), e => e.name === 'TimeoutError');
  } finally {
    AbortSignal.timeout = saved;
  }
});

test('a read rejected with a falsy reason is a failed read, never an empty answer', async () => {
  for (const reason of [undefined, null, 0, '', false]) {
    for (const fn of ['get-protocol-bond', 'pox', 'construct-lockup-output-script']) {
      stubApi({ rejectWith: { [fn]: reason } });
      await assert.rejects(verify(passing()), e => e instanceof Error && e.message.includes(fn === 'pox' ? '/v2/pox' : fn), `${fn} ${String(reason)}`);
    }
  }
});

test('only own network names are accepted, before any request', async () => {
  for (const network of ['constructor', 'toString', '__proto__', 'valueOf', 'hasOwnProperty', '', undefined]) {
    const calls = stubApi();
    await assert.rejects(verify(passing({ network })), /Choose a network this page supports/, String(network));
    assert.deepEqual(calls.requests, [], String(network));
  }
});

test('any valid c32 principal is accepted, including short ones; anything else is not', () => {
  for (const ok of ['SP000000000000000000002Q6VF78', 'SP00000000000000000005JA84HQ', 'ST000000000000000000002AMW42H', 'SP000000000000000000002Q6VF78.pox-5', ALLOWLISTED]) {
    assert.equal(isStacksPrincipal(ok), true, ok);
  }
  for (const bad of [ALLOWLISTED.toLowerCase(), 'SP000000000000000000002Q6VF79', `${ALLOWLISTED}.`, `${ALLOWLISTED}.1abc`, 'SX000000000000000000002Q6VF78', '', null]) {
    assert.equal(isStacksPrincipal(bad), false, String(bad));
  }
});

test('expected input is shown back only once decoded into a standard script template', async () => {
  for (const [expected, reason] of [
    ['e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa332', 'unreadable'],
    ['00', 'unreadable'],
    [`0020${'ab'.repeat(31)}`, 'unreadable'],
    ['37Rf1c6VoRDVNBXVuiiqLZdLehvksYa4Yf', 'unreadable'],
    ['xpub6BuKrNqTrGfsy8VAAdUW2KCxbHywuSKjg7hZuAXERXDv7GfuxUgUWdVRKNsgujcwdjEHCjaXWouPKi1m5gMgdWX8JpRcyMkrSxPe4Da3Lx8', 'unreadable'],
    [`0014${'11'.repeat(20)}`, 'mismatch'],
    [`5120${'11'.repeat(32)}`, 'mismatch'],
    [`76a914${'11'.repeat(20)}88ac`, 'mismatch'],
  ]) {
    stubApi();
    const r = await verify(passing({ expected }));
    assert.equal(r.comparison.reason, reason, expected);
    if (reason === 'unreadable') assert.equal(r.comparison.display, null, expected);
    else assert.equal(r.comparison.display, expected);
  }
});

test('the live-test guard skips transient failures only', async () => {
  const withCode = (code, nested = false) => {
    const inner = Object.assign(new Error(`connect ${code}`), { code });
    return new TypeError('fetch failed', { cause: nested ? new AggregateError([inner], 'all failed') : inner });
  };
  const transient = [
    new Error('Error calling read-only function. Response 429: Too Many Requests.'),
    new Error('Error calling read-only function. Response 408: Request Timeout.'),
    new Error('Error calling read-only function. Response 425: Too Early.'),
    new Error('Error fetching pox info. Response 503: Service Unavailable.'),
    new Error('Error fetching pox info. Response 500: Internal Server Error.'),
    withCode('ECONNRESET'),
    withCode('ECONNREFUSED'),
    withCode('ECONNREFUSED', true),
    withCode('ETIMEDOUT'),
    withCode('EAI_AGAIN'),
    withCode('UND_ERR_SOCKET'),
    withCode('UND_ERR_CONNECT_TIMEOUT'),
    withCode('EPIPE'),
    withCode('ENETUNREACH'),
    withCode('EHOSTUNREACH'),
    withCode('ECONNABORTED'),
    Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }),
    Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }),
  ];
  const real = [
    withCode('ENOTFOUND'),
    withCode('CERT_HAS_EXPIRED'),
    withCode('ERR_TLS_CERT_ALTNAME_INVALID'),
    withCode('UNABLE_TO_VERIFY_LEAF_SIGNATURE'),
    new TypeError('fetch failed'),
    new TypeError('fetch failed', { cause: new Error('unknown scheme') }),
    new Error('Error calling read-only function. Response 400: Bad Request.'),
    new Error('Error calling read-only function. Response 403: Forbidden.'),
    new Error('Error fetching pox info. Response 404: Not Found.'),
    new Error('bond 2 does not exist on mainnet'),
    new assert.AssertionError({ message: 'wrong address' }),
    new Error('… If the API is unreachable, check that https://api.private-1.hiro.so is up and that the bond exists on that network.'),
    new Error('socket hang up ECONNRESET in a message but no code'),
    Object.assign(new Error('get-protocol-bond did not answer within 0 s'), { name: 'TimeoutError' }),
    deadlineError(45_000),
    Object.assign(new Error('/v2/pox did not answer within 15 s'), { name: 'TimeoutError' }),
    new Error('Not all reads finished', { cause: Object.assign(new Error('get-staker-info did not answer within 0 s'), { name: 'TimeoutError' }) }),
    Object.assign(new Error('The verification was cancelled because the inputs changed.'), { name: 'AbortError' }),
    new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:3999'), { code: 'ECONNREFUSED', address: '127.0.0.1', port: 3999 }) }),
    new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED ::1:3999'), { code: 'ECONNREFUSED', address: '::1', port: 3999 }) }),
    new TypeError('fetch failed', { cause: new AggregateError([Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:3999'), { code: 'ECONNREFUSED', address: '127.0.0.1' })]) }),
    Object.assign(new Error('… If the API is unreachable, check that http://localhost:3999 is up and that the bond exists on that network.'), {
      cause: Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    }),
  ];
  for (const e of transient) {
    assert.equal(isTransient(e), true, e.message);
    const skipped = [];
    assert.equal(await skipOnTransient({ skip: m => skipped.push(m) }, async () => { throw e; }), undefined);
    assert.equal(skipped.length, 1, e.message);
  }
  for (const e of real) {
    assert.equal(isTransient(e), false, e.message);
    await assert.rejects(skipOnTransient({ skip: () => assert.fail('must not skip') }, async () => { throw e; }), e);
  }
});

test('the reachability probe skips only on transient answers', async () => {
  const t = () => {
    const skipped = [];
    return { skip: m => skipped.push(m), skipped };
  };
  const ok = t();
  assert.equal(await reachable(ok, 'https://x', async () => new Response('{}', { status: 200 })), true);
  assert.deepEqual(ok.skipped, []);

  for (const status of [429, 502, 503]) {
    const probe = t();
    assert.equal(await reachable(probe, 'https://x', async () => new Response('', { status })), false);
    assert.equal(probe.skipped.length, 1, String(status));
  }
  for (const status of [301, 403, 404]) {
    await assert.rejects(reachable(t(), 'https://x.invalid', async () => new Response('', { status })), new RegExp(`HTTP ${status}`));
  }
  const reset = t();
  assert.equal(
    await reachable(reset, 'https://x', async () => {
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('x'), { code: 'ECONNRESET' }) });
    }),
    false
  );
  const notFound = async () => {
    throw new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo ENOTFOUND api.hirro.so'), { code: 'ENOTFOUND' }) });
  };
  await assert.rejects(reachable(t(), 'https://api.hirro.so/v2/pox', notFound, { resolveControl: async () => ({}) }), /fetch failed/, 'online, wrong host: fails');
  const offline = t();
  assert.equal(
    await reachable(offline, 'https://api.hiro.so/v2/pox', notFound, {
      resolveControl: async () => {
        throw Object.assign(new Error('getaddrinfo ENOTFOUND github.com'), { code: 'ENOTFOUND' });
      },
    }),
    false,
    'offline: skips'
  );
  assert.match(offline.skipped[0], /offline/);
  await assert.rejects(
    reachable(t(), 'https://x.invalid', async () => {
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' }) });
    }, { resolveControl: async () => { throw new Error('never asked'); } }),
    /fetch failed/
  );
});

test('throwIfTransientGap surfaces a transient read error and lets the rest through', () => {
  const transient = Object.assign(new Error('x'), { name: 'TimeoutError' });
  assert.throws(() => throwIfTransientGap({ readErrors: { 'get-staker-info': transient } }), transient);
  const r = { readErrors: { 'get-staker-info': new Error('RuntimeCheck(UndefinedFunction("get-staker-info"))') } };
  assert.equal(throwIfTransientGap(r), r);
});

test('bond 2 on mainnet reproduces the pinned multisig lock address', async t => {
  if (!(await reachable(t, `${NETWORKS.mainnet.api}/v2/pox`))) return;

  const r = await skipOnTransient(t, () => live(async () => throwIfTransientGap(await verify(passing()))));
  if (!r) return;

  assert.equal(r.earlyUnlockBytes, BOND_2_EARLY);
  assert.equal(r.unlockHeight, BOND_2_HEIGHT);
  assert.equal(r.agree, true);
  assert.equal(r.contractScript, LOCK_OUTPUT);
  assert.equal(r.address, LOCK_ADDRESS);
  assert.equal(r.comparison.match, true);
  assert.deepEqual(r.notes, []);
});

test("the page's own read timeout makes a live test fail, not skip", async () => {
  globalThis.fetch = makeStub({ hang: ['get-protocol-bond'] }).fetch;
  const error = await verify(passing(), () => {}, { timeoutMs: 15 }).then(
    () => assert.fail('a hanging read must not resolve'),
    e => e
  );
  assert.equal(error.name, 'TimeoutError');
  assert.equal(isTransient(error), false);
  await assert.rejects(skipOnTransient({ skip: () => assert.fail('must not skip') }, async () => { throw error; }), error);
});

test('the stub refuses and records a request to the wrong host or contract for its network', async () => {
  const stub = makeStub({ network: 'mainnet' });
  for (const url of [
    'https://api.private-1.hiro.so/v2/pox',
    'https://api.testnet.hiro.so/v2/pox',
    'https://api.hiro.so/v2/contracts/call-read/ST000000000000000000002AMW42H/pox-5/get-protocol-bond',
    'https://api.hiro.so/v2/contracts/call-read/SP000000000000000000002Q6VF78/pox-4/get-protocol-bond',
  ]) {
    await assert.rejects(stub.fetch(url, { method: 'POST', body: '{"arguments":[]}' }), /stub:/, url);
  }
  assert.equal(takeViolations().length, 4);

  globalThis.fetch = makeStub({ network: 'private-1' }).fetch;
  await assert.rejects(verify(passing()), /stub:/, 'a mainnet verification against a private-1 stub is caught');
  assert.ok(takeViolations().length > 0);
});

test('the offline guard refuses and records any real request a non-live test makes', async () => {
  globalThis.fetch = guardFetch;
  await assert.rejects(verify(passing()), /non-live test reached for the network/);
  const attempts = takeAttempts();
  assert.ok(attempts.some(url => url.startsWith('https://api.hiro.so/')), attempts.join(', '));
});

test('a missing bond or a failed lockup-script read fails fast, without waiting on the other reads', async () => {
  for (const [stub, message] of [
    [{ bonds: [], hang: ['pox'] }, /does not exist/],
    [{ fail: { 'construct-lockup-output-script': 400 } }, /construct-lockup-output-script|400/],
  ]) {
    globalThis.fetch = makeStub(stub).fetch;
    const started = Date.now();
    await assert.rejects(verify(passing(), () => {}, { timeoutMs: 5_000 }), message);
    assert.ok(Date.now() - started < 1_000, `took ${Date.now() - started} ms`);
  }
});

test('a verification that fails early aborts the reads it left in flight', async () => {
  const stub = makeStub({ bonds: [], hang: ['pox'] });
  globalThis.fetch = stub.fetch;
  await assert.rejects(verify(passing(), () => {}, { timeoutMs: 5_000 }), /does not exist/);
  const pox = stub.requests.filter(r => r.url.endsWith('/v2/pox'));
  assert.equal(pox.length, 1);
  assert.ok(pox[0].signal.aborted, 'the /v2/pox read was aborted');
});

test('a cancelled verification aborts its requests and rejects at once', async () => {
  for (const hang of [['get-protocol-bond', 'pox'], ['construct-lockup-output-script']]) {
    const stub = makeStub({ hang });
    globalThis.fetch = stub.fetch;
    const controller = new AbortController();
    const pending = verify(passing(), () => {}, { timeoutMs: 10_000, signal: controller.signal });
    await new Promise(r => setTimeout(r, 20));
    const started = Date.now();
    controller.abort();
    await assert.rejects(pending, e => e.name === 'AbortError' && /cancelled/.test(e.message));
    assert.ok(Date.now() - started < 200);
    const inFlight = stub.requests.filter(r => hang.some(fn => r.url.endsWith(`/${fn}`)));
    assert.equal(inFlight.length, hang.length, hang.join(', '));
    assert.ok(inFlight.every(r => r.signal.aborted), 'every request still in flight was aborted');
  }

  const already = new AbortController();
  already.abort();
  globalThis.fetch = makeStub().fetch;
  await assert.rejects(verify(passing(), () => {}, { signal: already.signal }), /cancelled/);
});

test('verify refuses a key shaped like a Stacks private key unless the caller says it was confirmed', async () => {
  const AMBIGUOUS = '022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01';
  const single = { mode: 'single', unlockBytes: buildUnlockScript(AMBIGUOUS), altUnlockBytes: null };
  const stub = makeStub();
  globalThis.fetch = stub.fetch;
  await assert.rejects(verify(passing(single)), e => e.message === AMBIGUOUS_KEY_ERROR);
  assert.deepEqual(stub.requests, [], 'nothing sent');
  const r = await verify(passing({ ...single, ambiguousKeysConfirmed: true }));
  assert.equal(r.tail.keys[0], AMBIGUOUS);
});
