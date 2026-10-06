import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after } from 'node:test';

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@stacks/common';
import { Cl, cvToValue, deserializeCV, serializeCV } from '@stacks/transactions';

export const POX = JSON.parse(readFileSync(new URL('../fixtures/mainnet-pox.json', import.meta.url), 'utf8'));

export const BOND_2_EARLY = '2102fd9c38fb020cb9efe3f89f80cc118a27272828c477eaa0a5a6d7403ee8d8fc45ac';
export const BOND_2_HEIGHT = 994700;
export const BOND_2_TUPLE = Cl.tuple({
  'early-unlock-bytes': Cl.bufferFromHex(BOND_2_EARLY),
  'min-ustx-ratio': Cl.uint(500),
  'stx-value-ratio': Cl.uint(267384),
  'target-rate': Cl.uint(300),
});
const BOND_2_CV = Cl.some(BOND_2_TUPLE);

export const ALLOWLISTED = 'SP2TC7YMDH77T5GP41W6JZK3Q7AJ10ZJ36ZQNGQ79';
export const NOT_LISTED = 'SP72DMR3MJKS7RVBY33JVV7EEJSQ1PYDVKDP10FX';

export const VAULT = 'bc1q2t8hc5ssw5evn22w9ptvuhuux8k39nqn735hqz9yhqr4ttltl5nqfugtpv';
export const DESCRIPTOR =
  'wsh(sortedmulti(2,xpub6BuKrNqTrGfsy8VAAdUW2KCxbHywuSKjg7hZuAXERXDv7GfuxUgUWdVRKNsgujcwdjEHCjaXWouPKi1m5gMgdWX8JpRcyMkrSxPe4Da3Lx8/0/0,xpub6C4MQD2bVDTfdnVe5AYKB6gE7BE4yQeKBRgukQ4Hi3phDB5fCYKEAdViQ2n7kZQ1t728QV4wKGgiR5qGigjNNrm5DCGWYUZDRVNWYb8ZWGK/0/0))';
export const LOCK_ADDRESS = 'bc1qs4vfn4jc7va3lspxfw2ukxnwa9lj9024hf3t29p9g3j7r2ah9tqquj99qp';
export const LOCK_OUTPUT = '0020855899d658f33b1fc0264b95cb1a6ee97f22bd55ba62b514254465e1abb72ac0';

export const membershipTuple = bondIndex =>
  Cl.tuple({
    'bond-index': Cl.uint(bondIndex),
    'amount-ustx': Cl.uint(1_000_000_000),
    signer: Cl.principal(ALLOWLISTED),
    'is-l1-lock': Cl.bool(true),
    'amount-sats': Cl.uint(1_000_000),
  });

export const membershipIn = bondIndex => Cl.some(membershipTuple(bondIndex));

export const stakeTuple = (firstCycle, numCycles) =>
  Cl.tuple({
    'amount-ustx': Cl.uint(1_000_000_000),
    'first-reward-cycle': Cl.uint(firstCycle),
    'num-cycles': Cl.uint(numCycles),
    signer: Cl.principal(ALLOWLISTED),
  });

export const stakeOver = (firstCycle, numCycles) => Cl.some(stakeTuple(firstCycle, numCycles));

export const STUB_NETWORKS = {
  mainnet: { api: 'https://api.hiro.so', boot: 'SP000000000000000000002Q6VF78' },
  'private-1': { api: 'https://api.private-1.hiro.so', boot: 'ST000000000000000000002AMW42H' },
};

const VIOLATIONS = [];
after(() => assert.deepEqual(VIOLATIONS, [], 'a stubbed request went to the wrong host or contract'));

export const takeViolations = () => VIOLATIONS.splice(0);

function scriptNum(n) {
  const out = [];
  for (let v = BigInt(n); v > 0n; v >>= 8n) out.push(Number(v & 0xffn));
  if (out[out.length - 1] & 0x80) out.push(0);
  return out;
}

function pushHeight(height) {
  if (height === 0) return [0x00];
  if (height <= 16) return [0x50 + height];
  const bytes = scriptNum(height);
  return [bytes.length, ...bytes];
}

export function contractLockScriptHex(inputs) {
  return bytesToHex(contractLockScript(inputs));
}

export function contractLockupOutputScript(inputs) {
  return `0020${bytesToHex(sha256(contractLockScript(inputs)))}`;
}

function contractLockScript({ staker, unlockHeight, stakerUnlockHex, earlyUnlockHex }) {
  const principal = hexToBytes(serializeCV(Cl.principal(staker)));
  return Uint8Array.from([
    0x63,
    ...pushHeight(Number(unlockHeight)),
    0xb1,
    0x67,
    0x82,
    0x01,
    0x20,
    0x88,
    0xa8,
    0x20,
    ...sha256(sha256(principal)),
    0x88,
    ...hexToBytes(earlyUnlockHex),
    0x68,
    0x69,
    ...hexToBytes(stakerUnlockHex),
  ]);
}

export const DEFAULT_ACCOUNT = { balance: 1_000_000_000_000n, locked: 0n };

const hex128 = n => `0x${BigInt(n).toString(16).padStart(32, '0')}`;

export const undefinedFunction = fn =>
  new Response(JSON.stringify({ okay: false, cause: `RuntimeCheck(UndefinedFunction("${fn}"))` }), { status: 200 });

export function stubApi({
  allowance = Cl.some(Cl.uint(10_000_000)),
  contractHeight = BOND_2_HEIGHT,
  bonds = [2],
  membership = Cl.none(),
  stakerInfo = Cl.none(),
  burnHeight = POX.current_burnchain_block_height,
  pox = {},
  replies = {},
  hang = [],
  abortAs = 'reason',
  rejectWith = {},
  fail = {},
  network = 'mainnet',
  account = DEFAULT_ACCOUNT,
  lockupScript = null,
} = {}) {
  const calls = [];
  const requests = [];
  const { api, boot } = STUB_NETWORKS[network];
  const reply = cv => new Response(JSON.stringify({ okay: true, result: `0x${serializeCV(cv)}` }), { status: 200 });
  const never = signal =>
    new Promise((_, reject) => {
      if (!signal) return;
      const fail = () =>
        reject(abortAs === 'plain' ? Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }) : signal.reason);
      if (signal.aborted) fail();
      else signal.addEventListener('abort', fail, { once: true });
    });

  const fetch = async (url, init) => {
    const u = String(url);
    requests.push({ url: u, body: init?.body === undefined ? '' : String(init.body), signal: init?.signal ?? null, at: Date.now() });
    if (!u.startsWith(`${api}/`)) {
      VIOLATIONS.push(`${network}: request to ${u}, expected host ${api}`);
      throw new Error(`stub: ${u} is not on ${api}`);
    }
    if (u.includes('/v2/accounts/')) {
      calls.push({ fn: '/v2/accounts', args: [decodeURIComponent(u.split('/v2/accounts/')[1].split('?')[0])] });
      if (hang.includes('accounts')) return never(init?.signal);
      if (Object.hasOwn(rejectWith, 'accounts')) throw rejectWith.accounts;
      if (fail.accounts) return new Response('upstream said no', { status: fail.accounts });
      const body = typeof account === 'function' ? account() : { balance: hex128(account.balance), locked: hex128(account.locked), nonce: 0 };
      return new Response(JSON.stringify(body), { status: 200 });
    }
    if (u.endsWith('/v2/pox')) {
      if (hang.includes('pox')) return never(init?.signal);
      if (Object.hasOwn(rejectWith, 'pox')) throw rejectWith.pox;
      if (fail.pox) return new Response('upstream said no', { status: fail.pox });
      return new Response(JSON.stringify({ ...POX, current_burnchain_block_height: burnHeight, ...pox }), { status: 200 });
    }

    const contractPath = `${api}/v2/contracts/call-read/${boot}/pox-5/`;
    if (!u.startsWith(contractPath)) {
      VIOLATIONS.push(`${network}: read-only call ${u}, expected ${contractPath}…`);
      throw new Error(`stub: ${u} is not a call to ${boot}.pox-5`);
    }
    const fn = u.slice(contractPath.length).split(/[/?]/)[0];
    const args = JSON.parse(init.body).arguments.map(a => deserializeCV(a.replace(/^0x/, '')));
    calls.push({ fn, args: args.map(a => String(cvToValue(a))) });
    if (hang.includes(fn)) return never(init?.signal);
    if (Object.hasOwn(rejectWith, fn)) throw rejectWith[fn];
    if (fail[fn] === 'network') throw new TypeError('fetch failed', { cause: Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }) });
    if (fail[fn] === 'missing') return undefinedFunction(fn);
    if (fail[fn]) return new Response('upstream said no', { status: fail[fn] });
    if (fn in replies) return reply(replies[fn]);

    switch (fn) {
      case 'get-protocol-bond':
        return reply(bonds.includes(Number(cvToValue(args[0]))) ? BOND_2_CV : Cl.none());
      case 'get-bond-l1-unlock-height':
        if (contractHeight === null) return undefinedFunction(fn);
        return reply(Cl.uint(contractHeight));
      case 'get-bond-allowance':
        return reply(allowance);
      case 'get-bond-membership':
        return reply(membership);
      case 'get-staker-info':
        return reply(stakerInfo);
      case 'construct-lockup-output-script': {
        const [staker, height, unlock, early] = args.map(cvToValue);
        const script =
          lockupScript ??
          contractLockupOutputScript({
            staker,
            unlockHeight: Number(height),
            stakerUnlockHex: unlock.replace(/^0x/, ''),
            earlyUnlockHex: early.replace(/^0x/, ''),
          });
        return reply(Cl.ok(Cl.bufferFromHex(script)));
      }
      default:
        throw new Error(`unexpected call ${u}`);
    }
  };
  return { fetch, calls, requests };
}
