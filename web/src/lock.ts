import { bech32 } from '@scure/base';
import { buildLockScript, buildUnlockScript, computeBondUnlockHeight, fetchPoxInfo, firstPox5RewardCycle } from '@stacks/bitcoin-staking';
import type { PoxInfo } from '@stacks/bitcoin-staking';
import { hexToBytes } from '@stacks/common';
import { STACKS_MAINNET, STACKS_TESTNET } from '@stacks/network';
import { Cl, fetchCallReadOnlyFunction, validateStacksAddress } from '@stacks/transactions';
import type { ClarityValue } from '@stacks/transactions';

import { p2wshScript, readScriptTarget, targetNetworkMismatch } from './address.ts';
import { decodeReply, isHeight, POX5_REPLIES } from './clarity.ts';
import type { Pox5Read, Pox5Reply } from './clarity.ts';
import { describeUnlockScript } from './script-view.ts';
import { AMBIGUOUS_KEY_ERROR, AMBIGUOUS_KEY_RE, assertNoPrivateKey, assertScreened } from './secrets.ts';
import type { Comparison, ErrorLike, Network, NetworkName, Settled, VerifyFacts, VerifyInput, VerifyResult } from './types.ts';
import { deriveChecks } from './verdict.ts';

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export interface UnlockForm {
  mode: string;
  pubkey?: string;
  keys?: string[];
  threshold?: string | number;
  sorted?: boolean;
  rawHex?: string;
  trustedKeys?: string[];
  confirmAmbiguous?: boolean;
}

export interface StakerUnlock {
  unlockBytes: Uint8Array;
  altUnlockBytes: Uint8Array | null;
  altLabel: string;
  ambiguousKeysConfirmed: boolean;
}

interface WalletEntry {
  symbol?: string;
  address?: string;
  type?: string;
  publicKey?: string;
}

export interface WalletAddresses {
  stxAddress: string;
  btcPublicKey: string;
  btcAddress: string;
  btcType: string;
  taprootOnly: boolean;
  missing: ('stx' | 'btc')[];
  networkGuess: NetworkName | null;
}

export const NETWORKS: Record<NetworkName, Network> = {
  'private-1': {
    label: 'private-1',
    api: 'https://api.private-1.hiro.so',
    hrp: 'bcrt',
    boot: 'ST000000000000000000002AMW42H',
    stacks: STACKS_TESTNET,
    badge: 'badge-net',
    prefixes: ['ST', 'SN'],
  },
  mainnet: {
    label: 'mainnet',
    api: 'https://api.hiro.so',
    hrp: 'bc',
    boot: 'SP000000000000000000002Q6VF78',
    stacks: STACKS_MAINNET,
    badge: 'badge-main',
    prefixes: ['SP', 'SM'],
  },
};

export const READ_TIMEOUT_MS = 15_000;

export const PUBKEY_RE = /^0[23][0-9a-f]{64}$/;
export const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;

export const clean = (s: string | null | undefined) => (s || '').trim().replace(/^(?:0x)+/i, '');

export const normalizeKey = (s: string | null | undefined) => clean(s).toLowerCase();

export const isAmbiguousKey = (key: string | null | undefined) => AMBIGUOUS_KEY_RE.test(normalizeKey(key));

export const MAX_UNLOCK_BYTES = 683;

const isBondIndex = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 0;

export function buildMultisigUnlockScript(pubkeys: string[], threshold: number): Uint8Array {
  if (pubkeys.length < 1 || pubkeys.length > 16) {
    throw new Error(`multisig needs between 1 and 16 keys, got ${pubkeys.length}`);
  }
  if (threshold < 1 || threshold > pubkeys.length) {
    throw new Error(`threshold ${threshold} is out of range for ${pubkeys.length} key(s)`);
  }

  const parts: Uint8Array[] = [Uint8Array.of(0x50 + threshold)];
  for (const key of pubkeys) {
    const bytes = hexToBytes(clean(key));
    if (bytes.length !== 33) throw new Error(`expected a 33-byte compressed key, got ${bytes.length} bytes`);
    if (bytes[0] !== 0x02 && bytes[0] !== 0x03) {
      throw new Error(`compressed keys start with 02 or 03, got ${bytes[0].toString(16).padStart(2, '0')}`);
    }
    parts.push(Uint8Array.of(0x21), bytes);
  }
  parts.push(Uint8Array.of(0x50 + pubkeys.length), Uint8Array.of(0xae));

  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export const sortKeysBip67 = (keys: string[]) => [...keys].map(clean).sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1));

export function outputScriptToAddress(scriptHex: string, hrp: string): string {
  const s = hexToBytes(clean(scriptHex));
  if (s.length !== 34 || s[0] !== 0x00 || s[1] !== 0x20) {
    throw new Error('not a P2WSH output script');
  }
  return bech32.encode(hrp, [0, ...bech32.toWords(s.slice(2))], 256);
}

const NO_REASON = 'the read failed without giving a reason';

const errorText = (e: any): string => {
  if (e === undefined || e === null || e === '') return NO_REASON;
  return String(e instanceof Error || typeof e?.message === 'string' ? e.message : e).slice(0, 240) || NO_REASON;
};

const isErrorLike = (e: any): e is ErrorLike => typeof e === 'object' && e !== null && typeof e.message === 'string' && e.message !== '';

export function readFailure(read: string, error: unknown): ErrorLike {
  if (isErrorLike(error)) return error;
  return new Error(`${read} failed: ${errorText(error)}`);
}

export function errorSignature(e: any): { name: string; code: string } {
  const seen = new Set<object>();
  const codes: string[] = [];
  const walk = (err: any) => {
    if (!err || typeof err !== 'object' || seen.has(err)) return;
    seen.add(err);
    if (typeof err.code === 'string') codes.push(err.code);
    if (Array.isArray(err.errors)) err.errors.forEach(walk);
    walk(err.cause);
  };
  walk(e);
  return { name: typeof e?.name === 'string' ? e.name : 'Error', code: codes[0] ?? '' };
}

const CONTRACT_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_-]{0,39}$/;

export function isStacksPrincipal(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const [address, name, ...rest] = value.split('.');
  if (rest.length || !/^S[PTMN][0-9A-Z]+$/.test(address)) return false;
  let valid = false;
  try {
    valid = validateStacksAddress(address);
  } catch {
    valid = false;
  }
  return valid && (name === undefined || CONTRACT_NAME_RE.test(name));
}

export function validatePoxInfo(poxInfo: PoxInfo): PoxInfo {
  const fail: () => never = () => {
    throw new Error('/v2/pox returned cycle parameters this page cannot use');
  };
  if (!poxInfo || typeof poxInfo !== 'object') fail();
  const { firstBurnchainBlockHeight, rewardCycleLength, prepareCycleLength } = poxInfo;
  if (!isHeight(firstBurnchainBlockHeight)) fail();
  if (!Number.isSafeInteger(rewardCycleLength) || rewardCycleLength <= 0) fail();
  if (!Number.isSafeInteger(prepareCycleLength) || prepareCycleLength <= 0 || prepareCycleLength >= rewardCycleLength) fail();
  if (!Array.isArray(poxInfo.contractVersions)) fail();
  let firstCycle;
  try {
    firstCycle = firstPox5RewardCycle(poxInfo);
  } catch {
    fail();
  }
  if (firstCycle !== undefined && !isHeight(firstCycle)) fail();
  return poxInfo;
}

export function compareExpected(expectedInput: unknown, contractScript: string, hrp: string): Comparison | null {
  const target = readScriptTarget(expectedInput);
  if (target.kind === 'empty') return null;
  const display = target.display ?? null;
  if (target.kind === 'invalid') return { match: false, reason: target.reason, display };
  if (targetNetworkMismatch(target, hrp)) return { match: false, reason: 'wrong-network', display };
  return target.script === contractScript.toLowerCase()
    ? { match: true, reason: 'match', display }
    : { match: false, reason: 'mismatch', display };
}

const seconds = (ms: number) => `${Math.round(ms / 100) / 10} s`;

export function cancelledError(): Error {
  const e = new Error('The verification was cancelled because the inputs changed.');
  e.name = 'AbortError';
  return e;
}

export function timedRead<T>(
  what: string,
  timeoutMs: number,
  run: (fetch: Fetch) => T | Promise<T>,
  outer: AbortSignal | null = null
): Promise<T> {
  const controller = new AbortController();
  const reason = new Error(`${what} did not answer within ${seconds(timeoutMs)}`);
  reason.name = 'TimeoutError';
  const timer = setTimeout(() => controller.abort(reason), timeoutMs);
  const cancel = () => controller.abort(cancelledError());
  if (outer?.aborted) cancel();
  else outer?.addEventListener('abort', cancel, { once: true });
  const fetch: Fetch = (url, init = {}) => globalThis.fetch(url, { ...init, signal: controller.signal });
  let running: Promise<T>;
  try {
    running = Promise.resolve(run(fetch));
  } catch (e) {
    running = Promise.reject(e);
  }
  const done = () => {
    clearTimeout(timer);
    outer?.removeEventListener('abort', cancel);
  };
  return running.then(
    value => {
      done();
      return value;
    },
    error => {
      done();
      throw controller.signal.aborted ? controller.signal.reason : error;
    }
  );
}

const settle = <T>(promise: Promise<T>): Promise<Settled<T>> =>
  promise.then(
    (value): Settled<T> => ({ ok: true, value }),
    (error): Settled<T> => ({ ok: false, error })
  );

export const INPUT_LABELS: Partial<Record<keyof VerifyInput, string>> = {
  stxAddress: 'staker principal',
  expected: 'expected address',
  heightOverride: 'unlock height override',
};

function validateInput(input: VerifyInput): void {
  if (!input || typeof input !== 'object' || typeof input.network !== 'string' || !Object.hasOwn(NETWORKS, input.network)) {
    throw new Error('Choose a network this page supports.');
  }
  assertScreened(Object.entries(INPUT_LABELS).map(([key, label]) => ({ label, value: input[key as keyof VerifyInput] })));
  if (!isBondIndex(input.bondIndex)) throw new Error('The bond index must be a whole number, 0 or above.');
  if (!isStacksPrincipal(input.stxAddress)) throw new Error('The staker principal is not a valid Stacks address.');
  if (input.heightOverride !== undefined && (!Number.isSafeInteger(input.heightOverride) || input.heightOverride <= 0)) {
    throw new Error('The unlock height override must be a whole number above 0.');
  }
  if (!(input.unlockBytes instanceof Uint8Array) || !input.unlockBytes.length || input.unlockBytes.length > MAX_UNLOCK_BYTES) {
    throw new Error('The staker-unlock-bytes are missing or too long.');
  }
  if (describeUnlockScript(input.unlockBytes).keys.some(isAmbiguousKey) && input.ambiguousKeysConfirmed !== true) {
    throw new Error(AMBIGUOUS_KEY_ERROR);
  }
}

export async function verify(
  input: VerifyInput,
  progress: (message: string) => void = () => {},
  { timeoutMs = READ_TIMEOUT_MS, signal = null }: { timeoutMs?: number; signal?: AbortSignal | null } = {}
): Promise<VerifyResult> {
  validateInput(input);
  if (signal?.aborted) throw cancelledError();

  const reads = new AbortController();
  const cancel = () => reads.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    return await readAndCompare(input, progress, timeoutMs, reads.signal);
  } finally {
    signal?.removeEventListener('abort', cancel);
    reads.abort();
  }
}

async function readAndCompare(
  input: VerifyInput,
  progress: (message: string) => void,
  timeoutMs: number,
  signal: AbortSignal
): Promise<VerifyResult> {
  const net = NETWORKS[input.network];
  const notes: string[] = [];

  const unlockBytes = input.unlockBytes;
  const tail = describeUnlockScript(unlockBytes);
  const mode = input.mode === 'multi' || tail.kind === 'multisig' ? 'multi' : 'single';
  const client = (fetch: Fetch) => ({ baseUrl: net.api, fetch });

  const read = <T>(what: string, run: (fetch: Fetch) => T | Promise<T>) => timedRead(what, timeoutMs, run, signal);
  const readOnly = <F extends Pox5Read>(functionName: F, functionArgs: ClarityValue[]): Promise<Pox5Reply<F>> =>
    read(functionName, fetch =>
      fetchCallReadOnlyFunction({
        contractAddress: net.boot,
        contractName: 'pox-5',
        functionName,
        functionArgs,
        senderAddress: net.boot,
        network: net.stacks,
        client: client(fetch),
      }).then(cv => decodeReply(cv, POX5_REPLIES[functionName], functionName))
    );

  progress(`reading bond ${input.bondIndex}…`);
  const bondPending = settle(readOnly('get-protocol-bond', [Cl.uint(input.bondIndex)]));
  const poxPending = settle(read('/v2/pox', fetch => fetchPoxInfo({ network: net.stacks, client: client(fetch) })));

  const bondRead = await bondPending;
  if (!bondRead.ok) throw readFailure('get-protocol-bond', bondRead.error);
  if (bondRead.value === null) throw new Error(`bond ${input.bondIndex} does not exist on ${net.label}`);
  const earlyUnlockBytes = bondRead.value['early-unlock-bytes'];

  const poxRead = await poxPending;
  if (!poxRead.ok) throw readFailure('/v2/pox', poxRead.error);
  const poxInfo = validatePoxInfo(poxRead.value);
  const derivedHeight = computeBondUnlockHeight({ bondIndex: input.bondIndex, poxInfo });
  if (!isHeight(derivedHeight)) throw new Error('The unlock height could not be derived from /v2/pox.');
  const unlockHeight = input.heightOverride ?? derivedHeight;
  const heightOverridden = input.heightOverride !== undefined && input.heightOverride !== derivedHeight;

  progress('building the lock script…');
  let lockScript: Uint8Array;
  try {
    lockScript = buildLockScript({ stxAddress: input.stxAddress, unlockHeight, unlockBytes, earlyUnlockBytes });
  } catch (e) {
    if (!/earlyUnlockBytes:/.test(String((e as Error).message))) throw e;
    notes.push(`The bond's early-unlock-bytes fail the SDK shape check (${(e as Error).message}). Continuing without it.`);
    lockScript = buildLockScript({
      stxAddress: input.stxAddress,
      unlockHeight,
      unlockBytes,
      earlyUnlockBytes,
      validateEarlyUnlockBytes: false,
    });
  }
  const sdkScript = p2wshScript(lockScript);

  progress('asking pox-5 for the same script…');
  const contractRead = await settle(
    readOnly('construct-lockup-output-script', [
      Cl.principal(input.stxAddress),
      Cl.uint(unlockHeight),
      Cl.buffer(unlockBytes),
      Cl.bufferFromHex(earlyUnlockBytes),
    ])
  );
  if (!contractRead.ok) throw readFailure('construct-lockup-output-script', contractRead.error);
  const contractScript = contractRead.value;
  if (signal.aborted) throw cancelledError();

  const agree = sdkScript === contractScript;
  const address = outputScriptToAddress(contractScript, net.hrp);
  const comparison = compareExpected(input.expected ?? '', contractScript, net.hrp);

  const facts: VerifyFacts = {
    net,
    mode,
    tail,
    unlockBytes,
    earlyUnlockBytes,
    poxInfo,
    derivedHeight,
    unlockHeight,
    heightOverridden,
    lockScript,
    sdkScript,
    contractScript,
    agree,
    address,
    comparison,
    notes,
    bondIndex: input.bondIndex,
    stxAddress: input.stxAddress,
  };
  return { ...facts, checks: deriveChecks(facts) };
}

function approveAmbiguous(keys: string[], form: UnlockForm): boolean {
  const trusted = new Set((form.trustedKeys ?? []).map(normalizeKey));
  const ambiguous = keys.filter(k => AMBIGUOUS_KEY_RE.test(k));
  if (ambiguous.some(k => !trusted.has(k)) && form.confirmAmbiguous !== true) throw new Error(AMBIGUOUS_KEY_ERROR);
  return ambiguous.length > 0;
}

export function buildStakerUnlockBytes(form: UnlockForm): StakerUnlock {
  if (form.mode === 'single') {
    assertNoPrivateKey(form.pubkey);
    const pk = normalizeKey(form.pubkey);
    if (!pk) throw new Error('Enter the 33-byte compressed Bitcoin public key, or connect Leather to fill it in.');
    if (!PUBKEY_RE.test(pk)) throw new Error('A compressed public key is 66 hex characters starting with 02 or 03.');
    const ambiguousKeysConfirmed = approveAmbiguous([pk], form);
    return { unlockBytes: buildUnlockScript(pk), altUnlockBytes: null, altLabel: '', ambiguousKeysConfirmed };
  }

  if (form.mode === 'multi') {
    assertNoPrivateKey(form.keys ?? []);
    const keys = (form.keys ?? []).map(normalizeKey).filter(Boolean);
    if (!keys.length) throw new Error('Add the public keys of your Bitcoin vault.');
    for (const k of keys) {
      if (!PUBKEY_RE.test(k)) throw new Error(`"${k.slice(0, 12)}…" is not a 33-byte compressed public key.`);
    }
    if (new Set(keys.map(k => k.toLowerCase())).size !== keys.length) {
      throw new Error('The same public key appears twice — a multisig needs distinct keys.');
    }
    const m = Number(form.threshold);
    if (!Number.isInteger(m) || m < 1 || m > keys.length) {
      throw new Error(`Threshold must be between 1 and ${keys.length}.`);
    }
    const ambiguousKeysConfirmed = approveAmbiguous(keys, form);

    const sorted = sortKeysBip67(keys);
    return {
      unlockBytes: buildMultisigUnlockScript(form.sorted ? sorted : keys, m),
      altUnlockBytes: buildMultisigUnlockScript(form.sorted ? keys : sorted, m),
      altLabel: form.sorted ? 'the order you entered' : 'BIP-67 sorted',
      ambiguousKeysConfirmed,
    };
  }

  const raw = clean((form.rawHex ?? '').replace(/\s+/g, ''));
  if (!raw) throw new Error('Paste the staker-unlock-bytes hex.');
  if (!HEX_RE.test(raw) || raw.length % 2) throw new Error('staker-unlock-bytes must be an even-length hex string.');
  return { unlockBytes: hexToBytes(raw), altUnlockBytes: null, altLabel: '', ambiguousKeysConfirmed: false };
}

const HRP_NETWORK: Record<string, NetworkName | undefined> = { bc: 'mainnet', bcrt: 'private-1' };

export function pickWalletAddresses(list: unknown): WalletAddresses {
  const entries: WalletEntry[] = Array.isArray(list) ? list.filter(a => a && typeof a === 'object') : [];

  const stx =
    entries.find(a => a.symbol === 'STX') ??
    entries.find(a => /^S[PTMN][0-9A-Z]{37,}$/.test((a.address || '').split('.')[0]));

  const btcEntries = entries.filter(
    a => a.symbol === 'BTC' || /^(bc|tb|bcrt)1/.test(a.address || '')
  );
  const btc =
    btcEntries.find(a => a.type === 'p2wpkh' && a.publicKey) ??
    btcEntries.find(a => a.type !== 'p2tr' && a.publicKey) ??
    btcEntries.find(a => a.publicKey) ??
    null;

  const missing: ('stx' | 'btc')[] = [];
  if (!stx?.address) missing.push('stx');
  if (!btc?.publicKey) missing.push('btc');

  let networkGuess: NetworkName | null = null;
  if (stx?.address) networkGuess = /^S[PM]/.test(stx.address) ? 'mainnet' : 'private-1';
  else if (btc?.address) networkGuess = HRP_NETWORK[(btc.address.match(/^(bcrt|bc|tb)1/) ?? [])[1]] ?? null;

  return {
    stxAddress: stx?.address ?? '',
    btcPublicKey: btc?.publicKey ? normalizeKey(btc.publicKey) : '',
    btcAddress: btc?.address ?? '',
    btcType: btc?.type ?? '',
    taprootOnly: Boolean(btc) && btc!.type === 'p2tr',
    missing,
    networkGuess,
  };
}
