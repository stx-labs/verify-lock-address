import { bech32 } from '@scure/base';
import { buildLockScript, buildUnlockScript, computeBondUnlockHeight, fetchPoxInfo } from '@stacks/bitcoin-staking';
import { bytesToHex, hexToBytes } from '@stacks/common';
import { STACKS_MAINNET, STACKS_TESTNET } from '@stacks/network';
import { Cl, cvToValue, fetchCallReadOnlyFunction } from '@stacks/transactions';
import { sha256 } from '@noble/hashes/sha2.js';

import { describeUnlockScript } from './script-view.ts';
import type { Alternate, Comparison, Network, NetworkName, VerifyInput, VerifyResult } from './types.ts';

export interface UnlockForm {
  mode: string;
  pubkey?: string;
  keys?: string[];
  threshold?: string | number;
  sorted?: boolean;
  rawHex?: string;
}

export interface StakerUnlock {
  unlockBytes: Uint8Array;
  altUnlockBytes: Uint8Array | null;
  altLabel: string;
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

export const PUBKEY_RE = /^(0x)?0[23][0-9a-fA-F]{64}$/;
export const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;

export const clean = (s: string | null | undefined) => (s || '').trim().replace(/^0x/i, '');

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
    throw new Error(`not a P2WSH output script: ${scriptHex}`);
  }
  return bech32.encode(hrp, [0, ...bech32.toWords(s.slice(2))], 256);
}

export const wshOutputScript = (lockScript: Uint8Array) => `0020${bytesToHex(sha256(lockScript))}`;

export async function verify(input: VerifyInput, progress: (message: string) => void = () => {}): Promise<VerifyResult> {
  const net = NETWORKS[input.network];
  const network = { ...net.stacks, client: { baseUrl: net.api } };
  const notes: string[] = [];

  const unlockBytes = input.unlockBytes;
  const tail = describeUnlockScript(unlockBytes);

  progress('reading pox info…');
  const poxInfo = await fetchPoxInfo({ network });
  const derivedHeight = computeBondUnlockHeight({ bondIndex: input.bondIndex, poxInfo });
  const unlockHeight = input.heightOverride ?? derivedHeight;

  progress(`reading bond ${input.bondIndex}…`);
  const bondCv = await fetchCallReadOnlyFunction({
    contractAddress: net.boot,
    contractName: 'pox-5',
    functionName: 'get-protocol-bond',
    functionArgs: [Cl.uint(input.bondIndex)],
    senderAddress: net.boot,
    network,
  });
  const bondValue = cvToValue(bondCv);
  if (!bondValue?.value) throw new Error(`bond ${input.bondIndex} does not exist on ${net.label}`);
  const earlyUnlockBytes = clean(bondValue.value['early-unlock-bytes'].value);

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
  const sdkScript = wshOutputScript(lockScript);

  progress('asking pox-5 for the same script…');
  const onchainCv = await fetchCallReadOnlyFunction({
    contractAddress: net.boot,
    contractName: 'pox-5',
    functionName: 'construct-lockup-output-script',
    functionArgs: [
      Cl.principal(input.stxAddress),
      Cl.uint(unlockHeight),
      Cl.buffer(unlockBytes),
      Cl.bufferFromHex(earlyUnlockBytes),
    ],
    senderAddress: net.boot,
    network,
  });
  const d = cvToValue(onchainCv);
  const contractScript = clean(String(d.value?.value ?? d.value ?? d));

  const agree = sdkScript === contractScript;
  const address = outputScriptToAddress(contractScript, net.hrp);

  let alternate: Alternate | null = null;
  if (input.altUnlockBytes && bytesToHex(input.altUnlockBytes) !== bytesToHex(unlockBytes)) {
    try {
      const altLock = buildLockScript({
        stxAddress: input.stxAddress,
        unlockHeight,
        unlockBytes: input.altUnlockBytes,
        earlyUnlockBytes,
        validateEarlyUnlockBytes: false,
      });
      alternate = { label: input.altLabel, address: outputScriptToAddress(wshOutputScript(altLock), net.hrp) };
    } catch {}
  }

  let comparison: Comparison | null = null;
  if (input.expected) {
    const want = clean(input.expected).toLowerCase();
    comparison = {
      supplied: input.expected.trim(),
      match: want === contractScript.toLowerCase() || input.expected.trim() === address,
    };
  }

  return {
    net,
    tail,
    unlockBytes,
    earlyUnlockBytes,
    poxInfo,
    derivedHeight,
    unlockHeight,
    heightOverridden: input.heightOverride !== undefined && input.heightOverride !== derivedHeight,
    lockScript,
    sdkScript,
    contractScript,
    agree,
    address,
    alternate,
    comparison,
    notes,
    bondIndex: input.bondIndex,
    stxAddress: input.stxAddress,
  };
}

export function buildStakerUnlockBytes(form: UnlockForm): StakerUnlock {
  if (form.mode === 'single') {
    const pk = clean(form.pubkey);
    if (!pk) throw new Error('Enter the 33-byte compressed Bitcoin public key, or connect Leather to fill it in.');
    if (!PUBKEY_RE.test(pk)) throw new Error('A compressed public key is 66 hex characters starting with 02 or 03.');
    return { unlockBytes: buildUnlockScript(pk), altUnlockBytes: null, altLabel: '' };
  }

  if (form.mode === 'multi') {
    const keys = (form.keys ?? []).map(clean).filter(Boolean);
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

    const sorted = sortKeysBip67(keys);
    return {
      unlockBytes: buildMultisigUnlockScript(form.sorted ? sorted : keys, m),
      altUnlockBytes: buildMultisigUnlockScript(form.sorted ? keys : sorted, m),
      altLabel: form.sorted ? 'the order you entered' : 'BIP-67 sorted',
    };
  }

  const raw = clean((form.rawHex ?? '').replace(/\s+/g, ''));
  if (!raw) throw new Error('Paste the staker-unlock-bytes hex.');
  if (!HEX_RE.test(raw) || raw.length % 2) throw new Error('staker-unlock-bytes must be an even-length hex string.');
  return { unlockBytes: hexToBytes(raw), altUnlockBytes: null, altLabel: '' };
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
    btcPublicKey: btc?.publicKey ? clean(btc.publicKey) : '',
    btcAddress: btc?.address ?? '',
    btcType: btc?.type ?? '',
    taprootOnly: Boolean(btc) && btc!.type === 'p2tr',
    missing,
    networkGuess,
  };
}
