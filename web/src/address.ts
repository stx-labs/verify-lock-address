import { bech32, bech32m, createBase58check } from '@scure/base';
import { bytesToHex, hexToBytes } from '@stacks/common';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';

export type BitcoinNetwork = 'mainnet' | 'test';

export type InvalidTargetReason = 'mixed-case' | 'unreadable';

interface InvalidTarget {
  kind: 'invalid';
  reason: InvalidTargetReason;
  display?: undefined;
}

interface SegwitTarget {
  kind: 'segwit';
  hrp: string;
  script: string;
  display: string;
}

interface Base58Target {
  kind: 'p2sh' | 'p2pkh';
  network: BitcoinNetwork;
  script: string;
  display: string;
}

interface ScriptHexTarget {
  kind: 'script';
  template: string;
  script: string;
  display: string;
}

export type ScriptTarget = { kind: 'empty' } | InvalidTarget | SegwitTarget | Base58Target | ScriptHexTarget;

const base58check = createBase58check(sha256);

const P2SH_VERSIONS: Record<number, BitcoinNetwork> = { 0x05: 'mainnet', 0xc4: 'test' };
const P2PKH_VERSIONS: Record<number, BitcoinNetwork> = { 0x00: 'mainnet', 0x6f: 'test' };

const BECH32_HRP = /^(bc|tb|bcrt)1/i;

const SCRIPT_TEMPLATES = [
  { kind: 'p2wsh', re: /^0020[0-9a-f]{64}$/ },
  { kind: 'p2wpkh', re: /^0014[0-9a-f]{40}$/ },
  { kind: 'p2tr', re: /^5120[0-9a-f]{64}$/ },
  { kind: 'p2sh', re: /^a914[0-9a-f]{40}87$/ },
  { kind: 'p2pkh', re: /^76a914[0-9a-f]{40}88ac$/ },
];

const hash160 = (bytes: Uint8Array) => ripemd160(sha256(bytes));

const pushData = (bytes: Uint8Array) => `${bytes.length.toString(16).padStart(2, '0')}${bytesToHex(bytes)}`;

export const hrpNetwork = (hrp: string): BitcoinNetwork => (hrp === 'bc' ? 'mainnet' : 'test');

function readSegwit(text: string): InvalidTarget | SegwitTarget | null {
  if (!BECH32_HRP.test(text)) return null;
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) return { kind: 'invalid', reason: 'mixed-case' };
  const lower = text.toLowerCase();
  for (const codec of [bech32, bech32m]) {
    let decoded;
    try {
      decoded = codec.decode(lower, 90);
    } catch {
      continue;
    }
    const [version, ...rest] = decoded.words;
    if (version > 16 || (version === 0) !== (codec === bech32)) continue;
    let program;
    try {
      program = codec.fromWords(rest);
    } catch {
      continue;
    }
    if (program.length < 2 || program.length > 40) continue;
    if (version === 0 && program.length !== 20 && program.length !== 32) continue;
    const op = version === 0 ? '00' : (0x50 + version).toString(16);
    return { kind: 'segwit', hrp: decoded.prefix, script: `${op}${pushData(program)}`, display: lower };
  }
  return null;
}

function readBase58(text: string): Base58Target | null {
  let bytes;
  try {
    bytes = base58check.decode(text);
  } catch {
    return null;
  }
  if (bytes.length !== 21) return null;
  const [version] = bytes;
  const hash = bytesToHex(bytes.slice(1));
  const display = base58check.encode(bytes);
  if (version in P2SH_VERSIONS) return { kind: 'p2sh', network: P2SH_VERSIONS[version], script: `a914${hash}87`, display };
  if (version in P2PKH_VERSIONS) return { kind: 'p2pkh', network: P2PKH_VERSIONS[version], script: `76a914${hash}88ac`, display };
  return null;
}

function readScriptHex(text: string): ScriptHexTarget | null {
  const hex = text.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  const template = SCRIPT_TEMPLATES.find(t => t.re.test(hex));
  return template ? { kind: 'script', template: template.kind, script: hex, display: hex } : null;
}

export function readScriptTarget(input: unknown): ScriptTarget {
  const text = String(input ?? '').trim();
  if (!text) return { kind: 'empty' };
  return readScriptHex(text) ?? readBase58(text) ?? readSegwit(text) ?? { kind: 'invalid', reason: 'unreadable' };
}

export function p2wshScript(witnessScript: Uint8Array): string {
  return `0020${bytesToHex(sha256(witnessScript))}`;
}

export const p2shOf = (scriptHex: string) => `a914${bytesToHex(hash160(hexToBytes(scriptHex)))}87`;

export function vaultScripts(witnessScript: Uint8Array) {
  const p2wsh = p2wshScript(witnessScript);
  return { p2wsh, p2shP2wsh: p2shOf(p2wsh), p2shBare: p2shOf(bytesToHex(witnessScript)) };
}

export function targetNetworkMismatch(target: ScriptTarget, hrp: string): boolean {
  if (target.kind === 'segwit') return target.hrp !== hrp;
  if (target.kind === 'p2sh' || target.kind === 'p2pkh') return target.network !== hrpNetwork(hrp);
  return false;
}
