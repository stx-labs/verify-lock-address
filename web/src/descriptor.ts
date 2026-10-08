import { HDKey } from '@scure/bip32';
import { bytesToHex } from '@stacks/common';

import { assertNoPrivateKey, MAX_DESCRIPTOR_LENGTH, PRIVATE_KEY_ERROR, tooLongError } from './secrets.ts';

export const MAX_MULTISIG_KEYS = 20;

export type KeyNetwork = 'mainnet' | 'testnet';

export interface ParsedDescriptor {
  keys: string[];
  extendedKeys: string[];
  threshold: number;
  sorted: boolean;
  network: KeyNetwork | null;
  notes: string[];
}

interface ExtendedKeyKind {
  network: KeyNetwork;
  versions: { public: number; private: number };
}

const VERSIONS: Record<string, ExtendedKeyKind | undefined> = {
  xpub: { network: 'mainnet', versions: { public: 0x0488b21e, private: 0x0488ade4 } },
  tpub: { network: 'testnet', versions: { public: 0x043587cf, private: 0x04358394 } },
};

const INPUT_CHARSET =
  '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  let out = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
  for (let i = 0; i < 5; i += 1) if ((c0 >> BigInt(i)) & 1n) out ^= GENERATORS[i];
  return out;
}

export function descriptorChecksum(body: string): string {
  let c = 1n;
  let cls = 0;
  let clsCount = 0;
  for (const ch of body) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) throw new Error('The descriptor contains a character descriptors cannot hold.');
    c = polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    clsCount += 1;
    if (clsCount === 3) {
      c = polymod(c, cls);
      cls = 0;
      clsCount = 0;
    }
  }
  if (clsCount > 0) c = polymod(c, cls);
  for (let i = 0; i < 8; i += 1) c = polymod(c, 0);
  c ^= 1n;
  let out = '';
  for (let j = 0; j < 8; j += 1) out += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
  return out;
}

const SLIP132_PREFIXES = ['ypub', 'zpub', 'Ypub', 'Zpub', 'upub', 'vpub', 'Upub', 'Vpub'];

const RAW_KEY_RE = /^0[23][0-9a-fA-F]{64}$/;
const ORIGIN_RE = /^\[[0-9a-fA-F]{8}(\/\d+['hH]?)*\]/;
const EXTENDED_RE = /^([a-zA-Z]{4})([1-9A-HJ-NP-Za-km-z]+)((?:\/[^/]+)*)$/;

function deriveKey(expression: string, n: number, notes: string[]): { key: string; network: KeyNetwork | null } {
  const expr = expression.replace(ORIGIN_RE, '');

  if (RAW_KEY_RE.test(expr)) return { key: expr.toLowerCase(), network: null };
  if (/^04[0-9a-fA-F]{128}$/.test(expr)) {
    throw new Error('The descriptor has an uncompressed key; wsh() multisig needs 33-byte compressed keys.');
  }

  const m = expr.match(EXTENDED_RE);
  if (!m) throw new Error(`Key #${n} in the descriptor is not a public key or an extended public key.`);
  const [, prefix, , path] = m;

  if (/prv$/i.test(prefix)) throw new Error(PRIVATE_KEY_ERROR);
  const kind = VERSIONS[prefix];
  if (!kind && SLIP132_PREFIXES.includes(prefix)) {
    throw new Error(`Key #${n} in the descriptor is a SLIP-132 extended key (ypub, zpub…), which is not supported here; export the descriptor with xpub or tpub keys.`);
  }
  if (!kind) throw new Error(`Key #${n} in the descriptor is not a public key or an extended public key.`);

  let node: HDKey;
  try {
    node = HDKey.fromExtendedKey(expr.slice(0, expr.length - path.length), kind.versions);
  } catch {
    throw new Error(`Key #${n} in the descriptor is not a valid extended public key.`);
  }
  const indexes = path
    .split('/')
    .slice(1)
    .map(step => {
      if (step.startsWith('<')) throw new Error('Multipath <a;b> descriptors are not supported; pick the receive branch, e.g. /0/*.');
      if (/['hH]$/.test(step)) throw new Error('A hardened step after an extended public key cannot be derived without the private key.');
      if (step === '*') {
        if (!notes.includes(WILDCARD_NOTE)) notes.push(WILDCARD_NOTE);
        return 0;
      }
      if (!/^\d{1,10}$/.test(step)) throw new Error(`Key #${n} in the descriptor has a derivation step that is not a number.`);
      const index = Number(step);
      if (index >= HARDENED_OFFSET) {
        throw new Error(`Key #${n} in the descriptor has a derivation step of 2^31 or more, which is a hardened index and cannot be derived from a public key.`);
      }
      return index;
    });
  try {
    for (const index of indexes) node = node.deriveChild(index);
  } catch {
    throw new Error(`Key #${n} in the descriptor could not be derived along its path.`);
  }
  return { key: bytesToHex(node.publicKey!), network: kind.network };
}

const HARDENED_OFFSET = 2 ** 31;

const WILDCARD_NOTE =
  'The descriptor derives keys with /*; this uses index 0. A vault at another index has different keys and a different lock address.';

export function parseMultisigDescriptor(input: unknown): ParsedDescriptor {
  const written = String(input ?? '').trim();
  if (!written) throw new Error('Paste a wsh(multi(…)) or wsh(sortedmulti(…)) descriptor.');
  if (written.length > MAX_DESCRIPTOR_LENGTH) throw new Error(tooLongError('descriptor', MAX_DESCRIPTOR_LENGTH));
  assertNoPrivateKey(written);

  const hashes = written.split('#');
  if (hashes.length > 2) throw new Error('The descriptor has more than one # checksum.');
  const [writtenBody, sum] = hashes;
  if (sum !== undefined && descriptorChecksum(writtenBody) !== sum) {
    throw new Error('The descriptor checksum does not match its contents — it was altered or mistyped.');
  }
  const body = writtenBody.replace(/\s+/g, '');

  const m = body.match(/^wsh\((sortedmulti|multi)\(([^()]*)\)\)$/);
  if (!m) {
    if (/^wsh\(.*(after|older|sha256|hash160|and_v|or_i|or_d|andor)\(/.test(body)) {
      throw new Error(
        "This is a timelocked or hash-locked policy, not a plain multisig. The staker-unlock-bytes are the vault's own m-of-n script, so use the vault descriptor."
      );
    }
    throw new Error('Only wsh(multi(m,…)) and wsh(sortedmulti(m,…)) descriptors are supported.');
  }

  const [, fn, args] = m;
  const [thresholdRaw, ...expressions] = args.split(',');
  const threshold = /^\d{1,2}$/.test(thresholdRaw) ? Number(thresholdRaw) : NaN;
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('The descriptor threshold is not a whole number of 1 or more.');
  if (expressions.length < 1 || expressions.length > MAX_MULTISIG_KEYS) {
    throw new Error(`A multisig needs between 1 and ${MAX_MULTISIG_KEYS} keys, the descriptor has ${expressions.length}.`);
  }
  if (threshold > expressions.length) {
    throw new Error(`The threshold ${threshold} is more than the ${expressions.length} key(s) in the descriptor.`);
  }

  const notes: string[] = [];
  const derived = expressions.map((e, i) => deriveKey(e, i + 1, notes));
  const networks = new Set(derived.map(d => d.network).filter(Boolean));
  if (networks.size > 1) throw new Error('The descriptor mixes mainnet (xpub) and testnet (tpub) keys.');

  return {
    keys: derived.map(d => d.key),
    extendedKeys: derived.filter(d => d.network !== null).map(d => d.key),
    threshold,
    sorted: fn === 'sortedmulti',
    network: networks.size ? [...networks][0] : null,
    notes,
  };
}
