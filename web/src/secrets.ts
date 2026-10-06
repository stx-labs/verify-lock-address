import { base58 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';

const BASE58_RUN = /[1-9A-HJ-NP-Za-km-z]+/g;

const WIF_LENGTH_BY_LEAD = new Map([
  ['5', 51],
  ['9', 51],
  ['K', 52],
  ['L', 52],
  ['c', 52],
]);
const WIF_VERSIONS = new Set([0x80, 0xef]);

const EXTENDED_LENGTH = 111;
const EXTENDED_PRIVATE_VERSIONS = new Map([
  ['xprv', 0x0488ade4],
  ['yprv', 0x049d7878],
  ['zprv', 0x04b2430c],
  ['Yprv', 0x0295b005],
  ['Zprv', 0x02aa7a99],
  ['tprv', 0x04358394],
  ['uprv', 0x044a4e28],
  ['vprv', 0x045f18bc],
  ['Uprv', 0x024285b5],
  ['Vprv', 0x02575048],
]);

export const MAX_FIELD_LENGTH = 1024;
export const MAX_DESCRIPTOR_LENGTH = 16384;

export const PRIVATE_KEY_ERROR =
  'That looks like a private key. Never paste one anywhere — it was not sent anywhere, but clear it ' +
  'from this form. Use the public key (02… / 03…) or the xpub / tpub form instead.';

export const AMBIGUOUS_KEY_ERROR =
  'A key here is 66 hex characters ending in 01, which is also exactly what a Stacks private key looks like, and ' +
  'the two cannot be told apart from the text. Nothing was sent or shown. If it is a private key, clear it now. ' +
  'If you copied it from your wallet’s public-key export, tick “These are public keys from my wallet” and verify ' +
  'again, or fill the key from Leather or from an xpub descriptor instead.';

export type SecretKind = 'private' | 'ambiguous';

export interface ScreenedField {
  label: string;
  value: unknown;
  max?: number;
  keyField?: boolean;
}

export const privateKeyError = (label: string) =>
  `The ${label} field holds what looks like a private key. Never paste one anywhere — nothing was sent, ` +
  'but clear it from that field. Use the public key (02… / 03…) or the xpub / tpub form instead.';

export const tooLongError = (label: string, max: number) => `The ${label} field is longer than ${max} characters, which no valid value is.`;

function decodeBase58(window: string): Uint8Array | null {
  try {
    return base58.decode(window);
  } catch {
    return null;
  }
}

function checksumHolds(bytes: Uint8Array): boolean {
  const payloadLength = bytes.length - 4;
  const check = sha256(sha256(bytes.subarray(0, payloadLength)));
  for (let i = 0; i < 4; i += 1) if (check[i] !== bytes[payloadLength + i]) return false;
  return true;
}

function isWif(window: string): boolean {
  const compressed = window.length === 52;
  const bytes = decodeBase58(window);
  if (!bytes || bytes.length !== (compressed ? 38 : 37) || !WIF_VERSIONS.has(bytes[0])) return false;
  if (compressed && bytes[33] !== 0x01) return false;
  return checksumHolds(bytes);
}

function isExtendedPrivate(window: string): boolean {
  const bytes = decodeBase58(window);
  if (!bytes || bytes.length !== 82) return false;
  const version = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return version === EXTENDED_PRIVATE_VERSIONS.get(window.slice(0, 4)) && checksumHolds(bytes);
}

function runHasPrivateKey(run: string): boolean {
  for (let i = 0; i < run.length; i += 1) {
    const wifLength = WIF_LENGTH_BY_LEAD.get(run[i]);
    if (wifLength && i + wifLength <= run.length && isWif(run.slice(i, i + wifLength))) return true;
    if (i + EXTENDED_LENGTH <= run.length && EXTENDED_PRIVATE_VERSIONS.has(run.slice(i, i + 4))) {
      if (isExtendedPrivate(run.slice(i, i + EXTENDED_LENGTH))) return true;
    }
  }
  return false;
}

function textHasPrivateKey(text: string): boolean {
  for (const [run] of text.matchAll(BASE58_RUN)) {
    if (runHasPrivateKey(run)) return true;
  }
  return false;
}

const HEX_RUN = /[0-9a-fA-F]+/g;
const NOT_KEY_MATERIAL = /[^0-9A-Za-z]/g;

export const AMBIGUOUS_KEY_RE = /^0[23][0-9a-fA-F]{62}01$/;

const PUBLIC_HEX_RE = /^(0[23][0-9a-f]{64}|(0020|5120)[0-9a-f]*)$/i;
const RAW_KEY_LENGTH = 64;
const MAX_PADDED_KEY_LENGTH = 69;

function hexRunKind(run: string): SecretKind | null {
  if (run.length < RAW_KEY_LENGTH || run.length > MAX_PADDED_KEY_LENGTH) return null;
  if (run.length === RAW_KEY_LENGTH) return 'private';
  if (AMBIGUOUS_KEY_RE.test(run)) return 'ambiguous';
  return PUBLIC_HEX_RE.test(run) ? null : 'private';
}

export function readings(text: string): string[] {
  const normal = text.normalize('NFKC').replace(/\p{Cf}/gu, '');
  return [...new Set([text, normal, normal.replace(/\s+/g, ''), normal.replace(NOT_KEY_MATERIAL, '')])];
}

export function classifySecret(value: unknown): SecretKind | null {
  if (Array.isArray(value)) {
    const kinds = value.map(classifySecret);
    return kinds.includes('private') ? 'private' : kinds.includes('ambiguous') ? 'ambiguous' : null;
  }
  if (value === null || value === undefined) return null;
  let found: SecretKind | null = null;
  for (const text of readings(String(value))) {
    if (textHasPrivateKey(text)) return 'private';
    for (const [run] of text.matchAll(HEX_RUN)) {
      const kind = hexRunKind(run);
      if (kind === 'private') return 'private';
      if (kind) found = kind;
    }
  }
  return found;
}

export const containsPrivateKey = (value: unknown) => classifySecret(value) === 'private';

export const containsAmbiguousKey = (value: unknown) => classifySecret(value) === 'ambiguous';

export function assertNoPrivateKey(...values: unknown[]): void {
  const texts = (values.flat(Infinity) as unknown[]).filter(v => v !== null && v !== undefined).map(String);
  if (texts.some(t => t.length > MAX_DESCRIPTOR_LENGTH)) throw new Error(`A value is longer than ${MAX_DESCRIPTOR_LENGTH} characters, which no valid input is.`);
  if (texts.some(containsPrivateKey)) throw new Error(PRIVATE_KEY_ERROR);
}

export function screenFields(fields: ScreenedField[]): { label: string; error: string } | null {
  for (const { label, value, max = MAX_FIELD_LENGTH, keyField = false } of fields) {
    if (value === null || value === undefined) continue;
    const text = String(value);
    if (text.length > max) return { label, error: tooLongError(label, max) };
    const kind = classifySecret(text);
    if (kind === 'private' || (kind === 'ambiguous' && !keyField)) return { label, error: privateKeyError(label) };
  }
  return null;
}

export function assertScreened(fields: ScreenedField[]): void {
  const found = screenFields(fields);
  if (found) throw new Error(found.error);
}
