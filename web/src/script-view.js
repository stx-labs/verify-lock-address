// Disassembler for the pox-5 lockup script.
//
// The page needs more than `Script.decode` gives: byte offsets, the raw bytes of
// every push, and which of the three spliced segments each token came from. The
// segments are the point of the whole exercise — the scaffold is the contract's,
// `early-unlock-bytes` belongs to the bond, and only `staker-unlock-bytes` is yours.

/** Opcodes the lockup script and its two subscripts can plausibly contain. */
const OPCODES = {
  0x00: 'OP_0',
  0x4c: 'OP_PUSHDATA1',
  0x4d: 'OP_PUSHDATA2',
  0x4e: 'OP_PUSHDATA4',
  0x4f: 'OP_1NEGATE',
  0x61: 'OP_NOP',
  0x63: 'OP_IF',
  0x64: 'OP_NOTIF',
  0x67: 'OP_ELSE',
  0x68: 'OP_ENDIF',
  0x69: 'OP_VERIFY',
  0x6a: 'OP_RETURN',
  0x6d: 'OP_2DROP',
  0x75: 'OP_DROP',
  0x76: 'OP_DUP',
  0x7c: 'OP_SWAP',
  0x82: 'OP_SIZE',
  0x87: 'OP_EQUAL',
  0x88: 'OP_EQUALVERIFY',
  0x93: 'OP_ADD',
  0x94: 'OP_SUB',
  0x9a: 'OP_BOOLAND',
  0x9b: 'OP_BOOLOR',
  0x9c: 'OP_NUMEQUAL',
  0xa4: 'OP_MIN',
  0xa5: 'OP_MAX',
  0xa6: 'OP_RIPEMD160',
  0xa7: 'OP_SHA1',
  0xa8: 'OP_SHA256',
  0xa9: 'OP_HASH160',
  0xaa: 'OP_HASH256',
  0xab: 'OP_CODESEPARATOR',
  0xac: 'OP_CHECKSIG',
  0xad: 'OP_CHECKSIGVERIFY',
  0xae: 'OP_CHECKMULTISIG',
  0xaf: 'OP_CHECKMULTISIGVERIFY',
  0xb1: 'OP_CHECKLOCKTIMEVERIFY',
  0xb2: 'OP_CHECKSEQUENCEVERIFY',
};

const FLOW = new Set(['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN']);
const CRYPTO = new Set([
  'OP_CHECKSIG',
  'OP_CHECKSIGVERIFY',
  'OP_CHECKMULTISIG',
  'OP_CHECKMULTISIGVERIFY',
  'OP_SHA256',
  'OP_SHA1',
  'OP_HASH160',
  'OP_HASH256',
  'OP_RIPEMD160',
  'OP_CHECKLOCKTIMEVERIFY',
  'OP_CHECKSEQUENCEVERIFY',
]);

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

/** Minimal little-endian signed ScriptNum, the encoding CLTV heights use. */
export function decodeScriptNum(bytes) {
  if (bytes.length === 0) return 0;
  let n = 0n;
  for (let i = 0; i < bytes.length; i += 1) n |= BigInt(bytes[i]) << BigInt(8 * i);
  const signBit = 1n << BigInt(8 * bytes.length - 1);
  if (n & signBit) return -Number(n & ~signBit);
  return Number(n);
}

/**
 * Decode `bytes` into tokens carrying their absolute offset in the assembled
 * script. A truncated push yields a single `bad` token rather than throwing —
 * the whole point of the view is to show a malformed script rather than hide it.
 */
export function disassemble(bytes, baseOffset = 0) {
  const out = [];
  let i = 0;

  while (i < bytes.length) {
    const off = baseOffset + i;
    const b = bytes[i];

    // Data pushes: direct (0x01..0x4b) and the PUSHDATA1/2 prefixes.
    let dataLen = null;
    let headerLen = 1;

    if (b >= 0x01 && b <= 0x4b) {
      dataLen = b;
    } else if (b === 0x4c) {
      dataLen = bytes[i + 1];
      headerLen = 2;
    } else if (b === 0x4d) {
      dataLen = bytes[i + 1] | (bytes[i + 2] << 8);
      headerLen = 3;
    }

    if (dataLen !== null) {
      if (dataLen === undefined || i + headerLen + dataLen > bytes.length) {
        out.push({ off, kind: 'bad', text: `<truncated push: ${hex(bytes.slice(i))}>`, raw: bytes.slice(i) });
        break;
      }
      const data = bytes.slice(i + headerLen, i + headerLen + dataLen);
      out.push({
        off,
        kind: 'push',
        len: dataLen,
        data,
        pushHex: hex(bytes.slice(i, i + headerLen)),
        text: hex(data),
      });
      i += headerLen + dataLen;
      continue;
    }

    if (b >= 0x51 && b <= 0x60) {
      out.push({ off, kind: 'smallnum', n: b - 0x50, text: `OP_${b - 0x50}` });
      i += 1;
      continue;
    }

    const name = OPCODES[b];
    out.push(
      name
        ? { off, kind: 'op', op: name, text: name }
        : { off, kind: 'unknown', text: `OP_UNKNOWN(0x${b.toString(16).padStart(2, '0')})` }
    );
    i += 1;
  }

  return out;
}

/** CSS token class for a decoded token. */
export function tokenClass(tok) {
  if (tok.kind === 'bad' || tok.kind === 'unknown') return 't-bad';
  if (tok.kind === 'smallnum') return 't-num';
  if (tok.kind === 'op') {
    if (FLOW.has(tok.op)) return 't-flow';
    if (CRYPTO.has(tok.op)) return 't-crypto';
    return 't-op';
  }
  if (tok.len === 33) return 't-key';
  if (tok.len === 32) return 't-hash';
  if (tok.len <= 5) return 't-num';
  return 't-push';
}

/** How a push should read in the asm column. */
export function tokenText(tok) {
  if (tok.kind !== 'push') return tok.text;
  if (tok.len <= 5) return `${decodeScriptNum(tok.data)}`;
  return tok.text;
}

/**
 * Attach a human comment to each token. `segment` decides the vocabulary: the
 * same 33-byte push means "the bond's early-unlock key" in one segment and
 * "your key" in another, and that distinction is the one a staker must not miss.
 */
export function annotate(tokens, segment, ctx = {}) {
  let keyIndex = 0;
  let sawIf = false;

  return tokens.map(tok => {
    let cmt = '';

    if (segment === 'scaffold') {
      if (tok.kind === 'op' && tok.op === 'OP_IF') {
        sawIf = true;
        cmt = 'branch 1 — timelocked unlock';
      } else if (tok.kind === 'op' && tok.op === 'OP_ELSE') {
        cmt = 'branch 2 — early exit';
      } else if (tok.kind === 'op' && tok.op === 'OP_CHECKLOCKTIMEVERIFY') {
        cmt = 'unspendable until that burn height';
      } else if (tok.kind === 'op' && tok.op === 'OP_SIZE') {
        cmt = 'the revealed preimage…';
      } else if (tok.kind === 'op' && tok.op === 'OP_SHA256') {
        cmt = '…must sha256 to the committed hash';
      } else if (tok.kind === 'op' && tok.op === 'OP_ENDIF') {
        cmt = 'branches rejoin';
      } else if (tok.kind === 'op' && tok.op === 'OP_VERIFY') {
        cmt = 'consumes the branch result';
      } else if (tok.kind === 'push' && tok.len === 32) {
        cmt = 'sha256(sha256(consensus-buff(staker)))';
      } else if ((tok.kind === 'push' && tok.len <= 5) || tok.kind === 'smallnum') {
        const n = tok.kind === 'smallnum' ? tok.n : decodeScriptNum(tok.data);
        if (n === 32) cmt = '…must be exactly 32 bytes';
        else if (sawIf) cmt = `unlock height${ctx.unlockHeight === n ? '' : ' (?)'}`;
      }
    } else if (segment === 'early') {
      if (tok.kind === 'push' && tok.len === 33) {
        cmt = "the bond's early-unlock key — not yours";
      } else if (tok.kind === 'op' && tok.op === 'OP_CHECKSIG') {
        cmt = 'result feeds the shared OP_VERIFY';
      }
    } else if (segment === 'staker') {
      if (tok.kind === 'push' && tok.len === 33) {
        keyIndex += 1;
        cmt = `your key #${keyIndex} — check this against your wallet`;
      } else if (tok.kind === 'smallnum') {
        cmt = ctx.threshold === undefined
          ? ''
          : tok.n === ctx.threshold
            ? `threshold — ${tok.n} signature${tok.n === 1 ? '' : 's'} required`
            : `${tok.n} keys in the set`;
      } else if (tok.kind === 'op' && tok.op === 'OP_CHECKSIG') {
        cmt = 'final authorisation — one signature';
      } else if (tok.kind === 'op' && tok.op === 'OP_CHECKMULTISIG') {
        cmt = 'final authorisation — m of n';
      } else if (tok.kind === 'op' && (tok.op === 'OP_CHECKSIGVERIFY' || tok.op === 'OP_CHECKMULTISIGVERIFY')) {
        cmt = 'VERIFY variant leaves nothing on the stack';
      }
    }

    return { ...tok, cmt };
  });
}

/**
 * Read an `OP_m <keys…> OP_n OP_CHECKMULTISIG` / `<key> OP_CHECKSIG` tail back
 * out of raw bytes, so a pasted script describes itself the same way a built one does.
 */
export function describeUnlockScript(bytes) {
  const tokens = disassemble(bytes);
  const keys = tokens.filter(t => t.kind === 'push' && t.len === 33).map(t => t.text);
  const last = tokens[tokens.length - 1];
  const tail = last && last.kind === 'op' ? last.op : null;

  if (tail === 'OP_CHECKMULTISIG' || tail === 'OP_CHECKMULTISIGVERIFY') {
    const m = tokens[0]?.kind === 'smallnum' ? tokens[0].n : null;
    const n = tokens[tokens.length - 2]?.kind === 'smallnum' ? tokens[tokens.length - 2].n : null;
    return {
      kind: 'multisig',
      keys,
      threshold: m,
      total: n,
      label: m !== null && n !== null ? `${m}-of-${n}` : 'multisig',
      verify: tail === 'OP_CHECKMULTISIGVERIFY',
    };
  }

  if (tail === 'OP_CHECKSIG' || tail === 'OP_CHECKSIGVERIFY') {
    return {
      kind: 'single',
      keys,
      threshold: 1,
      total: keys.length,
      label: 'single key',
      verify: tail === 'OP_CHECKSIGVERIFY',
    };
  }

  return { kind: 'unknown', keys, threshold: null, total: keys.length, label: 'unrecognised tail', verify: false };
}
