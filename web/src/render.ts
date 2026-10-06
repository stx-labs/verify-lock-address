import { bytesToHex } from '@stacks/common';

import { fill, h, paragraphs } from './dom.ts';
import type { Child } from './dom.ts';
import { annotate, disassemble, tokenClass, tokenText } from './script-view.ts';
import type { Segment } from './script-view.ts';
import type { VerifyResult } from './types.ts';
import { computeVerdict, revealsComputed } from './verdict.ts';
import type { Check, CheckId, Verdict, VerdictState } from './verdict.ts';

interface CheckWords {
  title: string;
  detail: Child;
  headline?: string;
  sub?: string;
}

type CheckText = (check: Check, result: VerifyResult) => CheckWords;

interface SegmentInfo {
  key: Segment;
  name: string;
  src: string;
  bytes: Uint8Array;
  at: number;
}

const $ = (id: string) => document.getElementById(id) as HTMLElement;

const plural = (n: number | undefined, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

function scriptSegments(result: VerifyResult): { headLen: number; early: Uint8Array; segments: SegmentInfo[] } {
  const { lockScript, unlockBytes, tail } = result;
  const earlyLength = String(result.earlyUnlockBytes).length / 2;
  const headLen = lockScript.length - unlockBytes.length - 2 - earlyLength;
  if (!Number.isInteger(headLen) || headLen < 0) throw new Error('the lock script does not tile into its segments');
  const early = lockScript.slice(headLen, headLen + earlyLength);
  return {
    headLen,
    early,
    segments: [
      { key: 'scaffold', name: 'Lockup scaffold', src: 'pox-5 construct-lockup-script', bytes: lockScript.slice(0, headLen), at: 0 },
      { key: 'early', name: 'early-unlock-bytes', src: `bond ${result.bondIndex}, read from chain`, bytes: early, at: headLen },
      {
        key: 'scaffold',
        name: 'Lockup scaffold',
        src: 'both branches rejoin here',
        bytes: lockScript.slice(headLen + earlyLength, headLen + earlyLength + 2),
        at: headLen + earlyLength,
      },
      { key: 'staker', name: 'staker-unlock-bytes', src: `yours — ${tail.label}`, bytes: unlockBytes, at: headLen + earlyLength + 2 },
    ],
  };
}

const SWATCH: Record<Segment, string> = { scaffold: 'var(--sand-300)', early: 'var(--blue-400)', staker: 'var(--stacks-500)' };

function renderScript(result: VerifyResult): void {
  const { lockScript, tail, unlockHeight } = result;
  const { headLen, early, segments } = scriptSegments(result);

  fill(
    $('asmOut'),
    segments.map(seg => {
      const tokens = annotate(disassemble(seg.bytes, seg.at), seg.key, {
        unlockHeight,
        threshold: seg.key === 'staker' ? tail.threshold : undefined,
      });
      return [
        h(
          'div',
          { class: 'seghdr' },
          h('span', { class: 'sw', style: `background:${SWATCH[seg.key]}` }),
          h('span', { class: 'sn' }, seg.name),
          h('span', null, `· ${seg.src} · ${seg.bytes.length} bytes`)
        ),
        tokens.map(tok =>
          h(
            'div',
            { class: `line s-${seg.key}` },
            h('span', { class: 'off' }, tok.off.toString(16).padStart(4, '0')),
            h(
              'span',
              { class: 'body' },
              h('span', { class: `tok ${tokenClass(tok)}` }, tokenText(tok)),
              tok.cmt ? h('span', { class: 'cmt' }, tok.cmt) : null
            )
          )
        ),
      ];
    })
  );
  $('scriptLen').textContent = String(lockScript.length);

  const hex = bytesToHex(lockScript);
  const a = headLen * 2;
  const b = a + early.length * 2;
  const c = b + 4;
  fill(
    $('rawHexOut'),
    h('span', { class: 'h-scaffold' }, hex.slice(0, a)),
    h('span', { class: 'h-early' }, hex.slice(a, b)),
    h('span', { class: 'h-scaffold' }, hex.slice(b, c)),
    h('span', { class: 'h-staker' }, hex.slice(c))
  );
}

function heightDescription(result: VerifyResult): string {
  return result.heightOverridden
    ? `overridden — computeBondUnlockHeight gives ${result.derivedHeight}`
    : 'computeBondUnlockHeight';
}

const WITHHELD = 'withheld until you paste the destination from your wallet above';

function renderRows(result: VerifyResult): void {
  const { net } = result;
  const shown = revealsComputed(result);
  const rows: [string, string, boolean?][] = [
    ['Network', `${net.label} · ${net.api} · ${net.hrp}1…`, true],
    ['Staker principal', result.stxAddress],
    ['Bond index', String(result.bondIndex), true],
    ['Unlock height', `${result.unlockHeight}  (${heightDescription(result)})`],
    ['staker-unlock-bytes', bytesToHex(result.unlockBytes)],
    ['early-unlock-bytes', result.earlyUnlockBytes],
    ['Witness script', bytesToHex(result.lockScript)],
    ['Output script · SDK', shown ? result.sdkScript : WITHHELD, !shown],
    ['Output script · pox-5', shown ? result.contractScript : WITHHELD, !shown],
    ['Lock address', shown ? result.address : WITHHELD, !shown],
  ];

  fill(
    $('derivRows'),
    rows.map(([k, v, plain]) =>
      h('div', { class: 'row' }, h('div', { class: 'k' }, k), h('div', { class: plain ? 'v plain' : 'v' }, v))
    )
  );
}

const NOT_VERIFIED = 'Verify again before funding.';

function scriptText(check: Check, result: VerifyResult): CheckWords {
  if (check.status === 'pass') {
    return {
      title: 'The SDK and pox-5 derive the same output script',
      detail: 'Built locally in this browser and independently by the contract, from the same inputs.',
    };
  }
  if (check.status !== 'fail') {
    return { title: 'The SDK and pox-5 output scripts were not compared — not verified', detail: NOT_VERIFIED };
  }
  return {
    title: 'The SDK and pox-5 disagree — do not fund this address',
    headline: 'The SDK and the contract disagree',
    detail: revealsComputed(result)
      ? [`SDK ${result.sdkScript} vs contract ${result.contractScript}. Something in the inputs is not what the contract sees.`]
      : 'The output script built in this browser differs from the one pox-5 built from the same inputs. Something in the inputs is not what the contract sees.',
  };
}

function expectedText(check: Check, result: VerifyResult): CheckWords {
  const c = result.comparison;
  const shown = c?.display ? `Supplied: ${c.display}` : null;
  const ours = revealsComputed(result) ? `This page computed ${result.address}.` : null;
  if (check.status !== 'pass' && check.status !== 'fail' && check.reason !== 'missing') {
    return { title: 'The address you supplied was not compared — not verified', detail: NOT_VERIFIED };
  }
  switch (check.reason) {
    case 'match':
      return { title: 'The address you supplied matches', detail: shown };
    case 'missing':
      return {
        title: 'No address supplied to compare against',
        headline: 'Not compared — paste the destination from your wallet',
        sub:
          'Paste the destination your wallet approval popup shows into "Expected address" and verify again. The address ' +
          'this page computes is withheld until then, so the comparison can only be made against what your wallet shows.',
        detail: 'Paste the destination from the wallet approval popup to get a direct pass or fail.',
      };
    case 'mixed-case':
      return {
        title: 'The address you supplied does NOT match — it mixes upper and lower case',
        headline: 'The address does not match what you supplied',
        detail: 'A bech32 address is all lower case or all upper case; a mix is not a valid address. Paste it exactly as the wallet approval popup shows it.',
      };
    case 'unreadable':
      return {
        title: 'The address you supplied does NOT match — it is not a Bitcoin address or output script',
        headline: 'The address does not match what you supplied',
        detail: 'Paste the destination exactly as the wallet approval popup shows it.',
      };
    case 'wrong-network':
      return {
        title: 'The address you supplied does NOT match — it is for another network',
        headline: 'The address does not match what you supplied',
        detail: [shown, h('br'), `This page is checking ${result.net.label} (${result.net.hrp}1…). ${ours}`],
      };
    default:
      return {
        title: 'The address you supplied does NOT match',
        headline: 'The address does not match what you supplied',
        detail: [shown, h('br'), ours],
      };
  }
}

function tailText(check: Check, result: VerifyResult): CheckWords {
  const { tail } = result;
  if (check.status === 'pass') {
    return {
      title: `The tail is a well-formed ${tail.label} spend condition`,
      detail: 'It leaves a boolean for the script that follows, as the contract requires.',
    };
  }
  if (check.status !== 'fail') {
    return { title: 'The unlock tail was not checked — not verified', detail: NOT_VERIFIED };
  }
  if (check.reason === 'verify') {
    return {
      title: 'The tail uses a VERIFY variant — it leaves nothing on the stack',
      headline: 'The unlock tail is malformed',
      detail: 'OP_CHECKSIGVERIFY / OP_CHECKMULTISIGVERIFY consume the boolean the shared OP_VERIFY needs. Use the non-VERIFY opcode.',
    };
  }
  return {
    title: 'The unlock tail does not end in OP_CHECKSIG or OP_CHECKMULTISIG',
    headline: 'The unlock tail is malformed',
    detail: 'Both subscripts must leave a truthy value on the stack.',
  };
}

const CHECK_TEXT: Record<CheckId, CheckText> = {
  script: scriptText,
  expected: expectedText,
  tail: tailText,
};

function checkText(check: Check, result: VerifyResult): CheckWords {
  const text = CHECK_TEXT[check?.id];
  if (text) {
    try {
      return text(check, result);
    } catch {
      return { title: `The ${check.id} check could not be displayed — not verified`, detail: NOT_VERIFIED };
    }
  }
  return { title: 'A required check did not run — not verified', detail: NOT_VERIFIED };
}

const MARKS: Record<string, string[] | undefined> = {
  pass: ['✓', 'var(--green-500)'],
  fail: ['✕', 'var(--red-500)'],
  manual: ['☐', 'var(--text-secondary)'],
};
const UNKNOWN_MARK = ['—', 'var(--text-tertiary)'];

function checkItem(mark: string, title: Child, detail: Child, manual = false): HTMLElement {
  const [glyph, color] = MARKS[mark] ?? UNKNOWN_MARK;
  return h(
    'div',
    { class: manual ? 'check manual' : 'check' },
    h('span', { class: 'm', style: `color:${color}` }, glyph),
    h('div', null, h('div', { class: 't' }, title), h('div', { class: 'd' }, detail))
  );
}

function manualItems(result: VerifyResult): HTMLElement[] {
  const { tail } = result;
  const keys = Array.isArray(tail.keys) ? tail.keys : [];
  const keyList = keys.length ? keys.flatMap((k, i) => (i ? [h('br'), `#${i + 1} ${k}`] : [`#${i + 1} ${k}`])) : ['no keys found in the tail'];
  return [
    checkItem('manual', `These keys are yours, and ${tail.label} is the policy you intend`, [
      keyList,
      h('br'),
      h('br'),
      'This is the check that actually protects the funds. Everything above only proves the ' +
        'address is internally consistent with whatever keys were fed in — it cannot tell you they ' +
        'belong to you.' +
        (tail.threshold === 1 && (tail.total ?? 0) > 1 ? ' A 1-of-N policy means any single one of these keys can sweep the BTC alone.' : ''),
    ], true),
    checkItem(
      'manual',
      'The amount and the destination match the wallet approval popup',
      'Compare the address above with what the wallet displays after you click Lock BTC, and ' +
        'confirm the amount is what you intend to commit and at or above the minimum the app enforces.',
      true
    ),
  ];
}

function renderChecks(result: VerifyResult): void {
  const checks = Array.isArray(result.checks) ? result.checks : [];
  fill(
    $('checks'),
    checks.map(check => {
      const text = checkText(check, result);
      return checkItem(check.status, text.title, text.detail);
    }),
    manualItems(result)
  );
}

const VERDICT_STYLE: Record<VerdictState, { className: string; mark: string }> = {
  match: { className: 'verdict ok', mark: '✓' },
  fail: { className: 'verdict err', mark: '✕' },
  unverified: { className: 'verdict warn', mark: '!' },
};

function verdictWords(verdict: Verdict, result: VerifyResult): { title: string; sub: string } {
  if (verdict.state === 'match') {
    return {
      title: 'Match — this is the address to fund',
      sub: 'The address the wallet is about to fund is the P2WSH computed from the real bond parameters.',
    };
  }
  const text: Partial<CheckWords> = verdict.check ? checkText(verdict.check, result) : {};
  if (verdict.state === 'fail') {
    return {
      title: text.headline ?? 'Do not fund this address',
      sub: 'Do not fund this address until it is resolved. The detail is in the checks below.',
    };
  }
  return {
    title: text.headline ?? 'Not verified — a required check did not run',
    sub: text.sub ?? 'Do not fund this address yet: a required check did not run. The detail is in the checks below.',
  };
}

export function renderResult(result: VerifyResult): void {
  const verdict = computeVerdict(result);
  const style = VERDICT_STYLE[verdict.state];
  const words = verdictWords(verdict, result);

  $('verdict').className = style.className;
  $('verdictMark').textContent = style.mark;
  $('verdictTitle').textContent = words.title;

  const extras: Child[] = [...(Array.isArray(result.notes) ? result.notes : [])];
  fill($('verdictSub'), paragraphs([words.sub, ...extras]));

  const revealed = revealsComputed(result);
  $('addrText').textContent = revealed ? String(result.address) : 'Paste the destination from your wallet approval popup above to compare it';
  for (const copy of document.querySelectorAll<HTMLElement>('[data-copy="addrText"]')) copy.hidden = !revealed;
  $('tHeight').textContent = String(result.unlockHeight);
  $('tHeightSrc').textContent = result.heightOverridden ? `overridden · derived ${result.derivedHeight}` : 'computeBondUnlockHeight';
  $('tPolicy').textContent = String(result.tail.label);
  const keyCount = Array.isArray(result.tail.keys) ? result.tail.keys.length : 0;
  $('tPolicySrc').textContent = `${plural(keyCount, 'key')} in the tail`;
  $('tBond').textContent = String(result.bondIndex);
  $('tBondSrc').textContent = String(result.net.label);
  $('tSize').textContent = String(result.lockScript.length);

  try {
    renderScript(result);
  } catch {
    fill($('asmOut'), 'The script could not be laid out for display; the raw values are listed below.');
    fill($('rawHexOut'), bytesToHex(result.lockScript));
  }
  renderRows(result);
  renderChecks(result);

  $('results').hidden = false;
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
