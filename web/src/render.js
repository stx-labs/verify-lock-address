// Turns a `verify` result into the page. Kept apart from the event wiring so the
// whole render path can be exercised against a stub DOM.

import { bytesToHex, hexToBytes } from '@stacks/common';

import { annotate, disassemble, tokenClass, tokenText } from './script-view.js';

const $ = id => document.getElementById(id);

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function renderScript(result) {
  const { lockScript, unlockBytes, earlyUnlockBytes, tail, unlockHeight } = result;
  const early = hexToBytes(earlyUnlockBytes);

  // `buildLockScript` concatenates: scaffold | early-unlock-bytes | ENDIF VERIFY | staker.
  // The two scaffold pieces are the contract's; the offsets fall out of the lengths.
  const headLen = lockScript.length - unlockBytes.length - 2 - early.length;
  const segments = [
    { key: 'scaffold', name: 'Lockup scaffold', src: 'pox-5 construct-lockup-script', bytes: lockScript.slice(0, headLen), at: 0 },
    { key: 'early', name: 'early-unlock-bytes', src: `bond ${result.bondIndex}, read from chain`, bytes: early, at: headLen },
    { key: 'scaffold', name: 'Lockup scaffold', src: 'both branches rejoin here', bytes: lockScript.slice(headLen + early.length, headLen + early.length + 2), at: headLen + early.length },
    { key: 'staker', name: 'staker-unlock-bytes', src: `yours — ${tail.label}`, bytes: unlockBytes, at: headLen + early.length + 2 },
  ];

  const swatch = { scaffold: 'var(--sand-300)', early: 'var(--blue-400)', staker: 'var(--stacks-500)' };

  const html = segments
    .map(seg => {
      const tokens = annotate(disassemble(seg.bytes, seg.at), seg.key, {
        unlockHeight,
        threshold: seg.key === 'staker' ? tail.threshold : undefined,
      });
      const lines = tokens
        .map(tok => `<div class="line s-${seg.key}">
             <span class="off">${tok.off.toString(16).padStart(4, '0')}</span>
             <span class="body">
               <span class="tok ${tokenClass(tok)}">${esc(tokenText(tok))}</span>
               ${tok.cmt ? `<span class="cmt">${esc(tok.cmt)}</span>` : ''}
             </span>
           </div>`)
        .join('');
      return `<div class="seghdr">
                <span class="sw" style="background:${swatch[seg.key]}"></span>
                <span class="sn">${esc(seg.name)}</span>
                <span>· ${esc(seg.src)} · ${seg.bytes.length} bytes</span>
              </div>${lines}`;
    })
    .join('');

  $('asmOut').innerHTML = html;
  $('scriptLen').textContent = String(lockScript.length);

  const h = bytesToHex(lockScript);
  const a = headLen * 2;
  const b = a + early.length * 2;
  const c = b + 4;
  $('rawHexOut').innerHTML =
    `<span class="h-scaffold">${h.slice(0, a)}</span>` +
    `<span class="h-early">${h.slice(a, b)}</span>` +
    `<span class="h-scaffold">${h.slice(b, c)}</span>` +
    `<span class="h-staker">${h.slice(c)}</span>`;
}

function renderRows(result) {
  const { net } = result;
  const rows = [
    ['Network', `${net.label} · ${net.api} · ${net.hrp}1…`, true],
    ['Staker principal', result.stxAddress],
    ['Bond index', String(result.bondIndex), true],
    [
      'Unlock height',
      result.heightOverridden
        ? `${result.unlockHeight}  (overridden — computeBondUnlockHeight says ${result.derivedHeight})`
        : `${result.unlockHeight}  (computeBondUnlockHeight)`,
    ],
    ['staker-unlock-bytes', bytesToHex(result.unlockBytes)],
    ['early-unlock-bytes', result.earlyUnlockBytes],
    ['Witness script', bytesToHex(result.lockScript)],
    ['Output script · SDK', result.sdkScript],
    ['Output script · pox-5', result.contractScript],
    ['Lock address', result.address],
  ];

  $('derivRows').innerHTML = rows
    .map(([k, v, plain]) => `<div class="row"><div class="k">${esc(k)}</div><div class="v${plain ? ' plain' : ''}">${esc(v)}</div></div>`)
    .join('');
}

function renderChecks(result) {
  const { tail } = result;
  const keyList = tail.keys.map((k, i) => `#${i + 1} ${k}`).join('<br />');

  const checks = [
    {
      ok: result.agree,
      title: result.agree
        ? 'The SDK and pox-5 derive the same output script'
        : 'The SDK and pox-5 disagree — do not fund this address',
      detail: result.agree
        ? 'Built locally in this browser and independently by the contract, from the same inputs.'
        : `SDK ${result.sdkScript} vs contract ${result.contractScript}. Something in the inputs is not what the contract sees.`,
    },
    {
      ok: tail.kind !== 'unknown' && !tail.verify,
      title:
        tail.kind === 'unknown'
          ? 'The unlock tail does not end in OP_CHECKSIG or OP_CHECKMULTISIG'
          : tail.verify
            ? 'The tail uses a VERIFY variant — it leaves nothing on the stack'
            : `The tail is a well-formed ${tail.label} spend condition`,
      detail: tail.verify
        ? 'OP_CHECKSIGVERIFY / OP_CHECKMULTISIGVERIFY consume the boolean the shared OP_VERIFY needs. Use the non-VERIFY opcode.'
        : tail.kind === 'unknown'
          ? 'Both subscripts must leave a truthy value on the stack.'
          : 'It leaves a boolean for the script that follows, as the contract requires.',
    },
    {
      ok: result.comparison ? result.comparison.match : null,
      title: result.comparison
        ? result.comparison.match
          ? 'The address you supplied matches'
          : 'The address you supplied does NOT match'
        : 'No address supplied to compare against',
      detail: result.comparison
        ? `Supplied: ${result.comparison.supplied}`
        : 'Paste the destination from the wallet approval popup to get a direct pass or fail.',
    },
    {
      manual: true,
      title: `These keys are yours, and ${tail.label} is the policy you intend`,
      detail:
        `${keyList || 'no keys found in the tail'}<br /><br />` +
        'This is the check that actually protects the funds. Everything above only proves the ' +
        'address is internally consistent with whatever keys were fed in — it cannot tell you they ' +
        'belong to you.' +
        (tail.threshold === 1 && tail.total > 1
          ? ' A 1-of-N policy means any single one of these keys can sweep the BTC alone.'
          : ''),
    },
    {
      manual: true,
      title: 'The amount and the destination match the wallet approval popup',
      detail:
        'Compare the address above with what the wallet displays after you click Lock BTC, and ' +
        'confirm the amount is what you intend to commit and at or above the minimum the app enforces.',
    },
  ];

  $('checks').innerHTML = checks
    .map(c => {
      const mark = c.manual ? '☐' : c.ok === null ? '—' : c.ok ? '✓' : '✕';
      const color = c.manual
        ? 'var(--text-secondary)'
        : c.ok === null
          ? 'var(--text-tertiary)'
          : c.ok
            ? 'var(--green-500)'
            : 'var(--red-500)';
      return `<div class="check${c.manual ? ' manual' : ''}">
                <span class="m" style="color:${color}">${mark}</span>
                <div><div class="t">${esc(c.title)}</div><div class="d">${c.detail}</div></div>
              </div>`;
    })
    .join('');
}

export function renderResult(result) {
  const failed =
    !result.agree ||
    (result.comparison && !result.comparison.match) ||
    result.tail.kind === 'unknown' ||
    result.tail.verify;

  const v = $('verdict');
  v.className = `verdict ${failed ? 'err' : result.comparison ? 'ok' : 'warn'}`;
  $('verdictMark').textContent = failed ? '✕' : result.comparison ? '✓' : '!';
  $('verdictTitle').textContent = !result.agree
    ? 'The SDK and the contract disagree'
    : result.comparison && !result.comparison.match
      ? 'The address does not match what you supplied'
      : result.tail.kind === 'unknown' || result.tail.verify
        ? 'The unlock tail is malformed'
        : result.comparison
          ? 'Match — this is the address to fund'
          : 'Consistent — now check the keys are yours';
  $('verdictSub').innerHTML = failed
    ? 'Do not fund this address until it is resolved. The detail is in the checks below.'
    : result.comparison
      ? 'The address the wallet is about to fund is the P2WSH computed from the real bond parameters.'
      : 'The address below is internally consistent. Compare it against the wallet approval popup and confirm the keys.';

  $('addrText').textContent = result.address;
  $('tHeight').textContent = String(result.unlockHeight);
  $('tHeightSrc').textContent = result.heightOverridden ? `overridden · derived ${result.derivedHeight}` : 'computeBondUnlockHeight';
  $('tPolicy').textContent = result.tail.label;
  $('tPolicySrc').textContent = `${result.tail.keys.length} key${result.tail.keys.length === 1 ? '' : 's'} in the tail`;
  $('tBond').textContent = String(result.bondIndex);
  $('tBondSrc').textContent = result.net.label;
  $('tSize').textContent = String(result.lockScript.length);

  renderScript(result);
  renderRows(result);
  renderChecks(result);

  const extras = [...result.notes];
  if (result.alternate) {
    extras.push(
      `With the keys in ${esc(result.alternate.label)} order the address would be <code>${esc(result.alternate.address)}</code>. ` +
        'If that is the one your wallet shows, your wallet used that key-order policy.'
    );
  }
  const holder = $('verdictSub');
  if (extras.length) {
    holder.innerHTML += `<br /><br />${extras.join('<br /><br />')}`;
  }

  $('results').hidden = false;
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

