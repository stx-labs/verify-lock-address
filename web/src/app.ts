import { fill, h, paragraphs } from './dom.ts';
import type { Child } from './dom.ts';
import { buildStakerUnlockBytes, errorSignature, isStacksPrincipal, NETWORKS, normalizeKey, pickWalletAddresses, verify } from './lock.ts';
import type { StakerUnlock, WalletAddresses } from './lock.ts';
import { renderResult } from './render.ts';
import { AMBIGUOUS_KEY_ERROR, screenFields } from './secrets.ts';
import type { NetworkName, VerifyInput } from './types.ts';

type FieldId = 'bondIndex' | 'stxAddress' | 'pubkey' | 'expected' | 'heightOverride';

interface FieldEntry {
  label: string;
  value: string;
  el: HTMLElement;
  max?: number;
  keyField: boolean;
}

const $ = ((id: string) => document.getElementById(id)) as {
  (id: 'network'): HTMLSelectElement;
  (id: FieldId | 'confirmPubkeys'): HTMLInputElement;
  (id: 'verifyBtn' | 'connectBtn'): HTMLButtonElement;
  (id: string): HTMLElement;
};

const FIELD_LABELS: Record<FieldId, string> = {
  bondIndex: 'bond index',
  stxAddress: 'staker principal',
  pubkey: 'Bitcoin public key',
  expected: 'expected address',
  heightOverride: 'unlock height override',
};

const MODE_FIELDS: Record<'single', FieldId[]> = {
  single: ['bondIndex', 'stxAddress', 'pubkey', 'expected', 'heightOverride'],
};

const KEY_FIELDS = new Set<FieldId>(['pubkey']);

let walletKey: string | null = null;

let generation = 0;
let running: AbortController | null = null;

function setBusy(busy: boolean): void {
  $('paneLoading').hidden = !busy;
  $('verifyBtn').disabled = busy;
  if (busy) fill($('verifyBtn'), h('span', { class: 'spinner' }), 'Verifying');
  else $('verifyBtn').textContent = 'Verify lock address';
}

function invalidate(): void {
  generation += 1;
  if (running) {
    running.abort();
    running = null;
    setBusy(false);
  }
  $('results').hidden = true;
}

let confirmedFor: string | null = null;
let walletSession = 0;

const keySignature = () => JSON.stringify(['single', $('network').value, walletSession, normalizeKey($('pubkey').value)]);

function resetConfirmation(): void {
  confirmedFor = null;
  $('confirmPubkeys').checked = false;
  $('confirmPubkeysBox').hidden = true;
}

async function connectLeather(): Promise<WalletAddresses> {
  const provider = window.LeatherProvider;
  if (!provider) {
    throw new Error('Leather was not detected in this browser. Install or unlock the extension and reload.');
  }

  const res = await provider.request('getAddresses');
  const picked = pickWalletAddresses(res?.result?.addresses ?? []);

  if (picked.missing.length === 2) {
    throw new Error('Leather returned neither a Stacks address nor a Bitcoin public key. Unlock the extension and try again, or fill the fields in by hand.');
  }

  return picked;
}

function walletNotes(picked: WalletAddresses): Child[] {
  const notes: Child[] = [];

  if (picked.missing.includes('stx')) {
    notes.push([
      'Leather returned no Stacks address, so ',
      h('strong', null, 'enter the staker principal yourself'),
      ": the Stacks principal the staking app will register with. That is normally the account's single-key " +
        'SP… (mainnet) / ST… (private-1) address — a Bitcoin multisig vault has no Stacks principal of its own.',
    ]);
  }
  if (picked.missing.includes('btc')) {
    notes.push([
      'Leather returned no Bitcoin public key, so ',
      h('strong', null, 'paste the compressed key yourself'),
      ' — the 33-byte key whose signature will unlock the timelocked output.',
    ]);
  }
  if (picked.taprootOnly) {
    notes.push(
      'The only Bitcoin key returned is a taproot (p2tr) one — the untweaked internal key. The lockup ' +
        'tail is spent as a P2WSH input, so it normally carries the segwit v0 key from the p2wpkh ' +
        'account. Check this is the key you can actually sign with before you fund anything.'
    );
  }
  return notes;
}

function screen(entries: FieldEntry[]): void {
  const found = screenFields(entries.map(({ label, value, max, keyField }) => ({ label, value, max, keyField })));
  if (!found) return;
  entries.find(e => e.label === found.label)?.el?.focus();
  throw new Error(found.error);
}

function fieldEntry(id: FieldId): FieldEntry {
  return {
    label: FIELD_LABELS[id],
    value: $(id).value,
    el: $(id),
    keyField: KEY_FIELDS.has(id),
  };
}

function screenForm(mode: 'single'): void {
  screen(MODE_FIELDS[mode].map(fieldEntry));
}

function readWholeNumber<E>(id: 'bondIndex' | 'heightOverride', { min, empty }: { min: number; empty: () => E }): number | E {
  const el = $(id);
  if (el.validity?.badInput) throw new Error(`The ${FIELD_LABELS[id]} must be a whole number, ${min} or above.`);
  if (!el.value.trim()) return empty();
  const n = typeof el.valueAsNumber === 'number' && !Number.isNaN(el.valueAsNumber) ? el.valueAsNumber : Number(el.value.trim());
  if (!Number.isSafeInteger(n) || n < min) throw new Error(`The ${FIELD_LABELS[id]} must be a whole number, ${min} or above.`);
  return n;
}

function readForm(): { input: VerifyInput; warnings: string[] } {
  const mode = 'single';
  screenForm(mode);

  const network = $('network').value as NetworkName;
  if (!Object.hasOwn(NETWORKS, network)) throw new Error('Choose a network this page supports.');
  const stxAddress = $('stxAddress').value.trim();
  const expected = $('expected').value.trim();

  const bondIndex = readWholeNumber('bondIndex', {
    min: 0,
    empty: () => {
      throw new Error('Enter the bond index — the number in /enroll?bondIndex=…');
    },
  });
  if (!stxAddress) throw new Error('Enter the Stacks address of the staker.');
  if (!isStacksPrincipal(stxAddress)) throw new Error('The staker principal does not look like a Stacks address (SP… / ST…).');
  const heightOverride = readWholeNumber('heightOverride', { min: 1, empty: () => undefined });

  const net = NETWORKS[network];
  const warnings: string[] = [];
  if (!net.prefixes.some(p => stxAddress.startsWith(p))) {
    warnings.push(`The staker address is not a ${net.label} address (${net.prefixes.join(' / ')}…). Check the network selector.`);
  }

  if (confirmedFor !== keySignature()) resetConfirmation();
  const provenance = { trustedKeys: walletKey ? [walletKey] : [], confirmAmbiguous: confirmedFor !== null };
  let built: StakerUnlock;
  try {
    built = buildStakerUnlockBytes({ mode, pubkey: $('pubkey').value, ...provenance });
  } catch (e) {
    if ((e as Error).message === AMBIGUOUS_KEY_ERROR) {
      $('confirmPubkeysBox').hidden = false;
      $('pubkey').focus();
    }
    throw e;
  }
  const { unlockBytes, ambiguousKeysConfirmed } = built;

  return {
    input: {
      network,
      mode,
      bondIndex,
      stxAddress,
      unlockBytes,
      ambiguousKeysConfirmed,
      expected: expected || null,
      heightOverride,
    },
    warnings,
  };
}

function setNetworkBadge(): void {
  if (!Object.hasOwn(NETWORKS, $('network').value)) return;
  const net = NETWORKS[$('network').value as NetworkName];
  $('netBadge').className = `badge ${net.badge}`;
  $('netBadgeText').textContent = net.label;
  $('expected').placeholder = `${net.hrp}1… or the 34-byte output script hex`;
}

const LEATHER_CANCELLED = 4001;

function messageOf(e: any): string {
  const code = e?.code ?? e?.error?.code;
  if (code === LEATHER_CANCELLED) return 'You cancelled the request in Leather.';
  for (const text of [e?.message, e?.error?.message, typeof e === 'string' ? e : null]) {
    if (typeof text === 'string' && text.trim()) return text;
  }
  return 'Something went wrong.';
}

function showError(error: unknown, ...children: Child[]): void {
  const el = $('formErr');
  fill(el, messageOf(error), children);
  const { name, code } = errorSignature(error);
  el.dataset.errorName = name;
  el.dataset.errorCode = code;
  el.hidden = false;
}

function main(): void {
  setNetworkBadge();

  $('network').addEventListener('change', setNetworkBadge);
  $('network').addEventListener('change', resetConfirmation);
  $('confirmPubkeys').addEventListener('change', () => {
    confirmedFor = $('confirmPubkeys').checked ? keySignature() : null;
  });

  for (const type of ['input', 'change']) {
    document.addEventListener(type, ev => {
      if (ev.target instanceof Element && !ev.target.closest('#results')) invalidate();
    });
  }

  for (const id of ['stxAddress', 'pubkey'] as const) {
    $(id).addEventListener('input', () => $(id).classList.remove('prefilled'));
  }
  $('pubkey').addEventListener('input', () => {
    walletKey = null;
    resetConfirmation();
  });

  $('connectBtn').addEventListener('click', async () => {
    const btn = $('connectBtn');
    btn.disabled = true;
    btn.textContent = 'Connecting…';
    try {
      const w = await connectLeather();

      walletSession += 1;
      walletKey = null;
      resetConfirmation();
      invalidate();

      if (w.stxAddress) {
        $('stxAddress').value = w.stxAddress;
        $('stxAddress').classList.add('prefilled');
      }
      if (w.btcPublicKey) {
        walletKey = normalizeKey(w.btcPublicKey);
        $('pubkey').value = w.btcPublicKey;
        $('pubkey').classList.add('prefilled');
      }

      $('walletBadge').hidden = false;
      const label = w.stxAddress || w.btcAddress || w.btcPublicKey;
      $('walletBadgeText').textContent = label ? `${label.slice(0, 6)}…${label.slice(-4)}` : 'Leather';
      $('connectBtn').hidden = true;
      $('disconnectBtn').hidden = false;
      $('formErr').hidden = true;

      const notes = walletNotes(w);
      fill($('walletNote'), paragraphs(notes));
      $('walletNote').hidden = notes.length === 0;

      if (w.networkGuess && $('network').value !== w.networkGuess) {
        $('network').value = w.networkGuess;
        setNetworkBadge();
      }
    } catch (e) {
      showError(e);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Connect Leather';
    }
  });

  $('disconnectBtn').addEventListener('click', () => {
    walletSession += 1;
    walletKey = null;
    resetConfirmation();
    invalidate();
    $('walletBadge').hidden = true;
    $('connectBtn').hidden = false;
    $('disconnectBtn').hidden = true;
    $('walletNote').hidden = true;
    for (const id of ['stxAddress', 'pubkey'] as const) {
      $(id).value = '';
      $(id).classList.remove('prefilled');
    }
  });

  $('toggleHex').addEventListener('click', () => {
    const box = $('rawHexOut');
    box.hidden = !box.hidden;
    $('toggleHex').textContent = box.hidden ? 'Show hex' : 'Hide hex';
  });

  const copyTimers = new WeakMap<HTMLElement, ReturnType<typeof setTimeout>>();
  document.addEventListener('click', async ev => {
    const btn = (ev.target as Element).closest<HTMLElement>('[data-copy]');
    if (!btn) return;
    btn.dataset.label ??= btn.textContent;
    try {
      await navigator.clipboard.writeText($(btn.dataset.copy!).textContent);
      clearTimeout(copyTimers.get(btn));
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      copyTimers.set(
        btn,
        setTimeout(() => {
          btn.textContent = btn.dataset.label!;
          btn.classList.remove('copied');
        }, 1400)
      );
    } catch {
      btn.blur();
    }
  });

  $('verifyBtn').addEventListener('click', async () => {
    $('formErr').hidden = true;
    invalidate();
    const run = generation;

    let form: { input: VerifyInput; warnings: string[] };
    try {
      form = readForm();
    } catch (e) {
      showError(e);
      return;
    }

    const controller = new AbortController();
    running = controller;
    setBusy(true);

    try {
      const result = await verify(
        form.input,
        msg => {
          if (run === generation) $('loadNote').textContent = msg;
        },
        { signal: controller.signal }
      );
      if (run !== generation) return;
      result.notes.unshift(...form.warnings);
      renderResult(result);
    } catch (e) {
      if (run !== generation) return;
      showError(
        e,
        h('br'),
        h('br'),
        'If the API is unreachable, check that ',
        h('code', null, NETWORKS[form.input.network].api),
        ' is up and that the bond exists on that network.'
      );
    } finally {
      if (run === generation) {
        running = null;
        setBusy(false);
      }
    }
  });
}

main();
