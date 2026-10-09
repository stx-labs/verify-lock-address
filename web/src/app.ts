import { MAX_MULTISIG_KEYS, parseMultisigDescriptor } from './descriptor.ts';
import type { KeyNetwork, ParsedDescriptor } from './descriptor.ts';
import { fill, h, paragraphs } from './dom.ts';
import type { Child } from './dom.ts';
import { buildStakerUnlockBytes, errorSignature, isAmbiguousKey, isStacksPrincipal, NETWORKS, normalizeKey, pickWalletAddresses, verify } from './lock.ts';
import type { StakerUnlock, WalletAddresses } from './lock.ts';
import { renderResult } from './render.ts';
import { AMBIGUOUS_KEY_ERROR, MAX_DESCRIPTOR_LENGTH, screenFields } from './secrets.ts';
import type { Mode, NetworkName, VerifyInput } from './types.ts';

type FieldId = 'bondIndex' | 'stxAddress' | 'pubkey' | 'threshold' | 'vaultAddress' | 'descriptor' | 'expected' | 'heightOverride';

interface FieldEntry {
  label: string;
  value: string;
  el: HTMLElement;
  max?: number;
  keyField: boolean;
}

interface MultiState {
  source: 'manual' | 'wallet' | 'descriptor';
  network: KeyNetwork | null;
  networkKeys: string[];
  fromWallet: boolean;
}

const $ = ((id: string) => document.getElementById(id)) as {
  (id: 'network'): HTMLSelectElement;
  (id: 'descriptor'): HTMLTextAreaElement;
  (id: FieldId | 'sortKeys' | 'confirmPubkeys'): HTMLInputElement;
  (id: 'verifyBtn' | 'connectBtn'): HTMLButtonElement;
  (id: string): HTMLElement;
};

const FIELD_LABELS: Record<FieldId, string> = {
  bondIndex: 'bond index',
  stxAddress: 'staker principal',
  pubkey: 'Bitcoin public key',
  threshold: 'threshold',
  vaultAddress: 'vault address',
  descriptor: 'descriptor',
  expected: 'expected address',
  heightOverride: 'unlock height override',
};

const MODE_FIELDS: Record<Mode, FieldId[]> = {
  single: ['bondIndex', 'stxAddress', 'pubkey', 'expected', 'heightOverride'],
  multi: ['bondIndex', 'stxAddress', 'threshold', 'vaultAddress', 'expected', 'heightOverride'],
};

const KEY_FIELDS = new Set<FieldId>(['pubkey', 'descriptor']);

const trustedKeys = new Set<string>();

const trustKeys = (keys: string[]) => {
  for (const key of keys) trustedKeys.add(normalizeKey(key));
};

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

const keySignature = () =>
  JSON.stringify([currentMode(), $('network').value, walletSession, normalizeKey($('pubkey').value), readKeys().map(normalizeKey)]);

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

  const res = await provider.request('getAddresses', { allowPolicyAccounts: true });
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

const multi: MultiState = { source: 'manual', network: null, networkKeys: [], fromWallet: false };

function setMode(mode: Mode): void {
  for (const btn of $('modeSeg').querySelectorAll('button')) {
    btn.setAttribute('aria-selected', String(btn.dataset.mode === mode));
  }
  $('paneSingle').hidden = mode !== 'single';
  $('paneMulti').hidden = mode !== 'multi';
  $('vaultAddress').required = mode === 'multi';
  $('vaultAddress').setAttribute('aria-required', String(mode === 'multi'));
  resetConfirmation();
  invalidate();
}

const currentMode = () => $('modeSeg').querySelector<HTMLElement>('[aria-selected="true"]')!.dataset.mode as Mode;

function renumberKeys(): void {
  const rows = $('keyList').querySelectorAll('.keyrow');
  rows.forEach((row, i) => {
    row.querySelector('.idx')!.textContent = `#${i + 1}`;
    row.querySelector('button')!.disabled = rows.length === 1;
  });
}

function addKeyRow(value = '', prefilled = false): HTMLInputElement {
  const row = document.createElement('div');
  row.className = 'keyrow';

  const idx = document.createElement('span');
  idx.className = 'idx';

  const input = document.createElement('input');
  input.type = 'text';
  input.spellcheck = false;
  input.autocomplete = 'off';
  input.placeholder = '02… / 03… compressed public key';
  input.setAttribute('aria-label', 'Public key');
  input.value = value;
  if (prefilled) input.classList.add('prefilled');

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'iconbtn';
  remove.textContent = '×';
  remove.setAttribute('aria-label', 'Remove key');

  row.append(idx, input, remove);
  $('keyList').append(row);
  renumberKeys();
  return input;
}

function setKeys(keys: string[], prefilled: boolean): void {
  $('keyList').replaceChildren();
  const list = keys.length ? keys : ['', ''];
  for (const k of list) addKeyRow(k, prefilled && Boolean(k));
}

const readKeys = () => Array.from($('keyList').querySelectorAll('input'), i => i.value.trim());

function ambiguousKeyField(mode: Mode): HTMLInputElement {
  if (mode !== 'multi') return $('pubkey');
  const rows = Array.from($('keyList').querySelectorAll('input'));
  return rows.find(row => isAmbiguousKey(row.value)) ?? rows[0];
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
    max: id === 'descriptor' ? MAX_DESCRIPTOR_LENGTH : undefined,
    keyField: KEY_FIELDS.has(id),
  };
}

function screenForm(mode: Mode): void {
  const entries = MODE_FIELDS[mode].map(fieldEntry);
  if (mode === 'multi') {
    for (const [i, el] of Array.from($('keyList').querySelectorAll('input')).entries()) {
      entries.push({ label: `key #${i + 1}`, value: el.value, el, keyField: true });
    }
  }
  screen(entries);
}

const DIGITS_RE = /^\d+$/;

function readWholeNumber<E>(id: 'bondIndex' | 'heightOverride', { min, empty }: { min: number; empty: () => E }): number | E {
  const text = $(id).value.trim();
  if (!text) return empty();
  const n = DIGITS_RE.test(text) ? Number(text) : NaN;
  if (!Number.isSafeInteger(n) || n < min) throw new Error(`The ${FIELD_LABELS[id]} must be a whole number, ${min} or above.`);
  return n;
}

function fillMulti(parsed: ParsedDescriptor, source: MultiState['source'], vaultAddress = ''): void {
  const prefilled = source === 'wallet';
  setKeys(parsed.keys, prefilled);
  $('threshold').value = String(parsed.threshold);
  $('sortKeys').checked = parsed.sorted;
  $('vaultAddress').value = vaultAddress;
  for (const id of ['threshold', 'vaultAddress'] as const) $(id).classList.toggle('prefilled', prefilled && Boolean($(id).value));
  multi.source = source;
  multi.network = parsed.network;
  multi.networkKeys = parsed.network ? parsed.keys.map(k => k.toLowerCase()) : [];
  if (source === 'descriptor') trustedKeys.clear();
  trustKeys(parsed.extendedKeys);
  if (source === 'wallet') $('descriptorNote').hidden = true;
  setMode('multi');
}

function showVaultInfo(parsed: ParsedDescriptor, address: string): void {
  const policy = `${parsed.threshold}-of-${parsed.keys.length} ${parsed.sorted ? 'sortedmulti' : 'multi'}`;
  fill(
    $('vaultInfo'),
    h(
      'div',
      null,
      'From your Leather multisig account: a ',
      h('strong', null, policy),
      ' vault at ',
      h('code', null, address),
      '. The keys below were read from its descriptor.',
      parsed.notes.length ? [h('br'), h('br'), parsed.notes.flatMap((n, i) => (i ? [h('br'), n] : [n]))] : null
    )
  );
  $('vaultInfo').hidden = false;
}

function markEdited(): void {
  if (multi.source === 'wallet' && !$('vaultInfo').hidden) {
    fill(
      $('vaultInfo'),
      h('div', null, 'You changed what Leather supplied. The vault check will say whether these keys still reproduce the vault address.')
    );
  }
  multi.source = 'manual';
  const current = new Set(readKeys().map(normalizeKey));
  if (!multi.networkKeys.some(k => current.has(k))) {
    multi.network = null;
    multi.networkKeys = [];
  }
}

function clearMulti(): void {
  setKeys([], false);
  $('threshold').value = '2';
  $('sortKeys').checked = true;
  $('vaultAddress').value = '';
  $('vaultAddress').classList.remove('prefilled');
  $('threshold').classList.remove('prefilled');
  $('vaultInfo').hidden = true;
  $('descriptorNote').hidden = true;
  multi.source = 'manual';
  multi.network = null;
  multi.networkKeys = [];
  multi.fromWallet = false;
}

function dropWalletVault(): void {
  if (!multi.fromWallet) return;
  clearMulti();
  setMode('single');
}

const isPrefilled = (el: Element) => el.classList.contains('prefilled');

function dropWalletValues(): void {
  for (const id of ['stxAddress', 'pubkey', 'vaultAddress'] as const) {
    if (!isPrefilled($(id))) continue;
    $(id).value = '';
    $(id).classList.remove('prefilled');
  }
  if (isPrefilled($('threshold'))) {
    $('threshold').value = '2';
    $('threshold').classList.remove('prefilled');
  }
  if (!multi.fromWallet) return;
  const typed = Array.from($('keyList').querySelectorAll('input')).filter(el => !isPrefilled(el) && el.value.trim());
  if (!typed.length && !$('vaultAddress').value.trim()) {
    clearMulti();
    setMode('single');
    return;
  }
  setKeys(typed.map(el => el.value), false);
  $('vaultInfo').hidden = true;
  multi.source = 'manual';
  multi.fromWallet = false;
}

function readForm(): { input: VerifyInput; warnings: string[] } {
  const mode = currentMode();
  screenForm(mode);

  const network = $('network').value as NetworkName;
  if (!Object.hasOwn(NETWORKS, network)) throw new Error('Choose a network this page supports.');
  const stxAddress = $('stxAddress').value.trim();
  const expected = $('expected').value.trim();
  const vaultRaw = $('vaultAddress').value.trim();

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
  const provenance = { trustedKeys: [...trustedKeys], confirmAmbiguous: confirmedFor !== null };
  let built: StakerUnlock;
  try {
    built = buildStakerUnlockBytes(
      mode === 'multi'
        ? { mode, keys: readKeys(), threshold: $('threshold').value, sorted: $('sortKeys').checked, ...provenance }
        : { mode, pubkey: $('pubkey').value, ...provenance }
    );
  } catch (e) {
    if ((e as Error).message === AMBIGUOUS_KEY_ERROR) {
      $('confirmPubkeysBox').hidden = false;
      ambiguousKeyField(mode).focus();
    }
    throw e;
  }
  const { unlockBytes, altUnlockBytes, altLabel, ambiguousKeysConfirmed } = built;

  if (mode === 'multi' && multi.network) {
    const keysNet = multi.network === 'mainnet';
    if (keysNet !== (network === 'mainnet')) {
      warnings.push(
        `The descriptor's keys are ${keysNet ? 'mainnet (xpub)' : 'testnet (tpub)'} keys, but the network ` +
          `selected is ${net.label}. Check the network selector.`
      );
    }
  }

  return {
    input: {
      network,
      mode,
      bondIndex,
      stxAddress,
      unlockBytes,
      altUnlockBytes,
      altLabel,
      ambiguousKeysConfirmed,
      vaultAddress: mode === 'multi' ? vaultRaw : null,
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
  setKeys([], false);

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

  $('modeSeg').addEventListener('click', ev => {
    const btn = (ev.target as Element).closest<HTMLElement>('button[data-mode]');
    if (!btn) return;
    trustedKeys.clear();
    setMode(btn.dataset.mode as Mode);
  });

  $('addKeyBtn').addEventListener('click', () => {
    if ($('keyList').children.length >= MAX_MULTISIG_KEYS) return;
    resetConfirmation();
    addKeyRow().focus();
  });

  $('keyList').addEventListener('click', ev => {
    const btn = (ev.target as Element).closest('button');
    if (!btn || btn.disabled) return;
    btn.closest('.keyrow')!.remove();
    trustedKeys.clear();
    resetConfirmation();
    renumberKeys();
    markEdited();
    invalidate();
  });

  $('keyList').addEventListener('input', ev => {
    (ev.target as Element).classList.remove('prefilled');
    trustedKeys.clear();
    resetConfirmation();
    markEdited();
  });

  for (const id of ['threshold', 'sortKeys', 'vaultAddress']) {
    $(id).addEventListener(id === 'sortKeys' ? 'change' : 'input', () => {
      $(id).classList.remove('prefilled');
      markEdited();
    });
  }

  $('useDescriptorBtn').addEventListener('click', () => {
    const note = $('descriptorNote');
    try {
      screen([fieldEntry('descriptor')]);
      const parsed = parseMultisigDescriptor($('descriptor').value);
      invalidate();
      fillMulti(parsed, 'descriptor', $('vaultAddress').value);
      $('vaultInfo').hidden = true;
      note.textContent =
        `Filled ${parsed.keys.length} key${parsed.keys.length === 1 ? '' : 's'}, threshold ${parsed.threshold}, ` +
        `${parsed.sorted ? 'sorted (sortedmulti)' : 'in descriptor order (multi)'}.` +
        (parsed.notes.length ? ` ${parsed.notes.join(' ')}` : '');
      note.style.color = '';
    } catch (e) {
      note.textContent = messageOf(e);
      note.style.color = 'var(--text-error)';
    }
    note.hidden = false;
  });

  for (const id of ['stxAddress', 'pubkey'] as const) {
    $(id).addEventListener('input', () => $(id).classList.remove('prefilled'));
  }
  $('pubkey').addEventListener('input', () => {
    trustedKeys.clear();
    resetConfirmation();
  });

  $('connectBtn').addEventListener('click', async () => {
    const btn = $('connectBtn');
    btn.disabled = true;
    btn.textContent = 'Connecting…';
    try {
      const w = await connectLeather();

      walletSession += 1;
      trustedKeys.clear();
      resetConfirmation();
      invalidate();
      dropWalletVault();

      if (w.stxAddress) {
        $('stxAddress').value = w.stxAddress;
        $('stxAddress').classList.add('prefilled');
      }
      if (w.btcPublicKey) {
        trustKeys([w.btcPublicKey]);
        $('pubkey').value = w.btcPublicKey;
        $('pubkey').classList.add('prefilled');
      }

      const notes = walletNotes(w);
      if (w.vault) {
        try {
          const parsed = parseMultisigDescriptor(w.vault.descriptor);
          fillMulti(parsed, 'wallet', w.vault.address);
          showVaultInfo(parsed, w.vault.address);
        } catch (e) {
          clearMulti();
          $('vaultAddress').value = w.vault.address;
          $('vaultAddress').classList.add('prefilled');
          setMode('multi');
          notes.push(
            `Leather returned a multisig account, but its descriptor could not be read: ${messageOf(e)} ` +
              "Enter the vault's public keys and threshold by hand."
          );
        }
        multi.fromWallet = true;
      } else if (w.btcPublicKey) {
        setMode('single');
      }

      $('walletBadge').hidden = false;
      const label = w.stxAddress || w.btcAddress || w.vault?.address || w.btcPublicKey;
      $('walletBadgeText').textContent = label ? `${label.slice(0, 6)}…${label.slice(-4)}` : 'Leather';
      $('connectBtn').hidden = true;
      $('disconnectBtn').hidden = false;
      $('formErr').hidden = true;

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
    trustedKeys.clear();
    resetConfirmation();
    invalidate();
    $('walletBadge').hidden = true;
    $('connectBtn').hidden = false;
    $('disconnectBtn').hidden = true;
    $('walletNote').hidden = true;
    dropWalletValues();
    $('vaultInfo').hidden = true;
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
