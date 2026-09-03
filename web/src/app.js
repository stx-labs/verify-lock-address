import { buildStakerUnlockBytes, clean, NETWORKS, pickWalletAddresses, verify } from './lock.js';
import { renderResult } from './render.js';

const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

// ---------------------------------------------------------------- wallet

async function connectLeather() {
  const provider = window.LeatherProvider;
  if (!provider) {
    throw new Error('Leather was not detected in this browser. Install or unlock the extension and reload.');
  }

  const res = await provider.request('getAddresses');
  const picked = pickWalletAddresses(res?.result?.addresses ?? []);

  // Only a reply with nothing usable in it is an error. A partial one still
  // saves the staker a transcription, and the rest of the form is typeable.
  if (picked.missing.length === 2) {
    throw new Error('Leather returned neither a Stacks address nor a Bitcoin public key. Unlock the extension and try again, or fill the fields in by hand.');
  }

  return picked;
}

/** What the wallet could not supply, and what to do about it. */
function walletNotes(picked) {
  const notes = [];

  if (picked.missing.includes('stx')) {
    notes.push(
      'Leather returned no Stacks address, so <strong>enter the staker principal yourself</strong>. ' +
        'For a multisig staker it is the vault&#39;s SM…/SN… principal, which the extension would not know anyway.'
    );
  }
  if (picked.missing.includes('btc')) {
    notes.push(
      'Leather returned no Bitcoin public key, so <strong>paste the compressed key yourself</strong> — ' +
        'the 33-byte key whose signature will unlock the timelocked output.'
    );
  }
  if (picked.taprootOnly) {
    notes.push(
      `The only Bitcoin key returned is a taproot (p2tr) one — the untweaked internal key. The lockup ` +
        'tail is spent as a P2WSH input, so it normally carries the segwit v0 key from the p2wpkh ' +
        'account. Check this is the key you can actually sign with before you fund anything.'
    );
  }
  return notes;
}

// ---------------------------------------------------------------- form

/** Collect and validate the form into the shape `verify` wants. */
function readForm() {
  const network = $('network').value;
  const bondRaw = $('bondIndex').value.trim();
  const stxAddress = $('stxAddress').value.trim();
  const expected = $('expected').value.trim();
  const overrideRaw = $('heightOverride').value.trim();

  if (!bondRaw) throw new Error('Enter the bond index — the number in /enroll?bondIndex=…');
  const bondIndex = Number(bondRaw);
  if (!Number.isInteger(bondIndex) || bondIndex < 0) throw new Error('The bond index must be a whole number, 0 or above.');
  if (!stxAddress) throw new Error('Enter the Stacks address of the staker.');
  if (!/^S[PTMN][0-9A-Z]{37,}/.test(stxAddress.split('.')[0])) throw new Error(`"${stxAddress}" does not look like a Stacks address.`);

  const expectedPrefixes = NETWORKS[network].prefixes;
  const warnings = [];
  if (!expectedPrefixes.some(p => stxAddress.startsWith(p))) {
    warnings.push(
      `The staker address starts with ${stxAddress.slice(0, 2)}, but ${NETWORKS[network].label} uses ` +
        `${expectedPrefixes.join(' / ')}. Check the network selector.`
    );
  }

  const { unlockBytes, altUnlockBytes, altLabel } = buildStakerUnlockBytes({
    mode: 'single',
    pubkey: $('pubkey').value,
  });

  return {
    input: {
      network,
      bondIndex,
      stxAddress,
      unlockBytes,
      altUnlockBytes,
      altLabel,
      expected: expected || null,
      heightOverride: overrideRaw ? Number(overrideRaw) : undefined,
    },
    warnings,
  };
}

// ---------------------------------------------------------------- wiring

function setNetworkBadge() {
  const net = NETWORKS[$('network').value];
  $('netBadge').className = `badge ${net.badge}`;
  $('netBadgeText').textContent = net.label;
  $('expected').placeholder = `${net.hrp}1… or the 34-byte output script hex`;
}

function showError(msg) {
  const el = $('formErr');
  el.innerHTML = msg;
  el.hidden = false;
}

function main() {
  setNetworkBadge();

  $('network').addEventListener('change', setNetworkBadge);
  // A wallet-filled field is marked until the user edits it, so it is always clear
  // which values came from the extension and which were typed.
  for (const id of ['stxAddress', 'pubkey']) {
    $(id).addEventListener('input', () => $(id).classList.remove('prefilled'));
  }

  $('connectBtn').addEventListener('click', async () => {
    const btn = $('connectBtn');
    btn.disabled = true;
    btn.textContent = 'Connecting…';
    try {
      const w = await connectLeather();

      // Fill only what came back — an absent field must stay empty and editable
      // rather than being blanked out or marked as coming from the wallet.
      if (w.stxAddress) {
        $('stxAddress').value = w.stxAddress;
        $('stxAddress').classList.add('prefilled');
      }
      if (w.btcPublicKey) {
        $('pubkey').value = w.btcPublicKey;
        $('pubkey').classList.add('prefilled');
      }

      $('walletBadge').hidden = false;
      const label = w.stxAddress || w.btcAddress;
      $('walletBadgeText').textContent = `${label.slice(0, 6)}…${label.slice(-4)}`;
      $('connectBtn').hidden = true;
      $('disconnectBtn').hidden = false;
      $('formErr').hidden = true;

      const notes = walletNotes(w);
      $('walletNote').innerHTML = notes.join('<br /><br />');
      $('walletNote').hidden = notes.length === 0;

      // Leather's own network decides the address flavour; align the selector to it
      // rather than letting a mainnet key be checked against a regtest bond.
      if (w.networkGuess && $('network').value !== w.networkGuess) {
        $('network').value = w.networkGuess;
        setNetworkBadge();
      }
    } catch (e) {
      showError(esc(e.message || String(e)));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Connect Leather';
    }
  });

  $('disconnectBtn').addEventListener('click', () => {
    $('walletBadge').hidden = true;
    $('connectBtn').hidden = false;
    $('disconnectBtn').hidden = true;
    $('walletNote').hidden = true;
    for (const id of ['stxAddress', 'pubkey']) {
      $(id).value = '';
      $(id).classList.remove('prefilled');
    }
  });

  $('toggleHex').addEventListener('click', () => {
    const box = $('rawHexOut');
    box.hidden = !box.hidden;
    $('toggleHex').textContent = box.hidden ? 'Show hex' : 'Hide hex';
  });

  document.addEventListener('click', async ev => {
    const btn = ev.target.closest('[data-copy]');
    if (!btn) return;
    try {
      await navigator.clipboard.writeText($(btn.dataset.copy).textContent);
      const was = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = was;
        btn.classList.remove('copied');
      }, 1400);
    } catch {
      /* clipboard denied — the value is selectable by hand */
    }
  });

  $('verifyBtn').addEventListener('click', async () => {
    $('formErr').hidden = true;
    $('results').hidden = true;

    let form;
    try {
      form = readForm();
    } catch (e) {
      showError(esc(e.message || String(e)));
      return;
    }

    $('paneLoading').hidden = false;
    $('verifyBtn').disabled = true;
    $('verifyBtn').innerHTML = '<span class="spinner"></span>Verifying';

    try {
      const result = await verify(form.input, msg => {
        $('loadNote').textContent = msg;
      });
      result.notes.unshift(...form.warnings);
      renderResult(result);
    } catch (e) {
      showError(
        `${esc(e.message || String(e))}<br /><br />` +
          `If the API is unreachable, check that <code>${esc(NETWORKS[form.input.network].api)}</code> ` +
          'is up and that the bond exists on that network.'
      );
    } finally {
      $('paneLoading').hidden = true;
      $('verifyBtn').disabled = false;
      $('verifyBtn').textContent = 'Verify lock address';
    }
  });
}

main();
