# Verify Lock Address

Browser tool for [Stacks Bitcoin staking (SIP-045)](https://github.com/stacksgov/sips/blob/main/sips/sip-045/sip-045-pox-5-bitcoin-staking.md): recompute the P2WSH lock address for a bond from public inputs, then compare it to the destination your wallet asks you to sign.

**Live at:** [stx-labs.github.io/verify-lock-address](https://stx-labs.github.io/verify-lock-address/)

## What it checks

Given a bond index, Stacks staker principal, and Bitcoin unlock script, the app:

1. Derives the unlock height from on-chain POX info (`computeBondUnlockHeight`).
2. Builds the witness script in your browser with `@stacks/bitcoin-staking`.
3. Cross-checks the output script against read-only calls to [`ST000000000000000000002AMW42H.pox-5`](https://explorer.hiro.so/txid/ST000000000000000000002AMW42H.pox-5?chain=testnet&api=https%3A%2F%2Fapi.private-1.hiro.so) (private-1) or [`SP000000000000000000002Q6VF78.pox-5`](https://explorer.hiro.so/txid/SP000000000000000000002Q6VF78.pox-5?chain=mainnet) (mainnet).
4. Compares the result to the address or output-script hex your wallet's approval popup shows, pasted in. The comparison runs on the decoded output script (`web/src/address.ts`), so an all-upper-case bech32 address (as QR codes carry it) matches; a mixed-case one is invalid bech32 and fails with that reason, and an address for the other network is named as such.

Leather can prefill the Stacks address and Bitcoin public key. Keys are normalised before they are checked: every leading `0x` is removed and hex is lower-cased. A pasted private key (xprv and its SLIP-132 variants, WIF, or raw hex), in any field and inside any surrounding text, is refused, and the error never repeats it. Script construction runs in the browser. Only public Stacks API calls leave your machine.

Supported networks: **private-1** (regtest, `bcrt1…`) and **mainnet** (`bc1…`).

### What the page shows before and after a comparison

One function decides (`revealsComputed` in `web/src/verdict.ts`): the lock address, its Copy button, the SDK and pox-5 output scripts, and the scripts named in an SDK/contract disagreement are shown only after the "Address the wallet is about to fund" field held a value that decoded to an output script and was compared (a match, a mismatch, or the right script on another network). Unreadable text or a truncated address reveals nothing.

The remaining limits, stated plainly: after a real mismatch the page shows its own address as the differing side, so it could still be copied back into the field; that comparison then only confirms the page against itself. The witness script (and the staker-unlock-bytes inside it) is always shown so it can be inspected, and anyone who hashes it themselves gets the same address.

### How the verdict is decided

Every check produces `{ id, status: 'pass' | 'fail' | 'unknown', reason }`. There are three: the SDK and pox-5 derive the same output script (`script`), the pasted address matches (`expected`), and the unlock tail ends in `OP_CHECKSIG` or `OP_CHECKMULTISIG` rather than a VERIFY variant (`tail`). `web/src/verdict.ts` holds the required check ids and the one function that turns the checks into the verdict: ✓ only when every required check is present and passed, ✕ when any check failed, and "not verified" otherwise (a missing check, an unread one, a status it does not recognise). With no pasted address the result is "not verified", never a match. The banner, title and mark all come from that one result, and the text for each check is a `Record` over the check ids in `web/src/render.ts`, so a check added without its text does not compile.

pox-5 replies are matched against their exact Clarity type (`web/src/clarity.ts`): `get-protocol-bond` an `optional` tuple with exactly its fields and field types, `construct-lockup-output-script` an `(ok (buff 34))`. Any other shape (wrapped differently, an `err`, a missing, extra or retyped field) fails the verification. `/v2/pox` cycle parameters are validated where they are read, and unusable ones fail the verification instead of being derived from.

Every read returns `{ ok: true, value }` or `{ ok: false, error }`, and the code branches on `ok`, so a read that fails without a reason (rejected with `undefined`, `null`, `0`, `''`) is a failed read, never an empty answer.

Every request has a 15 s limit (`READ_TIMEOUT_MS`), enforced one way: an `AbortController` per request, aborted by a `setTimeout` that is cleared when the read answers (no `AbortSignal.timeout`, which older browsers lack, and no race). The aborted read fails with "`<read>` did not answer within 15 s", whatever the browser's own abort text, so the page never waits forever. A missing bond fails as soon as the bond read answers. A verification makes 3 requests: `/v2/pox` and 2 pox-5 read-only calls, each made once.

Any change to the form, the network or the wallet hides the previous result and aborts a verification still running: its requests are cancelled, the Verify button is usable again at once, and its result is discarded if it returns anyway.

### What never happens to your input

- No text is parsed as HTML. The results, checks, notes, banners and errors are built with DOM nodes (`web/src/dom.ts`), and every string becomes a text node.
- A private key never leaves its field. Every field is scanned before anything is rendered, put in an error, or sent, and `verify()` scans its input again before its first request.
- The scan reads each value four ways: as typed; after Unicode NFKC normalisation (full-width letters become ASCII) with every format character removed (`\p{Cf}`: zero-width spaces and joiners, soft hyphens, byte-order marks); that with all whitespace removed; and that with every character that is not a letter or digit removed (hyphens, dots, colons, commas). In each reading every run of base58 characters is tested, at every offset, for a WIF (51/52 characters, by lead character) or a BIP-32 extended private key (111 characters); only a valid base58check checksum with a private version byte counts, so public keys, xpubs, Stacks principals and Bitcoin addresses are not mistaken for one. Every maximal run of hex characters is tested too: exactly 64 hex characters (a raw private key) is refused, and so is any run of 65 to 69, which is a raw key with stray hex glued to it, unless it is a compressed public key (`02` / `03` and 66 long) or starts like a 34-byte output script (`0020` / `5120`). A 66-character run starting `02` / `03` and ending in `01` is the ambiguous case below. Longer runs (several keys or a whole script glued together) are public material and pass.
- A Stacks private key that starts with `02` or `03` (about 1 in 128 of them) has exactly the shape of a compressed public key that ends in `01` (about 1 in 256 of them), and no test on the text tells them apart. Outside the key field such a value is refused like any private key. In the key field it is accepted only when it is known to be public: Leather supplied it as a public key. Otherwise the page refuses with an explanation and shows a box, "These are public keys from my wallet's public-key export, not private keys"; only after it is ticked is the key used, sent or shown. The tick covers only the exact key value, network and wallet session it was given for: any edit (even one made without an input event), network change, or wallet connect or disconnect clears it, and `verify()` refuses such a key unless the caller says it was confirmed. This is the safest rule that still lets the real public keys through: refusing them all would lock out about 1 in 256 single-key stakers, and anything weaker would send a private key that happens to look like this.
- The error names the field ("The expected address field holds what looks like a private key…"), focuses it, and never quotes what was typed.
- Input length is capped before scanning: 1,024 characters per field, with a field-named error above that, so a huge paste cannot freeze the tab.
- The page only ever shows back a pasted address it fully decoded into a known form: a Bitcoin address, or a standard scriptPubKey template (P2WSH, P2WPKH, P2TR, P2SH, P2PKH). Any other text is unreadable and never displayed.

## Development

```bash
npm ci
npm run dev        # requires python3; static server at http://localhost:8123
npm run typecheck  # tsc, no output files
npm run build      # bundle web/src → web/app.js
npm test
```

Pushes to `main` type-check, build, test, and deploy `web/` to GitHub Pages.

The source is TypeScript. esbuild strips the types for the bundle and does not check them; `npm run typecheck` does. The tests import the `.ts` files directly through Node's type stripping, which is on by default from Node 22.18 and behind `--experimental-strip-types` (set in the `test` script) before that. Only erasable syntax is used (`erasableSyntaxOnly`): no enums, namespaces or parameter properties.

### Tests

- `test/helpers/stub-api.mjs` answers the reads `verify()` makes, and assembles `construct-lockup-output-script` itself, byte for byte as pox-5's `construct-lockup-script` does (its own script-number push, `to-consensus-buff?` of the staker via `serializeCV`, two SHA-256s), never with the page's `buildLockScript`. The stub can also return any other output script, which is how an SDK/contract disagreement is tested.
- The stub checks every request's host and contract principal against the network the test names (`https://api.hiro.so` and `SP000000000000000000002Q6VF78.pox-5` for mainnet, `https://api.private-1.hiro.so` and `ST000000000000000000002AMW42H.pox-5` for private-1). A request anywhere else is refused and recorded, and a recorded one fails the run.
- No non-live test touches the network. Test files install `test/helpers/offline.mjs`, which replaces `fetch` with a guard that refuses and records every request; a recorded one fails the run. Live tests switch to the real `fetch` explicitly (`live()`), and the reachability probe always uses it.
- The live tests (mainnet bond 2, private-1 bond 106) assert only facts that cannot change: the bond's early-unlock bytes, derived and contract-computed scripts and addresses.
- The live tests skip only when the API fails in transit: HTTP 408/425/429/5xx, a timeout or abort raised by the test's own probe, or a connection error whose `cause.code` is `ECONNRESET`, `ECONNREFUSED`, `ECONNABORTED`, `EPIPE`, `ENETUNREACH`, `EHOSTUNREACH`, `ETIMEDOUT`, `EAI_AGAIN`, `UND_ERR_SOCKET`, `UND_ERR_CONNECT_TIMEOUT`, `UND_ERR_HEADERS_TIMEOUT` or `UND_ERR_BODY_TIMEOUT`. The page's own read timeout ("did not answer within"), the page's own cancellation, and a refused connection to `localhost` / `127.0.0.1` / `::1` fail the test, so a broken `READ_TIMEOUT_MS` or a wrong host cannot pass CI as a skip. A bare `fetch failed`, a TLS or certificate error, or HTTP 403/404 fails too. When the API host does not resolve (`ENOTFOUND`), the probe resolves `github.com`; if that fails too the machine is offline and the test skips, and if it resolves the API host is wrong and the test fails.
- The page keeps a failure's error name and code: `#formErr` carries `data-error-name` / `data-error-code`. The live page test rebuilds the error from them, so a transient failure inside the page skips like any other.
- `test/invariants.test.mjs` fails if any file under `web/src` contains an HTML-parsing or code-evaluating sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `execCommand`, `insertHTML`, an `on…` event attribute or property, a `javascript:` URL, …).

## Layout

- `web/src/` — app wiring (`app.ts`), verification (`lock.ts`), the verdict and what may be revealed (`verdict.ts`), rendering (`render.ts`, `dom.ts`), Clarity reply shapes (`clarity.ts`), Bitcoin address decoding (`address.ts`), the private-key scanner (`secrets.ts`), the script viewer (`script-view.ts`), shared types (`types.ts`) and ambient declarations (`globals.d.ts`)
- `web/index.html` — page shell and styles
- `test/` — Node tests (lock math, verification, private-key screening, rendering, page smoke, source invariants); `test/helpers/` holds the API stub and the offline and live-test guards; `test/fixtures/` holds a recorded `/v2/pox` reply
