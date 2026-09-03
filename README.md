# Verify Lock Address

Browser tool for [Stacks Bitcoin staking (SIP-045)](https://github.com/stacksgov/sips/blob/main/sips/sip-045/sip-045-pox-5-bitcoin-staking.md): recompute the P2WSH lock address for a bond from public inputs, then compare it to the destination your wallet asks you to sign.

**Live at:** [stx-labs.github.io/verify-lock-address](https://stx-labs.github.io/verify-lock-address/)

## What it checks

Given a bond index, Stacks staker principal, and Bitcoin unlock script, the app:

1. Derives the unlock height from on-chain POX info
2. Builds the witness script in your browser with `@stacks/bitcoin-staking`
3. Cross-checks the output script against read-only calls to [`ST000000000000000000002AMW42H.pox-5`](https://explorer.hiro.so/txid/ST000000000000000000002AMW42H.pox-5?chain=testnet&api=https%3A%2F%2Fapi.private-1.hiro.so) (private-1) or [`SP000000000000000000002Q6VF78.pox-5`](https://explorer.hiro.so/txid/SP000000000000000000002Q6VF78.pox-5?chain=mainnet) (mainnet).
4. Optionally compares the result to an address or output-script hex you paste in.

Leather can prefill the Stacks address and Bitcoin public key. Script construction runs in the browser. Only public Stacks API calls leave your machine.

Supported networks: **private-1** (regtest, `bcrt1…`) and **mainnet** (`bc1…`).

## Development

```bash
npm ci
npm run dev      # static server at http://localhost:8123
npm run build    # bundle web/src → web/app.js
npm test
```

Pushes to `main` build, test, and deploy `web/` to GitHub Pages.

## Layout

- `web/src/` — app, lock verification logic, rendering
- `web/index.html` — page shell and styles
- `test/` — Node tests (lock math, rendering, page smoke)
