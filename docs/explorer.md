# Built-in Explorer

The Node daemon serves a read-only Explorer at `/explorer`. It is compiled into the `mrk`
binary and uses the same `/v1/rpc` WebSocket endpoint as the public CLI. Explorer routes use the
browser History API, so paths such as `/explorer/blocks/42` can be opened or refreshed directly.

The Explorer never handles keystores or signs and submits operations. It currently covers chain
status (including the serving Node's runtime version), retained blocks, bootstrap checkpoints,
operations, accounts, the Node registry, governance proposals, and the protocol treasury. The
checkpoint page reports only what the serving
Node retains and warns operators to verify roots through an independent channel. Network membership
and payment-session metadata are intentionally not indexed in the UI.

The Governance page lists every governable protocol parameter with its active value, configured
next-Epoch value, explicit future-Epoch changes, category, and Standard or Critical classification.
MRK amounts are formatted by the Node so the browser never rounds large base-unit integers.

Open `/explorer/checkpoints` directly or use **View checkpoints** on the Blocks page. Checkpoints
are ordered newest first and show their finalized height, time, and complete state root.

The Accounts page ranks funded addresses by spendable balance. Rankings use a deterministic
balance-descending, address-ascending order and remain fixed for one Epoch so cursor pagination is
stable. At each Epoch transition, each Node records the ranking from the previous Epoch's last
finalized state while committing the boundary block. The latest snapshot is stored in a dedicated
local Redb table and overwritten once per Epoch; it is not part of `LedgerState`, checkpoints, or the
consensus state root. The response identifies the snapshot Epoch and height. Individual account pages
continue to show the latest finalized balance.

Full Nodes can expose complete history. Lite Nodes show a retained-history notice and cannot serve
blocks that were pruned locally.

## Frontend development

The Vue 3 application lives in `mrk-node/ui/`. Run its development server with a Node RPC endpoint:

```bash
cd mrk-node/ui
npm ci
VITE_RPC_ENDPOINT=ws://127.0.0.1:8787/v1/rpc npm run dev
```

Use `../../scripts/build-ui.sh` after changing frontend source. The generated `mrk-node/ui/dist/index.html`,
`mrk-node/ui/dist/assets/app.js`, and `mrk-node/ui/dist/assets/app.css` files are committed because Cargo embeds them
at compile time and `cargo build --offline` must not invoke npm.

The Node serves strict Content Security Policy and MIME headers. Unknown paths below
`/explorer/assets/` return 404; other `/explorer/` paths fall back to the application shell.
