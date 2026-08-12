# MRK CLI MVP

> [!IMPORTANT]
> **Pre-release compatibility notice — remove this block at the first official release (`TODO(release): remove-pre-release-compatibility-notice`).** The protocol, persisted Ledger schema, operation format, and default parameters may change without migration support before release. Test and staging deployments must reinitialize their Ledger data after an incompatible change instead of expecting older state to be upgraded. The current fresh-Ledger defaults include a 1,800-second Epoch and a 500 MRK Epoch mint budget. Compatibility guarantees begin only with the official release.

This repository contains the executable MRK command-line implementation. It has one binary with two command namespaces:

- `mrk`: public account operations, transfers, private networks, treasury and chain queries.
- `mrk node`: all Node lifecycle, Validator, consensus and governance commands plus the long-running Relay daemon.

The current backend is an atomic local redb database with normalized state and history tables. Command semantics and signed operation formats are structured so the storage adapter can later be replaced by replicated MSL storage. The Node runtime provides authenticated WebSocket member routing, health and signed Probe endpoints, plus a separate authenticated Validator consensus channel. Standard Node voting starts at 20 Governance-Eligible Nodes and coexists with Node 1 direct governance until 50, when Node 1 direct authority ends and Critical proposals become available. Block production switches independently when there are both at least 20 eligible Nodes and at least four Active Validators; otherwise Node 1 remains the single producer.

## Build and test

```bash
cargo build --release --offline
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

The binary is produced at:

```text
target/release/mrk
```

Install for the current user:

```bash
./scripts/install.sh
```

Set `PREFIX=/usr/local` when installing system-wide with appropriate permissions. Deployment examples are provided in `deploy/` for an Nginx TLS 1.3 reverse proxy, the Relay Node service and the continuous Probe service. Replace the domain, certificate paths, Unix user, data directory and Node ID before enabling them.

Use `--data-dir PATH` or `MRK_DATA_DIR=PATH` to select an isolated state directory. An explicit `--data-dir` takes precedence over the environment variable; if both are omitted, all commands use `~/.mrk/`.

## Account and MRK

```bash
mrk account init --name default
mrk account address --account default
mrk account balance --account default

mrk account transfer \
  --account default \
  --to mrk1... \
  --amount 12.5MRK

mrk block operation status op_...
mrk account history --account default --limit 20
```

Signed operations are applied to the local state machine in deterministic submission order and initially return `PENDING`. They become `FINALIZED` only when included in either a Node 1 block or a block carrying a valid multi-Validator commit certificate. The operation ID is unchanged by finalization.

Use `--dry-run` to validate a transfer without signing. Every operation with a non-zero service fee unlocks its keystore first, displays the current and maximum service fee, and requires confirmation before submission; use the global `--yes` flag with `--output json` for automation. A private key is never accepted as a CLI argument. Keystores use Ed25519 keys encrypted with PBKDF2-HMAC-SHA256 and AES-256-GCM.

For non-interactive development and tests, the password can be provided through `MRK_KEYSTORE_PASSWORD`. Production automation should set `MRK_KEYSTORE_PASSWORD_FILE` to a root/service-managed file readable only by its owner; files accessible by group or others are rejected. The systemd example uses `LoadCredential` so the secret is not stored in the unit or process arguments.

## Genesis treasury

The fixed one-billion-MRK supply starts as `500,000,000 MRK` in a keyless protocol treasury and `500,000,000 MRK` in the Node emission pool. The treasury is part of MSL state, not an account with an exportable private key:

```bash
mrk treasury status
mrk treasury history --limit 20
```

Treasury spending remains frozen until there are at least 50 Governance-Eligible Nodes with 180 days of cumulative eligible service and at least four Active Validators. Spending must then use a Critical governance proposal:

```bash
mrk node --node default governance propose-treasury-spend \
  --title "Pay independent audit" \
  --to mrk1... \
  --amount 100000MRK \
  --reference sha256:<64-lowercase-hex>

mrk node --node default governance vote --proposal-id 1 --choice yes
mrk node --node validator-1 governance validator-vote --proposal-id 1 --choice yes
mrk node --node default governance finalize --proposal-id 1
mrk node --node default governance execute --proposal-id 1
```

Treasury snapshots contain only Governance-Eligible Nodes with at least 180 days of cumulative eligible service and require at least 50 such Nodes plus four Active Validators. A proposal needs both two-thirds of mature snapshot Node Power and two-thirds of the snapshotted Validator committee, followed by a 14-day vote and 30-day timelock. During the timelock, mature snapshot Nodes may run `governance veto --proposal-id ID`; veto power above one-third cancels execution.

Creation and execution enforce a 1% single-spend limit, a rolling 2% limit over 90 days, and a rolling 5% limit over 365 days. Execution transfers existing MRK to the recipient; it never mints MRK, and a proposal cannot execute twice.

## Diagnostics

```bash
mrk node --node default doctor
```

The Node doctor checks lifecycle state, Endpoint DNS/IP binding, Probe freshness and all three Node key permissions. JSON output is available with `--output json`; a failed check produces a non-zero exit status for monitoring systems.

The public listener exposes `/health` for process liveness and `/ready` for traffic readiness. Both report Node status, chain height/mode, last Block time, and pending-operation count. `/ready` returns HTTP 503 while draining/suspended/exited, before the first finalized Block, or when the tip is older than `max(120s, 6 × block_interval)`. Startup also refuses unknown Node-config or Ledger versions instead of attempting an implicit migration.

The same listener serves a read-only Web Explorer at `/explorer`. It provides clean, directly
addressable routes for retained Blocks, Operations, accounts, registered Nodes, governance, and
the protocol treasury. A Lite Node identifies its pruned history range in the interface; use a
Full Node when complete historical browsing is required. See [docs/explorer.md](docs/explorer.md)
for frontend development details.

## Private networks

```bash
mrk network create --name team --account default
mrk network fund --network team --amount 100MRK --account default
mrk network show --network team
mrk network policy show --network team
mrk member issue --network team --name client-a --account default
mrk member show --network team --name client-a
mrk member list --network team --rpc-endpoint wss://relay.example.com:9443/v1/rpc
mrk member revoke --network team --serial 1 --account default

mrk network policy set --network team \
  --max-session-amount 1MRK \
  --max-member-reserved 10MRK \
  --max-node-price-per-gib 100MRK \
  --max-session-minutes 1440
```

Member credentials and encrypted member keys are written below the selected data directory.
`member list` merges the finalized Network member registry with the live connection table of the
Relay Node selected by `--rpc-endpoint`. `ONLINE` therefore means connected to that Relay at the
reported observation time; it is not a chain-wide presence claim. No remote address or connection
identifier is exposed.
`member issue` does not report success or write the final member files until its operation is
Finalized. While waiting, the encrypted key is kept in a private `.issue.pending.json` file;
rerunning the same command resumes submission/finality checks. A concurrent command for the same
Network and member name is rejected and cannot overwrite the pending key.

## Member traffic pipe

First start the receiving member; without `--peer`, it accepts the first incoming channel:

```bash
mrk pipe \
  --network team \
  --member client-b \
  --endpoint relay.example.com
```

Then start the initiating member with the target Member name. `--peer` also accepts the random
`member_id` shown by `member issue` or `member show` for backward compatibility:

```bash
mrk pipe \
  --network team \
  --member client-a \
  --endpoint relay.example.com \
  --peer client-b \
  --max-auto-recovery-bytes 1048576
```

The initiating member signs a `ReserveSession` operation. The SDK applies the current
Owner policy, atomically reserves the shared Network Fund, waits for finality, and then
opens the channel.

After authentication and channel acceptance, the members authenticate an ephemeral X25519 key exchange with their Ed25519 member keys. `mrk pipe` then encrypts every stdin payload end to end with AES-256-GCM before sending it as an opaque Relay `DATA` frame; there is no plaintext fallback. Received payloads are authenticated and decrypted before being written to stdout. Status messages use stderr, so stdout remains safe for piping into another application. Each direction uses a separate session key and preserves order independently. The Relay can still observe member identifiers, traffic lengths, and timing, and billing covers the encrypted payloads and key-exchange overhead that it actually transports.

Pressing Ctrl+C starts a graceful close instead of terminating immediately. Each endpoint sends an authenticated FIN and a `CloseIntent`; the Node answers with a final `CheckpointRequest`, and the clients return the ordinary dual-signed final receipt. The CLI exits after the Node has persisted those receipts. The Node then finalizes settlement and releases the unused reservation in the background. A second Ctrl+C forces shutdown if the peer cannot complete the receipt exchange.

If a process disappears before that exchange, the Node keeps the unsigned tail only in memory and records a small authorization hold without DATA, sequence counters, or transcript state. On restart, `mrk pipe --max-auto-recovery-bytes N` first recovers matching interrupted sessions and only then opens a new session; the standalone `payment settle` command exposes the same limit for manual recovery. The default is zero. The recovery channel carries settlement frames only. If the Node itself restarted, the exact tail is gone and cannot be signed. The Node Owner may waive the claim with `node payment abandon`, or configure a bounded local auto-abandon policy. Only dual-signed receipts awaiting chain settlement are persisted, and they are deleted after finality.

The Rust client implementation lives in the standalone `mrk-sdk` workspace package and is imported as `mrk_sdk`. Shared protocol and storage types come from `mrk-core`, imported as `mrk_core`. `RelayConnection::open_auto` and `IncomingStream::accept` return an `EncryptedStream` implementing Tokio `AsyncRead + AsyncWrite`. Writes are automatically split below the Relay's advertised WebSocket limit; applications see one continuous byte stream and do not add message metadata.

C applications can use the same implementation through `mrk-ffi`. Build it with `cargo build --release --offline -p mrk-ffi`; the C header is `mrk-ffi/include/mrk_sdk.h`, and Linux artifacts are `target/release/libmrk.so` and `target/release/libmrk.a`.

```rust
use mrk_core::storage::DataPaths;
use mrk_sdk::{ClientOptions, MemberIdentity, RelayClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = DataPaths::new(None)?;
    let password = std::env::var("MRK_KEYSTORE_PASSWORD")?;
    let endpoint = "relay.example.com";
    let identity = MemberIdentity::from_relay(
        &paths, "team", "client-a", &password, endpoint, false, None,
    ).await?;
    let connection = RelayClient::connect(ClientOptions::new(endpoint, identity)).await?;
    let mut stream = connection.open_auto("<CLIENT_B_MEMBER_ID>").await?;

    stream.write_all(b"hello").await?;
    stream.shutdown().await?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await?;
    Ok(())
}
```

Paid Relay sessions use a finalized `PaymentAuthorization` that reserves Network Fund without paying the Node up front. By default every active member may create a bounded reservation; the Owner can update or disable the policy at any time, while finalized reservations retain their policy snapshot. Each direction pauses new DATA after 16 MiB or 15 seconds, whichever occurs first, while control frames remain live. The Node sends a `CheckpointRequest` containing the exact sequence, byte count, and transcript hash it observed. During a live session the sender and receiver match it against their in-memory transcript before signing. Only this dual-signed receipt can release the proportional `price_per_gib` amount to the Node. After both directions countersign their final checkpoints and the settlement finalizes, unused reservation returns to the Network Fund. Otherwise it remains claimable for seven days after expiry and is reclaimed by the next automatic reservation. Traffic settlement never mints MRK.

Payment checkpoint and receipt exchange is internal to the encrypted stream SDK. There is no standalone Payment SDK in this version; authorization, status, refund, and settlement operations remain available through `mrk payment`.

```bash
mrk payment status <AUTHORIZATION_ID_OR_SESSION_ID>
mrk payment history --network team [--member client-a]
mrk payment unsettled --network team --member client-a
mrk payment settle <AUTHORIZATION_ID> --network team --member client-a --endpoint relay.example.com --max-auto-recovery-bytes 1048576
mrk payment refund <AUTHORIZATION_ID> --account default
mrk node --node default payment unsettled
mrk node --node default payment policy set --max-auto-abandon-bytes 0
mrk node --node default payment policy set --network team --max-auto-abandon-bytes 1048576
mrk node --node default payment abandon <AUTHORIZATION_ID>
```

`payment status` accepts either the authorization ID or session ID.

Production clients require TLS 1.3 `wss://` with a publicly trusted certificate. Private deployments may add a PEM trust anchor with `--tls-ca /path/to/ca.pem`; hostname and certificate-purpose validation remain enabled. Loopback development may use `ws://127.0.0.1/... --allow-insecure-local`; plaintext WebSocket to non-loopback hosts is rejected.

Endpoint options accept `host` or `host:port` shorthand. A missing scheme defaults to `wss://`, and a missing path defaults to `/v1/relay` for Node and pipe endpoints or `/v1/rpc` for RPC and bootstrap endpoints. Explicit schemes and paths remain supported.

## Node lifecycle

```bash
mrk node init --lite --ledger-id mrk-devnet-1

mrk node run --listen 0.0.0.0:8787

# Joining nodes only; obtain the state_... root through an independent trusted channel.
mrk node bootstrap \
  --peer seed.example.com \
  --checkpoint-height 12345 \
  --checkpoint-root state_<64-lowercase-hex>

mrk node join --endpoint relay.example.com
mrk node update-reward-ip --endpoint new-relay.example.com
mrk node update-price --price-per-gib 0.03MRK

mrk node status
mrk node block checkpoints
mrk node backup
mrk node backup-verify ~/.mrk/backups/mrk-HEIGHT-TIME.json --expected-state-root state_...
mrk node restore ~/.mrk/backups/mrk-HEIGHT-TIME.json --expected-state-root state_...
mrk node probe --target-node-id 1 --watch
mrk node rewards
mrk node claim
mrk node drain
mrk node withdraw-service-bond
```

`mrk node run` starts the Unix administration Socket before registration. Genesis Node 1 registers on its empty chain. Every later Node first runs `mrk node bootstrap`, then `mrk node join`. A normalized WSS Endpoint can belong to only one non-`EXITED` Node; both registration and Reward IP updates reject an Endpoint held by another Node, and reuse becomes possible only after the previous Node's exit is finalized. A downloaded snapshot is accepted only when both its height and full SHA-256 state root match the operator-supplied checkpoint. Obtain that pair from an independent trusted release, quorum announcement, or comparison with multiple operators—not from the peer serving the snapshot. Peers retain the newest 24 scheduled checkpoint snapshots. Node operators can list their locally retained heights, finalized timestamps, and roots with `mrk node block checkpoints`; the listed roots still require independent verification before another Node trusts them. Automatic snapshots are materialized at most once per hour, while an explicitly requested latest snapshot is retained immediately. A pinned checkpoint therefore remains downloadable while the chain advances; the joining Node catches up from that fixed height after installation. The daemon remembers the peer, forwards its signed registration operation, and continuously downloads and verifies finalized catch-up blocks. It enables its public WSS listener after registration succeeds. All later `mrk node` commands also use that Socket. Public `mrk` queries use
`--rpc-endpoint relay.example.com` (or `MRK_RPC_ENDPOINT`).

`mrk node join` handles both initial registration and returning after exit. When the configured non-Genesis Node is `EXITED`, the command creates a new Node ID with the same Owner, Relay, and Reward keys. The old Node remains terminal and the new registry record exposes `previous_node_id`; Warmup, Probe history, service age, Bonds, governance eligibility, and Validator eligibility all restart. Joining again requires every reward and Bond balance on the old Node to be settled first and rejects an Owner that controls any other non-`EXITED` Node. An exited daemon keeps only its administration Socket open so the command can be submitted without exposing a public Relay prematurely.

`--price-per-gib` is optional on `mrk node join`. When omitted, the registering Node signs the median price of Nodes that are `ACTIVE`, currently own their IP Slot, and have a fresh Probe. An even sample uses the average of the two middle base-unit prices, rounded down; an empty sample uses `10MRK/GiB`. An explicit flag always overrides this default, and the signed registration operation still contains one concrete price.

`mrk node update-price` submits an Owner-signed `NodeRegistry.UpdatePrice` operation. The new price is advertised after the operation is applied and is used only when creating later Payment Authorizations; every existing authorization retains the price fixed when it was created. `ReserveSession` signs the expected Node price and is rejected if the quote changed before execution, so a price update cannot silently alter a member's authorization. Price changes do not alter the Endpoint, Reward IP, Warmup, or Probe state.

The public Node registry and the connectable Relay set are separate queries:

```bash
mrk registry list --rpc-endpoint wss://relay.example.com/v1/rpc
mrk registry list --status active --validator --limit 50
mrk registry show --node-id 7
mrk discover --limit 50 --rpc-endpoint wss://relay.example.com/v1/rpc
```

`registry list` returns finalized registrations in ascending Node ID order, including inactive and historical entries unless filtered. `--status` accepts `initialized`, `warming-up`, `active`, `draining`, `exited`, or `suspended`; `--validator` keeps only current Active Validators. `registry show` returns one public registration record. `discover` is the connection-oriented view: it returns only `ACTIVE` Nodes whose latest finalized Availability Probe is still valid and whose IP slot remains bound. Both list commands return `next_cursor`; pass it back with `--cursor` to read the next page. Base-unit amounts are strings in these new responses so clients do not lose precision when decoding JSON. A Node that never completes a finalized Availability Probe uses its registration time as the offline-timeout baseline, preventing an abandoned registration from holding an IP slot forever. IP reuse has no cooldown by default, so a released slot can bind to another Node immediately; governance can add a cooldown when needed.

Node storage has exactly two modes: `LITE` and `FULL`. `mrk node init --lite`
selects `LITE`; plain `mrk node init` selects `FULL`. The choice is persisted in the
Node configuration and shown by `mrk node status`. `LITE` is the bounded-storage
profile for current state, verified checkpoints, and recent history; `FULL`
retains the complete chain history. Chain state is persisted under
`~/.mrk/chain.redb`; only the `mrk node run` process opens redb. Other `mrk node`
commands use the single `~/.mrk/mrk.sock`. One data directory runs exactly one
`mrk node`; the Socket is not split into per-Node directories. The first Node initialized in a
data directory may set its consensus identity with `--ledger-id mrk-devnet-1`. IDs contain 3–64
lowercase ASCII letters, digits, or hyphens. Later Nodes must use the existing ID, while Bootstrap
inherits it from the trusted checkpoint; an initialized Ledger cannot be renamed. A running `LITE` daemon checks every
60 seconds and retains seven days of blocks using the current
`block-interval-seconds` cadence (for example, 201,600 blocks at 3 seconds),
every operation body referenced by those retained blocks, and at most 1,024 retained
operation IDs per account. Pending operations and current state are never
pruned. Blocks, immutable operation bodies, operation finality, account-history
links, and mutable state entities are stored in separate redb tables. The small
ledger metadata row does not embed accounts, networks, nodes, payment
authorizations, governance histories, or a second complete finalized state. The
latest finalized view is reconstructed from current entity rows plus sparse
differences. An operation row keeps one signed envelope and derives its expanded
query fields. A block commit keeps only each Validator ID, timestamp, and
signature because the remaining signed vote fields are fixed by its block. Block
production loads only current state, the chain tip, and pending operations; finalized history is read on demand
for queries, verification, backups, and pruning. The finalized prefix is replaced by a
height/hash/time checkpoint; logical deletion releases pages for reuse without
running an expensive whole-database compaction after every prune. `FULL` never
prunes history.

`mrk node backup` asks the running daemon for a transactionally consistent logical backup. It writes a `0600` JSON file under `~/.mrk/backups/` by default, refuses to overwrite an existing file, and records the chain height, state root, and a checksum over the complete payload. `backup-verify` validates the checksum, metadata, complete chain, and optional pinned state root without changing local state. `restore` is deliberately offline: stop `mrk node run`, supply the expected state root through an independent trusted channel, restore atomically, then run `mrk node doctor` before restarting. Copy backups off-host and rehearse this procedure before operating a Validator.

If a registered non-Genesis Node loses `chain.redb`, `mrk node run` keeps its local administration Socket available but does not start its public Relay until the Node record has been recovered. Install a freshly verified checkpoint with `mrk node bootstrap`; the existing Node ID and keys are preserved while public catch-up restores later blocks. Recovery rejects a checkpoint that assigns the saved Node ID to a different Owner. Deleting `chain.redb` is data loss, not a cache reset, and Genesis Node recovery still requires a verified backup or another independently trusted copy of the chain.

The public listener admits at most 2,048 concurrent connections and 128 connections per non-loopback source IP; loopback reverse proxies share the global limit. Each RPC WebSocket is limited to 120 requests and 20 mutation submissions per minute, and no RPC response may exceed 16 MiB. Relay channels and outbound queues retain their separate bounded backpressure limits.

The operator does not provide a public IP. Registration resolves it from the required `wss://` endpoint, preferring a public IPv4 address when both address families exist; Node startup verifies that the endpoint still resolves to the registered address, and external Probes provide the final reachability check. Private, loopback, link-local, CGNAT and reserved addresses are rejected. IPv4 addresses occupy one reward slot each; IPv6 addresses are grouped by `/64`.

Running the process alone does not earn MRK. `mrk node run` automatically performs the Availability Probes assigned to that Node: it connects directly to the target's registered `reward_ip`, verifies the Endpoint hostname through TLS SNI, validates the Relay-key response, and submits an Owner-key-signed attestation. Availability begins in the explicit `NODE1_TRUSTED` mode: Node 1 is absolutely trusted, may verify itself, and one Node 1 attestation is sufficient. At the first Epoch boundary with at least seven Active Validators the ledger irreversibly switches to `MULTI_VALIDATOR`; it then defaults to five Primary Verifiers with a three-vote quorum and never permits target self-verification. Falling below seven after activation pauses new Node Seconds instead of restoring Node 1 authority.

Each selected verifier signs a private Probe Ticket binding the ledger, Epoch, Epoch-relative slot, target, verifier and `PRIMARY/AUDIT` role. Every Epoch freezes its Availability settings and Validator set, so later governance or committee changes cannot invalidate an issued Ticket. The Ticket determines both the Challenge and a secret time within the 60-second slot, so the target cannot predict an honest verifier's check before receiving it. By default 5% of slots also require two of three disjoint Auditors when at least nine Active Validators are available. Audited slots earn time only after both quorums. A closed Epoch accepts its already-issued attestations for 30 seconds, then settles and removes its per-Epoch Node Seconds. Network observation disagreements withhold that Slot's reward but do not slash principal; only objective cryptographic conflicts such as double-signing are slashable. `mrk node probe` remains available for diagnosis and retries but obeys the same Ticket and timing rules.

This Availability state transition is part of the unreleased protocol/on-disk version 1. Before the first release, incompatible test data is deliberately rebuilt or explicitly bootstrapped instead of migrated implicitly.

Node initialization creates three separate encrypted keys:

- Node Owner Key for registration and lifecycle operations.
- Relay Key for signed Probe responses.
- Reward Key for spendable MRK income.

Use the Reward Key through the account alias `node:<name>`:

```bash
mrk account balance --account node:default
mrk account transfer --account node:default --to mrk1... --amount 1MRK
```

## Bootstrap governance

The first successfully registered Node receives Node ID 1. Its Owner public key is pinned in the ledger as the immutable Genesis authority; the local node name does not need to be `node1`. While fewer than 20 Nodes are governance-eligible, only that Owner key can execute direct governance actions:

```bash
mrk node --node default governance status

mrk node --node default governance set \
  --parameter probe-validity-seconds \
  --value 600

mrk node --node default governance pause-emission \
  --reason "emergency maintenance"

mrk node --node default governance resume-emission
```

A Governance-Eligible Node must be `ACTIVE`, have the required Service Bond, have accumulated the configured minimum finalized eligible service time (30 days by default), have a fresh quorum-confirmed Probe timestamp, and hold the required Governance Bond after its maturity period. The Governance Bond defaults to `10,000 MRK`, matures after 60 days, never increases Node Power, and becomes withdrawable 30 days after governance exit. Local heartbeat state never grants governance power. At 20 eligible Nodes, Standard Node voting becomes available while Node 1 retains direct actions. At 50, Node 1 direct actions are rejected with `node voting is required` and Critical proposals become available. If the count later falls below 50, Node 1 authority returns automatically. Registration remains permissionless in every mode.

```bash
mrk node --node default governance bond-status
mrk node --node default governance bond
mrk node --node default governance exit
mrk node --node default governance withdraw-bond
```

`governance bond` locks the missing amount from the Node Reward account. `governance exit` removes the Node from governance eligibility immediately and starts the 30-day withdrawal delay. A Node must fully withdraw its Governance Bond before draining.

The complete supported parameter set is `epoch-seconds`, `epoch-mint-amount`, `reward-immediate-bps`, `reward-vesting-seconds`, `validator-weight-bps`, `validator-signature-threshold-bps`, `service-bond`, `service-bond-unlock-seconds`, `offline-slash-seconds`, `warmup-seconds`, `heartbeat-grace-seconds`, `probe-validity-seconds`, `availability-slot-seconds`, `availability-verifier-count`, `availability-quorum`, `availability-audit-rate-bps`, `availability-auditor-count`, `availability-audit-quorum`, `ip-reuse-cooldown-seconds`, `governance-min-service-seconds`, `governance-bond`, `governance-bond-maturity-seconds`, `governance-bond-unlock-seconds`, `block-interval-seconds`, `validator-bond`, `max-active-validators`, `max-validator-rotations`, `validator-rotation-interval-epochs`, and `consensus-round-timeout-seconds`. Parameter batches may use `--effective-epoch EPOCH` to schedule atomic activation at a future Epoch; the target must still be in the future when the direct action or proposal execution is finalized. Omitting it preserves immediate Settings updates and next-Epoch activation for Epoch-scoped snapshots. See the [governance parameter reference](docs/blockchain.md#82-%E5%8F%AF%E6%B2%BB%E7%90%86%E5%8F%82%E6%95%B0) for defaults, ranges, cross-parameter constraints, proposal types, and activation timing. MRK-valued parameters use values such as `100MRK`. The required Service Bond defaults to `500MRK`. Epoch duration, mint amount, immediate reward share, vesting duration, Service Bond unlock duration, Governance Bond policy, and offline slash duration require Critical proposals. After the Service Bond is filled, each Epoch reward defaults to 25% immediately claimable; the other 75% is split from cumulative linear targets into daily tranches, quantized to Genesis-aligned 12-hour boundaries, and merged with every tranche for the same Node and unlock time. Buckets mature only when a finalized block crosses their unlock boundary. A finalized voluntary exit returns all locked buckets to Treasury, preserves already claimable rewards, and starts the Service Bond unlock delay (30 days by default). A Node with no new finalized successful Availability proof for 7 days is forcibly exited by the next finalized block; its Service Bond and locked reward buckets return to Treasury without an unlock, while claimable rewards remain. Reward queries are read-only, and claims transfer only previously finalized claimable MRK. Node warmup defaults to one day, requires a Critical proposal to change, and is snapshotted into `warmup_until` when each non-Genesis Node registers. Genesis Node 1 is immediately `ACTIVE` with `warmup_until = registered_at`; it still needs a successful Availability Probe before any Node Seconds can be credited.

Fee governance additionally supports `base-fee-per-unit`, `fee-min-multiplier-bps`, `fee-max-multiplier-bps`, `fee-target-units-per-epoch`, `fee-max-units-per-block`, `fee-adjustment-denominator`, `traffic-protocol-fee-bps`, and `traffic-treasury-share-bps`. These eight Critical parameters must be submitted as one atomic policy with `--effective-epoch` at least two Epochs ahead. Ordinary operation fees are fully burned; the default 1% traffic settlement fee is split equally between Treasury and Burn.

Every successful governance action is signed, receives a normal operation ID, increments the Genesis Owner nonce, and is stored in both the operation log and governance audit history. `pause-emission` stops new eligible Node Seconds without preventing Relay traffic, transfers, claims of already-earned MRK, or permissionless registration. It resets active heartbeat accounting at pause and resume boundaries so paused time cannot be rewarded.

At 20 or more eligible Nodes, Standard proposals are available alongside Node 1 direct governance. At 50, Node 1 direct commands close and Critical proposals become available:

```bash
mrk node governance propose-set --kind critical \
  --title "Change Epoch policy" \
  --parameter epoch-seconds --value 300 \
  --parameter epoch-mint-amount --value 100MRK
mrk node governance propose-set --kind critical \
  --title "Rotate Validators every six Epochs" \
  --parameter validator-rotation-interval-epochs --value 6
mrk node governance vote --proposal-id 1 --choice yes
mrk node governance finalize --proposal-id 1
mrk node governance execute --proposal-id 1
```

Proposal creation snapshots Node Power and locks `1,000 MRK`. Standard proposals require at least 20 eligible Nodes, vote for 7 days, require 50% participation, at least two-thirds YES among YES/NO power, and YES power strictly above 50% of the entire snapshot, then wait 7 days. Explicit ABSTAIN votes count toward participation but can never let a minority of YES power pass the absolute approval floor; not voting does not count as participation. Issuance, Validator and consensus parameters are Critical: they require at least 50 eligible Nodes, vote for 14 days, require YES power of at least two-thirds of the entire snapshot, then wait 30 days. An unexecuted proposal is cancelled and its bond refunded when eligibility falls below its kind's threshold: 20 for Standard or 50 for Critical. Node 1 direct governance is restored below 50.

Governance Power comes only from cumulative eligible service time, capped at 180 days; MRK, Service Bond, Governance Bond and Validator Bond amounts do not increase it. The per-Node share cap is dynamic: `max(1%, 1 / snapshot Node count)`, producing a 5% cap at the 20-Node Standard threshold, 2% at the 50-Node Critical threshold, and 1% from 100 Nodes onward.

## Validators and multi-Validator finality

A normal Relay Node is not automatically a Validator. It becomes a candidate by locking `50,000 MRK` from its Reward account:

```bash
mrk node validator status
mrk node validator join
mrk node validator committee
mrk node validator exit
mrk node validator withdraw-bond
```

At most 31 candidates are active in an Epoch. If there are 31 or fewer, all candidates are selected. With more candidates, committee selection is deterministic and rotates at most 10 seats at the governed Epoch interval, which defaults to every Epoch, preserving at least 21 seats. Ineligible seats and a committee below the minimum are repaired at the next Epoch boundary without waiting for the routine interval. Each height assigns one proposer by `(height + round)` rotation. Validators use their existing Node Owner key—there is no Operator or separate Validator identity—to sign `PROPOSE`, `PREVOTE`, and `PRECOMMIT`. Finality requires `floor(2N/3)+1` matching PRECOMMITs.

Multi-Validator block production requires at least 20 Governance-Eligible Nodes and four Active Validators. With zero to three Active Validators, Node 1 always produces blocks, including after Standard Node voting becomes available. Between 20 and 49 eligible Nodes, Standard Node voting and a four-Validator block committee may operate while Node 1 still retains direct governance; block production, proposal availability and Node 1 authority are independent thresholds.

`mrk node run` participates automatically when its Node is in the committee. Manual inspection and recovery commands are also available:

```bash
mrk node consensus status
mrk node consensus propose
mrk node consensus prevote
mrk node consensus precommit
mrk node consensus next-round
mrk node consensus sync-peer --target-node-id 2
```

Consensus peers use `/v1/consensus` with WebSocket subprotocol `mrk.consensus.v1`; member traffic remains isolated on `/v1/relay`. Authentication is mutual: the serving Validator signs a fresh challenge with its Owner key and the connecting Validator signs the challenge response with its Owner key. Peers first exchange signed pending operations, then reconcile the Proposal, PREVOTEs and PRECOMMITs at an equal height and round. A lagging peer requests contiguous finalized blocks and their operation bodies with `CATCH_UP_REQUEST/CATCH_UP_CHUNK`; it installs the resulting checkpoint only after validating chain continuity, the trusted committee transition, the commit certificates, operation signatures and the final state root. `mrk node run` automatically gossips with up to four deterministic ring neighbors every two seconds; a synchronization attempt is bounded to 60 seconds and one consensus message to 16 MiB. Conflicting signed votes at the same height/round/type create double-sign evidence and remove the Validator bond.

## Bootstrap block production

Below 20 Governance-Eligible Nodes, Genesis Node 1 is the only block producer. A block contains a monotonically increasing height, the previous block hash, timestamp, up to 10,000 ordered operation IDs, a state root, the producer identity and an Ed25519 Owner signature. The pending queue is bounded to the same 10,000-operation limit so a block always commits the complete pending state transition. Block and state identifiers use the complete 256-bit SHA-256 digest.

```bash
mrk --node default block status
mrk node --node default block produce
mrk block show --height 1
mrk node --node default block verify
```

`mrk node run` automatically produces a block every 10 seconds by default, including empty checkpoint blocks so online state continues to be committed. Node 1 may change the interval from 1 to 300 seconds with the governed `block-interval-seconds` parameter. Manual production rejects empty blocks unless `--allow-empty` is provided.

Multi-Validator consensus uses the same chain interval: a proposer cannot create a block before the previous finalized block timestamp plus `block-interval-seconds`, and every Validator enforces that boundary before voting. Empty and non-empty blocks use the same cadence. A slow consensus round delays finality naturally and never causes catch-up blocks to be produced faster than the configured interval.

All non-Node1 signing keys are rejected in Node 1 producer mode. The active Validator committee takes over only when there are at least 20 eligible Nodes and four Active Validators. If either count falls below its threshold, any unfinished consensus round is discarded and Node 1 resumes block production. Direct Node 1 governance is disabled at 50 eligible Nodes and restored when the count falls below 50.

`block verify` checks every height and previous-hash link, block hash, Genesis Owner signature, operation uniqueness, finality metadata, and all newly stored signed operations. Operations migrated from an older ledger can still be checkpointed, but are counted as `legacy_unverified_operations` when their original complete signed envelope was not stored.

While `mrk node run` is active, it serves:

```text
GET /health
GET /v1/probe?challenge=<16-to-512-character-random-value>
WSS /v1/rpc (mrk.rpc.v1)
```

The Probe response is signed by the Relay Key. The same listener serves WebSocket Upgrade at `/v1/relay`, `/v1/rpc`, and `/v1/consensus`. Place it behind a dedicated-IP TLS 1.3 reverse proxy for the externally advertised `wss://` endpoint; forward Upgrade and the `mrk.relay.v1`, `mrk.rpc.v1`, and `mrk.consensus.v1` subprotocols unchanged. Public RPC exposes ping, chain/block, balance/history, operation, treasury, network, Node registry, and Relay discovery reads. `operation.submit` accepts locally signed transfers and private-network operations; it never accepts a password or private key.

The present implementation persists the atomic MSL state in redb. One `mrk node run` process owns one data directory and exposes local Node administration through its single root-level `mrk.sock`, restricted to the same UID. Validator daemons use independent databases and replicate pending operations, consensus objects and finalized blocks over authenticated WSS. `FULL` peers can serve their retained history; a `LITE` peer explicitly rejects requests older than its pruning checkpoint. Public `chain.checkpoints` and the Explorer checkpoint page expose retained bootstrap checkpoint metadata, but their roots still require independent verification. `mrk discover` provides verified Relay candidates, but automatic peer selection and recovery from a trusted external snapshot remain deployment concerns.
