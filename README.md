# MRK CLI MVP

> [!IMPORTANT]
> **Pre-release compatibility notice — remove this block at the first official release (`TODO(release): remove-pre-release-compatibility-notice`).** The protocol, persisted Ledger schema, operation format, and default parameters may change without migration support before release. Test and staging deployments must reinitialize their Ledger data after an incompatible change instead of expecting older state to be upgraded. The current fresh-Ledger defaults include a 300-second Epoch and a 100 MRK Epoch mint budget. Compatibility guarantees begin only with the official release.

This repository contains the executable MRK command-line implementation. It has one binary with two command namespaces:

- `mrk`: public account operations, transfers, private networks, treasury and chain queries.
- `mrk node`: all Node lifecycle, Validator, consensus and governance commands plus the long-running Relay daemon.

The current backend is an atomic local MSL state file. Command semantics and signed operation formats are structured so the storage adapter can later be replaced by replicated MSL storage. The Node runtime provides authenticated WebSocket member routing, health and signed Probe endpoints, plus a separate authenticated Validator consensus channel. Governance switches from Genesis Node 1 to snapshot-based Node voting at 20 Governance-Eligible Nodes. Block production switches only when there are both at least 20 eligible Nodes and at least four Active Validators; otherwise Node 1 remains the single producer.

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

Use `--dry-run` to validate a transfer without signing, or `--yes --output json` for automation. A private key is never accepted as a CLI argument. Keystores use Ed25519 keys encrypted with PBKDF2-HMAC-SHA256 and AES-256-GCM.

For non-interactive development and tests, the password can be provided through `MRK_KEYSTORE_PASSWORD`. Production automation should set `MRK_KEYSTORE_PASSWORD_FILE` to a root/service-managed file readable only by its owner; files accessible by group or others are rejected. The systemd example uses `LoadCredential` so the secret is not stored in the unit or process arguments.

## Genesis treasury

The fixed one-billion-MRK supply starts as `500,000,000 MRK` in a keyless protocol treasury and `500,000,000 MRK` in the Node emission pool. The treasury is part of MSL state, not an account with an exportable private key:

```bash
mrk treasury status
mrk treasury history --limit 20
```

Treasury spending remains frozen until there are at least 20 Governance-Eligible Nodes with 180 days of cumulative eligible service and at least four Active Validators. Spending must then use a Critical governance proposal:

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

Treasury snapshots contain only Governance-Eligible Nodes with at least 180 days of cumulative eligible service and require at least 20 such Nodes plus four Active Validators. A proposal needs both two-thirds of mature snapshot Node Power and two-thirds of the snapshotted Validator committee, followed by a 14-day vote and 30-day timelock. During the timelock, mature snapshot Nodes may run `governance veto --proposal-id ID`; veto power above one-third cancels execution.

Creation and execution enforce a 1% single-spend limit, a rolling 2% limit over 90 days, and a rolling 5% limit over 365 days. Execution transfers existing MRK to the recipient; it never mints MRK, and a proposal cannot execute twice.

## Diagnostics

```bash
mrk node --node default doctor
```

The Node doctor checks lifecycle state, Endpoint DNS/IP binding, Probe freshness and all three Node key permissions. JSON output is available with `--output json`; a failed check produces a non-zero exit status for monitoring systems.

The public listener exposes `/health` for process liveness and `/ready` for traffic readiness. Both report Node status, chain height/mode, last Block time, and pending-operation count. `/ready` returns HTTP 503 while draining/suspended/exited, before the first finalized Block, or when the tip is older than `max(120s, 6 × block_interval)`. Startup also refuses unknown Node-config or Ledger versions instead of attempting an implicit migration.

## Private networks

```bash
mrk network create --name team --account default
mrk network fund --network team --amount 100MRK --account default
mrk member issue --network team --name client-a --account default
mrk member show --network team --name client-a
mrk member revoke --network team --serial 1 --account default

mrk payment authorize \
  --network team \
  --node-id 7 \
  --sender client-a \
  --receiver client-b \
  --max-amount 10MRK \
  --valid-minutes 1440 \
  --account default
```

Member credentials and encrypted member keys are written below the selected data directory.

## Member traffic pipe

First start the receiving member; without `--peer`, it accepts the first incoming channel:

```bash
mrk pipe \
  --network team \
  --member client-b \
  --endpoint wss://relay.example.com/v1/relay
```

Then start the initiating member with the target ID shown by `member issue` or `member show`:

```bash
mrk pipe \
  --network team \
  --member client-a \
  --endpoint wss://relay.example.com/v1/relay \
  --peer <CLIENT_B_MEMBER_ID> \
  --authorization <FINALIZED_AUTHORIZATION_ID>
```

After authentication and channel acceptance, stdin bytes are sent as opaque Relay `DATA` frames and received bytes are written to stdout. Status messages use stderr, so stdout remains safe for piping into another application. Each direction preserves order independently.

Paid Relay sessions use a finalized `PaymentAuthorization` that reserves Network Escrow without paying the Node up front. Each direction pauses new DATA after 64 MiB or two minutes, whichever occurs first, while control frames remain live. The sender signs a cumulative checkpoint and the receiver countersigns the matching delivered prefix; only this dual-signed receipt can release the proportional `price_per_gib` amount to the Node. Receipts are exchanged off chain and only the latest cumulative pair is needed for settlement. Unreceipted funds return after the authorization and seven-day claim window expire; traffic settlement never mints MRK.

```bash
mrk payment status <AUTHORIZATION_ID>
mrk payment refund <AUTHORIZATION_ID> --account default
```

Production clients require TLS 1.3 `wss://` with a publicly trusted certificate. Private deployments may add a PEM trust anchor with `--tls-ca /path/to/ca.pem`; hostname and certificate-purpose validation remain enabled. Loopback development may use `ws://127.0.0.1/... --allow-insecure-local`; plaintext WebSocket to non-loopback hosts is rejected.

## Node lifecycle

```bash
mrk node init --lite

mrk node run --listen 0.0.0.0:8787

# Joining nodes only; obtain the state_... root through an independent trusted channel.
mrk node bootstrap \
  --peer wss://seed.example.com/v1/rpc \
  --checkpoint-root state_<64-lowercase-hex>

mrk node register \
  --endpoint wss://relay.example.com/v1/relay \
  --price-per-gib 0.02MRK

mrk node status
mrk node backup
mrk node backup-verify ~/.mrk/backups/mrk-HEIGHT-TIME.json --expected-state-root state_...
mrk node restore ~/.mrk/backups/mrk-HEIGHT-TIME.json --expected-state-root state_...
mrk node probe --target-node-id 1 --watch
mrk node rewards
mrk node claim
mrk node drain
```

`mrk node run` starts the Unix administration Socket before registration. Genesis Node 1 registers on its empty chain. Every later Node first runs `mrk node bootstrap`, then `mrk node register`. A downloaded snapshot is accepted only when its full SHA-256 state root matches the operator-supplied root. Obtain that root from an independent trusted release, quorum announcement, or comparison with multiple operators—not from the peer serving the snapshot. The daemon remembers the peer, forwards its signed registration operation, and continuously downloads and verifies finalized catch-up blocks. It enables its public WSS listener after registration succeeds. All later `mrk node` commands also use that Socket. Public `mrk` queries use
`--rpc-endpoint wss://relay.example.com/v1/rpc` (or `MRK_RPC_ENDPOINT`).

The public Node registry and the connectable Relay set are separate queries:

```bash
mrk registry list --rpc-endpoint wss://relay.example.com/v1/rpc
mrk registry list --status active --validator --limit 50
mrk registry show --node-id 7
mrk discover --limit 50 --rpc-endpoint wss://relay.example.com/v1/rpc
```

`registry list` returns finalized registrations in ascending Node ID order, including inactive and historical entries unless filtered. `--status` accepts `initialized`, `warming-up`, `active`, `draining`, `exited`, or `suspended`; `--validator` keeps only current Active Validators. `registry show` returns one public registration record. `discover` is the connection-oriented view: it returns only `ACTIVE` Nodes whose latest finalized Availability Probe is still valid and whose IP slot remains bound. Both list commands return `next_cursor`; pass it back with `--cursor` to read the next page. Base-unit amounts are strings in these new responses so clients do not lose precision when decoding JSON.

Node storage has exactly two modes: `LITE` and `FULL`. `mrk node init --lite`
selects `LITE`; plain `mrk node init` selects `FULL`. The choice is persisted in the
Node configuration and shown by `mrk node status`. `LITE` is the bounded-storage
profile for current state, verified checkpoints, and recent history; `FULL`
retains the complete chain history. Chain state is persisted under
`~/.mrk/chain.redb`; only the `mrk node run` process opens redb. Other `mrk node`
commands use the single `~/.mrk/mrk.sock`. One data directory runs exactly one
`mrk node`; the Socket is not split into per-Node directories. A running `LITE` daemon checks every
60 seconds and retains the newest 65,536 blocks, operation bodies for the newest
complete-block suffix targeting 262,144 operations, and at most 1,024 retained
operation IDs per account. Pending operations and current state are never
pruned. The finalized prefix is replaced by a height/hash/time checkpoint and
redb is compacted after deletion. `FULL` never prunes history.

`mrk node backup` asks the running daemon for a transactionally consistent logical backup. It writes a `0600` JSON file under `~/.mrk/backups/` by default, refuses to overwrite an existing file, and records the chain height, state root, and a checksum over the complete payload. `backup-verify` validates the checksum, metadata, complete chain, and optional pinned state root without changing local state. `restore` is deliberately offline: stop `mrk node run`, supply the expected state root through an independent trusted channel, restore atomically, then run `mrk node doctor` before restarting. Copy backups off-host and rehearse this procedure before operating a Validator.

The public listener admits at most 2,048 concurrent connections and 128 connections per non-loopback source IP; loopback reverse proxies share the global limit. Each RPC WebSocket is limited to 120 requests and 20 mutation submissions per minute, and no RPC response may exceed 16 MiB. Relay channels and outbound queues retain their separate bounded backpressure limits.

The operator does not provide a public IP. Registration resolves it from the required `wss://` endpoint, preferring a public IPv4 address when both address families exist; Node startup verifies that the endpoint still resolves to the registered address, and external Probes provide the final reachability check. Private, loopback, link-local, CGNAT and reserved addresses are rejected. IPv4 addresses occupy one reward slot each; IPv6 addresses are grouped by `/64`.

Running the process alone does not earn MRK. `mrk node run` automatically performs the Availability Probes assigned to that Node: it connects directly to the target's registered `reward_ip`, verifies the Endpoint hostname through TLS SNI, validates the Relay-key response, and submits an Owner-key-signed attestation. Availability begins in the explicit `NODE1_TRUSTED` mode: Node 1 is absolutely trusted, may verify itself, and one Node 1 attestation is sufficient. At the first Epoch boundary with at least seven Active Validators the ledger irreversibly switches to `MULTI_VALIDATOR`; it then defaults to five Primary Verifiers with a three-vote quorum and never permits target self-verification. Falling below seven after activation pauses new Node Seconds instead of restoring Node 1 authority.

Each selected verifier signs a private Probe Ticket binding the ledger, Epoch, slot, target, verifier and `PRIMARY/AUDIT` role. The Ticket determines both the Challenge and a secret time within the 60-second slot, so the target cannot predict an honest verifier's check before receiving it. By default 5% of slots also require two of three disjoint Auditors when at least nine Active Validators are available. Audited slots earn time only after both quorums. Network observation disagreements withhold that Slot's reward but do not slash principal; only objective cryptographic conflicts such as double-signing are slashable. `mrk node probe` remains available for diagnosis and retries but obeys the same Ticket and timing rules.

This Availability state transition is part of the unreleased protocol/on-disk version 1. Before the first release, incompatible test data is deliberately rebuilt or explicitly bootstrapped instead of migrated implicitly.

Node initialization creates three separate encrypted keys:

- Node Owner Key for registration and lifecycle operations.
- Relay Key for signed Probe responses.
- Reward Key for Liquid MRK income.

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

A Governance-Eligible Node must be `ACTIVE`, have the minimum Service Bond, have accumulated the configured minimum finalized eligible service time (30 days by default), and have a fresh quorum-confirmed Probe timestamp. Local heartbeat state never grants governance power. At 20 eligible Nodes, Node 1 direct actions are rejected with `node voting is required`. If the count later falls below 20, Node 1 authority returns automatically. Registration remains permissionless in every mode.

The complete supported parameter set is `epoch-seconds`, `epoch-mint-amount`, `reward-immediate-bps`, `reward-vesting-seconds`, `validator-weight-bps`, `validator-signature-threshold-bps`, `min-service-bond`, `warmup-seconds`, `heartbeat-grace-seconds`, `probe-validity-seconds`, `availability-slot-seconds`, `availability-verifier-count`, `availability-quorum`, `availability-audit-rate-bps`, `availability-auditor-count`, `availability-audit-quorum`, `ip-reuse-cooldown-seconds`, `governance-min-service-seconds`, `block-interval-seconds`, `validator-bond`, `max-active-validators`, `max-validator-rotations`, and `consensus-round-timeout-seconds`. See the [governance parameter reference](docs/blockchain.md#82-%E5%8F%AF%E6%B2%BB%E7%90%86%E5%8F%82%E6%95%B0) for defaults, ranges, cross-parameter constraints, proposal types, and activation timing. MRK-valued parameters use values such as `100MRK`. Epoch duration, mint amount, immediate reward share, and vesting duration require Critical proposals and take effect with the next Epoch snapshot. After the Service Bond is filled, each Epoch reward defaults to 10% immediately claimable and 90% linearly vested over 180 days; vesting advances only when a finalized block crosses an Epoch boundary. Reward queries are read-only, and claims transfer only previously finalized claimable MRK. Node warmup also requires a Critical proposal and is snapshotted into `warmup_until` when each non-Genesis Node registers. Genesis Node 1 is immediately `ACTIVE` with `warmup_until = registered_at`; it still needs a successful Availability Probe before any Node Seconds can be credited.

Every successful governance action is signed, receives a normal operation ID, increments the Genesis Owner nonce, and is stored in both the operation log and governance audit history. `pause-emission` stops new eligible Node Seconds without preventing Relay traffic, transfers, claims of already-earned MRK, or permissionless registration. It resets active heartbeat accounting at pause and resume boundaries so paused time cannot be rewarded.

At 20 or more eligible Nodes, use distributed proposals instead of the direct commands:

```bash
mrk node governance propose-set --kind critical \
  --title "Change Epoch mint amount" \
  --parameter epoch-mint-amount --value 450MRK
mrk node governance vote --proposal-id 1 --choice yes
mrk node governance finalize --proposal-id 1
mrk node governance execute --proposal-id 1
```

Proposal creation snapshots Node Power and locks `1,000 MRK`. Standard proposals vote for 7 days, require 50% participation and at least two-thirds YES among YES/NO power, then wait 7 days. Issuance, Validator and consensus parameters are critical: they vote for 14 days, require YES power of at least two-thirds of the entire snapshot, then wait 30 days. If eligibility falls below 20, every unexecuted distributed proposal is cancelled and its bond is refunded before Node 1 direct governance resumes.

Governance Power comes only from cumulative eligible service time, capped at 180 days; MRK, Service Bond and Validator Bond do not increase it. The per-Node share cap is dynamic: `max(1%, 1 / snapshot Node count)`, producing a 5% cap at 20 Nodes, 2.5% at 40, and 1% from 100 Nodes onward.

## Validators and multi-Validator finality

A normal Relay Node is not automatically a Validator. It becomes a candidate by locking `50,000 MRK` from its Reward account:

```bash
mrk node validator status
mrk node validator join
mrk node validator committee
mrk node validator exit
mrk node validator withdraw-bond
```

At most 31 candidates are active in an Epoch. If there are 31 or fewer, all candidates are selected. With more candidates, committee selection is deterministic and rotates at most 10 seats per Epoch, preserving at least 21 seats. Each height assigns one proposer by `(height + round)` rotation. Validators use their existing Node Owner key—there is no Operator or separate Validator identity—to sign `PROPOSE`, `PREVOTE`, and `PRECOMMIT`. Finality requires `floor(2N/3)+1` matching PRECOMMITs.

Multi-Validator block production requires at least four Active Validators. With zero to three Active Validators, Node 1 always produces blocks, including when governance has already switched to distributed voting at 20 eligible Nodes. Node 1's temporary block-ordering role does not restore its direct governance authority.

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

All non-Node1 signing keys are rejected in Node 1 producer mode. The active Validator committee takes over only when there are at least 20 eligible Nodes and four Active Validators. If either count falls below its threshold, any unfinished consensus round is discarded and Node 1 resumes block production. Direct Node 1 governance is restored only when the eligible Node count falls below 20.

`block verify` checks every height and previous-hash link, block hash, Genesis Owner signature, operation uniqueness, finality metadata, and all newly stored signed operations. Operations migrated from an older ledger can still be checkpointed, but are counted as `legacy_unverified_operations` when their original complete signed envelope was not stored.

While `mrk node run` is active, it serves:

```text
GET /health
GET /v1/probe?challenge=<16-to-512-character-random-value>
WSS /v1/rpc (mrk.rpc.v1)
```

The Probe response is signed by the Relay Key. The same listener serves WebSocket Upgrade at `/v1/relay`, `/v1/rpc`, and `/v1/consensus`. Place it behind a dedicated-IP TLS 1.3 reverse proxy for the externally advertised `wss://` endpoint; forward Upgrade and the `mrk.relay.v1`, `mrk.rpc.v1`, and `mrk.consensus.v1` subprotocols unchanged. Public RPC exposes ping, chain/block, balance/history, operation, treasury, network, Node registry, and Relay discovery reads. `operation.submit` accepts locally signed transfers and private-network operations; it never accepts a password or private key.

The present implementation persists the atomic MSL state in redb. One `mrk node run` process owns one data directory and exposes local Node administration through its single root-level `mrk.sock`, restricted to the same UID. Validator daemons use independent databases and replicate pending operations, consensus objects and finalized blocks over authenticated WSS. `FULL` peers can serve their retained history; a `LITE` peer explicitly rejects requests older than its pruning checkpoint. `mrk discover` provides verified Relay candidates, but automatic peer selection and recovery from a trusted external snapshot remain deployment concerns.
