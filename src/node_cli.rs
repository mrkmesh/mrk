#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::{
        fs::PermissionsExt,
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

use chrono::Utc;
use clap::{Subcommand, ValueEnum};
use mrk::{
    Error, Result,
    amount::{format_mrk, parse_mrk},
    consensus::{
        CONSENSUS_PROTOCOL, ConsensusWireMessage, MAX_CATCH_UP_BLOCKS, MAX_CONSENSUS_MESSAGE_SIZE,
    },
    crypto::{decrypt_key, hex_lower, random_bytes, validate_keystore_password, verify_bytes},
    model::{
        AvailabilityMode, ConsensusVoteType, NodeRecord, NodeStatus, NodeStorageMode,
        RelayDirection, SignedOperation,
    },
    relay::{
        ChallengePayload, CheckpointRequest, CloseIntent, ErrorPayload, FrameType, IncomingPayload,
        MAX_FRAME_PAYLOAD, OpenPayload, RELAY_CHECKPOINT_FINAL_FLAG, RELAY_PAYMENT_WINDOW_BYTES,
        RELAY_PAYMENT_WINDOW_SECONDS, ReceiverReceipt, RelayFrame, SenderCheckpoint,
        WelcomePayload, WsMessage, read_ws_message, receiver_receipt_signing_bytes,
        relay_transcript_initial_hash, relay_transcript_next_hash, sender_checkpoint_hash,
        sender_checkpoint_signing_bytes, websocket_server_response,
        websocket_server_response_for_protocol, write_ws_message,
    },
    relay_client,
    service::{self, AuthenticatedMember},
    storage::{ActiveRelaySession, DataPaths, PendingTrafficSettlement, UnsettledRelaySession},
};
use serde::{Deserialize, Serialize};

const MAX_CHANNELS_PER_CONNECTION: usize = 256;
const OUTBOUND_QUEUE_MESSAGES: usize = 8;
const MAX_PUBLIC_CONNECTIONS: usize = 2_048;
const MAX_PUBLIC_CONNECTIONS_PER_IP: usize = 128;
const MAX_RPC_REQUESTS_PER_MINUTE: u32 = 120;
const MAX_RPC_MUTATIONS_PER_MINUTE: u32 = 20;
const RPC_PROTOCOL: &str = "mrk.rpc.v1";
const RELAY_RECOVERY_GRACE_SECONDS: i64 = 30;
const RELAY_UNKNOWN_TAIL_MAX_BYTES: u64 = 2 * RELAY_PAYMENT_WINDOW_BYTES;

thread_local! {
    static ADMIN_PASSWORD: RefCell<Option<String>> = const { RefCell::new(None) };
    static ADMIN_OUTPUT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[derive(Clone)]
struct Peer {
    network_id: String,
    member_id: String,
    sender: SyncSender<WsMessage>,
}

#[derive(Clone)]
struct Route {
    source: u64,
    destination: u64,
    accepted: bool,
    source_sequence: u64,
    destination_sequence: u64,
    authorization: Option<service::RelayAuthorizationView>,
    source_direction: DirectionState,
    destination_direction: DirectionState,
    recovery: bool,
}

#[derive(Clone)]
struct InterruptedRoute {
    authorization: service::RelayAuthorizationView,
    source_sequence: u64,
    destination_sequence: u64,
    source_direction: DirectionState,
    destination_direction: DirectionState,
    disconnected_at: i64,
}

#[derive(Clone, Default)]
struct DirectionState {
    cumulative_bytes: u64,
    transcript_hash: String,
    window_started_at: Option<i64>,
    window_started_bytes: u64,
    checkpoint_due: bool,
    awaiting_receipt: bool,
    pending_checkpoint: Option<SenderCheckpoint>,
    checkpoint_request: Option<CheckpointRequest>,
    final_receipt_persisted: bool,
}

#[derive(Default)]
struct HubState {
    next_connection_id: u64,
    next_channel_id: u32,
    peers: HashMap<u64, Peer>,
    member_connections: HashMap<(String, String), Vec<u64>>,
    routes: HashMap<u32, Route>,
    interrupted_routes: HashMap<String, InterruptedRoute>,
    last_recovery_policy_at: i64,
}

struct RelayHub {
    state: Mutex<HubState>,
    paths: Option<DataPaths>,
    node_id: Option<u64>,
    settlement_wakeup: Option<SyncSender<()>>,
    node_name: Option<String>,
    node_password: Option<String>,
}

impl Default for RelayHub {
    fn default() -> Self {
        Self {
            state: Mutex::new(HubState::default()),
            paths: None,
            node_id: None,
            settlement_wakeup: None,
            node_name: None,
            node_password: None,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize)]
enum Output {
    Text,
    Json,
}

#[derive(Serialize)]
struct LocalNodeStatus {
    #[serde(flatten)]
    node: NodeRecord,
    storage_mode: NodeStorageMode,
    availability_mode: AvailabilityMode,
    availability_earning_enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct AdminRequest {
    node: String,
    output: Output,
    command: DaemonCommand,
}

#[derive(Serialize, Deserialize)]
struct AdminResponse {
    ok: bool,
    output: Vec<u8>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RpcRequest {
    id: u64,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct RpcResponse {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: &'static str,
    message: String,
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum DaemonCommand {
    Doctor,
    Init {
        #[arg(long)]
        lite: bool,
    },
    Bootstrap {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        checkpoint_height: u64,
        #[arg(long)]
        checkpoint_root: String,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
    },
    Backup {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    BackupVerify {
        path: PathBuf,
        #[arg(long)]
        expected_state_root: Option<String>,
    },
    Restore {
        path: PathBuf,
        #[arg(long)]
        expected_state_root: String,
    },
    Register {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        price_per_gib: String,
    },
    UpdateRewardIp {
        #[arg(long)]
        endpoint: String,
    },
    Run {
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: SocketAddr,
        #[arg(long, hide = true)]
        #[serde(default)]
        allow_insecure_local: bool,
    },
    Status,
    Rewards,
    Probe {
        #[arg(long)]
        target_node_id: u64,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(30..=300))]
        interval_seconds: u64,
    },
    Claim,
    WithdrawServiceBond,
    Drain,
    Block {
        #[command(subcommand)]
        command: BlockCommand,
    },
    Validator {
        #[command(subcommand)]
        command: ValidatorCommand,
    },
    Consensus {
        #[command(subcommand)]
        command: ConsensusCommand,
    },
    Governance {
        #[command(subcommand)]
        command: GovernanceCommand,
    },
    Payment {
        #[command(subcommand)]
        command: NodePaymentCommand,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum NodePaymentCommand {
    Unsettled,
    Abandon {
        authorization_id: String,
    },
    Policy {
        #[command(subcommand)]
        command: NodePaymentPolicyCommand,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum NodePaymentPolicyCommand {
    Show {
        #[arg(long)]
        network: Option<String>,
    },
    Set {
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        max_auto_abandon_bytes: u64,
    },
    Clear {
        #[arg(long)]
        network: String,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum ClientCommand {
    Block {
        #[command(subcommand)]
        command: BlockCommand,
    },
    Validator {
        #[command(subcommand)]
        command: ValidatorCommand,
    },
    Consensus {
        #[command(subcommand)]
        command: ConsensusCommand,
    },
    Governance {
        #[command(subcommand)]
        command: GovernanceCommand,
    },
    Treasury {
        #[command(subcommand)]
        command: TreasuryCommand,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum BlockCommand {
    Status,
    Produce {
        #[arg(long)]
        allow_empty: bool,
    },
    Show {
        #[arg(long)]
        height: u64,
    },
    Verify,
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum ValidatorCommand {
    Status,
    Join,
    Committee,
    Exit,
    WithdrawBond,
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum ConsensusCommand {
    Status,
    Propose,
    Prevote {
        #[arg(long, conflicts_with = "nil")]
        block_hash: Option<String>,
        #[arg(long)]
        nil: bool,
    },
    Precommit {
        #[arg(long, conflicts_with = "nil")]
        block_hash: Option<String>,
        #[arg(long)]
        nil: bool,
    },
    NextRound,
    SyncPeer {
        #[arg(long)]
        target_node_id: u64,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
    },
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum GovernanceCommand {
    Status,
    List,
    Proposal {
        #[arg(long)]
        proposal_id: u64,
    },
    ProposeSet {
        #[arg(long, value_enum)]
        kind: ProposalKind,
        #[arg(long)]
        title: String,
        #[arg(long, value_parser = governance_parameter_parser)]
        parameter: String,
        #[arg(long)]
        value: String,
    },
    ProposePause {
        #[arg(long, value_enum, default_value_t = ProposalKind::Standard)]
        kind: ProposalKind,
        #[arg(long)]
        title: String,
        #[arg(long)]
        reason: String,
    },
    ProposeResume {
        #[arg(long, value_enum, default_value_t = ProposalKind::Standard)]
        kind: ProposalKind,
        #[arg(long)]
        title: String,
    },
    ProposeTreasurySpend {
        #[arg(long)]
        title: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        reference: String,
    },
    Vote {
        #[arg(long)]
        proposal_id: u64,
        #[arg(long, value_enum)]
        choice: VoteChoice,
    },
    ValidatorVote {
        #[arg(long)]
        proposal_id: u64,
        #[arg(long, value_enum)]
        choice: VoteChoice,
    },
    Veto {
        #[arg(long)]
        proposal_id: u64,
    },
    Finalize {
        #[arg(long)]
        proposal_id: u64,
    },
    Execute {
        #[arg(long)]
        proposal_id: u64,
    },
    Set {
        #[arg(long, value_parser = governance_parameter_parser)]
        parameter: String,
        #[arg(long)]
        value: String,
    },
    PauseEmission {
        #[arg(long)]
        reason: String,
    },
    ResumeEmission,
}

#[derive(Subcommand, Serialize, Deserialize)]
pub(crate) enum TreasuryCommand {
    Status,
    History {
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limit: u64,
    },
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub(crate) enum ProposalKind {
    Standard,
    Critical,
}

impl From<ProposalKind> for mrk::model::GovernanceProposalKind {
    fn from(value: ProposalKind) -> Self {
        match value {
            ProposalKind::Standard => Self::Standard,
            ProposalKind::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub(crate) enum VoteChoice {
    Yes,
    No,
    Abstain,
}

impl From<VoteChoice> for mrk::model::GovernanceVoteChoice {
    fn from(value: VoteChoice) -> Self {
        match value {
            VoteChoice::Yes => Self::Yes,
            VoteChoice::No => Self::No,
            VoteChoice::Abstain => Self::Abstain,
        }
    }
}

fn governance_parameter_parser(value: &str) -> std::result::Result<String, String> {
    const PARAMETERS: &[&str] = &[
        "epoch-seconds",
        "epoch-mint-amount",
        "reward-immediate-bps",
        "reward-vesting-seconds",
        "validator-weight-bps",
        "validator-signature-threshold-bps",
        "required-service-bond",
        "service-bond-unlock-seconds",
        "offline-slash-seconds",
        "warmup-seconds",
        "heartbeat-grace-seconds",
        "probe-validity-seconds",
        "availability-slot-seconds",
        "availability-verifier-count",
        "availability-quorum",
        "availability-audit-rate-bps",
        "availability-auditor-count",
        "availability-audit-quorum",
        "ip-reuse-cooldown-seconds",
        "governance-min-service-seconds",
        "block-interval-seconds",
        "validator-bond",
        "max-active-validators",
        "max-validator-rotations",
        "consensus-round-timeout-seconds",
    ];
    if PARAMETERS.contains(&value) {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "unsupported parameter; expected one of: {}",
            PARAMETERS.join(", ")
        ))
    }
}

impl RelayHub {
    fn production(
        paths: DataPaths,
        node_id: u64,
        settlement_wakeup: SyncSender<()>,
        node_name: String,
        node_password: String,
    ) -> Result<Self> {
        paths.promote_active_relay_sessions(Utc::now().timestamp())?;
        auto_abandon_lost_relay_sessions(
            &paths,
            &node_name,
            &node_password,
            node_id,
            Utc::now().timestamp(),
            &HashSet::new(),
        );
        Ok(Self {
            state: Mutex::new(HubState::default()),
            paths: Some(paths),
            node_id: Some(node_id),
            settlement_wakeup: Some(settlement_wakeup),
            node_name: Some(node_name),
            node_password: Some(node_password),
        })
    }

    fn register(&self, member: AuthenticatedMember, sender: SyncSender<WsMessage>) -> Result<u64> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::msg("relay connection state lock is poisoned"))?;
        let key = (member.network_id.clone(), member.member_id.clone());
        let current = state.member_connections.get(&key).map_or(0, Vec::len);
        if current >= member.max_connections as usize {
            return Err(Error::msg("member connection limit reached"));
        }
        state.next_connection_id = state.next_connection_id.saturating_add(1).max(1);
        let connection_id = state.next_connection_id;
        state.peers.insert(
            connection_id,
            Peer {
                network_id: member.network_id,
                member_id: member.member_id,
                sender,
            },
        );
        state
            .member_connections
            .entry(key)
            .or_default()
            .push(connection_id);
        Ok(connection_id)
    }

    fn unregister(&self, connection_id: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(peer) = state.peers.remove(&connection_id) else {
            return;
        };
        let key = (peer.network_id, peer.member_id);
        if let Some(connections) = state.member_connections.get_mut(&key) {
            connections.retain(|candidate| *candidate != connection_id);
            if connections.is_empty() {
                state.member_connections.remove(&key);
            }
        }
        let closed = state
            .routes
            .iter()
            .filter_map(|(channel_id, route)| {
                (route.source == connection_id || route.destination == connection_id).then_some((
                    *channel_id,
                    route.source,
                    route.destination,
                    route.authorization.clone(),
                    route.clone(),
                ))
            })
            .collect::<Vec<_>>();
        for (channel_id, source, destination, authorization, route) in closed {
            state.routes.remove(&channel_id);
            if let (Some(paths), Some(view)) = (&self.paths, authorization)
                && !(route.source_direction.final_receipt_persisted
                    && route.destination_direction.final_receipt_persisted)
            {
                let interrupted_at = Utc::now().timestamp();
                let authorization_id = view.authorization.authorization_id.clone();
                state.interrupted_routes.insert(
                    authorization_id.clone(),
                    InterruptedRoute {
                        authorization: view.clone(),
                        source_sequence: route.source_sequence,
                        destination_sequence: route.destination_sequence,
                        source_direction: route.source_direction,
                        destination_direction: route.destination_direction,
                        disconnected_at: interrupted_at,
                    },
                );
                let authorization = view.authorization;
                let _ = paths.store_unsettled_relay_session(&UnsettledRelaySession {
                    authorization_id: authorization.authorization_id,
                    network_id: authorization.network_id,
                    network_commitment: authorization.network_commitment,
                    node_id: authorization.node_id,
                    sender_member_id: authorization.sender_member_id,
                    receiver_member_id: authorization.receiver_member_id,
                    disconnected_at: interrupted_at,
                });
                let _ = paths.remove_active_relay_session(&authorization_id);
            } else if let (Some(paths), Some(view)) = (&self.paths, &route.authorization) {
                let authorization_id = &view.authorization.authorization_id;
                let _ = paths.remove_active_relay_session(authorization_id);
                let _ = paths.remove_unsettled_relay_session(authorization_id);
            }
            let other = if source == connection_id {
                destination
            } else {
                source
            };
            if let Some(other_peer) = state.peers.get(&other) {
                let _ = send_relay_frame(
                    &other_peer.sender,
                    RelayFrame {
                        frame_type: FrameType::Close,
                        flags: 0,
                        channel_id,
                        sequence: 0,
                        payload: Vec::new(),
                    },
                );
            }
        }
    }

    fn tick_payment_windows(&self, now: i64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::msg("relay connection state lock is poisoned"))?;
        let mut requests = Vec::new();
        for (channel_id, route) in &mut state.routes {
            if route.recovery {
                continue;
            }
            let Some(view) = &route.authorization else {
                continue;
            };
            for (connection_id, direction, sequence, direction_state) in [
                (
                    route.source,
                    RelayDirection::SenderToReceiver,
                    route.source_sequence,
                    &mut route.source_direction,
                ),
                (
                    route.destination,
                    RelayDirection::ReceiverToSender,
                    route.destination_sequence,
                    &mut route.destination_direction,
                ),
            ] {
                let elapsed = direction_state.window_started_at.is_some_and(|started| {
                    now.saturating_sub(started) >= RELAY_PAYMENT_WINDOW_SECONDS
                });
                if elapsed
                    && direction_state.cumulative_bytes > direction_state.window_started_bytes
                    && direction_state.checkpoint_request.is_none()
                    && !direction_state.awaiting_receipt
                {
                    let request = schedule_checkpoint_request(
                        view,
                        direction,
                        sequence,
                        direction_state,
                        false,
                        now,
                    );
                    requests.push((connection_id, *channel_id, request));
                }
            }
        }
        for (connection_id, channel_id, request) in requests {
            let peer = state
                .peers
                .get(&connection_id)
                .ok_or_else(|| Error::msg("checkpoint sender is no longer connected"))?;
            send_relay_frame(
                &peer.sender,
                RelayFrame {
                    frame_type: FrameType::CheckpointRequest,
                    flags: if request.final_checkpoint {
                        RELAY_CHECKPOINT_FINAL_FLAG
                    } else {
                        0
                    },
                    channel_id,
                    sequence: request.sequence,
                    payload: serde_json::to_vec(&request)?,
                },
            )?;
        }
        Ok(())
    }

    fn tick_interrupted_routes(&self, now: i64) {
        let (Some(paths), Some(node_name), Some(password)) =
            (&self.paths, &self.node_name, &self.node_password)
        else {
            return;
        };
        let (candidates, in_memory_authorizations) = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.last_recovery_policy_at == now {
                return;
            }
            state.last_recovery_policy_at = now;
            let in_memory = state
                .interrupted_routes
                .keys()
                .cloned()
                .collect::<HashSet<_>>();
            let candidates = state
                .interrupted_routes
                .iter()
                .filter(|(_, route)| {
                    now.saturating_sub(route.disconnected_at) >= RELAY_RECOVERY_GRACE_SECONDS
                })
                .map(|(authorization_id, route)| {
                    let unsigned_bytes = route
                        .source_direction
                        .cumulative_bytes
                        .saturating_sub(route.source_direction.window_started_bytes)
                        .saturating_add(
                            route
                                .destination_direction
                                .cumulative_bytes
                                .saturating_sub(route.destination_direction.window_started_bytes),
                        );
                    (
                        authorization_id.clone(),
                        route.authorization.clone(),
                        unsigned_bytes,
                    )
                })
                .collect::<Vec<_>>();
            (candidates, in_memory)
        };
        let pending_authorizations = match paths.pending_traffic_settlements() {
            Ok(pending) => pending
                .into_iter()
                .map(|pending| pending.sender_checkpoint.authorization_id)
                .collect::<HashSet<_>>(),
            Err(error) => {
                eprintln!("could not read pending Relay receipts: {error}");
                return;
            }
        };
        for (authorization_id, view, unsigned_bytes) in candidates {
            if pending_authorizations.contains(&authorization_id) {
                continue;
            }
            let config = match paths.read_node_config(node_name) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("could not read Relay auto-abandon policy: {error}");
                    return;
                }
            };
            let limit = config
                .relay_auto_abandon
                .max_bytes_for(&view.authorization.network_commitment);
            if !record_auto_abandon_budget(paths, &view.authorization, unsigned_bytes, limit, now) {
                continue;
            }
            match service::abandon_traffic_authorization_with_note(
                paths,
                node_name,
                password,
                &authorization_id,
                &format!(
                    "node automatically abandoned {unsigned_bytes} bytes after Relay recovery timeout"
                ),
                now,
            ) {
                Ok(operation_id) => {
                    eprintln!(
                        "Relay auto-abandoned {unsigned_bytes} bytes for {authorization_id} ({operation_id})"
                    );
                    if let Ok(mut state) = self.state.lock() {
                        state.interrupted_routes.remove(&authorization_id);
                    }
                }
                Err(error) => {
                    eprintln!("Relay auto-abandon failed for {authorization_id}: {error}");
                }
            }
        }
        auto_abandon_lost_relay_sessions(
            paths,
            node_name,
            password,
            self.node_id.unwrap_or_default(),
            now,
            &in_memory_authorizations,
        );
    }

    fn handle_frame(&self, connection_id: u64, frame: RelayFrame) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::msg("relay connection state lock is poisoned"))?;
        let source_peer = state
            .peers
            .get(&connection_id)
            .cloned()
            .ok_or_else(|| Error::msg("relay connection is not registered"))?;
        match frame.frame_type {
            FrameType::Open => {
                if state
                    .routes
                    .values()
                    .filter(|route| {
                        route.source == connection_id || route.destination == connection_id
                    })
                    .count()
                    >= MAX_CHANNELS_PER_CONNECTION
                {
                    return send_protocol_error(
                        &source_peer.sender,
                        "CHANNEL_LIMIT",
                        "connection channel limit reached",
                    );
                }
                let request: OpenPayload = serde_json::from_slice(&frame.payload)?;
                let mut recovery = false;
                let mut recovery_session = None;
                if state.routes.values().any(|route| {
                    route.authorization.as_ref().is_some_and(|view| {
                        view.authorization.authorization_id == request.authorization_id
                    })
                }) {
                    return Err(Error::msg(
                        "payment authorization already has an active Relay channel",
                    ));
                }
                if let Some(paths) = &self.paths
                    && paths.pending_traffic_settlements()?.iter().any(|pending| {
                        pending.sender_checkpoint.authorization_id == request.authorization_id
                    })
                {
                    return Err(Error::msg(
                        "payment authorization has an unsettled receipt; retry after settlement",
                    ));
                }
                if let (Some(paths), Some(node_id)) = (&self.paths, self.node_id) {
                    let holds = active_unsettled_relay_sessions(paths, node_id)?;
                    let recovery_hold = holds
                        .iter()
                        .find(|hold| hold.authorization_id == request.authorization_id)
                        .cloned();
                    if recovery_hold.is_some() {
                        recovery_session = state
                            .interrupted_routes
                            .get(&request.authorization_id)
                            .cloned();
                        if recovery_session.is_none() {
                            return send_protocol_error(
                                &source_peer.sender,
                                "RECOVERY_STATE_LOST",
                                "the Node restarted after this interrupted session; it can only be abandoned",
                            );
                        }
                        recovery = true;
                    }
                    if holds.iter().any(|hold| {
                        hold.network_id == source_peer.network_id
                            && hold.authorization_id != request.authorization_id
                    }) {
                        return send_protocol_error(
                            &source_peer.sender,
                            "RECOVERY_REQUIRED",
                            "an interrupted Relay session must be settled or abandoned before opening a new paid session",
                        );
                    }
                }
                let destination = state
                    .member_connections
                    .get(&(source_peer.network_id.clone(), request.peer_id.clone()))
                    .and_then(|connections| connections.first())
                    .copied()
                    .ok_or_else(|| Error::msg("target member is not online"))?;
                let destination_peer = state.peers.get(&destination).expect("online peer");
                let authorization = match (&self.paths, self.node_id) {
                    (Some(paths), Some(node_id)) => Some(if recovery {
                        service::validate_relay_recovery_open(
                            paths,
                            &request.authorization_id,
                            node_id,
                            &source_peer.network_id,
                            &source_peer.member_id,
                            &destination_peer.member_id,
                            Utc::now().timestamp(),
                        )?
                    } else {
                        service::validate_relay_open(
                            paths,
                            &request.authorization_id,
                            node_id,
                            &source_peer.network_id,
                            &source_peer.member_id,
                            &destination_peer.member_id,
                            Utc::now().timestamp(),
                        )?
                    }),
                    _ => None,
                };
                let (
                    source_direction,
                    destination_direction,
                    source_sequence,
                    destination_sequence,
                    session_id,
                ) = if let Some(view) = &authorization {
                    let authorization = &view.authorization;
                    let direction_state = |direction| {
                        let settled = authorization
                            .directions
                            .get(&direction)
                            .cloned()
                            .unwrap_or_default();
                        let initial = relay_transcript_initial_hash(
                            &view.ledger_id,
                            authorization.node_id,
                            &authorization.authorization_id,
                            &authorization.session_id,
                            direction,
                        );
                        DirectionState {
                            cumulative_bytes: settled.settled_payload_bytes,
                            transcript_hash: settled.settled_transcript_hash.unwrap_or(initial),
                            window_started_at: None,
                            window_started_bytes: settled.settled_payload_bytes,
                            checkpoint_due: false,
                            awaiting_receipt: false,
                            pending_checkpoint: None,
                            checkpoint_request: None,
                            final_receipt_persisted: settled.finalized,
                        }
                    };
                    let source_settled = authorization
                        .directions
                        .get(&RelayDirection::SenderToReceiver)
                        .cloned()
                        .unwrap_or_default();
                    let destination_settled = authorization
                        .directions
                        .get(&RelayDirection::ReceiverToSender)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(recovery) = &recovery_session {
                        if recovery.source_sequence < source_settled.settled_sequence
                            || recovery.destination_sequence < destination_settled.settled_sequence
                        {
                            return Err(Error::msg(
                                "in-memory Relay recovery state is older than chain settlement",
                            ));
                        }
                        (
                            recovery.source_direction.clone(),
                            recovery.destination_direction.clone(),
                            recovery.source_sequence,
                            recovery.destination_sequence,
                            authorization.session_id.clone(),
                        )
                    } else {
                        (
                            direction_state(RelayDirection::SenderToReceiver),
                            direction_state(RelayDirection::ReceiverToSender),
                            source_settled.settled_sequence,
                            destination_settled.settled_sequence,
                            authorization.session_id.clone(),
                        )
                    }
                } else {
                    (
                        DirectionState::default(),
                        DirectionState::default(),
                        0,
                        0,
                        String::new(),
                    )
                };
                state.next_channel_id = state.next_channel_id.wrapping_add(1).max(1);
                while state.routes.contains_key(&state.next_channel_id) {
                    state.next_channel_id = state.next_channel_id.wrapping_add(1).max(1);
                }
                let channel_id = state.next_channel_id;
                if !recovery && let (Some(paths), Some(view)) = (&self.paths, &authorization) {
                    let authorization = &view.authorization;
                    paths.store_active_relay_session(&ActiveRelaySession {
                        authorization_id: authorization.authorization_id.clone(),
                        network_id: authorization.network_id.clone(),
                        network_commitment: authorization.network_commitment.clone(),
                        node_id: authorization.node_id,
                        sender_member_id: authorization.sender_member_id.clone(),
                        receiver_member_id: authorization.receiver_member_id.clone(),
                        opened_at: Utc::now().timestamp(),
                    })?;
                }
                state.routes.insert(
                    channel_id,
                    Route {
                        source: connection_id,
                        destination,
                        accepted: false,
                        source_sequence,
                        destination_sequence,
                        authorization,
                        source_direction,
                        destination_direction,
                        recovery,
                    },
                );
                let incoming = IncomingPayload {
                    peer_id: source_peer.member_id,
                    authorization_id: request.authorization_id,
                    session_id,
                    metadata: if recovery {
                        "mrk-recovery-v1".to_owned()
                    } else {
                        request.metadata
                    },
                };
                let destination_peer = state.peers.get(&destination).expect("online peer");
                let result = send_relay_frame(
                    &destination_peer.sender,
                    RelayFrame {
                        frame_type: FrameType::Incoming,
                        flags: 0,
                        channel_id,
                        sequence: 0,
                        payload: serde_json::to_vec(&incoming)?,
                    },
                );
                if result.is_err()
                    && let Some(route) = state.routes.remove(&channel_id)
                    && !route.recovery
                    && let (Some(paths), Some(view)) = (&self.paths, route.authorization)
                {
                    let _ = paths.remove_active_relay_session(&view.authorization.authorization_id);
                }
                result
            }
            FrameType::Accept | FrameType::Reject => {
                let mut checkpoint_requests = Vec::new();
                let source = {
                    let route = state
                        .routes
                        .get_mut(&frame.channel_id)
                        .ok_or_else(|| Error::msg("unknown relay channel"))?;
                    if route.destination != connection_id || route.accepted {
                        return Err(Error::msg(
                            "only the destination may answer a pending channel",
                        ));
                    }
                    let source = route.source;
                    if matches!(frame.frame_type, FrameType::Accept) {
                        route.accepted = true;
                        if route.recovery {
                            let view = route.authorization.as_ref().expect("paid recovery route");
                            if !route.source_direction.final_receipt_persisted {
                                checkpoint_requests.push((
                                    route.source,
                                    schedule_checkpoint_request(
                                        view,
                                        RelayDirection::SenderToReceiver,
                                        route.source_sequence,
                                        &mut route.source_direction,
                                        true,
                                        Utc::now().timestamp(),
                                    ),
                                ));
                            }
                            if !route.destination_direction.final_receipt_persisted {
                                checkpoint_requests.push((
                                    route.destination,
                                    schedule_checkpoint_request(
                                        view,
                                        RelayDirection::ReceiverToSender,
                                        route.destination_sequence,
                                        &mut route.destination_direction,
                                        true,
                                        Utc::now().timestamp(),
                                    ),
                                ));
                            }
                        }
                    }
                    source
                };
                if matches!(frame.frame_type, FrameType::Reject)
                    && let Some(route) = state.routes.remove(&frame.channel_id)
                    && !route.recovery
                    && let (Some(paths), Some(view)) = (&self.paths, route.authorization)
                {
                    paths.remove_active_relay_session(&view.authorization.authorization_id)?;
                }
                let source_sender = state
                    .peers
                    .get(&source)
                    .expect("route source")
                    .sender
                    .clone();
                let channel_id = frame.channel_id;
                send_relay_frame(&source_sender, frame)?;
                for (connection_id, request) in checkpoint_requests {
                    let sender = &state
                        .peers
                        .get(&connection_id)
                        .ok_or_else(|| Error::msg("recovery participant disconnected"))?
                        .sender;
                    send_relay_frame(
                        sender,
                        RelayFrame {
                            frame_type: FrameType::CheckpointRequest,
                            flags: RELAY_CHECKPOINT_FINAL_FLAG,
                            channel_id,
                            sequence: request.sequence,
                            payload: serde_json::to_vec(&request)?,
                        },
                    )?;
                }
                Ok(())
            }
            FrameType::Data => {
                let route = state
                    .routes
                    .get_mut(&frame.channel_id)
                    .ok_or_else(|| Error::msg("unknown relay channel"))?;
                if !route.accepted {
                    return Err(Error::msg("relay channel has not been accepted"));
                }
                let is_source = if route.source == connection_id {
                    true
                } else if route.destination == connection_id {
                    false
                } else {
                    return Err(Error::msg("connection does not own relay channel"));
                };
                let current_direction = if is_source {
                    &route.source_direction
                } else {
                    &route.destination_direction
                };
                let current_sequence = if is_source {
                    route.source_sequence
                } else {
                    route.destination_sequence
                };
                if route.recovery {
                    return Err(Error::msg(
                        "recovery channel permits checkpoint and receipt frames only",
                    ));
                }
                if current_direction.awaiting_receipt
                    || current_direction.checkpoint_request.is_some()
                {
                    return Err(Error::msg(
                        "relay direction is paused for a Node-requested checkpoint",
                    ));
                }
                if frame.sequence != current_sequence.saturating_add(1) {
                    return Err(Error::msg("relay DATA sequence is not strictly increasing"));
                }
                if let Some(view) = &route.authorization {
                    let now = Utc::now().timestamp();
                    if now
                        >= if route.recovery {
                            view.authorization.claim_until
                        } else {
                            view.authorization.valid_until
                        }
                    {
                        return Err(Error::msg("payment authorization has expired"));
                    }
                    let next_window_bytes = current_direction
                        .cumulative_bytes
                        .saturating_sub(current_direction.window_started_bytes)
                        .checked_add(frame.payload.len() as u64)
                        .ok_or_else(|| Error::msg("Relay payment window overflow"))?;
                    if next_window_bytes > RELAY_PAYMENT_WINDOW_BYTES {
                        return Err(Error::msg(
                            "Relay DATA frame crosses the payment window boundary",
                        ));
                    }
                    let source_bytes = route
                        .source_direction
                        .cumulative_bytes
                        .checked_add(if is_source {
                            frame.payload.len() as u64
                        } else {
                            0
                        })
                        .ok_or_else(|| Error::msg("Relay byte counter overflow"))?;
                    let destination_bytes = route
                        .destination_direction
                        .cumulative_bytes
                        .checked_add(if is_source {
                            0
                        } else {
                            frame.payload.len() as u64
                        })
                        .ok_or_else(|| Error::msg("Relay byte counter overflow"))?;
                    let source_already_paid = view
                        .authorization
                        .directions
                        .get(&RelayDirection::SenderToReceiver)
                        .map_or(0, |item| item.settled_amount);
                    let destination_already_paid = view
                        .authorization
                        .directions
                        .get(&RelayDirection::ReceiverToSender)
                        .map_or(0, |item| item.settled_amount);
                    let required = relay_price(source_bytes, view.authorization.price_per_gib)?
                        .saturating_sub(source_already_paid)
                        .checked_add(
                            relay_price(destination_bytes, view.authorization.price_per_gib)?
                                .saturating_sub(destination_already_paid),
                        )
                        .ok_or_else(|| Error::msg("Relay payment amount overflow"))?;
                    if required > view.authorization.reserved_remaining {
                        return Err(Error::msg(
                            "payment authorization has insufficient remaining MRK",
                        ));
                    }
                }
                let authorization = route.authorization.clone();
                let (destination, sequence, direction, expected_direction) = if is_source {
                    (
                        route.destination,
                        &mut route.source_sequence,
                        &mut route.source_direction,
                        RelayDirection::SenderToReceiver,
                    )
                } else {
                    (
                        route.source,
                        &mut route.destination_sequence,
                        &mut route.destination_direction,
                        RelayDirection::ReceiverToSender,
                    )
                };
                *sequence = frame.sequence;
                let mut checkpoint_request = None;
                if let Some(view) = &authorization {
                    let now = Utc::now().timestamp();
                    direction.window_started_at.get_or_insert(now);
                    direction.cumulative_bytes = direction
                        .cumulative_bytes
                        .checked_add(frame.payload.len() as u64)
                        .ok_or_else(|| Error::msg("relay byte counter overflow"))?;
                    direction.transcript_hash = relay_transcript_next_hash(
                        &direction.transcript_hash,
                        frame.sequence,
                        &frame.payload,
                    );
                    if !route.recovery
                        && direction
                            .cumulative_bytes
                            .saturating_sub(direction.window_started_bytes)
                            >= RELAY_PAYMENT_WINDOW_BYTES
                    {
                        checkpoint_request = Some(schedule_checkpoint_request(
                            view,
                            expected_direction,
                            frame.sequence,
                            direction,
                            false,
                            now,
                        ));
                    }
                }
                let destination = state.peers.get(&destination).expect("route destination");
                send_relay_frame(&destination.sender, frame.clone())?;
                if let Some(request) = checkpoint_request {
                    send_relay_frame(
                        &source_peer.sender,
                        RelayFrame {
                            frame_type: FrameType::CheckpointRequest,
                            flags: 0,
                            channel_id: frame.channel_id,
                            sequence: request.sequence,
                            payload: serde_json::to_vec(&request)?,
                        },
                    )?;
                }
                Ok(())
            }
            FrameType::CloseIntent => {
                let route = state
                    .routes
                    .get_mut(&frame.channel_id)
                    .ok_or_else(|| Error::msg("unknown relay channel"))?;
                let view = route
                    .authorization
                    .as_ref()
                    .ok_or_else(|| Error::msg("relay channel has no payment authorization"))?;
                let intent: CloseIntent = serde_json::from_slice(&frame.payload)?;
                let (direction, expected_direction, expected_sequence, expected_sender) =
                    if route.source == connection_id {
                        (
                            &mut route.source_direction,
                            RelayDirection::SenderToReceiver,
                            route.source_sequence,
                            view.authorization.sender_member_id.as_str(),
                        )
                    } else if route.destination == connection_id {
                        (
                            &mut route.destination_direction,
                            RelayDirection::ReceiverToSender,
                            route.destination_sequence,
                            view.authorization.receiver_member_id.as_str(),
                        )
                    } else {
                        return Err(Error::msg("connection does not own relay channel"));
                    };
                let now = Utc::now().timestamp();
                if direction.awaiting_receipt
                    || intent.authorization_id != view.authorization.authorization_id
                    || intent.session_id != view.authorization.session_id
                    || intent.direction != expected_direction
                    || intent.sequence != expected_sequence
                    || intent.cumulative_sent_bytes != direction.cumulative_bytes
                    || intent.transcript_hash != direction.transcript_hash
                    || intent.requested_at > now.saturating_add(30)
                    || expected_sender != source_peer.member_id
                {
                    return Err(Error::msg("invalid Relay CloseIntent"));
                }
                let request = if let Some(request) = &direction.checkpoint_request {
                    if !request.final_checkpoint {
                        return Err(Error::msg(
                            "periodic checkpoint must finish before closing Relay direction",
                        ));
                    }
                    request.clone()
                } else {
                    schedule_checkpoint_request(
                        view,
                        expected_direction,
                        expected_sequence,
                        direction,
                        true,
                        now,
                    )
                };
                send_relay_frame(
                    &source_peer.sender,
                    RelayFrame {
                        frame_type: FrameType::CheckpointRequest,
                        flags: RELAY_CHECKPOINT_FINAL_FLAG,
                        channel_id: frame.channel_id,
                        sequence: request.sequence,
                        payload: serde_json::to_vec(&request)?,
                    },
                )
            }
            FrameType::SenderCheckpoint => {
                let route = state
                    .routes
                    .get_mut(&frame.channel_id)
                    .ok_or_else(|| Error::msg("unknown relay channel"))?;
                let view = route
                    .authorization
                    .as_ref()
                    .ok_or_else(|| Error::msg("relay channel has no payment authorization"))?;
                let checkpoint: SenderCheckpoint = serde_json::from_slice(&frame.payload)?;
                let (destination, direction, expected_direction, expected_sender, public_key) =
                    if route.source == connection_id {
                        (
                            route.destination,
                            &mut route.source_direction,
                            RelayDirection::SenderToReceiver,
                            view.authorization.sender_member_id.as_str(),
                            view.sender_public_key.as_str(),
                        )
                    } else if route.destination == connection_id {
                        (
                            route.source,
                            &mut route.destination_direction,
                            RelayDirection::ReceiverToSender,
                            view.authorization.receiver_member_id.as_str(),
                            view.receiver_public_key.as_str(),
                        )
                    } else {
                        return Err(Error::msg("connection does not own relay channel"));
                    };
                let now = Utc::now().timestamp();
                let request = direction.checkpoint_request.as_ref().ok_or_else(|| {
                    Error::msg("Relay SenderCheckpoint was not requested by the Node")
                })?;
                if direction.awaiting_receipt
                    || checkpoint.ledger_id != view.ledger_id
                    || checkpoint.protocol_version != mrk::model::PROTOCOL_VERSION
                    || checkpoint.direction != expected_direction
                    || checkpoint.sender_member_id != expected_sender
                    || checkpoint.authorization_id != view.authorization.authorization_id
                    || checkpoint.session_id != view.authorization.session_id
                    || checkpoint.node_id != view.authorization.node_id
                    || checkpoint.sequence
                        != if expected_direction == RelayDirection::SenderToReceiver {
                            route.source_sequence
                        } else {
                            route.destination_sequence
                        }
                    || checkpoint.cumulative_sent_bytes != direction.cumulative_bytes
                    || checkpoint.transcript_hash != direction.transcript_hash
                    || checkpoint.sequence != request.sequence
                    || checkpoint.cumulative_sent_bytes != request.cumulative_sent_bytes
                    || checkpoint.transcript_hash != request.transcript_hash
                    || checkpoint.final_checkpoint != request.final_checkpoint
                    || checkpoint.checkpoint_at < request.requested_at
                    || checkpoint.checkpoint_at < view.authorization.created_at
                    || checkpoint.checkpoint_at
                        > if route.recovery {
                            view.authorization.claim_until
                        } else {
                            view.authorization.valid_until
                        }
                    || checkpoint.checkpoint_at > now.saturating_add(30)
                    || checkpoint.final_checkpoint
                        != (frame.flags & RELAY_CHECKPOINT_FINAL_FLAG != 0)
                {
                    return Err(Error::msg("invalid Node-requested Relay SenderCheckpoint"));
                }
                verify_bytes(
                    public_key,
                    &sender_checkpoint_signing_bytes(&checkpoint)?,
                    &checkpoint.sender_signature,
                )?;
                direction.awaiting_receipt = true;
                direction.pending_checkpoint = Some(checkpoint);
                let destination = state.peers.get(&destination).expect("route destination");
                send_relay_frame(&destination.sender, frame)
            }
            FrameType::ReceiverReceipt => {
                let route = state
                    .routes
                    .get_mut(&frame.channel_id)
                    .ok_or_else(|| Error::msg("unknown relay channel"))?;
                let view = route
                    .authorization
                    .as_ref()
                    .ok_or_else(|| Error::msg("relay channel has no payment authorization"))?;
                let receipt: ReceiverReceipt = serde_json::from_slice(&frame.payload)?;
                let (destination, direction, expected_receiver, public_key) = if route.destination
                    == connection_id
                    && receipt.direction == RelayDirection::SenderToReceiver
                {
                    (
                        route.source,
                        &mut route.source_direction,
                        view.authorization.receiver_member_id.as_str(),
                        view.receiver_public_key.as_str(),
                    )
                } else if route.source == connection_id
                    && receipt.direction == RelayDirection::ReceiverToSender
                {
                    (
                        route.destination,
                        &mut route.destination_direction,
                        view.authorization.sender_member_id.as_str(),
                        view.sender_public_key.as_str(),
                    )
                } else {
                    return Err(Error::msg("ReceiverReceipt came from the wrong member"));
                };
                let checkpoint = direction
                    .pending_checkpoint
                    .as_ref()
                    .ok_or_else(|| Error::msg("ReceiverReceipt has no pending checkpoint"))?;
                if receipt.receiver_member_id != expected_receiver
                    || receipt.ledger_id != view.ledger_id
                    || receipt.protocol_version != mrk::model::PROTOCOL_VERSION
                    || receipt.authorization_id != checkpoint.authorization_id
                    || receipt.session_id != checkpoint.session_id
                    || receipt.node_id != checkpoint.node_id
                    || receipt.sequence != checkpoint.sequence
                    || receipt.cumulative_received_bytes != checkpoint.cumulative_sent_bytes
                    || receipt.transcript_hash != checkpoint.transcript_hash
                    || receipt.sender_checkpoint_hash != sender_checkpoint_hash(checkpoint)?
                    || receipt.received_at < checkpoint.checkpoint_at
                    || receipt.received_at.saturating_sub(checkpoint.checkpoint_at) > 30
                    || receipt.received_at
                        > if route.recovery {
                            view.authorization.claim_until
                        } else {
                            view.authorization.valid_until
                        }
                {
                    return Err(Error::msg("invalid Relay ReceiverReceipt"));
                }
                verify_bytes(
                    public_key,
                    &receiver_receipt_signing_bytes(&receipt)?,
                    &receipt.receiver_signature,
                )?;
                if let Some(paths) = &self.paths {
                    paths.store_pending_traffic_settlement(&PendingTrafficSettlement {
                        sender_checkpoint: checkpoint.clone(),
                        receiver_receipt: receipt,
                        submission_operation_id: None,
                    })?;
                    if let Some(wakeup) = &self.settlement_wakeup {
                        let _ = wakeup.try_send(());
                    }
                }
                direction.final_receipt_persisted = checkpoint.final_checkpoint;
                direction.window_started_at = None;
                direction.window_started_bytes = direction.cumulative_bytes;
                direction.checkpoint_due = false;
                direction.awaiting_receipt = false;
                direction.pending_checkpoint = None;
                direction.checkpoint_request = None;
                let fully_final = route.source_direction.final_receipt_persisted
                    && route.destination_direction.final_receipt_persisted;
                let authorization_id = view.authorization.authorization_id.clone();
                if fully_final && let Some(paths) = &self.paths {
                    paths.remove_unsettled_relay_session(&authorization_id)?;
                }
                let destination_sender = state
                    .peers
                    .get(&destination)
                    .expect("route destination")
                    .sender
                    .clone();
                if fully_final {
                    state.interrupted_routes.remove(&authorization_id);
                }
                send_relay_frame(&destination_sender, frame)
            }
            FrameType::Close => {
                let route = state
                    .routes
                    .remove(&frame.channel_id)
                    .ok_or_else(|| Error::msg("unknown relay channel"))?;
                let destination = if route.source == connection_id {
                    route.destination
                } else if route.destination == connection_id {
                    route.source
                } else {
                    return Err(Error::msg("connection does not own relay channel"));
                };
                if route.source_direction.final_receipt_persisted
                    && route.destination_direction.final_receipt_persisted
                    && let (Some(paths), Some(view)) = (&self.paths, &route.authorization)
                {
                    paths.remove_unsettled_relay_session(&view.authorization.authorization_id)?;
                    paths.remove_active_relay_session(&view.authorization.authorization_id)?;
                    state
                        .interrupted_routes
                        .remove(&view.authorization.authorization_id);
                }
                let destination = state.peers.get(&destination).expect("route destination");
                send_relay_frame(&destination.sender, frame)
            }
            FrameType::Ping => send_relay_frame(
                &source_peer.sender,
                RelayFrame {
                    frame_type: FrameType::Pong,
                    ..frame
                },
            ),
            FrameType::Pong => Ok(()),
            _ => Err(Error::msg(
                "relay frame type is invalid after authentication",
            )),
        }
    }
}

fn schedule_checkpoint_request(
    view: &service::RelayAuthorizationView,
    direction: RelayDirection,
    sequence: u64,
    state: &mut DirectionState,
    final_checkpoint: bool,
    requested_at: i64,
) -> CheckpointRequest {
    let request = CheckpointRequest {
        authorization_id: view.authorization.authorization_id.clone(),
        session_id: view.authorization.session_id.clone(),
        direction,
        sequence,
        cumulative_sent_bytes: state.cumulative_bytes,
        transcript_hash: state.transcript_hash.clone(),
        requested_at,
        final_checkpoint,
    };
    state.checkpoint_due = true;
    state.checkpoint_request = Some(request.clone());
    request
}

fn active_unsettled_relay_sessions(
    paths: &DataPaths,
    node_id: u64,
) -> Result<Vec<UnsettledRelaySession>> {
    let ledger = paths.read_ledger()?;
    let mut active = Vec::new();
    for session in paths.unsettled_relay_sessions()? {
        let is_active = ledger
            .payment_authorizations
            .get(&session.authorization_id)
            .is_some_and(|authorization| {
                authorization.node_id == node_id
                    && authorization.refunded_at.is_none()
                    && authorization.closed_at.is_none()
                    && authorization.reserved_remaining > 0
            });
        if is_active {
            active.push(session);
        } else {
            paths.remove_unsettled_relay_session(&session.authorization_id)?;
        }
    }
    Ok(active)
}

fn record_auto_abandon_budget(
    paths: &DataPaths,
    authorization: &mrk::model::PaymentAuthorizationRecord,
    abandoned_bytes: u64,
    limit: u64,
    now: i64,
) -> bool {
    match paths.try_record_relay_auto_abandon(
        &authorization.network_commitment,
        &[
            authorization.sender_member_id.as_str(),
            authorization.receiver_member_id.as_str(),
        ],
        abandoned_bytes,
        limit,
        &authorization.authorization_id,
        now,
    ) {
        Ok(recorded) => recorded,
        Err(error) => {
            eprintln!(
                "could not record Relay auto-abandon budget for {}: {error}",
                authorization.authorization_id
            );
            false
        }
    }
}

fn auto_abandon_lost_relay_sessions(
    paths: &DataPaths,
    node_name: &str,
    password: &str,
    node_id: u64,
    now: i64,
    excluded_authorizations: &HashSet<String>,
) {
    let config = match paths.read_node_config(node_name) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("could not read Relay auto-abandon policy: {error}");
            return;
        }
    };
    let ledger = match paths.read_ledger() {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("could not read Relay authorizations for recovery: {error}");
            return;
        }
    };
    let holds = match active_unsettled_relay_sessions(paths, node_id) {
        Ok(holds) => holds,
        Err(error) => {
            eprintln!("could not read interrupted Relay sessions: {error}");
            return;
        }
    };
    let pending_authorizations = match paths.pending_traffic_settlements() {
        Ok(pending) => pending
            .into_iter()
            .map(|pending| pending.sender_checkpoint.authorization_id)
            .collect::<HashSet<_>>(),
        Err(error) => {
            eprintln!("could not read pending Relay receipts: {error}");
            return;
        }
    };
    for hold in holds {
        if excluded_authorizations.contains(&hold.authorization_id)
            || pending_authorizations.contains(&hold.authorization_id)
        {
            continue;
        }
        let Some(authorization) = ledger.payment_authorizations.get(&hold.authorization_id) else {
            continue;
        };
        let limit = config
            .relay_auto_abandon
            .max_bytes_for(&authorization.network_commitment);
        if limit < RELAY_UNKNOWN_TAIL_MAX_BYTES
            || !record_auto_abandon_budget(
                paths,
                authorization,
                RELAY_UNKNOWN_TAIL_MAX_BYTES,
                limit,
                now,
            )
        {
            continue;
        }
        match service::abandon_traffic_authorization_with_note(
            paths,
            node_name,
            password,
            &authorization.authorization_id,
            &format!(
                "node automatically abandoned an unknown Relay tail bounded by {RELAY_UNKNOWN_TAIL_MAX_BYTES} bytes after restart"
            ),
            now,
        ) {
            Ok(operation_id) => eprintln!(
                "Relay auto-abandoned unknown tail up to {RELAY_UNKNOWN_TAIL_MAX_BYTES} bytes for {} ({operation_id})",
                authorization.authorization_id
            ),
            Err(error) => eprintln!(
                "Relay auto-abandon failed for {}: {error}",
                authorization.authorization_id
            ),
        }
    }
}

fn relay_price(payload_bytes: u64, price_per_gib: u128) -> Result<u128> {
    if payload_bytes == 0 || price_per_gib == 0 {
        return Ok(0);
    }
    let gib = 1024_u128 * 1024 * 1024;
    u128::from(payload_bytes)
        .checked_mul(price_per_gib)
        .and_then(|value| value.checked_add(gib - 1))
        .map(|value| value / gib)
        .ok_or_else(|| Error::msg("Relay payment amount overflow"))
}

#[derive(Default)]
struct PublicConnectionCounts {
    total: usize,
    by_ip: HashMap<std::net::IpAddr, usize>,
}

#[derive(Default)]
struct PublicConnectionLimiter {
    counts: Mutex<PublicConnectionCounts>,
}

struct PublicConnectionGuard {
    limiter: Arc<PublicConnectionLimiter>,
    ip: std::net::IpAddr,
}

impl PublicConnectionLimiter {
    fn try_acquire(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<PublicConnectionGuard> {
        let mut counts = self.counts.lock().ok()?;
        let per_ip = counts.by_ip.get(&ip).copied().unwrap_or_default();
        let per_ip_limit = if ip.is_loopback() {
            MAX_PUBLIC_CONNECTIONS
        } else {
            MAX_PUBLIC_CONNECTIONS_PER_IP
        };
        if counts.total >= MAX_PUBLIC_CONNECTIONS || per_ip >= per_ip_limit {
            return None;
        }
        counts.total += 1;
        *counts.by_ip.entry(ip).or_default() += 1;
        Some(PublicConnectionGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for PublicConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.limiter.counts.lock() {
            counts.total = counts.total.saturating_sub(1);
            if let Some(value) = counts.by_ip.get_mut(&self.ip) {
                *value = value.saturating_sub(1);
                if *value == 0 {
                    counts.by_ip.remove(&self.ip);
                }
            }
        }
    }
}

fn send_relay_frame(sender: &SyncSender<WsMessage>, frame: RelayFrame) -> Result<()> {
    sender
        .try_send(WsMessage::Binary(frame.encode()?))
        .map_err(|_| Error::msg("relay outbound queue is full or disconnected"))
}

fn send_protocol_error(sender: &SyncSender<WsMessage>, code: &str, message: &str) -> Result<()> {
    send_relay_frame(
        sender,
        RelayFrame::control(
            FrameType::Error,
            serde_json::to_vec(&ErrorPayload {
                code: code.to_owned(),
                message: message.to_owned(),
            })?,
        ),
    )
}

pub(crate) fn run_node_command(
    paths: &DataPaths,
    node: String,
    output_json: bool,
    command: DaemonCommand,
) -> Result<()> {
    let output = if output_json {
        Output::Json
    } else {
        Output::Text
    };
    if !matches!(
        command,
        DaemonCommand::Init { .. }
            | DaemonCommand::Run { .. }
            | DaemonCommand::BackupVerify { .. }
            | DaemonCommand::Restore { .. }
    ) {
        return call_admin_socket(paths, node, output, command);
    }
    execute_daemon_command(paths, node, output, command)
}

fn execute_daemon_command(
    paths: &DataPaths,
    node_name: String,
    output: Output,
    command: DaemonCommand,
) -> Result<()> {
    let cli = ClientInvocation {
        node: node_name,
        output,
    };
    match command {
        DaemonCommand::Doctor => {
            let report = service::node_diagnostics(paths, &cli.node, Utc::now().timestamp())?;
            print_value(cli.output, &report, || diagnostic_text(&report))?;
            if !report.ok {
                return Err(Error::msg("doctor found one or more failed checks"));
            }
        }
        DaemonCommand::Init { lite } => {
            let directory = paths.node_dir(&cli.node)?;
            if directory.exists() {
                return Err(Error::msg(format!("node '{}' already exists", cli.node)));
            }
            let password = read_new_password()?;
            let storage_mode = if lite {
                NodeStorageMode::Lite
            } else {
                NodeStorageMode::Full
            };
            let config =
                service::init_node_with_storage_mode(paths, &cli.node, &password, storage_mode)?;
            print_value(cli.output, &config, || {
                format!(
                    "Node: {}\nStorage mode: {}\nOwner: {}\nRelay: {}\nReward: {} (use mrk account balance --account node:{})\nDirectory: {}",
                    config.name,
                    config.storage_mode,
                    config.owner_address,
                    config.relay_address,
                    config.reward_address,
                    config.name,
                    paths.node_dir(&config.name).unwrap().display()
                )
            })?;
        }
        DaemonCommand::Register {
            endpoint,
            price_per_gib,
        } => {
            let password = read_password("Node Owner password: ")?;
            let node = service::register_node(
                paths,
                &cli.node,
                &password,
                &endpoint,
                &price_per_gib,
                Utc::now().timestamp(),
            )?;
            print_value(cli.output, &node, || {
                format!(
                    "Node ID: {}\nStatus: {}\nEndpoint: {}\nIP slot: {}",
                    node.node_id, node.status, node.endpoint, node.ip_slot
                )
            })?;
        }
        DaemonCommand::UpdateRewardIp { endpoint } => {
            let password = read_password("Node Owner password: ")?;
            let (operation_id, node) = service::update_reward_ip(
                paths,
                &cli.node,
                &password,
                &endpoint,
                Utc::now().timestamp(),
            )?;
            print_value(
                cli.output,
                &serde_json::json!({
                    "operation_id": operation_id,
                    "status": "PENDING",
                    "node": node,
                }),
                || {
                    format!(
                        "SUBMITTED\nOperation: {operation_id}\nStatus: {}\nEndpoint: {}\nIP slot: {}",
                        node.status, node.endpoint, node.ip_slot
                    )
                },
            )?;
        }
        DaemonCommand::Bootstrap {
            peer,
            checkpoint_height,
            checkpoint_root,
            allow_insecure_local,
            tls_ca,
        } => {
            let value = relay_client::run_rpc_call(
                &peer,
                "chain.bootstrap",
                serde_json::json!({ "height": checkpoint_height }),
                allow_insecure_local,
                tls_ca.as_deref(),
            )?;
            let snapshot: service::BootstrapSnapshot = serde_json::from_value(value)?;
            let report = service::install_bootstrap_snapshot(
                paths,
                service::BootstrapInstallRequest {
                    name: &cli.node,
                    peer: &peer,
                    expected_height: checkpoint_height,
                    expected_state_root: &checkpoint_root,
                    allow_insecure_local,
                    tls_ca: tls_ca.as_deref(),
                },
                snapshot,
            )?;
            print_value(cli.output, &report, || {
                format!(
                    "BOOTSTRAPPED\nLedger: {}\nHeight: {}\nState root: {}\nPeer: {}",
                    report.ledger_id, report.height, report.state_root, report.peer
                )
            })?;
        }
        DaemonCommand::Backup { output } => {
            let report = service::backup_ledger(paths, output.as_deref(), Utc::now().timestamp())?;
            print_value(cli.output, &report, || {
                format!(
                    "BACKUP_OK\nPath: {}\nHeight: {}\nState root: {}\nChecksum: {}\nBytes: {}",
                    report.path, report.height, report.state_root, report.checksum, report.bytes
                )
            })?;
        }
        DaemonCommand::BackupVerify {
            path,
            expected_state_root,
        } => {
            let report = service::verify_ledger_backup(&path, expected_state_root.as_deref())?;
            print_value(cli.output, &report, || {
                format!(
                    "BACKUP_VERIFIED\nPath: {}\nHeight: {}\nState root: {}\nChecksum: {}\nBytes: {}",
                    report.path, report.height, report.state_root, report.checksum, report.bytes
                )
            })?;
        }
        DaemonCommand::Restore {
            path,
            expected_state_root,
        } => {
            if UnixStream::connect(paths.daemon_socket_path()).is_ok() {
                return Err(Error::msg(
                    "refusing restore while mrk node run is active; stop the daemon first",
                ));
            }
            let report =
                service::restore_ledger_backup(paths, &cli.node, &path, &expected_state_root)?;
            print_value(cli.output, &report, || {
                format!(
                    "RESTORE_OK\nPath: {}\nHeight: {}\nState root: {}\nChecksum: {}\nBytes: {}",
                    report.path, report.height, report.state_root, report.checksum, report.bytes
                )
            })?;
        }
        DaemonCommand::Run {
            listen,
            allow_insecure_local,
        } => {
            let password = read_password("Node keystore password: ")?;
            run_node_server(paths, &cli.node, &password, listen, allow_insecure_local)?;
        }
        DaemonCommand::Status => {
            let node = service::node_record(paths, &cli.node)?;
            let storage_mode = paths.read_node_config(&cli.node)?.storage_mode;
            let ledger = paths.read_ledger()?;
            let availability_mode = ledger.availability_mode;
            let availability_earning_enabled = availability_mode == AvailabilityMode::Node1Trusted
                || ledger.consensus.active_validators.len()
                    >= service::MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS;
            let status = LocalNodeStatus {
                node,
                storage_mode,
                availability_mode,
                availability_earning_enabled,
            };
            print_value(cli.output, &status, || {
                format!(
                    "Node ID: {}\nStatus: {}\nStorage mode: {}\nAvailability mode: {}\nAvailability earning: {}\nEndpoint: {}\nIP slot: {}\nWarmup until: {}\nWarmup remaining: {}s\nLast heartbeat: {}\nLast Probe: {}\nProbe count: {}",
                    status.node.node_id,
                    status.node.status,
                    status.storage_mode,
                    status.availability_mode,
                    status.availability_earning_enabled,
                    status.node.endpoint,
                    status.node.ip_slot,
                    status.node.warmup_until,
                    status
                        .node
                        .warmup_until
                        .saturating_sub(Utc::now().timestamp())
                        .max(0),
                    status
                        .node
                        .last_heartbeat
                        .map_or_else(|| "never".to_owned(), |value| value.to_string()),
                    status
                        .node
                        .last_probe_success
                        .map_or_else(|| "never".to_owned(), |value| value.to_string()),
                    status.node.probe_success_count
                )
            })?;
        }
        DaemonCommand::Rewards => {
            let rewards = service::node_rewards(paths, &cli.node)?;
            print_value(cli.output, &rewards, || {
                format!(
                    "Node ID: {}\nStatus: {}\nEpoch seconds: {}\nTotal seconds: {}\nService Bond: {}\nService Bond unlock at: {}\nOffline slashed at: {}\nSlashed Service Bond: {}\nSlashed vesting: {}\nClaimable: {}\nVesting: {}\nVesting schedules: {}",
                    rewards.node_id,
                    rewards.status,
                    rewards.epoch_eligible_seconds,
                    rewards.total_eligible_seconds,
                    rewards.service_bond_display,
                    rewards
                        .service_bond_unlock_at
                        .map_or_else(|| "not scheduled".to_owned(), |value| value.to_string()),
                    rewards
                        .offline_slashed_at
                        .map_or_else(|| "never".to_owned(), |value| value.to_string()),
                    rewards.offline_slashed_service_bond_display,
                    rewards.offline_slashed_vesting_reward_display,
                    rewards.claimable_reward_display,
                    rewards.vesting_reward_display,
                    rewards.vesting_schedule_count,
                )
            })?;
        }
        DaemonCommand::Probe {
            target_node_id,
            allow_insecure_local,
            watch,
            interval_seconds,
        } => {
            let password = read_password("Node Owner password: ")?;
            loop {
                match relay_client::run_node_probe(
                    paths.clone(),
                    cli.node.clone(),
                    password.clone(),
                    target_node_id,
                    allow_insecure_local,
                ) {
                    Ok(submission) => print_value(cli.output, &submission, || {
                        format!(
                            "PROBE_ATTESTED\nOperation: {}\nTarget Node: {}\nVerifier Node: {}\nSlot: {}\nRole: {}\nPrimary: {}/{}\nAudit required: {}\nAudit: {}/{}\nCredited seconds: {}",
                            submission.operation_id,
                            submission.target_node_id,
                            submission.verifier_node_id,
                            submission.slot,
                            submission.role,
                            submission.primary_attestation_count,
                            submission.primary_quorum,
                            submission.audit_required,
                            submission.audit_attestation_count,
                            submission.audit_quorum,
                            submission.credited_seconds,
                        )
                    })?,
                    Err(error) if watch => eprintln!("Probe failed: {error}"),
                    Err(error) => return Err(error),
                }
                if !watch {
                    break;
                }
                thread::sleep(Duration::from_secs(interval_seconds));
            }
        }
        DaemonCommand::Claim => {
            let password = read_password("Node Owner password: ")?;
            let (operation_id, amount) =
                service::claim_node_rewards(paths, &cli.node, &password, Utc::now().timestamp())?;
            print_value(
                cli.output,
                &serde_json::json!({
                    "operation_id": operation_id,
                    "amount_base_units": amount.to_string(),
                    "status": "PENDING",
                }),
                || {
                    format!(
                        "SUBMITTED\nOperation: {operation_id}\nClaimed: {}",
                        format_mrk(amount)
                    )
                },
            )?;
        }
        DaemonCommand::WithdrawServiceBond => {
            let password = read_password("Node Owner password: ")?;
            let (operation_id, amount) = service::withdraw_service_bond(
                paths,
                &cli.node,
                &password,
                Utc::now().timestamp(),
            )?;
            print_value(
                cli.output,
                &serde_json::json!({
                    "operation_id": operation_id,
                    "amount_base_units": amount.to_string(),
                    "status": "PENDING",
                }),
                || {
                    format!(
                        "SUBMITTED\nOperation: {operation_id}\nWithdrawn Service Bond: {}",
                        format_mrk(amount)
                    )
                },
            )?;
        }
        DaemonCommand::Drain => {
            let password = read_password("Node Owner password: ")?;
            let operation_id =
                service::drain_node(paths, &cli.node, &password, Utc::now().timestamp())?;
            print_value(
                cli.output,
                &serde_json::json!({
                    "operation_id": operation_id,
                    "status": "DRAINING",
                }),
                || format!("DRAINING\nOperation: {operation_id}"),
            )?;
        }
        DaemonCommand::Block { command } => execute_client_command(
            paths,
            cli.node,
            matches!(cli.output, Output::Json),
            ClientCommand::Block { command },
        )?,
        DaemonCommand::Validator { command } => execute_client_command(
            paths,
            cli.node,
            matches!(cli.output, Output::Json),
            ClientCommand::Validator { command },
        )?,
        DaemonCommand::Consensus { command } => execute_client_command(
            paths,
            cli.node,
            matches!(cli.output, Output::Json),
            ClientCommand::Consensus { command },
        )?,
        DaemonCommand::Governance { command } => execute_client_command(
            paths,
            cli.node,
            matches!(cli.output, Output::Json),
            ClientCommand::Governance { command },
        )?,
        DaemonCommand::Payment { command } => match command {
            NodePaymentCommand::Unsettled => {
                let node = service::node_record(paths, &cli.node)?;
                let unsettled = service::unsettled_payments(paths, None, None, Some(node.node_id))?;
                print_value(cli.output, &unsettled, || {
                    if unsettled.is_empty() {
                        return "No unsettled Relay sessions.".to_owned();
                    }
                    unsettled
                        .iter()
                        .map(|item| {
                            format!(
                                "{}  network={}  sender={}  receiver={}  disconnected_at={}",
                                item.session.authorization_id,
                                item.session.network_commitment,
                                item.session.sender_member_id,
                                item.session.receiver_member_id,
                                item.session.disconnected_at,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })?;
            }
            NodePaymentCommand::Abandon { authorization_id } => {
                let password = read_password("Node Owner password: ")?;
                let operation_id = service::abandon_traffic_authorization(
                    paths,
                    &cli.node,
                    &password,
                    &authorization_id,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "operation_id": operation_id,
                        "authorization_id": authorization_id,
                        "status": "FINALIZED",
                    }),
                    || {
                        format!(
                            "ABANDONED\nAuthorization: {authorization_id}\nRefund operation: {operation_id}"
                        )
                    },
                )?;
            }
            NodePaymentCommand::Policy { command } => match command {
                NodePaymentPolicyCommand::Show { network } => {
                    let config = paths.read_node_config(&cli.node)?;
                    let commitment = network
                        .as_deref()
                        .map(|network| service::network_by_alias(paths, network))
                        .transpose()?
                        .map(|network| network.commitment);
                    let effective = commitment
                        .as_deref()
                        .map(|commitment| config.relay_auto_abandon.max_bytes_for(commitment));
                    let value = serde_json::json!({
                        "default_max_auto_abandon_bytes": config.relay_auto_abandon.default_max_bytes,
                        "network": network,
                        "network_commitment": commitment,
                        "effective_max_auto_abandon_bytes": effective,
                        "network_overrides": config.relay_auto_abandon.network_max_bytes,
                    });
                    print_value(cli.output, &value, || {
                        if let (Some(network), Some(effective)) =
                            (value["network"].as_str(), effective)
                        {
                            format!("Network: {network}\nMax auto-abandon bytes: {effective}")
                        } else {
                            format!(
                                "Default max auto-abandon bytes: {}\nNetwork overrides: {}",
                                config.relay_auto_abandon.default_max_bytes,
                                config.relay_auto_abandon.network_max_bytes.len(),
                            )
                        }
                    })?;
                }
                NodePaymentPolicyCommand::Set {
                    network,
                    max_auto_abandon_bytes,
                } => {
                    let mut config = paths.read_node_config(&cli.node)?;
                    let commitment = network
                        .as_deref()
                        .map(|network| service::network_by_alias(paths, network))
                        .transpose()?
                        .map(|network| network.commitment);
                    if let Some(commitment) = &commitment {
                        config
                            .relay_auto_abandon
                            .network_max_bytes
                            .insert(commitment.clone(), max_auto_abandon_bytes);
                    } else {
                        config.relay_auto_abandon.default_max_bytes = max_auto_abandon_bytes;
                    }
                    paths.write_node_config(&config)?;
                    let value = serde_json::json!({
                        "network": network,
                        "network_commitment": commitment,
                        "max_auto_abandon_bytes": max_auto_abandon_bytes,
                    });
                    print_value(cli.output, &value, || {
                        format!("Max auto-abandon bytes: {max_auto_abandon_bytes}")
                    })?;
                }
                NodePaymentPolicyCommand::Clear { network } => {
                    let commitment = service::network_by_alias(paths, &network)?.commitment;
                    let mut config = paths.read_node_config(&cli.node)?;
                    config
                        .relay_auto_abandon
                        .network_max_bytes
                        .remove(&commitment);
                    let effective = config.relay_auto_abandon.default_max_bytes;
                    paths.write_node_config(&config)?;
                    let value = serde_json::json!({
                        "network": network,
                        "network_commitment": commitment,
                        "max_auto_abandon_bytes": effective,
                        "inherited": true,
                    });
                    print_value(cli.output, &value, || {
                        format!("Network override cleared; max auto-abandon bytes: {effective}")
                    })?;
                }
            },
        },
    }
    Ok(())
}

fn call_admin_socket(
    paths: &DataPaths,
    node: String,
    output: Output,
    command: DaemonCommand,
) -> Result<()> {
    let socket_path = paths.daemon_socket_path();
    let mut stream = UnixStream::connect(&socket_path).map_err(|error| {
        Error::msg(format!(
            "cannot connect to mrk node at {}: {error}; start it with 'mrk node --node {node} run'",
            socket_path.display()
        ))
    })?;
    let request = serde_json::to_vec(&AdminRequest {
        node,
        output,
        command,
    })?;
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response: AdminResponse = serde_json::from_slice(&response)?;
    std::io::stdout().write_all(&response.output)?;
    if response.ok {
        Ok(())
    } else {
        Err(Error::msg(
            response
                .error
                .unwrap_or_else(|| "mrk node request failed".to_owned()),
        ))
    }
}

struct ClientInvocation {
    node: String,
    output: Output,
}

pub(crate) fn execute_client_command(
    paths: &DataPaths,
    node: String,
    output_json: bool,
    command: ClientCommand,
) -> Result<()> {
    let cli = ClientInvocation {
        node,
        output: if output_json {
            Output::Json
        } else {
            Output::Text
        },
    };
    match command {
        ClientCommand::Block { command } => match command {
            BlockCommand::Status => {
                let status = service::block_status(paths, Utc::now().timestamp())?;
                print_value(cli.output, &status, || {
                    format!(
                        "Mode: {}\nHeight: {}\nLast block: {}\nPending operations: {}\nNode 1 production: {}\nGovernance-Eligible Nodes: {}/{}\nActive Validators: {}/{}\nAvailability mode: {}\nAvailability earning: {}",
                        status.mode,
                        status.height,
                        status.last_block_hash.as_deref().unwrap_or("none"),
                        status.pending_operation_count,
                        status.node1_production_enabled,
                        status.governance_eligible_count,
                        status.threshold,
                        status.active_validator_count,
                        status.minimum_active_validators,
                        status.availability_mode,
                        status.availability_earning_enabled,
                    )
                })?;
            }
            BlockCommand::Produce { allow_empty } => {
                let password = read_password("Genesis Node Owner password: ")?;
                let block = service::produce_node1_block(
                    paths,
                    &cli.node,
                    &password,
                    allow_empty,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &block, || {
                    format!(
                        "BLOCK_FINALIZED\nHeight: {}\nHash: {}\nPrevious: {}\nOperations: {}\nState root: {}",
                        block.height,
                        block.block_hash,
                        block.previous_block_hash,
                        block.operation_ids.len(),
                        block.state_root,
                    )
                })?;
            }
            BlockCommand::Show { height } => {
                let block = service::block_by_height(paths, height)?;
                print_value(cli.output, &block, || {
                    format!(
                        "Height: {}\nHash: {}\nPrevious: {}\nProducer: Node {}\nOperations: {}\nState root: {}",
                        block.height,
                        block.block_hash,
                        block.previous_block_hash,
                        block.producer_node_id,
                        block.operation_ids.len(),
                        block.state_root,
                    )
                })?;
            }
            BlockCommand::Verify => {
                let report = service::verify_blockchain(paths)?;
                print_value(cli.output, &report, || {
                    format!(
                        "Valid: {}\nHeight: {}\nChecked operations: {}\nLegacy unverified operations: {}\nDetail: {}",
                        report.ok,
                        report.height,
                        report.checked_operations,
                        report.legacy_unverified_operations,
                        report.detail,
                    )
                })?;
                if !report.ok {
                    return Err(Error::msg("blockchain verification failed"));
                }
            }
        },
        ClientCommand::Validator { command } => match command {
            ValidatorCommand::Status => {
                let status = service::validator_status(paths, &cli.node)?;
                print_value(cli.output, &status, || {
                    format!(
                        "Node ID: {}\nCandidate: {}\nActive Validator: {}\nValidator Bond: {} / {}\nCandidate since: {}\nLast epoch: {}\nConsecutive epochs: {}\nBond unlock: {}",
                        status.node_id,
                        status.candidate,
                        status.active_validator,
                        status.validator_bond_display,
                        status.required_bond_display,
                        status
                            .candidate_since
                            .map_or_else(|| "never".to_owned(), |value| value.to_string()),
                        status
                            .last_validator_epoch
                            .map_or_else(|| "never".to_owned(), |value| value.to_string()),
                        status.consecutive_epochs,
                        status
                            .bond_unlock_at
                            .map_or_else(|| "not requested".to_owned(), |value| value.to_string()),
                    )
                })?;
            }
            ValidatorCommand::Join => {
                let password = read_password("Node keystore password: ")?;
                let receipt = service::join_validator_pool(
                    paths,
                    &cli.node,
                    &password,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &receipt, || {
                    format!(
                        "SUBMITTED\nOperation: {}\nNode ID: {}\nBonded: {}\nTotal Validator Bond: {}",
                        receipt.operation_id,
                        receipt.node_id,
                        receipt.bonded_display,
                        receipt.total_validator_bond_display,
                    )
                })?;
            }
            ValidatorCommand::Committee => {
                let committee = service::validator_committee(paths, Utc::now().timestamp())?;
                print_value(cli.output, &committee, || {
                    format!(
                        "Epoch: {}\nValidator set: {}\nActive: {:?}\nCandidates: {:?}\nQuorum: {}\nNext height: {}\nRound: {}\nProposer: {}",
                        committee.epoch,
                        committee.validator_set_hash,
                        committee.active_validator_ids,
                        committee.candidate_node_ids,
                        committee.quorum,
                        committee.next_height,
                        committee.current_round,
                        committee
                            .proposer_node_id
                            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    )
                })?;
            }
            ValidatorCommand::Exit => {
                let password = read_password("Node Owner password: ")?;
                let operation_id = service::request_validator_exit(
                    paths,
                    &cli.node,
                    &password,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"operation_id": operation_id, "status": "PENDING"}),
                    || format!("SUBMITTED\nOperation: {operation_id}"),
                )?;
            }
            ValidatorCommand::WithdrawBond => {
                let password = read_password("Node Owner password: ")?;
                let (operation_id, amount) = service::withdraw_validator_bond(
                    paths,
                    &cli.node,
                    &password,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "operation_id": operation_id,
                        "status": "PENDING",
                        "amount_base_units": amount.to_string(),
                    }),
                    || {
                        format!(
                            "SUBMITTED\nOperation: {operation_id}\nWithdrawn: {}",
                            format_mrk(amount)
                        )
                    },
                )?;
            }
        },
        ClientCommand::Consensus { command } => match command {
            ConsensusCommand::Status => {
                let status = service::consensus_status(paths, Utc::now().timestamp())?;
                print_value(cli.output, &status, || {
                    format!(
                        "Mode: {}\nHeight: {}\nRound: {}\nProposer: {}\nProposal: {}\nPREVOTEs: {}/{}\nPRECOMMITs: {}/{}\nValidators: {:?}",
                        status.mode,
                        status.height,
                        status.round,
                        status
                            .proposer_node_id
                            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                        status.proposal_block_hash.as_deref().unwrap_or("none"),
                        status.prevote_count,
                        status.quorum,
                        status.precommit_count,
                        status.quorum,
                        status.active_validator_ids,
                    )
                })?;
            }
            ConsensusCommand::Propose => {
                let password = read_password("Validator Owner password: ")?;
                let block = service::propose_consensus_block(
                    paths,
                    &cli.node,
                    &password,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &block, || {
                    format!(
                        "PROPOSED\nHeight: {}\nRound: {}\nHash: {}\nOperations: {}",
                        block.height,
                        block.consensus_round,
                        block.block_hash,
                        block.operation_ids.len(),
                    )
                })?;
            }
            ConsensusCommand::Prevote { block_hash, nil } => {
                let target = consensus_vote_target(paths, block_hash, nil)?;
                let password = read_password("Validator Owner password: ")?;
                let (vote, _) = service::cast_consensus_vote(
                    paths,
                    &cli.node,
                    &password,
                    ConsensusVoteType::Prevote,
                    target,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &vote, || {
                    format!(
                        "PREVOTE\nHeight: {}\nRound: {}\nValue: {}",
                        vote.height,
                        vote.round,
                        vote.block_hash.as_deref().unwrap_or("NIL")
                    )
                })?;
            }
            ConsensusCommand::Precommit { block_hash, nil } => {
                let target = consensus_vote_target(paths, block_hash, nil)?;
                let password = read_password("Validator Owner password: ")?;
                let (vote, finalized) = service::cast_consensus_vote(
                    paths,
                    &cli.node,
                    &password,
                    ConsensusVoteType::Precommit,
                    target,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"vote": vote, "finalized_block": finalized}),
                    || {
                        if let Some(block) = finalized {
                            format!(
                                "PRECOMMIT\nFINALIZED block {} {}",
                                block.height, block.block_hash
                            )
                        } else {
                            format!(
                                "PRECOMMIT\nHeight: {}\nRound: {}\nValue: {}",
                                vote.height,
                                vote.round,
                                vote.block_hash.as_deref().unwrap_or("NIL")
                            )
                        }
                    },
                )?;
            }
            ConsensusCommand::NextRound => {
                let round = service::advance_consensus_round(paths, Utc::now().timestamp())?;
                print_value(cli.output, &serde_json::json!({"round": round}), || {
                    format!("Advanced to consensus round {round}")
                })?;
            }
            ConsensusCommand::SyncPeer {
                target_node_id,
                allow_insecure_local,
                tls_ca,
            } => {
                let password = read_password("Validator Owner password: ")?;
                let responses = relay_client::sync_consensus_peer(
                    paths.clone(),
                    cli.node,
                    password,
                    target_node_id,
                    allow_insecure_local,
                    tls_ca,
                )?;
                print_value(cli.output, &responses, || {
                    format!(
                        "Consensus peer Node {target_node_id} accepted {} synchronized messages",
                        responses.len()
                    )
                })?;
            }
        },
        ClientCommand::Treasury { command } => match command {
            TreasuryCommand::Status => {
                let status = service::treasury_status(paths, Utc::now().timestamp())?;
                print_value(cli.output, &status, || {
                    format!(
                        "Treasury: {}\nGenesis allocation: {}\nSpent: {} ({} transfers)\nGovernance-Eligible Nodes: {}\nMature treasury voters: {}\nActive Validators: {} (minimum {})\nSpending enabled: {}\nSingle-spend limit: {}\n90-day usage: {} / {}\n365-day usage: {} / {}",
                        status.balance_display,
                        status.genesis_allocation_display,
                        status.total_spent_display,
                        status.spend_count,
                        status.governance_eligible_count,
                        status.mature_governance_node_count,
                        status.active_validator_count,
                        status.minimum_active_validators,
                        status.spending_enabled,
                        status.current_single_spend_limit_display,
                        status.ninety_day_spent_display,
                        status.ninety_day_limit_display,
                        status.annual_spent_display,
                        status.annual_limit_display,
                    )
                })?;
            }
            TreasuryCommand::History { limit } => {
                let history = service::treasury_history(paths, limit as usize)?;
                print_value(cli.output, &history, || {
                    if history.is_empty() {
                        "No treasury spending history.".to_owned()
                    } else {
                        history
                            .iter()
                            .map(|spend| {
                                format!(
                                    "Proposal {}  {}  {}  {}",
                                    spend.proposal_id,
                                    format_mrk(spend.amount),
                                    spend.recipient,
                                    spend.operation_id,
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                })?;
            }
        },
        ClientCommand::Governance { command } => match command {
            GovernanceCommand::Status => {
                let status = service::governance_status(paths, Utc::now().timestamp())?;
                print_value(cli.output, &status, || {
                    format!(
                        "Mode: {}\nGenesis Node: {}\nGovernance-Eligible Nodes: {}/{}\nNode 1 direct actions: {}\nAvailability mode: {}\nAvailability activated epoch: {}\nCurrent Epoch duration: {}s\nNext Epoch duration: {}s\nCurrent Epoch mint: {}\nNext Epoch mint: {}\nCurrent immediate reward: {} bps\nNext immediate reward: {} bps\nCurrent reward vesting: {}s\nNext reward vesting: {}s\nEmission paused: {}{}",
                        status.mode,
                        status
                            .genesis_node_id
                            .map_or_else(|| "not registered".to_owned(), |id| id.to_string()),
                        status.governance_eligible_count,
                        status.threshold,
                        status.node1_direct_actions_enabled,
                        status.availability_mode,
                        status
                            .availability_activated_epoch
                            .map_or_else(|| "not activated".to_owned(), |epoch| epoch.to_string()),
                        status.current_epoch_seconds,
                        status.settings.epoch_seconds,
                        format_mrk(status.current_epoch_mint_amount),
                        format_mrk(status.settings.epoch_mint_amount),
                        status.current_reward_immediate_bps,
                        status.settings.reward_immediate_bps,
                        status.current_reward_vesting_seconds,
                        status.settings.reward_vesting_seconds,
                        status.emission_paused,
                        status
                            .pause_reason
                            .as_ref()
                            .map_or_else(String::new, |reason| format!(" ({reason})"))
                    )
                })?;
            }
            GovernanceCommand::List => {
                let proposals = service::governance_proposals(paths)?;
                print_value(cli.output, &proposals, || {
                    if proposals.is_empty() {
                        "No governance proposals.".to_owned()
                    } else {
                        proposals
                            .iter()
                            .map(|proposal| {
                                format!(
                                    "{}  {:?}  {:?}  {}",
                                    proposal.proposal_id,
                                    proposal.kind,
                                    proposal.status,
                                    proposal.title
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                })?;
            }
            GovernanceCommand::Proposal { proposal_id } => {
                let (proposal, tally) = service::governance_proposal(paths, proposal_id)?;
                print_value(
                    cli.output,
                    &serde_json::json!({"proposal": proposal, "tally": tally}),
                    || governance_proposal_text(&proposal, &tally),
                )?;
            }
            GovernanceCommand::ProposeSet {
                kind,
                title,
                parameter,
                value,
            } => {
                let password = read_password("Governance Node keystore password: ")?;
                let proposal = service::create_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    kind.into(),
                    &title,
                    mrk::model::GovernanceProposalAction::SetParameter { parameter, value },
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &proposal, || {
                    format!(
                        "PROPOSAL_CREATED\nID: {}\nVoting ends: {}\nExecute after: {}",
                        proposal.proposal_id, proposal.voting_ends_at, proposal.execute_after
                    )
                })?;
            }
            GovernanceCommand::ProposePause {
                kind,
                title,
                reason,
            } => {
                let password = read_password("Governance Node keystore password: ")?;
                let proposal = service::create_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    kind.into(),
                    &title,
                    mrk::model::GovernanceProposalAction::PauseEmission { reason },
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &proposal, || {
                    format!("PROPOSAL_CREATED\nID: {}", proposal.proposal_id)
                })?;
            }
            GovernanceCommand::ProposeResume { kind, title } => {
                let password = read_password("Governance Node keystore password: ")?;
                let proposal = service::create_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    kind.into(),
                    &title,
                    mrk::model::GovernanceProposalAction::ResumeEmission,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &proposal, || {
                    format!("PROPOSAL_CREATED\nID: {}", proposal.proposal_id)
                })?;
            }
            GovernanceCommand::ProposeTreasurySpend {
                title,
                to,
                amount,
                reference,
            } => {
                let amount = parse_mrk(&amount)?;
                let password = read_password("Governance Node keystore password: ")?;
                let proposal = service::create_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    mrk::model::GovernanceProposalKind::Critical,
                    &title,
                    mrk::model::GovernanceProposalAction::TreasurySpend {
                        recipient: to,
                        amount,
                        reference_hash: reference,
                    },
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &proposal, || {
                    format!(
                        "TREASURY_PROPOSAL_CREATED\nID: {}\nAmount: {}\nVoting ends: {}\nExecute after: {}",
                        proposal.proposal_id,
                        format_mrk(amount),
                        proposal.voting_ends_at,
                        proposal.execute_after,
                    )
                })?;
            }
            GovernanceCommand::Vote {
                proposal_id,
                choice,
            } => {
                let password = read_password("Governance Node Owner password: ")?;
                let (operation_id, tally) = service::vote_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    proposal_id,
                    choice.into(),
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"operation_id": operation_id, "status": "PENDING", "tally": tally}),
                    || {
                        format!(
                            "VOTE_SUBMITTED\nOperation: {operation_id}\nYES: {}  NO: {}  ABSTAIN: {}",
                            tally.yes_power, tally.no_power, tally.abstain_power
                        )
                    },
                )?;
            }
            GovernanceCommand::ValidatorVote {
                proposal_id,
                choice,
            } => {
                let password = read_password("Validator Node Owner password: ")?;
                let (operation_id, tally) = service::validator_vote_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    proposal_id,
                    choice.into(),
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"operation_id": operation_id, "status": "PENDING", "tally": tally}),
                    || {
                        format!(
                            "VALIDATOR_VOTE_SUBMITTED\nOperation: {operation_id}\nYES: {}/{} required",
                            tally.validator_yes, tally.validator_quorum
                        )
                    },
                )?;
            }
            GovernanceCommand::Veto { proposal_id } => {
                let password = read_password("Mature Governance Node Owner password: ")?;
                let (operation_id, tally) = service::veto_treasury_proposal(
                    paths,
                    &cli.node,
                    &password,
                    proposal_id,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"operation_id": operation_id, "status": "PENDING", "tally": tally}),
                    || {
                        format!(
                            "TREASURY_VETO_SUBMITTED\nOperation: {operation_id}\nVeto power: {}/{}\nProposal status: {:?}",
                            tally.timelock_veto_power, tally.total_power, tally.status
                        )
                    },
                )?;
            }
            GovernanceCommand::Finalize { proposal_id } => {
                let password = read_password("Governance Node Owner password: ")?;
                let (operation_id, tally) = service::finalize_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    proposal_id,
                    Utc::now().timestamp(),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"operation_id": operation_id, "status": "PENDING", "tally": tally}),
                    || {
                        format!(
                            "PROPOSAL_{:?}\nOperation: {operation_id}\nYES: {}  NO: {}  ABSTAIN: {}",
                            tally.status, tally.yes_power, tally.no_power, tally.abstain_power
                        )
                    },
                )?;
            }
            GovernanceCommand::Execute { proposal_id } => {
                let password = read_password("Governance Node Owner password: ")?;
                let receipt = service::execute_governance_proposal(
                    paths,
                    &cli.node,
                    &password,
                    proposal_id,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &receipt, || {
                    format!(
                        "EXECUTION_SUBMITTED\nOperation: {}\nProposal: {proposal_id}",
                        receipt.operation_id
                    )
                })?;
            }
            GovernanceCommand::Set { parameter, value } => {
                let password = read_password("Genesis Node Owner password: ")?;
                let receipt = service::governance_set_parameter(
                    paths,
                    &cli.node,
                    &password,
                    &parameter,
                    &value,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &receipt, || {
                    format!(
                        "SUBMITTED\nOperation: {}\nAction: {}\nParameter: {}\nNew value: {}",
                        receipt.operation_id,
                        receipt.action,
                        receipt.payload["parameter"].as_str().unwrap_or_default(),
                        receipt.payload["new_value"].as_str().unwrap_or_default()
                    )
                })?;
            }
            GovernanceCommand::PauseEmission { reason } => {
                let password = read_password("Genesis Node Owner password: ")?;
                let receipt = service::governance_pause_emission(
                    paths,
                    &cli.node,
                    &password,
                    &reason,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &receipt, || {
                    format!(
                        "SUBMITTED\nOperation: {}\nNode emission paused",
                        receipt.operation_id
                    )
                })?;
            }
            GovernanceCommand::ResumeEmission => {
                let password = read_password("Genesis Node Owner password: ")?;
                let receipt = service::governance_resume_emission(
                    paths,
                    &cli.node,
                    &password,
                    Utc::now().timestamp(),
                )?;
                print_value(cli.output, &receipt, || {
                    format!(
                        "SUBMITTED\nOperation: {}\nNode emission resumed",
                        receipt.operation_id
                    )
                })?;
            }
        },
    }
    Ok(())
}

fn run_node_server(
    paths: &DataPaths,
    name: &str,
    password: &str,
    listen: SocketAddr,
    allow_insecure_local: bool,
) -> Result<()> {
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    decrypt_key(&owner_file, password)?;
    service::ensure_runtime_compatibility(paths, name)?;
    if paths.read_ledger()?.finalized_checkpoint.is_some() {
        service::bootstrap_snapshot(paths)?;
    }
    let (admin_listener, _admin_guard) = bind_admin_socket(paths, name)?;
    let mut public_listener = None;
    let mut availability_worker_started = false;
    let mut public_sync_worker_started = false;
    let mut hub = None;
    let mut last_history_prune = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now);
    let public_connection_limiter = Arc::new(PublicConnectionLimiter::default());
    println!(
        "MRK node '{name}' admin socket: {}",
        paths.daemon_socket_path().display()
    );
    if paths.read_node_config(name)?.node_id.is_none() {
        println!(
            "Node is not registered; keep this process running and use 'mrk node register' from another shell."
        );
    }
    loop {
        match admin_listener.accept() {
            Ok((stream, _)) => {
                let paths = paths.clone();
                let name = name.to_owned();
                let password = password.to_owned();
                thread::spawn(move || {
                    if let Err(error) = handle_admin_connection(&paths, &name, &password, stream) {
                        eprintln!("admin request error: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }

        if !public_sync_worker_started && paths.read_node_config(name)?.bootstrap_peer.is_some() {
            let sync_paths = paths.clone();
            let sync_name = name.to_owned();
            thread::spawn(move || {
                loop {
                    if let Err(error) =
                        relay_client::run_public_chain_sync(sync_paths.clone(), sync_name.clone())
                        && std::env::var_os("MRK_SYNC_DEBUG").is_some()
                    {
                        eprintln!("public chain sync failed: {error}");
                    }
                    thread::sleep(Duration::from_secs(2));
                }
            });
            public_sync_worker_started = true;
        }

        let Some(node_id) = paths.read_node_config(name)?.node_id else {
            thread::sleep(Duration::from_millis(100));
            continue;
        };

        if hub.is_none() {
            let settlement_wakeup = spawn_traffic_settlement_worker(
                paths.clone(),
                name.to_owned(),
                password.to_owned(),
            );
            hub = Some(Arc::new(RelayHub::production(
                paths.clone(),
                node_id,
                settlement_wakeup,
                name.to_owned(),
                password.to_owned(),
            )?));
            spawn_consensus_gossip(paths.clone(), name.to_owned(), password.to_owned());
        }

        if public_listener.is_none() {
            let public_ip = if allow_insecure_local {
                let endpoint = service::node_record(paths, name)?.endpoint;
                let host = url::Url::parse(&endpoint)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned));
                let local_endpoint = host.is_some_and(|host| {
                    host.eq_ignore_ascii_case("localhost")
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|address| address.is_loopback())
                });
                if !listen.ip().is_loopback() || !local_endpoint {
                    return Err(Error::msg(
                        "--allow-insecure-local requires a loopback listener and loopback Node endpoint",
                    ));
                }
                listen.ip()
            } else {
                service::verify_registered_endpoint(paths, name)?
            };
            let listener = TcpListener::bind(listen)?;
            listener.set_nonblocking(true)?;
            public_listener = Some(listener);
            service::restart_consensus_timer(paths, Utc::now().timestamp())?;
            println!("Public WSS listener: {listen}");
            println!("Registered public IP: {public_ip}");
            println!(
                "Relay: /v1/relay  RPC: /v1/rpc  Consensus: /v1/consensus  Health: /health  Ready: /ready  Probe: /v1/probe?challenge=<random>"
            );
        }

        if !availability_worker_started {
            let worker_paths = paths.clone();
            let worker_name = name.to_owned();
            let worker_password = password.to_owned();
            let ticket_signer = service::availability_ticket_signer(paths, name, password)?;
            thread::spawn(move || {
                loop {
                    match relay_client::run_availability_probe_batch(
                        worker_paths.clone(),
                        worker_name.clone(),
                        worker_password.clone(),
                        &ticket_signer,
                        allow_insecure_local,
                        512,
                        32,
                    ) {
                        Ok(report) if report.failed > 0 => eprintln!(
                            "availability Probe batch: {} submitted, {} failed",
                            report.submitted, report.failed
                        ),
                        Ok(report) if report.selected > 0 => println!(
                            "availability Probe batch: {} attestations submitted",
                            report.submitted
                        ),
                        Ok(_) => thread::sleep(Duration::from_secs(1)),
                        Err(error) => {
                            eprintln!("availability Probe worker error: {error}");
                            thread::sleep(Duration::from_secs(2));
                        }
                    }
                }
            });
            availability_worker_started = true;
        }

        if last_history_prune.elapsed() >= Duration::from_secs(60) {
            let report = service::prune_lite_history(paths, name)?;
            if report.pruned_blocks > 0 || report.pruned_operations > 0 {
                println!(
                    "LITE history pruned: {} blocks, {} operations; retained from height {}",
                    report.pruned_blocks,
                    report.pruned_operations,
                    report.pruned_through_height.saturating_add(1)
                );
            }
            last_history_prune = Instant::now();
        }

        if let Some(hub) = &hub {
            let now = Utc::now().timestamp();
            hub.tick_payment_windows(now)?;
            hub.tick_interrupted_routes(now);
        }

        let node = service::node_tick(paths, name, Utc::now().timestamp())?;
        if matches!(node.status, NodeStatus::Exited) {
            println!("Node drained and exited.");
            return Ok(());
        }
        if matches!(node.status, NodeStatus::Suspended) {
            return Err(Error::msg(format!(
                "node cannot run while status is {}",
                node.status
            )));
        }
        if let Some(block) =
            service::produce_node1_block_if_due(paths, name, password, Utc::now().timestamp())?
        {
            println!(
                "Produced block {} {} ({} operations)",
                block.height,
                block.block_hash,
                block.operation_ids.len()
            );
        }
        match drive_validator_consensus_once(paths, name, password, Utc::now().timestamp()) {
            Ok(events) => {
                for event in events {
                    println!("{event}");
                }
            }
            Err(error) => eprintln!("consensus driver error: {error}"),
        }
        match public_listener
            .as_ref()
            .expect("listener initialized")
            .accept()
        {
            Ok((stream, remote)) => {
                let Some(connection_guard) = public_connection_limiter.try_acquire(remote.ip())
                else {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                };
                let paths = paths.clone();
                let name = name.to_owned();
                let password = password.to_owned();
                let hub = Arc::clone(hub.as_ref().expect("Relay Hub initialized"));
                thread::spawn(move || {
                    let _connection_guard = connection_guard;
                    if let Err(error) = handle_connection(&paths, &name, &password, stream, hub) {
                        eprintln!("request error: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn spawn_traffic_settlement_worker(
    paths: DataPaths,
    name: String,
    password: String,
) -> SyncSender<()> {
    let (wakeup, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        loop {
            if let Err(error) = flush_pending_traffic_settlements(&paths, &name, &password)
                && std::env::var_os("MRK_RELAY_DEBUG").is_some()
            {
                eprintln!("traffic settlement flush failed: {error}");
            }
            match receiver.recv_timeout(Duration::from_secs(300)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
    wakeup
}

fn flush_pending_traffic_settlements(paths: &DataPaths, name: &str, password: &str) -> Result<()> {
    for pending in paths.pending_traffic_settlements()? {
        if let Err(error) = flush_one_traffic_settlement(paths, name, password, pending) {
            eprintln!("traffic settlement item failed: {error}");
        }
    }
    Ok(())
}

fn flush_one_traffic_settlement(
    paths: &DataPaths,
    name: &str,
    password: &str,
    mut pending: PendingTrafficSettlement,
) -> Result<()> {
    let authorization_id = pending.sender_checkpoint.authorization_id.clone();
    let direction = pending.sender_checkpoint.direction;
    let pending_sequence = pending.sender_checkpoint.sequence;
    let ledger = paths.read_ledger()?;
    let authorization = ledger.payment_authorizations.get(&authorization_id);
    let already_settled = authorization
        .and_then(|authorization| authorization.directions.get(&direction))
        .is_some_and(|settled| {
            if pending.sender_checkpoint.final_checkpoint {
                settled.finalized
            } else {
                settled.settled_payload_bytes >= pending.sender_checkpoint.cumulative_sent_bytes
            }
        });
    if already_settled {
        return paths.remove_pending_traffic_settlement_if_not_newer(
            &authorization_id,
            direction,
            pending_sequence,
            pending.sender_checkpoint.final_checkpoint,
        );
    }
    if authorization.is_some_and(|authorization| {
        authorization.refunded_at.is_some() || Utc::now().timestamp() > authorization.claim_until
    }) {
        return paths.remove_pending_traffic_settlement_if_not_newer(
            &authorization_id,
            direction,
            pending_sequence,
            pending.sender_checkpoint.final_checkpoint,
        );
    }
    if let Some(operation_id) = &pending.submission_operation_id {
        match ledger
            .operations
            .get(operation_id)
            .map(|record| &record.status)
        {
            Some(mrk::model::OperationStatus::Finalized) => {
                return paths.remove_pending_traffic_settlement_if_not_newer(
                    &authorization_id,
                    direction,
                    pending_sequence,
                    pending.sender_checkpoint.final_checkpoint,
                );
            }
            Some(mrk::model::OperationStatus::Pending) => return Ok(()),
            _ => pending.submission_operation_id = None,
        }
    }
    let operation_id = service::submit_traffic_settlement(
        paths,
        name,
        password,
        pending.sender_checkpoint.clone(),
        pending.receiver_receipt.clone(),
        Utc::now().timestamp(),
    )?;
    pending.submission_operation_id = Some(operation_id);
    paths.store_pending_traffic_settlement(&pending)
}

struct AdminSocketGuard {
    path: PathBuf,
}

impl Drop for AdminSocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn bind_admin_socket(paths: &DataPaths, _name: &str) -> Result<(UnixListener, AdminSocketGuard)> {
    let path = paths.daemon_socket_path();
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err(Error::msg(
                "mrk node is already running for this data directory",
            ));
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok((listener, AdminSocketGuard { path }))
}

fn handle_admin_connection(
    paths: &DataPaths,
    node_name: &str,
    password: &str,
    mut stream: UnixStream,
) -> Result<()> {
    if unix_peer_uid(&stream)? != unsafe { libc::geteuid() } {
        return Err(Error::msg(
            "admin socket peer UID does not match mrk node UID",
        ));
    }
    let mut request = Vec::new();
    stream.read_to_end(&mut request)?;
    let request: AdminRequest = serde_json::from_slice(&request)?;
    if request.node != node_name {
        return Err(Error::msg("admin request targets a different node"));
    }
    if matches!(
        request.command,
        DaemonCommand::Init { .. }
            | DaemonCommand::Run { .. }
            | DaemonCommand::BackupVerify { .. }
            | DaemonCommand::Restore { .. }
    ) {
        return Err(Error::msg(
            "command is not available through the admin socket",
        ));
    }

    ADMIN_PASSWORD.with(|slot| *slot.borrow_mut() = Some(password.to_owned()));
    ADMIN_OUTPUT.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let result = execute_daemon_command(paths, request.node, request.output, request.command);
    let output = ADMIN_OUTPUT.with(|slot| slot.borrow_mut().take().unwrap_or_default());
    ADMIN_PASSWORD.with(|slot| *slot.borrow_mut() = None);
    let response = match result {
        Ok(()) => AdminResponse {
            ok: true,
            output,
            error: None,
        },
        Err(error) => AdminResponse {
            ok: false,
            output,
            error: Some(error.to_string()),
        },
    };
    stream.write_all(&serde_json::to_vec(&response)?)?;
    Ok(())
}

fn unix_peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(Error::msg("admin socket returned invalid peer credentials"));
    }
    Ok(unsafe { credential.assume_init() }.uid)
}

fn drive_validator_consensus_once(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<Vec<String>> {
    let mut events = Vec::new();
    let mut status = service::consensus_status(paths, now)?;
    if status.mode != "MULTI_VALIDATOR" {
        return Ok(events);
    }
    let node_id = paths
        .read_node_config(name)?
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    if !status.active_validator_ids.contains(&node_id) {
        return Ok(events);
    }

    if status.proposal_block_hash.is_none() && status.proposer_node_id == Some(node_id) {
        let block = service::propose_consensus_block(paths, name, password, now)?;
        events.push(format!(
            "Proposed block {} {} at round {}",
            block.height, block.block_hash, block.consensus_round
        ));
        status = service::consensus_status(paths, now)?;
    }

    if let Some(block_hash) = status.proposal_block_hash.clone() {
        let ledger = paths.read_ledger()?;
        let has_prevote = ledger.consensus.prevotes.contains_key(&node_id);
        let has_precommit = ledger.consensus.precommits.contains_key(&node_id);
        drop(ledger);
        if !has_prevote {
            service::cast_consensus_vote(
                paths,
                name,
                password,
                ConsensusVoteType::Prevote,
                Some(block_hash.clone()),
                now,
            )?;
            events.push(format!("PREVOTE block {block_hash}"));
            status = service::consensus_status(paths, now)?;
        }
        if !has_precommit && status.prevote_count >= status.quorum {
            let (_, finalized) = service::cast_consensus_vote(
                paths,
                name,
                password,
                ConsensusVoteType::Precommit,
                Some(block_hash.clone()),
                now,
            )?;
            if let Some(block) = finalized {
                events.push(format!(
                    "Finalized block {} {}",
                    block.height, block.block_hash
                ));
            } else {
                events.push(format!("PRECOMMIT block {block_hash}"));
            }
            return Ok(events);
        }
    }

    if let Some(started_at) = status.round_started_at {
        let multiplier = 1_i64.checked_shl(status.round.min(5)).unwrap_or(32);
        let timeout = paths
            .read_ledger()?
            .settings
            .consensus_round_timeout_seconds
            .saturating_mul(multiplier)
            .clamp(5, 60);
        if now.saturating_sub(started_at) >= timeout {
            let round = service::advance_consensus_round(paths, now)?;
            events.push(format!("Advanced consensus to round {round}"));
        }
    }
    Ok(events)
}

const CONSENSUS_GOSSIP_FANOUT: usize = 4;

fn consensus_gossip_peer_ids(active: &[u64], local_node_id: u64, fanout: usize) -> Vec<u64> {
    let Some(local_index) = active.iter().position(|node_id| *node_id == local_node_id) else {
        return Vec::new();
    };
    let target_count = fanout.min(active.len().saturating_sub(1));
    let mut peers = Vec::with_capacity(target_count);
    for distance in 1..active.len() {
        for index in [
            (local_index + distance) % active.len(),
            (local_index + active.len() - distance) % active.len(),
        ] {
            let peer = active[index];
            if peer != local_node_id && !peers.contains(&peer) {
                peers.push(peer);
                if peers.len() == target_count {
                    return peers;
                }
            }
        }
    }
    peers
}

fn spawn_consensus_gossip(paths: DataPaths, name: String, password: String) {
    thread::spawn(move || {
        loop {
            let local_node_id = paths
                .read_node_config(&name)
                .ok()
                .and_then(|config| config.node_id);
            let status = local_node_id
                .and_then(|_| service::consensus_status(&paths, Utc::now().timestamp()).ok());
            if let (Some(local_node_id), Some(status)) = (local_node_id, status)
                && status.mode == "MULTI_VALIDATOR"
                && status.active_validator_ids.contains(&local_node_id)
            {
                let mut peers = consensus_gossip_peer_ids(
                    &status.active_validator_ids,
                    local_node_id,
                    CONSENSUS_GOSSIP_FANOUT,
                );
                if let Some(proposer) = status.proposer_node_id
                    && proposer != local_node_id
                    && !peers.contains(&proposer)
                {
                    if peers.len() == CONSENSUS_GOSSIP_FANOUT {
                        peers.pop();
                    }
                    peers.insert(0, proposer);
                }
                thread::scope(|scope| {
                    for peer_node_id in peers {
                        let paths = paths.clone();
                        let name = name.clone();
                        let password = password.clone();
                        scope.spawn(move || {
                            let allow_insecure_local =
                                service::node_record_by_id(&paths, peer_node_id)
                                    .ok()
                                    .and_then(|node| url::Url::parse(&node.endpoint).ok())
                                    .and_then(|url| url.host_str().map(str::to_owned))
                                    .is_some_and(|host| {
                                        host.eq_ignore_ascii_case("localhost")
                                            || host
                                                .parse::<std::net::IpAddr>()
                                                .is_ok_and(|address| address.is_loopback())
                                    });
                            if let Err(error) = relay_client::sync_consensus_peer(
                                paths,
                                name,
                                password,
                                peer_node_id,
                                allow_insecure_local,
                                None,
                            ) && std::env::var_os("MRK_CONSENSUS_DEBUG").is_some()
                            {
                                eprintln!(
                                    "consensus sync with Node {peer_node_id} failed: {error}"
                                );
                            }
                        });
                    }
                });
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

fn handle_connection(
    paths: &DataPaths,
    name: &str,
    password: &str,
    mut stream: TcpStream,
    hub: Arc<RelayHub>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let request = read_http_request(&mut stream)?;
    let request =
        std::str::from_utf8(&request).map_err(|_| Error::msg("request is not valid UTF-8 HTTP"))?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| Error::msg("invalid HTTP request line"))?;
    if target == "/v1/relay" {
        let response = websocket_server_response(request)?;
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        return handle_relay_connection(paths, name, stream, hub);
    }
    if target == "/v1/consensus" {
        let response =
            websocket_server_response_for_protocol(request, "/v1/consensus", CONSENSUS_PROTOCOL)?;
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        return handle_consensus_connection(paths, name, password, stream);
    }
    if target == "/v1/rpc" {
        let response = websocket_server_response_for_protocol(request, "/v1/rpc", RPC_PROTOCOL)?;
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        return handle_rpc_connection(paths, stream);
    }
    let (status, body) = if target == "/health" || target == "/ready" {
        let node = service::node_record(paths, name)?;
        let chain = service::block_status(paths, Utc::now().timestamp())?;
        let ledger = paths.read_ledger()?;
        let max_block_age = ledger
            .settings
            .block_interval_seconds
            .saturating_mul(6)
            .max(120);
        let ready = !matches!(
            node.status,
            NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
        ) && chain.height > 0
            && chain.last_block_at.is_some_and(|timestamp| {
                Utc::now().timestamp().saturating_sub(timestamp) <= max_block_age
            });
        (
            if target == "/ready" && !ready {
                "503 Service Unavailable"
            } else {
                "200 OK"
            },
            serde_json::to_string(&serde_json::json!({
                "status": if ready { "ready" } else { "degraded" },
                "ready": ready,
                "node_id": node.node_id,
                "node_status": node.status,
                "ip_slot": node.ip_slot,
                "chain_height": chain.height,
                "chain_mode": chain.mode,
                "last_block_at": chain.last_block_at,
                "pending_operations": chain.pending_operation_count,
                "availability_mode": ledger.availability_mode,
                "availability_earning_enabled": ledger.availability_mode == AvailabilityMode::Node1Trusted
                    || ledger.consensus.active_validators.len()
                        >= service::MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
                "active_validators": ledger.consensus.active_validators.len(),
            }))?,
        )
    } else if let Some(query) = target.strip_prefix("/v1/probe?challenge=") {
        let challenge = percent_decode(query)?;
        (
            "200 OK",
            serde_json::to_string(&service::node_probe_response(
                paths, name, password, &challenge,
            )?)?,
        )
    } else {
        ("404 Not Found", "{\"error\":\"not found\"}".to_owned())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

fn handle_rpc_connection(paths: &DataPaths, mut stream: TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(65)))?;
    let mut rate_window_started = Instant::now();
    let mut request_count = 0_u32;
    let mut mutation_count = 0_u32;
    loop {
        let bytes = match read_ws_message(&mut stream, true) {
            Ok(WsMessage::Binary(bytes)) => bytes,
            Ok(WsMessage::Ping(payload)) => {
                write_ws_message(&mut stream, &WsMessage::Pong(payload), false)?;
                continue;
            }
            Ok(WsMessage::Pong(_)) => continue,
            Ok(WsMessage::Close(payload)) => {
                write_ws_message(&mut stream, &WsMessage::Close(payload), false)?;
                return Ok(());
            }
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if rate_window_started.elapsed() >= Duration::from_secs(60) {
            rate_window_started = Instant::now();
            request_count = 0;
            mutation_count = 0;
        }
        request_count = request_count.saturating_add(1);
        let response = match serde_json::from_slice::<RpcRequest>(&bytes) {
            Ok(request) => {
                let id = request.id;
                let is_mutation = request.method == "operation.submit";
                if is_mutation {
                    mutation_count = mutation_count.saturating_add(1);
                }
                if request_count > MAX_RPC_REQUESTS_PER_MINUTE
                    || mutation_count > MAX_RPC_MUTATIONS_PER_MINUTE
                {
                    RpcResponse {
                        id,
                        result: None,
                        error: Some(RpcError {
                            code: "RATE_LIMITED",
                            message: "RPC connection rate limit exceeded".to_owned(),
                        }),
                    }
                } else {
                    match execute_public_rpc(paths, request) {
                        Ok(result) => RpcResponse {
                            id,
                            result: Some(result),
                            error: None,
                        },
                        Err(error) => RpcResponse {
                            id,
                            result: None,
                            error: Some(RpcError {
                                code: "INVALID_REQUEST",
                                message: error.to_string(),
                            }),
                        },
                    }
                }
            }
            Err(error) => RpcResponse {
                id: 0,
                result: None,
                error: Some(RpcError {
                    code: "INVALID_JSON",
                    message: error.to_string(),
                }),
            },
        };
        let mut response_bytes = serde_json::to_vec(&response)?;
        if response_bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
            response_bytes = serde_json::to_vec(&RpcResponse {
                id: response.id,
                result: None,
                error: Some(RpcError {
                    code: "RESPONSE_TOO_LARGE",
                    message: "RPC response exceeds 16 MiB; use a newer checkpoint or smaller query"
                        .to_owned(),
                }),
            })?;
        }
        write_ws_message(&mut stream, &WsMessage::Binary(response_bytes), false)?;
    }
}

fn execute_public_rpc(paths: &DataPaths, request: RpcRequest) -> Result<serde_json::Value> {
    let now = Utc::now().timestamp();
    let result = match request.method.as_str() {
        "system.ping" => {
            let ledger = paths.read_ledger()?;
            serde_json::json!({
                "protocol": RPC_PROTOCOL,
                "protocol_version": mrk::model::PROTOCOL_VERSION,
                "ledger_id": ledger.ledger_id,
                "time": now,
            })
        }
        "chain.status" => serde_json::to_value(service::block_status(paths, now)?)?,
        "chain.bootstrap" => {
            let snapshot = match request.params.get("height") {
                Some(height) => {
                    let height = height
                        .as_u64()
                        .ok_or_else(|| Error::msg("RPC parameter 'height' must be a u64"))?;
                    service::bootstrap_snapshot_at(paths, height)?
                }
                None => service::bootstrap_snapshot(paths)?,
            };
            serde_json::to_value(snapshot)?
        }
        "chain.catch_up" => {
            let from_height = rpc_u64(&request.params, "from_height")?;
            serde_json::to_value(service::consensus_catch_up_chunk(
                paths,
                from_height,
                mrk::consensus::MAX_CATCH_UP_BLOCKS,
            )?)?
        }
        "block.get" => {
            let height = rpc_u64(&request.params, "height")?;
            serde_json::to_value(service::block_by_height(paths, height)?)?
        }
        "account.balance" => {
            let address = rpc_str(&request.params, "address")?;
            serde_json::to_value(service::balance(paths, address)?)?
        }
        "account.history" => {
            let address = rpc_str(&request.params, "address")?;
            let limit = request
                .params
                .get("limit")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(20)
                .min(1_000) as usize;
            serde_json::to_value(service::account_history(paths, address, limit)?)?
        }
        "operation.get" => {
            let operation_id = rpc_str(&request.params, "operation_id")?;
            serde_json::to_value(service::operation(paths, operation_id)?)?
        }
        "operation.submit" => {
            let public_key = rpc_str(&request.params, "public_key")?.to_owned();
            let operation: SignedOperation = serde_json::from_value(
                request
                    .params
                    .get("operation")
                    .cloned()
                    .ok_or_else(|| Error::msg("missing 'operation' parameter"))?,
            )?;
            let operation_id = service::submit_consensus_operation(
                paths,
                mrk::consensus::PendingOperationEnvelope {
                    public_key,
                    operation,
                },
                now,
            )?;
            serde_json::json!({ "operation_id": operation_id, "status": "PENDING" })
        }
        "network.get" => {
            let alias = rpc_str(&request.params, "alias")?;
            serde_json::to_value(service::network_by_alias(paths, alias)?)?
        }
        "node.list" => {
            let status = rpc_optional_node_status(&request.params, "status")?;
            let validator_only = rpc_optional_bool(&request.params, "validator")?.unwrap_or(false);
            let cursor = rpc_optional_u64(&request.params, "cursor")?;
            let limit = rpc_page_limit(&request.params)?;
            serde_json::to_value(service::registry_nodes(
                paths,
                status,
                validator_only,
                cursor,
                limit,
            )?)?
        }
        "node.get" => {
            let node_id = rpc_u64(&request.params, "node_id")?;
            serde_json::to_value(service::registry_node_by_id(paths, node_id)?)?
        }
        "node.discover" => {
            let cursor = rpc_optional_u64(&request.params, "cursor")?;
            let limit = rpc_page_limit(&request.params)?;
            serde_json::to_value(service::discover_relays(paths, cursor, limit, now)?)?
        }
        "payment.get" => {
            let authorization_id = rpc_str(&request.params, "authorization_id")?;
            serde_json::to_value(service::relay_authorization_view(paths, authorization_id)?)?
        }
        "payment.status" => {
            let identifier = rpc_str(&request.params, "identifier")?;
            serde_json::to_value(service::payment_authorization_status(paths, identifier)?)?
        }
        "payment.history" => {
            let network = rpc_str(&request.params, "network")?;
            let member = request
                .params
                .get("member")
                .and_then(serde_json::Value::as_str);
            let limit = request
                .params
                .get("limit")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(20)
                .min(1_000) as usize;
            serde_json::to_value(service::payment_history(paths, network, member, limit)?)?
        }
        "payment.unsettled" => {
            let network = request
                .params
                .get("network")
                .and_then(serde_json::Value::as_str);
            let member = request
                .params
                .get("member")
                .and_then(serde_json::Value::as_str);
            serde_json::to_value(service::unsettled_payments(paths, network, member, None)?)?
        }
        "treasury.status" => serde_json::to_value(service::treasury_status(paths, now)?)?,
        "treasury.history" => {
            let limit = request
                .params
                .get("limit")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(20)
                .min(1_000) as usize;
            serde_json::to_value(service::treasury_history(paths, limit)?)?
        }
        _ => {
            return Err(Error::msg(format!(
                "unknown RPC method: {}",
                request.method
            )));
        }
    };
    Ok(result)
}

fn rpc_str<'a>(params: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    params
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::msg(format!("missing or invalid '{name}' parameter")))
}

fn rpc_u64(params: &serde_json::Value, name: &str) -> Result<u64> {
    params
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::msg(format!("missing or invalid '{name}' parameter")))
}

fn rpc_optional_u64(params: &serde_json::Value, name: &str) -> Result<Option<u64>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))
}

fn rpc_optional_bool(params: &serde_json::Value, name: &str) -> Result<Option<bool>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))
}

fn rpc_page_limit(params: &serde_json::Value) -> Result<usize> {
    let limit = params.get("limit").map_or(Ok(50), |value| {
        value
            .as_u64()
            .ok_or_else(|| Error::msg("invalid 'limit' parameter"))
    })?;
    if !(1..=1_000).contains(&limit) {
        return Err(Error::msg("page limit must be between 1 and 1000"));
    }
    Ok(limit as usize)
}

fn rpc_optional_node_status(
    params: &serde_json::Value,
    name: &str,
) -> Result<Option<mrk::model::NodeStatus>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))?;
    let normalized = value.replace('-', "_").to_ascii_uppercase();
    let status = match normalized.as_str() {
        "INITIALIZED" => mrk::model::NodeStatus::Initialized,
        "WARMING_UP" => mrk::model::NodeStatus::WarmingUp,
        "ACTIVE" => mrk::model::NodeStatus::Active,
        "DRAINING" => mrk::model::NodeStatus::Draining,
        "EXITED" => mrk::model::NodeStatus::Exited,
        "SUSPENDED" => mrk::model::NodeStatus::Suspended,
        _ => {
            return Err(Error::msg(format!(
                "invalid '{name}' parameter: expected initialized, warming-up, active, draining, exited, or suspended"
            )));
        }
    };
    Ok(Some(status))
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1_024);
    let mut byte = [0_u8; 1];
    while request.len() < 8_192 {
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(Error::msg("HTTP request headers exceed 8 KiB"))
}

fn handle_consensus_connection(
    paths: &DataPaths,
    name: &str,
    password: &str,
    mut stream: TcpStream,
) -> Result<()> {
    let challenge =
        service::create_consensus_challenge(paths, name, password, Utc::now().timestamp())?;
    write_consensus_message(
        &mut stream,
        &ConsensusWireMessage::Challenge {
            challenge: challenge.clone(),
        },
    )?;
    let hello_message = read_ws_message(&mut stream, true)?;
    let WsMessage::Binary(hello_bytes) = hello_message else {
        return Err(Error::msg("first consensus message must be binary HELLO"));
    };
    if hello_bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
        return Err(Error::msg("consensus message exceeds 16 MiB"));
    }
    let ConsensusWireMessage::Hello { hello } = serde_json::from_slice(&hello_bytes)? else {
        return Err(Error::msg("first consensus message must be HELLO"));
    };
    let peer_node_id =
        service::authenticate_consensus_peer(paths, &challenge, &hello, Utc::now().timestamp())?;
    write_consensus_message(
        &mut stream,
        &ConsensusWireMessage::Welcome {
            server_node_id: challenge.server_node_id,
            authenticated_validator_node_id: peer_node_id,
        },
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(65)))?;
    loop {
        let message = match read_ws_message(&mut stream, true) {
            Ok(WsMessage::Binary(bytes)) => {
                if bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
                    return Err(Error::msg("consensus message exceeds 16 MiB"));
                }
                serde_json::from_slice(&bytes)?
            }
            Ok(WsMessage::Ping(payload)) => {
                write_ws_message(&mut stream, &WsMessage::Pong(payload), false)?;
                continue;
            }
            Ok(WsMessage::Pong(_)) => continue,
            Ok(WsMessage::Close(payload)) => {
                write_ws_message(&mut stream, &WsMessage::Close(payload), false)?;
                return Ok(());
            }
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let response = match message {
            ConsensusWireMessage::Proposal { block } => {
                match service::submit_consensus_proposal(paths, block, Utc::now().timestamp()) {
                    Ok(submission) => ConsensusWireMessage::Ack {
                        kind: if submission.duplicate {
                            "DUPLICATE_PROPOSAL".to_owned()
                        } else {
                            "PROPOSAL".to_owned()
                        },
                        finalized_height: None,
                    },
                    Err(error) => ConsensusWireMessage::Error {
                        code: "INVALID_PROPOSAL".to_owned(),
                        message: error.to_string(),
                    },
                }
            }
            ConsensusWireMessage::Vote { vote } => {
                match service::submit_consensus_vote(paths, vote, Utc::now().timestamp()) {
                    Ok(submission) => ConsensusWireMessage::Ack {
                        kind: if submission.double_sign_detected {
                            "DOUBLE_SIGN_EVIDENCE".to_owned()
                        } else if submission.duplicate {
                            "DUPLICATE_VOTE".to_owned()
                        } else {
                            "VOTE".to_owned()
                        },
                        finalized_height: submission.finalized_block.map(|block| block.height),
                    },
                    Err(error) => ConsensusWireMessage::Error {
                        code: "INVALID_VOTE".to_owned(),
                        message: error.to_string(),
                    },
                }
            }
            ConsensusWireMessage::Operation { envelope } => {
                match service::submit_consensus_operation(paths, envelope, Utc::now().timestamp()) {
                    Ok(_) => ConsensusWireMessage::Ack {
                        kind: "OPERATION".to_owned(),
                        finalized_height: None,
                    },
                    Err(error) => ConsensusWireMessage::Error {
                        code: "INVALID_OPERATION".to_owned(),
                        message: error.to_string(),
                    },
                }
            }
            ConsensusWireMessage::StatusRequest => ConsensusWireMessage::Status {
                status: serde_json::to_value(service::consensus_status(
                    paths,
                    Utc::now().timestamp(),
                )?)?,
            },
            ConsensusWireMessage::SyncRequest { height, round } => {
                let status = service::consensus_status(paths, Utc::now().timestamp())?;
                let ledger = paths.read_ledger()?;
                let aligned = height == status.height && round == status.round;
                ConsensusWireMessage::SyncState {
                    height: status.height,
                    round: status.round,
                    proposal: aligned
                        .then_some(ledger.consensus.proposal)
                        .flatten()
                        .map(|proposal| proposal.block),
                    prevotes: if aligned {
                        ledger.consensus.prevotes.into_values().collect()
                    } else {
                        Vec::new()
                    },
                    precommits: if aligned {
                        ledger.consensus.precommits.into_values().collect()
                    } else {
                        Vec::new()
                    },
                    pending_operations: if aligned {
                        service::consensus_pending_operations(paths)?
                    } else {
                        Vec::new()
                    },
                }
            }
            ConsensusWireMessage::CatchUpRequest { from_height } => {
                match consensus_catch_up_response(paths, from_height) {
                    Ok(response) => response,
                    Err(error) => ConsensusWireMessage::Error {
                        code: "CATCH_UP_UNAVAILABLE".to_owned(),
                        message: error.to_string(),
                    },
                }
            }
            ConsensusWireMessage::Ping { timestamp } => ConsensusWireMessage::Pong { timestamp },
            _ => ConsensusWireMessage::Error {
                code: "UNEXPECTED_MESSAGE".to_owned(),
                message: "message is not valid after consensus authentication".to_owned(),
            },
        };
        write_consensus_message(&mut stream, &response)?;
    }
}

fn consensus_catch_up_response(
    paths: &DataPaths,
    from_height: u64,
) -> Result<ConsensusWireMessage> {
    let mut block_limit = MAX_CATCH_UP_BLOCKS;
    loop {
        let chunk = service::consensus_catch_up_chunk(paths, from_height, block_limit)?;
        let block_count = chunk.blocks.len();
        let response = ConsensusWireMessage::CatchUpChunk {
            tip_height: chunk.tip_height,
            blocks: chunk.blocks,
            operations: chunk.operations,
            finalized_checkpoint_json: chunk
                .finalized_checkpoint
                .map(|checkpoint| serde_json::to_string(&checkpoint))
                .transpose()?,
        };
        if serde_json::to_vec(&response)?.len() <= MAX_CONSENSUS_MESSAGE_SIZE {
            return Ok(response);
        }
        if block_count <= 1 {
            return Err(Error::msg(
                "one catch-up block and its finalized checkpoint exceed the 16 MiB consensus message limit",
            ));
        }
        block_limit = (block_count / 2).max(1);
    }
}

fn write_consensus_message(stream: &mut TcpStream, message: &ConsensusWireMessage) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
        return Err(Error::msg("consensus message exceeds 16 MiB"));
    }
    write_ws_message(stream, &WsMessage::Binary(bytes), false)
}

fn handle_relay_connection(
    paths: &DataPaths,
    name: &str,
    mut stream: TcpStream,
    hub: Arc<RelayHub>,
) -> Result<()> {
    let node = service::node_record(paths, name)?;
    let relay_key = paths.read_keyfile(&paths.node_relay_key_path(name)?)?;
    let challenge = ChallengePayload {
        challenge: hex_lower(&random_bytes::<32>()?),
        relay_public_key: relay_key.public_key,
        node_id: node.node_id,
        timestamp: Utc::now().timestamp(),
    };
    let challenge_frame =
        RelayFrame::control(FrameType::Challenge, serde_json::to_vec(&challenge)?);
    write_ws_message(
        &mut stream,
        &WsMessage::Binary(challenge_frame.encode()?),
        false,
    )?;
    let hello_message = read_ws_message(&mut stream, true)?;
    let WsMessage::Binary(hello_bytes) = hello_message else {
        return Err(Error::msg("first relay message must be binary HELLO"));
    };
    let hello_frame = RelayFrame::decode(&hello_bytes)?;
    if hello_frame.frame_type != FrameType::Hello {
        return Err(Error::msg("first relay frame must be HELLO"));
    }
    let hello = serde_json::from_slice(&hello_frame.payload)?;
    let member = service::authenticate_member(paths, &challenge, &hello, Utc::now().timestamp())?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(OUTBOUND_QUEUE_MESSAGES);
    let mut writer = stream.try_clone()?;
    let connection_id = hub.register(member, sender.clone())?;
    thread::spawn(move || {
        while let Ok(message) = receiver.recv() {
            if write_ws_message(&mut writer, &message, false).is_err() {
                break;
            }
        }
    });
    send_relay_frame(
        &sender,
        RelayFrame::control(
            FrameType::Welcome,
            serde_json::to_vec(&WelcomePayload {
                connection_id,
                max_channels: MAX_CHANNELS_PER_CONNECTION as u32,
                max_message_size: MAX_FRAME_PAYLOAD as u32,
                heartbeat_seconds: 30,
            })?,
        ),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(65)))?;
    let result = loop {
        match read_ws_message(&mut stream, true) {
            Ok(WsMessage::Binary(bytes)) => {
                if let Err(error) = hub.handle_frame(connection_id, RelayFrame::decode(&bytes)?) {
                    let _ = send_protocol_error(&sender, "INVALID_FRAME", &error.to_string());
                    break Err(error);
                }
            }
            Ok(WsMessage::Ping(payload)) => {
                sender
                    .try_send(WsMessage::Pong(payload))
                    .map_err(|_| Error::msg("relay outbound queue is full"))?;
            }
            Ok(WsMessage::Pong(_)) => {}
            Ok(WsMessage::Close(payload)) => {
                let _ = sender.try_send(WsMessage::Close(payload));
                break Ok(());
            }
            Err(Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break Ok(());
            }
            Err(error) => break Err(error),
        }
    };
    hub.unregister(connection_id);
    result
}

fn percent_decode(input: &str) -> Result<String> {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(Error::msg("invalid percent-encoded challenge"));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| Error::msg("invalid percent-encoded challenge"))?;
            output.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| Error::msg("invalid percent-encoded challenge"))?,
            );
            index += 3;
        } else {
            output.push(if bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| Error::msg("challenge is not valid UTF-8"))
}

fn read_new_password() -> Result<String> {
    if let Some(password) = password_from_environment()? {
        validate_keystore_password(&password)?;
        return Ok(password);
    }
    let first = read_password("New node keystore password: ")?;
    let second = read_password("Confirm node keystore password: ")?;
    if first != second {
        return Err(Error::msg("keystore passwords do not match"));
    }
    validate_keystore_password(&first)?;
    Ok(first)
}

fn read_password(prompt: &str) -> Result<String> {
    if let Some(password) = ADMIN_PASSWORD.with(|slot| slot.borrow().clone()) {
        return Ok(password);
    }
    if let Some(password) = password_from_environment()? {
        return Ok(password);
    }
    rpassword::prompt_password(prompt).map_err(Error::from)
}

fn password_from_environment() -> Result<Option<String>> {
    if let Ok(path) = std::env::var("MRK_KEYSTORE_PASSWORD_FILE") {
        let metadata = std::fs::metadata(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::msg(
                    "MRK_KEYSTORE_PASSWORD_FILE must not be accessible by group or others",
                ));
            }
        }
        if metadata.len() > 4_096 {
            return Err(Error::msg("keystore password file exceeds 4 KiB"));
        }
        let password = std::fs::read_to_string(path)?;
        let password = password.trim_end_matches(['\r', '\n']).to_owned();
        if password.is_empty() {
            return Err(Error::msg("keystore password file is empty"));
        }
        return Ok(Some(password));
    }
    Ok(std::env::var("MRK_KEYSTORE_PASSWORD").ok())
}

fn diagnostic_text(report: &service::DiagnosticReport) -> String {
    report
        .checks
        .iter()
        .map(|check| {
            format!(
                "{}  {}  {}",
                if check.ok { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn consensus_vote_target(
    paths: &DataPaths,
    block_hash: Option<String>,
    nil: bool,
) -> Result<Option<String>> {
    if nil {
        return Ok(None);
    }
    if block_hash.is_some() {
        return Ok(block_hash);
    }
    service::consensus_status(paths, Utc::now().timestamp())?
        .proposal_block_hash
        .map(Some)
        .ok_or_else(|| Error::msg("no proposal exists; provide --block-hash or use --nil"))
}

fn governance_proposal_text(
    proposal: &mrk::model::GovernanceProposalRecord,
    tally: &service::GovernanceTallyView,
) -> String {
    format!(
        "Proposal: {}\nTitle: {}\nKind: {:?}\nStatus: {:?}\nProposer Node: {}\nVoting ends: {}\nExecute after: {}\nNode YES: {}\nNode NO: {}\nNode ABSTAIN: {}\nNode total power: {}\nValidator YES: {}\nValidator NO: {}\nValidator ABSTAIN: {}\nValidator quorum: {} / {}\nTimelock veto power: {}",
        proposal.proposal_id,
        proposal.title,
        proposal.kind,
        proposal.status,
        proposal.proposer_node_id,
        proposal.voting_ends_at,
        proposal.execute_after,
        tally.yes_power,
        tally.no_power,
        tally.abstain_power,
        tally.total_power,
        tally.validator_yes,
        tally.validator_no,
        tally.validator_abstain,
        tally.validator_quorum,
        tally.validator_total,
        tally.timelock_veto_power,
    )
}

fn print_value<T: Serialize>(
    output: Output,
    value: &T,
    text: impl FnOnce() -> String,
) -> Result<()> {
    let rendered = match output {
        Output::Text => text(),
        Output::Json => serde_json::to_string_pretty(value)?,
    };
    let captured = ADMIN_OUTPUT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(buffer) = slot.as_mut() {
            buffer.extend_from_slice(rendered.as_bytes());
            buffer.push(b'\n');
            true
        } else {
            false
        }
    });
    if !captured {
        println!("{rendered}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(network_id: &str, member_id: &str) -> AuthenticatedMember {
        AuthenticatedMember {
            network_id: network_id.to_owned(),
            member_id: member_id.to_owned(),
            max_connections: 1,
        }
    }

    fn queued_frame(receiver: &std::sync::mpsc::Receiver<WsMessage>) -> RelayFrame {
        let WsMessage::Binary(bytes) = receiver.try_recv().unwrap() else {
            panic!("expected binary relay frame");
        };
        RelayFrame::decode(&bytes).unwrap()
    }

    #[test]
    fn relay_hub_routes_only_within_network_and_preserves_sequence() {
        let hub = RelayHub::default();
        let (alice_sender, alice_receiver) = std::sync::mpsc::sync_channel(8);
        let (bob_sender, bob_receiver) = std::sync::mpsc::sync_channel(8);
        let (mallory_sender, _mallory_receiver) = std::sync::mpsc::sync_channel(8);
        let alice = hub
            .register(member("network-a", "alice"), alice_sender)
            .unwrap();
        let bob = hub
            .register(member("network-a", "bob"), bob_sender)
            .unwrap();
        let mallory = hub
            .register(member("network-b", "mallory"), mallory_sender)
            .unwrap();

        hub.handle_frame(
            alice,
            RelayFrame::control(
                FrameType::Open,
                serde_json::to_vec(&OpenPayload {
                    peer_id: "bob".into(),
                    authorization_id: String::new(),
                    metadata: "tcp".into(),
                })
                .unwrap(),
            ),
        )
        .unwrap();
        let incoming = queued_frame(&bob_receiver);
        assert_eq!(incoming.frame_type, FrameType::Incoming);
        let channel_id = incoming.channel_id;

        hub.handle_frame(
            bob,
            RelayFrame {
                frame_type: FrameType::Accept,
                flags: 0,
                channel_id,
                sequence: 0,
                payload: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(queued_frame(&alice_receiver).frame_type, FrameType::Accept);

        let data = RelayFrame {
            frame_type: FrameType::Data,
            flags: 0,
            channel_id,
            sequence: 1,
            payload: b"opaque".to_vec(),
        };
        hub.handle_frame(alice, data.clone()).unwrap();
        assert_eq!(queued_frame(&bob_receiver), data);
        assert!(hub.handle_frame(alice, data).is_err());

        let cross_network = RelayFrame::control(
            FrameType::Open,
            serde_json::to_vec(&OpenPayload {
                peer_id: "mallory".into(),
                authorization_id: String::new(),
                metadata: String::new(),
            })
            .unwrap(),
        );
        assert!(hub.handle_frame(alice, cross_network).is_err());
        hub.unregister(mallory);
    }

    #[test]
    fn relay_hub_applies_bounded_queue_backpressure() {
        let hub = RelayHub::default();
        let (alice_sender, _alice_receiver) = std::sync::mpsc::sync_channel(1);
        let (bob_sender, _bob_receiver) = std::sync::mpsc::sync_channel(1);
        let alice = hub
            .register(member("network", "alice"), alice_sender)
            .unwrap();
        hub.register(member("network", "bob"), bob_sender.clone())
            .unwrap();
        bob_sender.try_send(WsMessage::Ping(Vec::new())).unwrap();

        let open = RelayFrame::control(
            FrameType::Open,
            serde_json::to_vec(&OpenPayload {
                peer_id: "bob".into(),
                authorization_id: String::new(),
                metadata: String::new(),
            })
            .unwrap(),
        );
        assert!(hub.handle_frame(alice, open).is_err());
    }

    #[test]
    fn relay_node_requests_checkpoint_when_time_window_expires() {
        let hub = RelayHub::default();
        let (alice_sender, alice_receiver) = std::sync::mpsc::sync_channel(8);
        let (bob_sender, _bob_receiver) = std::sync::mpsc::sync_channel(8);
        let alice = hub
            .register(member("network", "alice"), alice_sender)
            .unwrap();
        let bob = hub.register(member("network", "bob"), bob_sender).unwrap();
        let now = Utc::now().timestamp();
        let authorization = mrk::model::PaymentAuthorizationRecord {
            authorization_id: "authorization".to_owned(),
            network_commitment: "commitment".to_owned(),
            network_id: "network".to_owned(),
            payer_address: "payer".to_owned(),
            node_id: 1,
            sender_member_id: "alice".to_owned(),
            receiver_member_id: "bob".to_owned(),
            session_id: "11".repeat(32),
            price_per_gib: 1,
            max_amount: 1,
            reserved_remaining: 1,
            settled_amount: 0,
            created_at: now - 1_000,
            valid_until: now + 1_000,
            claim_until: now + 2_000,
            refunded_at: None,
            closed_at: None,
            directions: std::collections::BTreeMap::new(),
            initiator_member_id: "alice".to_owned(),
            spending_policy_revision: 1,
        };
        hub.state.lock().unwrap().routes.insert(
            7,
            Route {
                source: alice,
                destination: bob,
                accepted: true,
                source_sequence: 1,
                destination_sequence: 0,
                authorization: Some(service::RelayAuthorizationView {
                    ledger_id: "ledger".to_owned(),
                    authorization,
                    sender_public_key: "sender-key".to_owned(),
                    receiver_public_key: "receiver-key".to_owned(),
                    finalized: true,
                }),
                source_direction: DirectionState {
                    cumulative_bytes: 10,
                    transcript_hash: "transcript".to_owned(),
                    window_started_at: Some(now - RELAY_PAYMENT_WINDOW_SECONDS),
                    window_started_bytes: 0,
                    ..DirectionState::default()
                },
                destination_direction: DirectionState::default(),
                recovery: false,
            },
        );

        hub.tick_payment_windows(now).unwrap();
        let frame = queued_frame(&alice_receiver);
        assert_eq!(frame.frame_type, FrameType::CheckpointRequest);
        let request: CheckpointRequest = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(request.sequence, 1);
        assert_eq!(request.cumulative_sent_bytes, 10);
        assert_eq!(request.transcript_hash, "transcript");
        assert!(!request.final_checkpoint);
    }

    #[test]
    fn consensus_gossip_uses_bounded_bidirectional_ring_neighbors() {
        let active = (1..=10).collect::<Vec<_>>();
        assert_eq!(consensus_gossip_peer_ids(&active, 1, 4), vec![2, 10, 3, 9]);
        assert_eq!(
            consensus_gossip_peer_ids(&[1, 2, 3, 4], 3, 4),
            vec![4, 2, 1]
        );
        assert!(consensus_gossip_peer_ids(&active, 99, 4).is_empty());
    }

    #[test]
    fn public_connection_limiter_enforces_and_releases_per_ip_capacity() {
        let limiter = Arc::new(PublicConnectionLimiter::default());
        let ip = "203.0.113.7".parse().unwrap();
        let mut guards = (0..MAX_PUBLIC_CONNECTIONS_PER_IP)
            .map(|_| limiter.try_acquire(ip).expect("within per-IP limit"))
            .collect::<Vec<_>>();
        assert!(limiter.try_acquire(ip).is_none());
        guards.pop();
        assert!(limiter.try_acquire(ip).is_some());
    }
}
