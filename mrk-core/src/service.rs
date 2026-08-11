use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::{Host, Url};

use crate::{
    Error, Result,
    amount::{MAX_SUPPLY, format_mrk, parse_mrk},
    chain::{
        block_is_due, consensus_timer_started_at, height as chain_height,
        next_block_at as next_block_timestamp, next_height as next_block_height,
        state_root as ledger_state_root, tip_hash as chain_tip_hash,
        tip_timestamp as chain_tip_timestamp,
    },
    crypto::{
        EncryptedKeyFile, address_from_public_key, decrypt_key, generate_keyfile, hex_lower,
        random_bytes, sha256_full_id, sha256_id, sign_bytes, validate_address,
        validate_keystore_password, verify_bytes,
    },
    endpoint::{RELAY_PATH, RPC_PATH, normalize_websocket_url},
    fee,
    model::{
        AVAILABILITY_FINALITY_GRACE_SECONDS, AvailabilityMode, AvailabilitySlotRecord,
        AvailabilityVerifierRole, BlockConsensusMode, BlockRecord, ConsensusProposal,
        ConsensusVote, ConsensusVoteType, DEFAULT_OPERATION_VALIDITY_SECONDS,
        DEFAULT_RELAY_PRICE_PER_GIB, DoubleSignEvidence, EpochContext, GenesisAuthority,
        GovernanceActionRecord, GovernanceProposalAction, GovernanceProposalKind,
        GovernanceProposalRecord, GovernanceProposalStatus, GovernanceValidatorVoteRecord,
        GovernanceVoteChoice, GovernanceVoteRecord, IpSlotRecord, LedgerSettings, LedgerState,
        LocalNodeConfig, MemberCredential, MemberRecord, NetworkRecord, NetworkSpendingPolicy,
        NodeRecord, NodeStatus, NodeStorageMode, OperationRecord, OperationStatus,
        PROTOCOL_VERSION, PaymentAuthorizationRecord, REWARD_VESTING_QUANTIZATION_SECONDS,
        REWARD_VESTING_STEP_SECONDS, RelayDirection, RewardVestingBucket, SignedOperation,
        TrafficDirectionSettlement, TreasurySpendRecord, UnsignedOperation,
    },
    operation::{
        add_history, id as operation_id, sign as sign_operation,
        sort_pending as sort_pending_operation_ids, verify as verify_operation,
    },
    relay::{
        ChallengePayload, HelloPayload, ProbePayload, RELAY_PAYMENT_CLAIM_SECONDS, ReceiverReceipt,
        SenderCheckpoint, credential_signing_bytes, hello_signing_bytes,
        receiver_receipt_signing_bytes, sender_checkpoint_hash, sender_checkpoint_signing_bytes,
    },
    storage::{DataPaths, UnsettledRelaySession, atomic_write_json, read_json, validate_name},
};

pub use crate::store::{
    HistoryPruneReport, LITE_BLOCK_RETENTION_SECONDS, LITE_RETAIN_ACCOUNT_OPERATIONS,
    lite_retain_blocks,
};

pub const GOVERNANCE_NODE_THRESHOLD: usize = 20;
pub const CRITICAL_GOVERNANCE_NODE_THRESHOLD: usize = 50;
pub const NODE1_DIRECT_GOVERNANCE_END_THRESHOLD: usize = 50;
pub const MULTI_VALIDATOR_NODE_THRESHOLD: usize = 20;
pub const MIN_ACTIVE_VALIDATORS: usize = 4;
pub const MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS: usize = 7;
pub const MIN_AUDITED_AVAILABILITY_VALIDATORS: usize = 9;
pub const MAX_BLOCK_OPERATIONS: usize = 10_000;
const BPS_DENOMINATOR: u128 = 10_000;
const NODE1_SINGLE_PRODUCER_WEIGHT_BPS: u32 = 20_000;
const GENESIS_PREVIOUS_BLOCK_HASH: &str = "GENESIS";
const VALIDATOR_BOND_UNLOCK_SECONDS: i64 = 30 * 86_400;
const MULTI_VALIDATOR_BLOCK_VERSION: u32 = 2;
const GOVERNANCE_PROPOSAL_BOND: u128 = 1_000 * crate::amount::MRK_SCALE;
const STANDARD_VOTING_SECONDS: i64 = 7 * 86_400;
const STANDARD_TIMELOCK_SECONDS: i64 = 7 * 86_400;
const CRITICAL_VOTING_SECONDS: i64 = 14 * 86_400;
const CRITICAL_TIMELOCK_SECONDS: i64 = 30 * 86_400;
const TREASURY_SINGLE_SPEND_BPS: u128 = 100;
const TREASURY_NINETY_DAY_SPEND_BPS: u128 = 200;
const TREASURY_ANNUAL_SPEND_BPS: u128 = 500;
const TREASURY_MATURE_SERVICE_SECONDS: u64 = 180 * 86_400;
type GovernanceParameterSchedule = BTreeMap<u64, BTreeMap<String, String>>;
const FEE_GOVERNANCE_PARAMETERS: [&str; 8] = [
    "base-fee-per-unit",
    "fee-min-multiplier-bps",
    "fee-max-multiplier-bps",
    "fee-target-units-per-epoch",
    "fee-max-units-per-block",
    "fee-adjustment-denominator",
    "traffic-protocol-fee-bps",
    "traffic-treasury-share-bps",
];

#[derive(Clone, Debug, Serialize)]
pub struct BalanceView {
    pub address: String,
    pub balance: u128,
    pub balance_display: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FeeQuoteView {
    pub policy_version: u64,
    pub multiplier_bps: u32,
    pub units: u64,
    pub fee: u128,
    pub fee_display: String,
    pub recommended_max_fee: u128,
    pub recommended_max_fee_display: String,
}

pub fn fee_quote(
    paths: &DataPaths,
    module: &str,
    action: &str,
    payload: &Value,
) -> Result<FeeQuoteView> {
    let ledger = paths.read_ledger()?;
    let quote = fee::quote(&ledger, module, action, payload)?;
    Ok(FeeQuoteView {
        policy_version: quote.policy_version,
        multiplier_bps: ledger.fee_multiplier_bps,
        units: quote.units,
        fee: quote.fee,
        fee_display: format_mrk(quote.fee),
        recommended_max_fee: quote.recommended_max_fee,
        recommended_max_fee_display: format_mrk(quote.recommended_max_fee),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRankingEntryView {
    pub rank: u64,
    pub address: String,
    pub balance_base_units: String,
    pub balance_display: String,
    pub balance_share_bps: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccountRankingListView {
    pub accounts: Vec<AccountRankingEntryView>,
    pub funded_account_count: usize,
    pub total_account_balance_base_units: String,
    pub total_account_balance_display: String,
    pub snapshot_epoch: u64,
    pub snapshot_height: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferPreview {
    pub ledger_id: String,
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub fee: u128,
    pub total: u128,
    pub nonce: u64,
    pub valid_until: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferReceipt {
    pub operation_id: String,
    pub status: OperationStatus,
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub fee: u128,
    pub submitted_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeRewardsView {
    pub node_id: u64,
    pub status: NodeStatus,
    pub epoch_eligible_seconds: u64,
    pub total_eligible_seconds: u64,
    pub service_bond: u128,
    pub service_bond_display: String,
    pub service_bond_unlock_at: Option<i64>,
    pub offline_slashed_at: Option<i64>,
    pub offline_slashed_service_bond: u128,
    pub offline_slashed_service_bond_display: String,
    pub offline_slashed_vesting_reward: u128,
    pub offline_slashed_vesting_reward_display: String,
    pub claimable_reward: u128,
    pub claimable_reward_display: String,
    pub vesting_reward: u128,
    pub vesting_reward_display: String,
    pub vesting_bucket_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryNodeView {
    pub node_id: u64,
    pub previous_node_id: Option<u64>,
    pub name: String,
    pub owner_address: String,
    pub owner_public_key: String,
    pub relay_public_key: String,
    pub reward_address: String,
    pub endpoint: String,
    pub reward_ip: String,
    pub price_per_gib_base_units: String,
    pub price_per_gib_display: String,
    pub status: NodeStatus,
    pub registered_at: i64,
    pub warmup_until: i64,
    pub active_since: Option<i64>,
    pub last_probe_success: Option<i64>,
    pub probe_success_count: u64,
    pub availability: Option<RegistryNodeAvailability>,
    pub probe_valid_until: Option<i64>,
    pub offline_exit_at: Option<i64>,
    pub owns_ip_slot: bool,
    pub ip_slot_reusable_at: Option<i64>,
    pub service_bond_base_units: String,
    pub service_bond_display: String,
    pub service_bond_unlock_at: Option<i64>,
    pub governance_bond_base_units: String,
    pub governance_bond_display: String,
    pub governance_bonded_at: Option<i64>,
    pub governance_exit_requested_at: Option<i64>,
    pub governance_bond_unlock_at: Option<i64>,
    pub offline_slashed_at: Option<i64>,
    pub validator: bool,
    pub validator_candidate: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryNodeAvailability {
    Online,
    ProbeStale,
    Unverified,
    IpSlotUnavailable,
    ExitPending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryNodeListView {
    pub nodes: Vec<RegistryNodeView>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayDiscoveryView {
    pub node_id: u64,
    pub endpoint: String,
    pub reward_ip: String,
    pub price_per_gib_base_units: String,
    pub price_per_gib_display: String,
    pub last_probe_success: i64,
    pub probe_valid_until: i64,
    pub validator: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayDiscoveryListView {
    pub relays: Vec<RelayDiscoveryView>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberPresenceView {
    pub name: String,
    pub member_id: String,
    pub serial: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub online: bool,
    pub connection_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberPresenceListView {
    pub network: String,
    pub network_id: String,
    pub relay_node_id: u64,
    pub observed_at: i64,
    pub members: Vec<MemberPresenceView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AvailabilityProbeRequest {
    pub target: NodeRecord,
    pub verifier_node_id: u64,
    pub epoch: u64,
    pub slot: i64,
    pub role: AvailabilityVerifierRole,
    pub ticket_signature: String,
    pub scheduled_at: i64,
    pub challenge: String,
}

pub struct AvailabilityTicketSigner {
    node_id: u64,
    owner_key: Ed25519KeyPair,
}

pub fn availability_ticket_signer(
    paths: &DataPaths,
    verifier_name: &str,
    password: &str,
) -> Result<AvailabilityTicketSigner> {
    let node_id = paths
        .read_node_config(verifier_name)?
        .node_id
        .ok_or_else(|| Error::msg("Probe verifier Node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(verifier_name)?)?;
    Ok(AvailabilityTicketSigner {
        node_id,
        owner_key: decrypt_key(&owner_file, password)?,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct AvailabilitySubmissionView {
    pub operation_id: String,
    pub target_node_id: u64,
    pub verifier_node_id: u64,
    pub slot: i64,
    pub role: AvailabilityVerifierRole,
    pub primary_attestation_count: usize,
    pub primary_quorum: u32,
    pub audit_required: bool,
    pub audit_attestation_count: usize,
    pub audit_quorum: u32,
    pub credited_seconds: u64,
}

pub struct AvailabilityAttestationRequest {
    pub epoch: u64,
    pub slot: i64,
    pub role: AvailabilityVerifierRole,
    pub ticket_signature: String,
    pub response: ProbePayload,
    pub now: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapSnapshot {
    pub ledger_id: String,
    pub height: u64,
    pub state_root: String,
    pub checkpoint: LedgerState,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootstrapCheckpointView {
    pub height: u64,
    pub finalized_at: i64,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootstrapInstallReport {
    pub ledger_id: String,
    pub height: u64,
    pub state_root: String,
    pub peer: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerBackupPayload {
    pub format_version: u32,
    pub created_at: i64,
    pub ledger_id: String,
    pub height: u64,
    pub state_root: String,
    pub ledger: LedgerState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerBackup {
    pub checksum: String,
    pub payload: LedgerBackupPayload,
}

#[derive(Clone, Debug, Serialize)]
pub struct LedgerBackupReport {
    pub path: String,
    pub height: u64,
    pub state_root: String,
    pub checksum: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceStatusView {
    pub mode: String,
    pub threshold: usize,
    pub critical_threshold: usize,
    pub node1_direct_end_threshold: usize,
    pub governance_eligible_count: usize,
    pub governance_eligible_node_ids: Vec<u64>,
    pub genesis_node_id: Option<u64>,
    pub genesis_owner_address: Option<String>,
    pub node1_direct_actions_enabled: bool,
    pub emission_paused: bool,
    pub pause_reason: Option<String>,
    pub current_epoch_number: u64,
    pub current_epoch_started_at: i64,
    pub current_epoch_ends_at: i64,
    pub current_epoch_seconds: i64,
    pub current_epoch_mint_amount: u128,
    pub current_epoch_mint_amount_display: String,
    pub current_reward_immediate_bps: u32,
    pub current_reward_vesting_seconds: i64,
    pub availability_mode: AvailabilityMode,
    pub availability_activated_at: Option<i64>,
    pub availability_activated_epoch: Option<u64>,
    pub minimum_decentralized_availability_validators: usize,
    pub settings: LedgerSettings,
    pub scheduled_parameter_changes: BTreeMap<u64, BTreeMap<String, String>>,
    pub parameters: Vec<GovernanceParameterView>,
    pub last_action_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceParameterView {
    pub name: String,
    pub category: String,
    pub governance: String,
    pub current_value: String,
    pub configured_value: String,
    pub scheduled_changes: Vec<ScheduledGovernanceParameterView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScheduledGovernanceParameterView {
    pub effective_epoch: u64,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceReceipt {
    pub operation_id: String,
    pub status: OperationStatus,
    pub action: String,
    pub signer_node_id: u64,
    pub executed_at: i64,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceBondStatusView {
    pub node_id: u64,
    pub eligible: bool,
    pub governance_bond: u128,
    pub governance_bond_display: String,
    pub required_bond: u128,
    pub required_bond_display: String,
    pub bonded_at: Option<i64>,
    pub matures_at: Option<i64>,
    pub exit_requested_at: Option<i64>,
    pub bond_unlock_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceBondReceipt {
    pub operation_id: String,
    pub status: OperationStatus,
    pub node_id: u64,
    pub bonded: u128,
    pub bonded_display: String,
    pub total_governance_bond: u128,
    pub total_governance_bond_display: String,
    pub bonded_at: i64,
    pub matures_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TreasuryStatusView {
    pub balance: u128,
    pub balance_display: String,
    pub genesis_allocation: u128,
    pub genesis_allocation_display: String,
    pub total_spent: u128,
    pub total_spent_display: String,
    pub spend_count: usize,
    pub governance_eligible_count: usize,
    pub active_validator_count: usize,
    pub minimum_active_validators: usize,
    pub spending_enabled: bool,
    pub single_spend_limit_bps: u128,
    pub current_single_spend_limit: u128,
    pub current_single_spend_limit_display: String,
    pub mature_governance_node_count: usize,
    pub minimum_mature_governance_nodes: usize,
    pub ninety_day_spent: u128,
    pub ninety_day_spent_display: String,
    pub ninety_day_limit: u128,
    pub ninety_day_limit_display: String,
    pub annual_spent: u128,
    pub annual_spent_display: String,
    pub annual_limit: u128,
    pub annual_limit_display: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GovernanceTallyView {
    pub proposal_id: u64,
    pub status: GovernanceProposalStatus,
    pub total_power: u128,
    pub yes_power: u128,
    pub no_power: u128,
    pub abstain_power: u128,
    pub participation_power: u128,
    pub validator_total: usize,
    pub validator_yes: usize,
    pub validator_no: usize,
    pub validator_abstain: usize,
    pub validator_quorum: usize,
    pub timelock_veto_power: u128,
    pub voting_ends_at: i64,
    pub execute_after: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockStatusView {
    pub mode: String,
    pub height: u64,
    pub burned_base_units: String,
    pub burned_display: String,
    pub total_settled_traffic_bytes: String,
    pub total_settled_traffic_display: String,
    pub last_block_hash: Option<String>,
    pub last_block_at: Option<i64>,
    pub pending_operation_count: usize,
    pub producer_node_id: Option<u64>,
    pub node1_production_enabled: bool,
    pub governance_eligible_count: usize,
    pub threshold: usize,
    pub active_validator_count: usize,
    pub minimum_active_validators: usize,
    pub availability_mode: AvailabilityMode,
    pub availability_earning_enabled: bool,
    pub minimum_decentralized_availability_validators: usize,
    pub pruned_through_height: u64,
    pub retained_block_count: usize,
    pub retained_operation_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockSummaryView {
    pub height: u64,
    pub block_hash: String,
    pub timestamp: i64,
    pub producer_node_id: u64,
    pub operation_count: usize,
    pub consensus_mode: BlockConsensusMode,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockListView {
    pub blocks: Vec<BlockSummaryView>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockOperationListView {
    pub operations: Vec<OperationRecord>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockVerificationReport {
    pub ok: bool,
    pub height: u64,
    pub checked_operations: usize,
    pub legacy_unverified_operations: usize,
    pub pruned_through_height: u64,
    pub pruned_operation_count: u64,
    pub detail: String,
}

pub const BOOTSTRAP_CHECKPOINT_RETENTION: usize = crate::checkpoint::RETENTION;
pub const BOOTSTRAP_CHECKPOINT_INTERVAL_SECONDS: i64 = crate::checkpoint::INTERVAL_SECONDS;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusCatchUpChunk {
    pub tip_height: u64,
    pub blocks: Vec<BlockRecord>,
    pub operations: Vec<OperationRecord>,
    pub finalized_checkpoint: Option<Box<LedgerState>>,
}

pub fn consensus_catch_up_chunk(
    paths: &DataPaths,
    from_height: u64,
    max_blocks: usize,
) -> Result<ConsensusCatchUpChunk> {
    let history = paths.consensus_catch_up_history(from_height, max_blocks)?;
    Ok(ConsensusCatchUpChunk {
        tip_height: history.tip_height,
        blocks: history.blocks,
        operations: history.operations,
        finalized_checkpoint: history.finalized_checkpoint,
    })
}

pub fn apply_consensus_catch_up(
    paths: &DataPaths,
    blocks: Vec<BlockRecord>,
    operations: Vec<OperationRecord>,
    finalized_checkpoint: LedgerState,
) -> Result<u64> {
    if blocks.is_empty() {
        return Ok(chain_height(&paths.read_ledger()?));
    }
    let height = paths.with_ledger_mut(|ledger| {
        let local_height = chain_height(ledger);
        let local_tip_hash = chain_tip_hash(ledger)
            .unwrap_or(GENESIS_PREVIOUS_BLOCK_HASH)
            .to_owned();
        let mut expected_previous = local_tip_hash;
        for (offset, block) in blocks.iter().enumerate() {
            let expected_height = local_height + 1 + offset as u64;
            if block.height != expected_height || block.previous_block_hash != expected_previous {
                return Err(Error::msg(
                    "catch-up blocks are not a contiguous chain extension",
                ));
            }
            expected_previous = block.block_hash.clone();
        }
        let new_height = blocks.last().expect("non-empty").height;
        let finalized_operation_ids = blocks
            .iter()
            .flat_map(|block| block.operation_ids.iter())
            .collect::<BTreeSet<_>>();
        if ledger.pending_operation_ids.iter().any(|operation_id| {
            !finalized_operation_ids.contains(operation_id)
                && !finalized_checkpoint
                    .pending_operation_ids
                    .contains(operation_id)
        }) {
            return Err(Error::msg(
                "catch-up would discard a locally pending operation",
            ));
        }
        if finalized_checkpoint.ledger_id != ledger.ledger_id
            || finalized_checkpoint.genesis_authority != ledger.genesis_authority
            || finalized_checkpoint.pruned_through_height != new_height
            || finalized_checkpoint.pruned_tip_hash.as_deref()
                != blocks.last().map(|block| block.block_hash.as_str())
            || finalized_checkpoint.pruned_tip_timestamp
                != blocks.last().map(|block| block.timestamp)
        {
            return Err(Error::msg(
                "catch-up finalized checkpoint metadata is invalid",
            ));
        }
        for (node_id, local_node) in &ledger.nodes {
            if let Some(remote_node) = finalized_checkpoint.nodes.get(node_id)
                && (remote_node.owner_address != local_node.owner_address
                    || remote_node.owner_public_key != local_node.owner_public_key)
            {
                return Err(Error::msg(format!(
                    "catch-up attempted to replace immutable Owner identity for Node {node_id}"
                )));
            }
        }
        if ledger.consensus.active_validators.len() >= MIN_ACTIVE_VALIDATORS
            && let Some(first_multi) = blocks
                .iter()
                .find(|block| block.consensus_mode == BlockConsensusMode::MultiValidator)
            && first_multi.validator_node_ids != ledger.consensus.active_validators
        {
            return Err(Error::msg(
                "first catch-up Validator set does not match the locally trusted committee",
            ));
        }
        let mut previous_validators: Option<&[u64]> = None;
        for block in blocks
            .iter()
            .filter(|block| block.consensus_mode == BlockConsensusMode::MultiValidator)
        {
            if let Some(previous) = previous_validators {
                let overlap = block
                    .validator_node_ids
                    .iter()
                    .filter(|node_id| previous.contains(node_id))
                    .count();
                if overlap < consensus_quorum(previous.len()) {
                    return Err(Error::msg(
                        "catch-up Validator rotation does not preserve a trusted quorum",
                    ));
                }
            }
            previous_validators = Some(&block.validator_node_ids);
        }

        let local_heartbeats = ledger
            .nodes
            .iter()
            .map(|(node_id, node)| (*node_id, node.last_heartbeat))
            .collect::<BTreeMap<_, _>>();
        let mut candidate = finalized_checkpoint;
        for (node_id, node) in &mut candidate.nodes {
            node.last_heartbeat = local_heartbeats.get(node_id).copied().flatten();
        }
        let mut combined_blocks = ledger.blocks.clone();
        combined_blocks.extend(blocks);
        candidate.blocks = combined_blocks;
        candidate.pruned_through_height = ledger.pruned_through_height;
        candidate.pruned_tip_hash = ledger.pruned_tip_hash.clone();
        candidate.pruned_tip_timestamp = ledger.pruned_tip_timestamp;
        let mut combined_operations = ledger.operations.clone();
        combined_operations.extend(
            operations
                .into_iter()
                .map(|operation| (operation.operation_id.clone(), operation)),
        );
        combined_operations.extend(candidate.operations.clone());
        candidate.operations = combined_operations;
        candidate.finalized_checkpoint = None;
        let checkpoint_root = ledger_state_root(&candidate)?;
        let finalized_root = &candidate.blocks.last().expect("combined chain").state_root;
        if &checkpoint_root != finalized_root {
            return Err(Error::msg(format!(
                "catch-up checkpoint root {checkpoint_root} does not match finalized root {finalized_root}",
            )));
        }
        verify_blockchain_inner(&candidate)?;
        *ledger = candidate;
        update_finalized_checkpoint(ledger);
        Ok(new_height)
    })?;
    persist_latest_bootstrap_checkpoint(paths)?;
    Ok(height)
}

pub fn prune_lite_history(paths: &DataPaths, name: &str) -> Result<HistoryPruneReport> {
    let config = paths.read_node_config(name)?;
    let ledger = paths.read_ledger()?;
    let retained_block_limit = lite_retain_blocks(ledger.settings.block_interval_seconds);
    if config.storage_mode != NodeStorageMode::Lite
        || (ledger.blocks.len() <= retained_block_limit
            && ledger
                .accounts
                .values()
                .all(|account| account.operation_ids.len() <= LITE_RETAIN_ACCOUNT_OPERATIONS))
    {
        return Ok(HistoryPruneReport {
            pruned_through_height: ledger.pruned_through_height,
            retained_blocks: ledger.blocks.len(),
            retained_operations: ledger.operations.len(),
            ..HistoryPruneReport::default()
        });
    }
    let report = paths.with_ledger_mut(|ledger| {
        Ok(crate::store::prune_history(
            ledger,
            retained_block_limit,
            LITE_RETAIN_ACCOUNT_OPERATIONS,
        ))
    })?;
    Ok(report)
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorStatusView {
    pub node_id: u64,
    pub candidate: bool,
    pub active_validator: bool,
    pub validator_bond: u128,
    pub validator_bond_display: String,
    pub required_bond: u128,
    pub required_bond_display: String,
    pub candidate_since: Option<i64>,
    pub last_validator_epoch: Option<u64>,
    pub consecutive_epochs: u64,
    pub exit_requested_at: Option<i64>,
    pub bond_unlock_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorCommitteeView {
    pub epoch: u64,
    pub validator_set_hash: String,
    pub active_validator_ids: Vec<u64>,
    pub candidate_node_ids: Vec<u64>,
    pub max_active_validators: u32,
    pub max_rotations_per_selection: u32,
    pub rotation_interval_epochs: u32,
    pub last_selection_epoch: Option<u64>,
    pub next_scheduled_rotation_epoch: u64,
    pub quorum: usize,
    pub next_height: u64,
    pub current_round: u32,
    pub proposer_node_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorBondReceipt {
    pub operation_id: String,
    pub status: OperationStatus,
    pub node_id: u64,
    pub bonded: u128,
    pub bonded_display: String,
    pub total_validator_bond: u128,
    pub total_validator_bond_display: String,
    pub candidate: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockSigningPayload {
    version: u32,
    ledger_id: String,
    height: u64,
    previous_block_hash: String,
    timestamp: i64,
    producer_node_id: u64,
    producer_owner_address: String,
    operation_ids: Vec<String>,
    state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MultiValidatorBlockSigningPayload {
    version: u32,
    ledger_id: String,
    height: u64,
    previous_block_hash: String,
    timestamp: i64,
    producer_node_id: u64,
    producer_owner_address: String,
    operation_ids: Vec<String>,
    state_root: String,
    consensus_mode: BlockConsensusMode,
    consensus_round: u32,
    validator_set_hash: String,
    validator_epoch: u64,
    validator_node_ids: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConsensusVoteSigningPayload {
    ledger_id: String,
    height: u64,
    round: u32,
    vote_type: ConsensusVoteType,
    block_hash: Option<String>,
    validator_set_hash: String,
    validator_node_id: u64,
    timestamp: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusStatusView {
    pub mode: String,
    pub height: u64,
    pub round: u32,
    pub round_started_at: Option<i64>,
    pub next_block_at: Option<i64>,
    pub proposer_node_id: Option<u64>,
    pub proposal_block_hash: Option<String>,
    pub prevote_count: usize,
    pub precommit_count: usize,
    pub prevote_validator_ids: Vec<u64>,
    pub precommit_validator_ids: Vec<u64>,
    pub quorum: usize,
    pub active_validator_ids: Vec<u64>,
    pub validator_set_hash: String,
    pub locked_validators: BTreeMap<u64, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusSubmissionView {
    pub accepted: bool,
    pub duplicate: bool,
    pub double_sign_detected: bool,
    pub finalized_block: Option<BlockRecord>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    pub ok: bool,
    pub checks: Vec<DiagnosticCheck>,
}

impl DiagnosticReport {
    fn new(checks: Vec<DiagnosticCheck>) -> Self {
        Self {
            ok: checks.iter().all(|check| check.ok),
            checks,
        }
    }
}

pub fn create_account(paths: &DataPaths, name: &str, password: &str) -> Result<EncryptedKeyFile> {
    let keyfile = create_local_account(paths, name, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_account(ledger, &keyfile)?;
        Ok(())
    })?;
    Ok(keyfile)
}

pub fn create_local_account(
    paths: &DataPaths,
    name: &str,
    password: &str,
) -> Result<EncryptedKeyFile> {
    validate_name(name)?;
    let path = paths.account_key_path(name)?;
    if path.exists() {
        return Err(Error::msg(format!("account '{name}' already exists")));
    }
    let keyfile = generate_keyfile(password)?;
    paths.write_keyfile(&path, &keyfile)?;
    Ok(keyfile)
}

pub fn system_diagnostics(paths: &DataPaths) -> Result<DiagnosticReport> {
    let ledger = paths.read_ledger()?;
    let mut checks = Vec::new();
    let supply_consistent = ledger
        .pool_remaining
        .checked_add(ledger.lifetime_minted)
        .is_some_and(|total| total == crate::amount::MAX_SUPPLY);
    checks.push(DiagnosticCheck {
        name: "supply_invariant".to_owned(),
        ok: supply_consistent,
        detail: format!(
            "pool_remaining={} lifetime_minted={} max_supply={}",
            ledger.pool_remaining,
            ledger.lifetime_minted,
            crate::amount::MAX_SUPPLY
        ),
    });
    let genesis_treasury_consistent = ledger.genesis_treasury_minted
        == crate::amount::GENESIS_TREASURY_ALLOCATION
        && ledger.lifetime_minted >= ledger.genesis_treasury_minted;
    checks.push(DiagnosticCheck {
        name: "genesis_treasury_invariant".to_owned(),
        ok: genesis_treasury_consistent,
        detail: format!(
            "genesis_treasury_minted={} expected={} current_treasury={}",
            ledger.genesis_treasury_minted,
            crate::amount::GENESIS_TREASURY_ALLOCATION,
            ledger.treasury,
        ),
    });
    checks.push(private_permissions_check(
        "data_directory_permissions",
        &paths.root,
        true,
    ));
    checks.push(DiagnosticCheck {
        name: "ledger_readable".to_owned(),
        ok: true,
        detail: format!(
            "accounts={} networks={} nodes={} operations={}",
            ledger.accounts.len(),
            ledger.networks.len(),
            ledger.nodes.len(),
            ledger.operations.len()
        ),
    });
    let (genesis_ok, genesis_detail) = match (ledger.nodes.get(&1), &ledger.genesis_authority) {
        (None, None) if ledger.nodes.is_empty() => {
            (true, "Genesis Node 1 is not registered yet".to_owned())
        }
        (Some(node), Some(authority))
            if authority.node_id == 1
                && authority.owner_address == node.owner_address
                && authority.owner_public_key == node.owner_public_key =>
        {
            (true, format!("Node 1 owner={}", authority.owner_address))
        }
        (Some(node), None) => (
            true,
            format!(
                "legacy ledger; Node 1 owner={} will be pinned on first governance action",
                node.owner_address
            ),
        ),
        _ => (
            false,
            "Genesis authority is missing or does not match registered Node 1".to_owned(),
        ),
    };
    checks.push(DiagnosticCheck {
        name: "genesis_authority_integrity".to_owned(),
        ok: genesis_ok,
        detail: genesis_detail,
    });
    let (blockchain_ok, blockchain_detail) = if ledger.nodes.is_empty() {
        (true, "waiting for Genesis Node 1".to_owned())
    } else {
        match verify_blockchain_inner(&ledger) {
            Ok((operations, legacy)) => (
                true,
                format!(
                    "height={} committed_operations={operations} legacy_unverified={legacy}",
                    ledger.blocks.len()
                ),
            ),
            Err(error) => (false, error.to_string()),
        }
    };
    checks.push(DiagnosticCheck {
        name: "blockchain_integrity".to_owned(),
        ok: blockchain_ok,
        detail: blockchain_detail,
    });
    Ok(DiagnosticReport::new(checks))
}

pub fn node_diagnostics(paths: &DataPaths, name: &str, now: i64) -> Result<DiagnosticReport> {
    let node = node_record(paths, name)?;
    let ledger = paths.read_ledger()?;
    let mut checks = Vec::new();
    checks.push(DiagnosticCheck {
        name: "node_state".to_owned(),
        ok: !matches!(node.status, NodeStatus::Exited | NodeStatus::Suspended),
        detail: node.status.to_string(),
    });
    checks.push(match verify_registered_endpoint(paths, name) {
        Ok(ip) => DiagnosticCheck {
            name: "endpoint_dns".to_owned(),
            ok: true,
            detail: format!("{} resolves to registered {ip}", node.endpoint),
        },
        Err(error) => DiagnosticCheck {
            name: "endpoint_dns".to_owned(),
            ok: false,
            detail: error.to_string(),
        },
    });
    let probe_age = node
        .last_probe_success
        .map(|probe| now.saturating_sub(probe));
    checks.push(DiagnosticCheck {
        name: "probe_freshness".to_owned(),
        ok: probe_age.is_some_and(|age| age <= ledger.settings.probe_validity_seconds),
        detail: probe_age.map_or_else(
            || "no successful Probe recorded".to_owned(),
            |age| {
                format!(
                    "last success {age}s ago; validity {}s",
                    ledger.settings.probe_validity_seconds
                )
            },
        ),
    });
    checks.push(private_permissions_check(
        "owner_key_permissions",
        &paths.node_owner_key_path(name)?,
        false,
    ));
    checks.push(private_permissions_check(
        "relay_key_permissions",
        &paths.node_relay_key_path(name)?,
        false,
    ));
    checks.push(private_permissions_check(
        "reward_key_permissions",
        &paths.node_reward_key_path(name)?,
        false,
    ));
    Ok(DiagnosticReport::new(checks))
}

fn private_permissions_check(
    name: &str,
    path: &std::path::Path,
    directory: bool,
) -> DiagnosticCheck {
    let metadata = std::fs::metadata(path);
    match metadata {
        Err(error) => DiagnosticCheck {
            name: name.to_owned(),
            ok: false,
            detail: format!("{}: {error}", path.display()),
        },
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let actual = metadata.permissions().mode() & 0o777;
                let allowed = if directory { 0o700 } else { 0o600 };
                DiagnosticCheck {
                    name: name.to_owned(),
                    ok: actual & !allowed == 0,
                    detail: format!(
                        "{} mode={actual:03o} expected<={allowed:03o}",
                        path.display()
                    ),
                }
            }
            #[cfg(not(unix))]
            {
                DiagnosticCheck {
                    name: name.to_owned(),
                    ok: true,
                    detail: format!(
                        "{} exists; ACL inspection is platform-specific",
                        path.display()
                    ),
                }
            }
        }
    }
}

pub fn account_keyfile(paths: &DataPaths, name: &str) -> Result<EncryptedKeyFile> {
    if let Some(node_name) = name.strip_prefix("node:") {
        validate_name(node_name)?;
        return paths.read_keyfile(&paths.node_reward_key_path(node_name)?);
    }
    paths.read_keyfile(&paths.account_key_path(name)?)
}

pub fn balance(paths: &DataPaths, address: &str) -> Result<BalanceView> {
    validate_address(address)?;
    let ledger = paths.read_ledger()?;
    let state = ledger.accounts.get(address).cloned().unwrap_or_default();
    Ok(BalanceView {
        address: address.to_owned(),
        balance: state.balance,
        balance_display: format_mrk(state.balance),
        nonce: state.nonce,
    })
}

pub fn account_rankings(
    paths: &DataPaths,
    cursor: Option<&str>,
    limit: usize,
) -> Result<AccountRankingListView> {
    validate_registry_page_limit(limit)?;
    let (ledger_id, epoch, snapshot) = paths.account_ranking_snapshot()?;
    let snapshot = snapshot.ok_or_else(|| {
        Error::msg("account ranking will be available after the first completed Epoch")
    })?;
    if snapshot.ledger_id != ledger_id || snapshot.epoch.checked_add(1) != Some(epoch) {
        return Err(Error::msg(
            "account ranking is waiting for this Node's next completed Epoch",
        ));
    }
    let offset = cursor.map_or(Ok(0), |cursor| {
        parse_account_ranking_cursor(cursor, snapshot.epoch, snapshot.height)
    })?;
    if offset > snapshot.accounts.len() {
        return Err(Error::msg("account ranking cursor is out of range"));
    }
    let end = offset.saturating_add(limit).min(snapshot.accounts.len());
    let accounts = snapshot.accounts[offset..end]
        .iter()
        .enumerate()
        .map(|(index, account)| AccountRankingEntryView {
            rank: (offset + index) as u64 + 1,
            address: account.address.clone(),
            balance_base_units: account.balance.to_string(),
            balance_display: format_mrk(account.balance),
            balance_share_bps: u32::try_from(
                account
                    .balance
                    .saturating_mul(BPS_DENOMINATOR)
                    .checked_div(snapshot.total_balance)
                    .unwrap_or(0),
            )
            .expect("account balance share is at most 10,000 bps"),
        })
        .collect();
    let next_cursor = (end < snapshot.accounts.len())
        .then(|| account_ranking_cursor(snapshot.epoch, snapshot.height, end));
    Ok(AccountRankingListView {
        accounts,
        funded_account_count: snapshot.accounts.len(),
        total_account_balance_base_units: snapshot.total_balance.to_string(),
        total_account_balance_display: format_mrk(snapshot.total_balance),
        snapshot_epoch: snapshot.epoch,
        snapshot_height: snapshot.height,
        next_cursor,
    })
}

fn account_ranking_cursor(epoch: u64, height: u64, offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(format!("{epoch}:{height}:{offset}"))
}

fn parse_account_ranking_cursor(cursor: &str, epoch: u64, height: u64) -> Result<usize> {
    let decoded = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| Error::msg("account ranking cursor is invalid"))?;
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| Error::msg("account ranking cursor is invalid"))?;
    let mut fields = decoded.split(':');
    let cursor_epoch = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| Error::msg("account ranking cursor is invalid"))?;
    let cursor_height = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| Error::msg("account ranking cursor is invalid"))?;
    let offset = fields
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|_| fields.next().is_none())
        .ok_or_else(|| Error::msg("account ranking cursor is invalid"))?;
    if cursor_epoch != epoch || cursor_height != height {
        return Err(Error::msg(
            "account ranking cursor belongs to another snapshot",
        ));
    }
    Ok(offset)
}

pub fn treasury_status(paths: &DataPaths, now: i64) -> Result<TreasuryStatusView> {
    let ledger = paths.read_ledger()?;
    let eligible_count = governance_eligible_node_ids(&ledger, now).len();
    let mature_count = treasury_governance_node_ids(&ledger, now).len();
    let active_validator_count = ledger.consensus.active_validators.len();
    let total_spent = ledger
        .treasury_spends
        .iter()
        .try_fold(0_u128, |total, spend| total.checked_add(spend.amount))
        .ok_or_else(|| Error::msg("treasury spend history overflow"))?;
    let limit = ledger.treasury.saturating_mul(TREASURY_SINGLE_SPEND_BPS) / 10_000;
    let ninety_day_spent = treasury_spent_since(&ledger, now - 90 * 86_400)?;
    let annual_spent = treasury_spent_since(&ledger, now - 365 * 86_400)?;
    let ninety_day_limit = ledger
        .treasury
        .saturating_mul(TREASURY_NINETY_DAY_SPEND_BPS)
        / 10_000;
    let annual_limit = ledger.treasury.saturating_mul(TREASURY_ANNUAL_SPEND_BPS) / 10_000;
    Ok(TreasuryStatusView {
        balance: ledger.treasury,
        balance_display: format_mrk(ledger.treasury),
        genesis_allocation: ledger.genesis_treasury_minted,
        genesis_allocation_display: format_mrk(ledger.genesis_treasury_minted),
        total_spent,
        total_spent_display: format_mrk(total_spent),
        spend_count: ledger.treasury_spends.len(),
        governance_eligible_count: eligible_count,
        active_validator_count,
        minimum_active_validators: MIN_ACTIVE_VALIDATORS,
        spending_enabled: mature_count >= CRITICAL_GOVERNANCE_NODE_THRESHOLD
            && active_validator_count >= MIN_ACTIVE_VALIDATORS,
        single_spend_limit_bps: TREASURY_SINGLE_SPEND_BPS,
        current_single_spend_limit: limit,
        current_single_spend_limit_display: format_mrk(limit),
        mature_governance_node_count: mature_count,
        minimum_mature_governance_nodes: CRITICAL_GOVERNANCE_NODE_THRESHOLD,
        ninety_day_spent,
        ninety_day_spent_display: format_mrk(ninety_day_spent),
        ninety_day_limit,
        ninety_day_limit_display: format_mrk(ninety_day_limit),
        annual_spent,
        annual_spent_display: format_mrk(annual_spent),
        annual_limit,
        annual_limit_display: format_mrk(annual_limit),
    })
}

pub fn treasury_history(paths: &DataPaths, limit: usize) -> Result<Vec<TreasurySpendRecord>> {
    let ledger = paths.read_ledger()?;
    Ok(ledger
        .treasury_spends
        .iter()
        .rev()
        .take(limit.min(1_000))
        .cloned()
        .collect())
}

pub fn preview_transfer(
    paths: &DataPaths,
    account: &str,
    to: &str,
    amount_text: &str,
    now: i64,
) -> Result<TransferPreview> {
    let keyfile = account_keyfile(paths, account)?;
    validate_address(to)?;
    if keyfile.address == to {
        return Err(Error::msg("refusing to transfer MRK to the same address"));
    }
    let amount = parse_mrk(amount_text)?;
    if amount == 0 {
        return Err(Error::msg("transfer amount must be greater than zero"));
    }
    let ledger = paths.read_ledger()?;
    let payload = json!({
        "to": to,
        "amount_base_units": amount.to_string(),
    });
    let fee = fee::quote(&ledger, "Asset", "Transfer", &payload)?.fee;
    let total = amount
        .checked_add(fee)
        .ok_or_else(|| Error::msg("transfer total overflow"))?;
    let sender = ledger
        .accounts
        .get(&keyfile.address)
        .cloned()
        .unwrap_or_default();
    if sender.balance < total {
        return Err(Error::msg(format!(
            "insufficient spendable MRK: available {}, required {}",
            format_mrk(sender.balance),
            format_mrk(total)
        )));
    }
    Ok(TransferPreview {
        ledger_id: ledger.ledger_id,
        from: keyfile.address,
        to: to.to_owned(),
        amount,
        fee,
        total,
        nonce: sender.nonce + 1,
        valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
    })
}

pub fn transfer(
    paths: &DataPaths,
    account: &str,
    password: &str,
    to: &str,
    amount_text: &str,
    now: i64,
) -> Result<TransferReceipt> {
    let preview = preview_transfer(paths, account, to, amount_text, now)?;
    let keyfile = account_keyfile(paths, account)?;
    let key_pair = decrypt_key(&keyfile, password)?;
    paths.with_ledger_mut(|ledger| {
        if now > preview.valid_until {
            return Err(Error::msg("transfer expired before it could be submitted"));
        }
        let current = ledger
            .accounts
            .get(&preview.from)
            .cloned()
            .unwrap_or_default();
        if current.nonce + 1 != preview.nonce {
            return Err(Error::msg(
                "account nonce changed; preview the transfer again",
            ));
        }
        if current.balance < preview.total {
            return Err(Error::msg(
                "account balance changed; preview the transfer again",
            ));
        }
        let payload = json!({
            "to": preview.to,
            "amount_base_units": preview.amount.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&keyfile, &key_pair),
            "Asset",
            "Transfer",
            preview.nonce,
            preview.valid_until,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        if let Some(existing) = ledger.operations.get(&operation_id) {
            return Ok(TransferReceipt {
                operation_id,
                status: existing.status.clone(),
                from: preview.from.clone(),
                to: preview.to.clone(),
                amount: preview.amount,
                fee: preview.fee,
                submitted_at: existing.created_at,
            });
        }
        verify_operation(&signed, &keyfile.public_key)?;
        {
            let sender = ledger
                .accounts
                .get_mut(&preview.from)
                .expect("sender exists");
            sender.balance -= preview.amount;
        }
        ledger
            .accounts
            .entry(preview.to.clone())
            .or_default()
            .balance = ledger
            .accounts
            .get(&preview.to)
            .map(|account| account.balance)
            .unwrap_or_default()
            .checked_add(preview.amount)
            .ok_or_else(|| Error::msg("recipient balance overflow"))?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &preview.to, &operation_id);
        Ok(TransferReceipt {
            operation_id,
            status: OperationStatus::Pending,
            from: preview.from.clone(),
            to: preview.to.clone(),
            amount: preview.amount,
            fee: preview.fee,
            submitted_at: now,
        })
    })
}

pub struct TransferSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub to: &'a str,
    pub amount_text: &'a str,
    pub nonce: u64,
    pub valid_until: i64,
    pub max_fee_base_units: u128,
    pub fee_policy_version: u64,
}

pub struct PublicOperationSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub module: &'a str,
    pub action: &'a str,
    pub nonce: u64,
    pub valid_until: i64,
    pub max_fee_base_units: u128,
    pub fee_policy_version: u64,
    pub payload: Value,
}

pub fn sign_public_operation(
    keyfile: &EncryptedKeyFile,
    password: &str,
    request: PublicOperationSigningRequest<'_>,
) -> Result<SignedOperation> {
    let key_pair = decrypt_key(keyfile, password)?;
    let unsigned = UnsignedOperation {
        ledger_id: request.ledger_id.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        module: request.module.to_owned(),
        action: request.action.to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: request.nonce,
        valid_until: request.valid_until,
        max_fee_base_units: request.max_fee_base_units,
        fee_policy_version: request.fee_policy_version,
        payload: request.payload,
    };
    Ok(SignedOperation {
        signature: sign_bytes(&key_pair, &serde_json::to_vec(&unsigned)?),
        unsigned,
    })
}

pub fn sign_transfer_for_submission(
    keyfile: &EncryptedKeyFile,
    password: &str,
    request: TransferSigningRequest<'_>,
) -> Result<(String, SignedOperation)> {
    validate_address(request.to)?;
    if keyfile.address == request.to {
        return Err(Error::msg("refusing to transfer MRK to the same address"));
    }
    let amount = parse_mrk(request.amount_text)?;
    if amount == 0 {
        return Err(Error::msg("transfer amount must be greater than zero"));
    }
    let key_pair = decrypt_key(keyfile, password)?;
    let unsigned = UnsignedOperation {
        ledger_id: request.ledger_id.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        module: "Asset".to_owned(),
        action: "Transfer".to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: request.nonce,
        valid_until: request.valid_until,
        max_fee_base_units: request.max_fee_base_units,
        fee_policy_version: request.fee_policy_version,
        payload: json!({
            "to": request.to,
            "amount_base_units": amount.to_string(),
        }),
    };
    let signature = sign_bytes(&key_pair, &serde_json::to_vec(&unsigned)?);
    Ok((
        keyfile.public_key.clone(),
        SignedOperation {
            unsigned,
            signature,
        },
    ))
}

pub fn submit_signed_transfer(
    paths: &DataPaths,
    public_key: &str,
    operation: SignedOperation,
    now: i64,
) -> Result<TransferReceipt> {
    let submitted_at = operation
        .unsigned
        .valid_until
        .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS);
    let public_key_bytes = STANDARD
        .decode(public_key)
        .map_err(|_| Error::msg("operation public key is not valid base64"))?;
    if address_from_public_key(&public_key_bytes) != operation.unsigned.signer {
        return Err(Error::msg("operation public key does not match signer"));
    }
    verify_operation(&operation, public_key)?;
    if operation.unsigned.protocol_version != PROTOCOL_VERSION
        || operation.unsigned.module != "Asset"
        || operation.unsigned.action != "Transfer"
    {
        return Err(Error::msg("unsupported signed operation"));
    }
    if now > operation.unsigned.valid_until {
        return Err(Error::msg("signed transfer has expired"));
    }
    let to = operation
        .unsigned
        .payload
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg("signed transfer is missing recipient"))?
        .to_owned();
    validate_address(&to)?;
    let amount = parse_payload_u128(&operation.unsigned.payload, "amount_base_units")?;
    if amount == 0 {
        return Err(Error::msg("signed transfer amount is invalid"));
    }
    let operation_id = operation_id(&operation)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg("signed transfer targets a different ledger"));
        }
        let fee = fee::validate_envelope(ledger, &operation.unsigned)?.fee;
        let total = amount
            .checked_add(fee)
            .ok_or_else(|| Error::msg("signed transfer total overflow"))?;
        if let Some(existing) = ledger.operations.get(&operation_id) {
            return Ok(TransferReceipt {
                operation_id: operation_id.clone(),
                status: existing.status.clone(),
                from: operation.unsigned.signer.clone(),
                to: to.clone(),
                amount,
                fee,
                submitted_at: existing.created_at,
            });
        }
        let sender = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &sender.public_key {
            Some(existing) if existing != public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => sender.public_key = Some(public_key.to_owned()),
            _ => {}
        }
        if operation.unsigned.account_nonce != sender.nonce + 1 {
            return Err(Error::msg("operation nonce is not the next account nonce"));
        }
        if sender.balance < total {
            return Err(Error::msg("insufficient spendable MRK"));
        }
        sender.balance -= amount;
        ledger.accounts.entry(to.clone()).or_default().balance = ledger
            .accounts
            .get(&to)
            .map(|account| account.balance)
            .unwrap_or_default()
            .checked_add(amount)
            .ok_or_else(|| Error::msg("recipient balance overflow"))?;
        finalize_operation(ledger, &operation, &operation_id, submitted_at)?;
        add_history(ledger, &to, &operation_id);
        Ok(TransferReceipt {
            operation_id,
            status: OperationStatus::Pending,
            from: operation.unsigned.signer,
            to,
            amount,
            fee,
            submitted_at,
        })
    })
}

fn parse_payload_u128(payload: &Value, name: &str) -> Result<u128> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg(format!("signed operation is missing '{name}'")))?
        .parse()
        .map_err(|_| Error::msg(format!("signed operation '{name}' is invalid")))
}

pub fn network_by_alias(paths: &DataPaths, alias: &str) -> Result<NetworkRecord> {
    let ledger = paths.read_ledger()?;
    let commitment = resolve_network(&ledger, alias)?;
    ledger
        .networks
        .get(&commitment)
        .cloned()
        .ok_or_else(|| Error::msg("network registry is inconsistent"))
}

pub fn new_network_identity() -> Result<(String, String)> {
    let network_bytes = random_bytes::<32>()?;
    Ok((
        URL_SAFE_NO_PAD.encode(network_bytes),
        sha256_id("net", &network_bytes),
    ))
}

pub struct MemberIssueSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub network: &'a NetworkRecord,
    pub member_name: &'a str,
    pub valid_days: i64,
    pub nonce: u64,
    pub now: i64,
    pub max_fee_base_units: u128,
    pub fee_policy_version: u64,
}

pub fn prepare_member_issue(
    owner_file: &EncryptedKeyFile,
    password: &str,
    request: MemberIssueSigningRequest<'_>,
) -> Result<(EncryptedKeyFile, MemberCredential, SignedOperation)> {
    validate_name(request.member_name)?;
    if !(1..=365).contains(&request.valid_days) {
        return Err(Error::msg(
            "member credential validity must be between 1 and 365 days",
        ));
    }
    if request.network.owner_address != owner_file.address {
        return Err(Error::msg("only the Network Owner can issue members"));
    }
    let owner_key = decrypt_key(owner_file, password)?;
    let member_file = generate_keyfile(password)?;
    let mut credential = MemberCredential {
        version: PROTOCOL_VERSION,
        network_id: request.network.network_id.clone(),
        member_id: hex_lower(&random_bytes::<16>()?),
        member_public_key: member_file.public_key.clone(),
        permissions: vec![
            "connect".to_owned(),
            "send".to_owned(),
            "receive".to_owned(),
        ],
        max_connections: 1,
        serial: request.network.next_member_serial,
        issued_at: request.now,
        expires_at: request.now + request.valid_days * 86_400,
        owner_signature: String::new(),
    };
    credential.owner_signature = sign_bytes(&owner_key, &credential_signing_bytes(&credential)?);
    let operation = sign_public_operation(
        owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: request.ledger_id,
            module: "NetworkRegistry",
            action: "IssueMember",
            nonce: request.nonce,
            valid_until: request.now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            max_fee_base_units: request.max_fee_base_units,
            fee_policy_version: request.fee_policy_version,
            payload: json!({
                "network_commitment": request.network.commitment,
                "member_name": request.member_name,
                "credential": credential,
            }),
        },
    )?;
    Ok((member_file, credential, operation))
}

pub fn store_member_files(
    paths: &DataPaths,
    network: &str,
    member: &str,
    keyfile: &EncryptedKeyFile,
    credential: &MemberCredential,
) -> Result<std::path::PathBuf> {
    let key_path = paths.member_key_path(network, member)?;
    paths.write_keyfile(&key_path, keyfile)?;
    let credential_path = paths.member_credential_path(network, member)?;
    if let Some(parent) = credential_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_json(&credential_path, credential)?;
    Ok(credential_path)
}

pub struct SenderCheckpointSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub node_id: u64,
    pub authorization_id: &'a str,
    pub session_id: &'a str,
    pub direction: RelayDirection,
    pub sequence: u64,
    pub cumulative_sent_bytes: u64,
    pub transcript_hash: &'a str,
    pub checkpoint_at: i64,
}

pub fn sign_sender_checkpoint(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
    password: &str,
    request: SenderCheckpointSigningRequest<'_>,
) -> Result<SenderCheckpoint> {
    sign_sender_checkpoint_with_final(paths, network_name, member_name, password, request, false)
}

pub fn sign_final_sender_checkpoint(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
    password: &str,
    request: SenderCheckpointSigningRequest<'_>,
) -> Result<SenderCheckpoint> {
    sign_sender_checkpoint_with_final(paths, network_name, member_name, password, request, true)
}

fn sign_sender_checkpoint_with_final(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
    password: &str,
    request: SenderCheckpointSigningRequest<'_>,
    final_checkpoint: bool,
) -> Result<SenderCheckpoint> {
    let credential = member_credential(paths, network_name, member_name)?;
    let keyfile = paths.read_keyfile(&paths.member_key_path(network_name, member_name)?)?;
    if keyfile.public_key != credential.member_public_key {
        return Err(Error::msg(
            "member credential and key do not match for traffic checkpoint",
        ));
    }
    let key = decrypt_key(&keyfile, password)?;
    let mut checkpoint = SenderCheckpoint {
        ledger_id: request.ledger_id.to_owned(),
        protocol_version: PROTOCOL_VERSION,
        node_id: request.node_id,
        authorization_id: request.authorization_id.to_owned(),
        session_id: request.session_id.to_owned(),
        direction: request.direction,
        sequence: request.sequence,
        cumulative_sent_bytes: request.cumulative_sent_bytes,
        transcript_hash: request.transcript_hash.to_owned(),
        checkpoint_at: request.checkpoint_at,
        sender_member_id: credential.member_id,
        final_checkpoint,
        sender_signature: String::new(),
    };
    checkpoint.sender_signature = sign_bytes(&key, &sender_checkpoint_signing_bytes(&checkpoint)?);
    Ok(checkpoint)
}

pub fn sign_receiver_receipt(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
    password: &str,
    checkpoint: &SenderCheckpoint,
    received_at: i64,
) -> Result<ReceiverReceipt> {
    let credential = member_credential(paths, network_name, member_name)?;
    let keyfile = paths.read_keyfile(&paths.member_key_path(network_name, member_name)?)?;
    if keyfile.public_key != credential.member_public_key {
        return Err(Error::msg(
            "member credential and key do not match for traffic receipt",
        ));
    }
    let key = decrypt_key(&keyfile, password)?;
    let mut receipt = ReceiverReceipt {
        ledger_id: checkpoint.ledger_id.clone(),
        protocol_version: checkpoint.protocol_version,
        node_id: checkpoint.node_id,
        authorization_id: checkpoint.authorization_id.clone(),
        session_id: checkpoint.session_id.clone(),
        direction: checkpoint.direction,
        sequence: checkpoint.sequence,
        cumulative_received_bytes: checkpoint.cumulative_sent_bytes,
        transcript_hash: checkpoint.transcript_hash.clone(),
        sender_checkpoint_hash: sender_checkpoint_hash(checkpoint)?,
        received_at,
        receiver_member_id: credential.member_id,
        receiver_signature: String::new(),
    };
    receipt.receiver_signature = sign_bytes(&key, &receiver_receipt_signing_bytes(&receipt)?);
    Ok(receipt)
}

pub fn submit_signed_network_operation(
    paths: &DataPaths,
    public_key: &str,
    operation: SignedOperation,
    now: i64,
) -> Result<Value> {
    let submitted_at = operation
        .unsigned
        .valid_until
        .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS);
    let public_key_bytes = STANDARD
        .decode(public_key)
        .map_err(|_| Error::msg("operation public key is not valid base64"))?;
    if address_from_public_key(&public_key_bytes) != operation.unsigned.signer {
        return Err(Error::msg("operation public key does not match signer"));
    }
    verify_operation(&operation, public_key)?;
    if operation.unsigned.protocol_version != PROTOCOL_VERSION
        || now > operation.unsigned.valid_until
    {
        return Err(Error::msg(
            "signed operation version or validity is invalid",
        ));
    }
    let operation_id = operation_id(&operation)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg("signed operation targets a different ledger"));
        }
        let signer = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &signer.public_key {
            Some(existing) if existing != public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => signer.public_key = Some(public_key.to_owned()),
            _ => {}
        }
        if operation.unsigned.account_nonce != signer.nonce + 1 {
            return Err(Error::msg("operation nonce is not the next account nonce"));
        }
        let result = match (
            operation.unsigned.module.as_str(),
            operation.unsigned.action.as_str(),
        ) {
            ("NetworkRegistry", "CreateNetwork") => {
                let alias = payload_str(&operation.unsigned.payload, "alias")?.to_owned();
                validate_name(&alias)?;
                if ledger.network_aliases.contains_key(&alias) {
                    return Err(Error::msg(format!(
                        "network alias '{alias}' already exists"
                    )));
                }
                let network_id = payload_str(&operation.unsigned.payload, "network_id")?.to_owned();
                let network_bytes = URL_SAFE_NO_PAD
                    .decode(&network_id)
                    .map_err(|_| Error::msg("network ID is not valid base64url"))?;
                let commitment = sha256_id("net", &network_bytes);
                if payload_str(&operation.unsigned.payload, "network_commitment")? != commitment {
                    return Err(Error::msg("network commitment does not match network ID"));
                }
                let record = NetworkRecord {
                    network_id,
                    commitment: commitment.clone(),
                    alias: alias.clone(),
                    owner_address: operation.unsigned.signer.clone(),
                    owner_public_key: public_key.to_owned(),
                    created_at: submitted_at,
                    escrow_balance: 0,
                    next_member_serial: 1,
                    members: BTreeMap::new(),
                    spending_policy: Default::default(),
                };
                ledger.network_aliases.insert(alias, commitment.clone());
                ledger.networks.insert(commitment, record.clone());
                serde_json::to_value(record)?
            }
            ("NetworkEscrow", "FundNetwork") => {
                let commitment = payload_network_commitment(ledger, &operation.unsigned.payload)?;
                let amount = parse_payload_u128(&operation.unsigned.payload, "amount_base_units")?;
                if amount == 0 {
                    return Err(Error::msg("fund amount must be greater than zero"));
                }
                if ledger.networks[&commitment].owner_address != operation.unsigned.signer {
                    return Err(Error::msg("only the Network Owner can fund this network"));
                }
                if ledger.accounts[&operation.unsigned.signer].balance < amount {
                    return Err(Error::msg("insufficient spendable MRK"));
                }
                ledger
                    .accounts
                    .get_mut(&operation.unsigned.signer)
                    .expect("signer account")
                    .balance -= amount;
                ledger
                    .networks
                    .get_mut(&commitment)
                    .expect("network")
                    .escrow_balance += amount;
                json!({ "operation_id": operation_id, "status": "PENDING" })
            }
            ("NetworkEscrow", "SetSpendingPolicy") => {
                let commitment = payload_network_commitment(ledger, &operation.unsigned.payload)?;
                let revision = operation
                    .unsigned
                    .payload
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::msg("spending policy revision is invalid"))?;
                let enabled = operation
                    .unsigned
                    .payload
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| Error::msg("spending policy enabled flag is invalid"))?;
                let max_session_amount = parse_payload_u128(
                    &operation.unsigned.payload,
                    "max_session_amount_base_units",
                )?;
                let max_member_reserved = parse_payload_u128(
                    &operation.unsigned.payload,
                    "max_member_reserved_base_units",
                )?;
                let max_node_price_per_gib = parse_payload_u128(
                    &operation.unsigned.payload,
                    "max_node_price_per_gib_base_units",
                )?;
                let max_session_minutes = operation
                    .unsigned
                    .payload
                    .get("max_session_minutes")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| Error::msg("spending policy session duration is invalid"))?;
                let network = ledger.networks.get_mut(&commitment).expect("network");
                if network.owner_address != operation.unsigned.signer
                    || network.owner_public_key != public_key
                {
                    return Err(Error::msg(
                        "only the Network Owner can update its spending policy",
                    ));
                }
                if revision != network.spending_policy.revision.saturating_add(1) {
                    return Err(Error::msg("spending policy revision is stale"));
                }
                let policy = NetworkSpendingPolicy {
                    revision,
                    enabled,
                    max_session_amount,
                    max_member_reserved,
                    max_node_price_per_gib,
                    max_session_minutes,
                };
                validate_network_spending_policy(&policy)?;
                network.spending_policy = policy.clone();
                serde_json::to_value(policy)?
            }
            ("TrafficPayment", "ReserveSession") => {
                let commitment = payload_network_commitment(ledger, &operation.unsigned.payload)?;
                let reclaimed = ledger
                    .payment_authorizations
                    .values_mut()
                    .filter(|authorization| {
                        authorization.network_commitment == commitment
                            && authorization.refunded_at.is_none()
                            && authorization.closed_at.is_none()
                            && submitted_at > authorization.claim_until
                    })
                    .try_fold(0_u128, |total, authorization| {
                        let amount = authorization.reserved_remaining;
                        authorization.reserved_remaining = 0;
                        authorization.refunded_at = Some(submitted_at);
                        total
                            .checked_add(amount)
                            .ok_or_else(|| Error::msg("automatic reservation reclaim overflow"))
                    })?;
                if reclaimed > 0 {
                    let network = ledger.networks.get_mut(&commitment).expect("network");
                    network.escrow_balance = network
                        .escrow_balance
                        .checked_add(reclaimed)
                        .ok_or_else(|| Error::msg("Network Fund overflow during reclaim"))?;
                }
                let node_id = operation
                    .unsigned
                    .payload
                    .get("node_id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::msg("payment Node ID is invalid"))?;
                let sender_member_id =
                    payload_str(&operation.unsigned.payload, "sender_member_id")?.to_owned();
                let receiver_member_id =
                    payload_str(&operation.unsigned.payload, "receiver_member_id")?.to_owned();
                let session_id = payload_str(&operation.unsigned.payload, "session_id")?.to_owned();
                if sender_member_id == receiver_member_id {
                    return Err(Error::msg(
                        "payment sender and receiver must be different members",
                    ));
                }
                validate_payment_session_id(&session_id)?;
                if ledger
                    .payment_authorizations
                    .values()
                    .any(|authorization| authorization.session_id == session_id)
                {
                    return Err(Error::msg("payment Session ID is already in use"));
                }
                let requested_max_amount =
                    parse_payload_u128(&operation.unsigned.payload, "max_amount_base_units")?;
                if requested_max_amount == 0 {
                    return Err(Error::msg(
                        "payment maximum amount must be greater than zero",
                    ));
                }
                let authorization_valid_until = operation
                    .unsigned
                    .payload
                    .get("authorization_valid_until")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| Error::msg("payment authorization expiry is invalid"))?;
                let expected_policy_revision = operation
                    .unsigned
                    .payload
                    .get("spending_policy_revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::msg("spending policy revision is invalid"))?;
                let expected_price_per_gib = validate_price_per_gib(parse_payload_u128(
                    &operation.unsigned.payload,
                    "expected_price_per_gib_base_units",
                )?)?;
                let node = ledger
                    .nodes
                    .get(&node_id)
                    .ok_or_else(|| Error::msg("payment Node is not registered"))?;
                if matches!(
                    node.status,
                    NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
                ) {
                    return Err(Error::msg("payment Node is not accepting new sessions"));
                }
                if node.price_per_gib != expected_price_per_gib {
                    return Err(Error::msg(
                        "Relay Node price changed; refresh the quote before reserving a session",
                    ));
                }
                let price_per_gib = expected_price_per_gib;
                let network = ledger.networks.get(&commitment).expect("network");
                let policy = &network.spending_policy;
                if !policy.enabled {
                    return Err(Error::msg("member spending is disabled for this Network"));
                }
                if policy.revision != expected_policy_revision {
                    return Err(Error::msg("spending policy revision is stale"));
                }
                if price_per_gib > policy.max_node_price_per_gib {
                    return Err(Error::msg("Relay Node price exceeds the Network policy"));
                }
                if authorization_valid_until <= submitted_at
                    || authorization_valid_until.saturating_sub(submitted_at)
                        > i64::from(policy.max_session_minutes).saturating_mul(60)
                {
                    return Err(Error::msg(
                        "payment authorization exceeds the Network session duration policy",
                    ));
                }
                let sender = network
                    .members
                    .values()
                    .find(|member| member.member_id == sender_member_id)
                    .ok_or_else(|| Error::msg("payment sender member is not registered"))?;
                if sender.public_key != public_key
                    || address_from_public_key(
                        &STANDARD
                            .decode(&sender.public_key)
                            .map_err(|_| Error::msg("member public key is not valid base64"))?,
                    ) != operation.unsigned.signer
                {
                    return Err(Error::msg(
                        "only the initiating Network member can reserve a session",
                    ));
                }
                for member_id in [&sender_member_id, &receiver_member_id] {
                    let member = network
                        .members
                        .values()
                        .find(|member| &member.member_id == member_id)
                        .ok_or_else(|| Error::msg("payment member is not registered"))?;
                    if member.revoked_at.is_some() || member.expires_at < authorization_valid_until
                    {
                        return Err(Error::msg(
                            "payment member is revoked or expires before the authorization",
                        ));
                    }
                }
                let member_reserved = ledger
                    .payment_authorizations
                    .values()
                    .filter(|authorization| {
                        authorization.network_commitment == commitment
                            && authorization.initiator_member_id == sender_member_id
                            && authorization.refunded_at.is_none()
                    })
                    .try_fold(0_u128, |total, authorization| {
                        total
                            .checked_add(authorization.reserved_remaining)
                            .ok_or_else(|| Error::msg("member reservation total overflow"))
                    })?;
                let member_capacity = policy.max_member_reserved.saturating_sub(member_reserved);
                let max_amount = requested_max_amount
                    .min(policy.max_session_amount)
                    .min(member_capacity)
                    .min(network.escrow_balance);
                if max_amount == 0 {
                    return Err(Error::msg(
                        "Network Fund or member reservation capacity is exhausted",
                    ));
                }
                let network = ledger.networks.get_mut(&commitment).expect("network");
                network.escrow_balance -= max_amount;
                let mut directions = BTreeMap::new();
                directions.insert(
                    RelayDirection::SenderToReceiver,
                    TrafficDirectionSettlement::default(),
                );
                directions.insert(
                    RelayDirection::ReceiverToSender,
                    TrafficDirectionSettlement::default(),
                );
                let record = PaymentAuthorizationRecord {
                    authorization_id: operation_id.clone(),
                    network_commitment: commitment,
                    network_id: network.network_id.clone(),
                    payer_address: network.owner_address.clone(),
                    node_id,
                    sender_member_id: sender_member_id.clone(),
                    receiver_member_id,
                    session_id,
                    price_per_gib,
                    max_amount,
                    reserved_remaining: max_amount,
                    settled_amount: 0,
                    traffic_protocol_fee_bps: ledger.settings.fee_policy.traffic_protocol_fee_bps,
                    traffic_treasury_share_bps: ledger
                        .settings
                        .fee_policy
                        .traffic_treasury_share_bps,
                    created_at: submitted_at,
                    valid_until: authorization_valid_until,
                    claim_until: authorization_valid_until
                        .saturating_add(RELAY_PAYMENT_CLAIM_SECONDS),
                    refunded_at: None,
                    closed_at: None,
                    directions,
                    initiator_member_id: sender_member_id,
                    spending_policy_revision: expected_policy_revision,
                };
                ledger
                    .payment_authorizations
                    .insert(operation_id.clone(), record.clone());
                serde_json::to_value(record)?
            }
            ("TrafficPayment", "Refund") => {
                let authorization_id =
                    payload_str(&operation.unsigned.payload, "authorization_id")?.to_owned();
                let authorization_snapshot = ledger
                    .payment_authorizations
                    .get(&authorization_id)
                    .cloned()
                    .ok_or_else(|| Error::msg("payment authorization was not found"))?;
                let node_owner = ledger
                    .nodes
                    .get(&authorization_snapshot.node_id)
                    .map(|node| node.owner_address.as_str());
                let payer_requested =
                    authorization_snapshot.payer_address == operation.unsigned.signer;
                let node_abandoned = node_owner == Some(operation.unsigned.signer.as_str());
                if !payer_requested && !node_abandoned {
                    return Err(Error::msg(
                        "only the payment owner or serving Node Owner can request a refund",
                    ));
                }
                if payer_requested && submitted_at <= authorization_snapshot.claim_until {
                    return Err(Error::msg(
                        "payment authorization claim window is still open",
                    ));
                }
                let authorization = ledger
                    .payment_authorizations
                    .get_mut(&authorization_id)
                    .expect("authorization snapshot exists");
                if authorization.refunded_at.is_some() {
                    return Err(Error::msg("payment authorization was already refunded"));
                }
                let refund = authorization.reserved_remaining;
                authorization.reserved_remaining = 0;
                authorization.refunded_at = Some(submitted_at);
                ledger
                    .networks
                    .get_mut(&authorization.network_commitment)
                    .ok_or_else(|| Error::msg("payment Network is missing"))?
                    .escrow_balance = ledger.networks[&authorization.network_commitment]
                    .escrow_balance
                    .checked_add(refund)
                    .ok_or_else(|| Error::msg("Network Escrow overflow"))?;
                json!({
                    "authorization_id": authorization_id,
                    "refunded_amount_base_units": refund.to_string(),
                })
            }
            ("NetworkRegistry", "RevokeMember") => {
                let commitment = payload_network_commitment(ledger, &operation.unsigned.payload)?;
                let serial = operation
                    .unsigned
                    .payload
                    .get("serial")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::msg("member serial is invalid"))?;
                let network = ledger.networks.get_mut(&commitment).expect("network");
                if network.owner_address != operation.unsigned.signer {
                    return Err(Error::msg("only the Network Owner can revoke members"));
                }
                let member = network
                    .members
                    .values_mut()
                    .find(|member| member.serial == serial)
                    .ok_or_else(|| Error::msg(format!("member serial {serial} not found")))?;
                if member.revoked_at.is_some() {
                    return Err(Error::msg("member is already revoked"));
                }
                member.revoked_at = Some(submitted_at);
                json!({ "operation_id": operation_id, "status": "PENDING" })
            }
            ("NetworkRegistry", "IssueMember") => {
                let commitment = payload_network_commitment(ledger, &operation.unsigned.payload)?;
                let member_name =
                    payload_str(&operation.unsigned.payload, "member_name")?.to_owned();
                validate_name(&member_name)?;
                let credential: MemberCredential = serde_json::from_value(
                    operation
                        .unsigned
                        .payload
                        .get("credential")
                        .cloned()
                        .ok_or_else(|| Error::msg("member credential is missing"))?,
                )?;
                let network = ledger.networks.get_mut(&commitment).expect("network");
                if network.owner_address != operation.unsigned.signer
                    || network.owner_public_key != public_key
                {
                    return Err(Error::msg("only the Network Owner can issue members"));
                }
                if network.members.contains_key(&member_name)
                    || credential.network_id != network.network_id
                    || credential.serial != network.next_member_serial
                    || credential.version != PROTOCOL_VERSION
                    || credential.issued_at > submitted_at
                    || submitted_at.saturating_sub(credential.issued_at) > 30
                    || credential.expires_at <= submitted_at
                {
                    return Err(Error::msg("member credential state is invalid"));
                }
                verify_bytes(
                    public_key,
                    &credential_signing_bytes(&credential)?,
                    &credential.owner_signature,
                )?;
                network.next_member_serial += 1;
                network.members.insert(
                    member_name.clone(),
                    MemberRecord {
                        name: member_name,
                        member_id: credential.member_id.clone(),
                        public_key: credential.member_public_key.clone(),
                        serial: credential.serial,
                        issued_at: credential.issued_at,
                        expires_at: credential.expires_at,
                        revoked_at: None,
                        credential_signature: credential.owner_signature.clone(),
                    },
                );
                serde_json::to_value(credential)?
            }
            _ => return Err(Error::msg("unsupported signed network operation")),
        };
        finalize_operation(ledger, &operation, &operation_id, submitted_at)?;
        Ok(result)
    })
}

fn payload_str<'a>(payload: &'a Value, name: &str) -> Result<&'a str> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg(format!("signed operation is missing '{name}'")))
}

fn payload_network_commitment(ledger: &LedgerState, payload: &Value) -> Result<String> {
    let commitment = payload_str(payload, "network_commitment")?;
    if !ledger.networks.contains_key(commitment) {
        return Err(Error::msg(format!("network not found: {commitment}")));
    }
    Ok(commitment.to_owned())
}

fn validate_network_spending_policy(policy: &NetworkSpendingPolicy) -> Result<()> {
    if policy.max_session_amount == 0
        || policy.max_session_amount > MAX_SUPPLY
        || policy.max_member_reserved < policy.max_session_amount
        || policy.max_member_reserved > MAX_SUPPLY
    {
        return Err(Error::msg(
            "spending policy amounts must be positive and member capacity must cover one session",
        ));
    }
    if policy.max_node_price_per_gib == 0 || policy.max_node_price_per_gib > MAX_SUPPLY {
        return Err(Error::msg("spending policy Node price limit is invalid"));
    }
    if !(1..=30 * 24 * 60).contains(&policy.max_session_minutes) {
        return Err(Error::msg(
            "spending policy session duration must be between 1 minute and 30 days",
        ));
    }
    Ok(())
}

fn validate_payment_session_id(session_id: &str) -> Result<()> {
    if session_id.len() != 64
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::msg(
            "payment Session ID must be 32-byte lowercase hex",
        ));
    }
    Ok(())
}

pub fn operation(paths: &DataPaths, operation_id: &str) -> Result<OperationRecord> {
    paths.stored_operation(operation_id)
}

pub fn consensus_pending_operations(
    paths: &DataPaths,
) -> Result<Vec<crate::consensus::PendingOperationEnvelope>> {
    let ledger = paths.read_ledger()?;
    ledger
        .pending_operation_ids
        .iter()
        .map(|operation_id| {
            let record = ledger
                .operations
                .get(operation_id)
                .ok_or_else(|| Error::msg("pending operation record is missing"))?;
            let operation = record
                .signed_operation
                .clone()
                .ok_or_else(|| Error::msg("pending operation has no signed envelope"))?;
            let public_key = ledger
                .accounts
                .get(&operation.unsigned.signer)
                .and_then(|account| account.public_key.clone())
                .ok_or_else(|| Error::msg("pending operation signer key is missing"))?;
            Ok(crate::consensus::PendingOperationEnvelope {
                public_key,
                operation,
            })
        })
        .collect()
}

fn submit_consensus_operation_strict(
    paths: &DataPaths,
    envelope: crate::consensus::PendingOperationEnvelope,
    now: i64,
) -> Result<String> {
    let operation_id_value = operation_id(&envelope.operation)?;
    if paths
        .read_ledger()?
        .operations
        .contains_key(&operation_id_value)
    {
        return Ok(operation_id_value);
    }
    let applied = match (
        envelope.operation.unsigned.module.as_str(),
        envelope.operation.unsigned.action.as_str(),
    ) {
        ("Asset", "Transfer") => {
            submit_signed_transfer(paths, &envelope.public_key, envelope.operation, now).map(|_| ())
        }
        ("NetworkRegistry", _)
        | ("NetworkEscrow", _)
        | ("TrafficPayment", "ReserveSession" | "Refund") => {
            submit_signed_network_operation(paths, &envelope.public_key, envelope.operation, now)
                .map(|_| ())
        }
        ("Governance", _) => {
            submit_signed_governance_operation(paths, &envelope.public_key, envelope.operation, now)
        }
        ("NodeRegistry", _)
        | ("NodeEmissionController", _)
        | ("StakeVault", _)
        | ("Availability", _)
        | ("TrafficPayment", "Settle") => {
            submit_signed_node_operation(paths, &envelope.public_key, envelope.operation, now)
        }
        _ => {
            return Err(Error::msg(format!(
                "consensus operation replay is not implemented for {}.{}",
                envelope.operation.unsigned.module, envelope.operation.unsigned.action
            )));
        }
    };
    applied?;
    Ok(operation_id_value)
}

fn finalize_rejected_consensus_operation(
    paths: &DataPaths,
    envelope: crate::consensus::PendingOperationEnvelope,
    now: i64,
    reason: &str,
) -> Result<String> {
    let operation = envelope.operation;
    let operation_id_value = operation_id(&operation)?;
    verify_operation(&operation, &envelope.public_key)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id
            || operation.unsigned.protocol_version != PROTOCOL_VERSION
            || now > operation.unsigned.valid_until
        {
            return Err(Error::msg(
                "rejected operation envelope is invalid or expired",
            ));
        }
        let signer = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &signer.public_key {
            Some(existing) if existing != &envelope.public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => signer.public_key = Some(envelope.public_key),
            _ => {}
        }
        if operation.unsigned.account_nonce != signer.nonce + 1 {
            return Err(Error::msg(
                "rejected operation nonce is not the next account nonce",
            ));
        }
        finalize_operation(ledger, &operation, &operation_id_value, now)?;
        let record = ledger
            .operations
            .get_mut(&operation_id_value)
            .expect("rejected operation record exists");
        record.status = OperationStatus::Rejected;
        record.error = Some(reason.chars().take(512).collect());
        Ok(operation_id_value)
    })
}

pub fn submit_consensus_operation(
    paths: &DataPaths,
    envelope: crate::consensus::PendingOperationEnvelope,
    now: i64,
) -> Result<String> {
    match submit_consensus_operation_strict(paths, envelope.clone(), now) {
        Ok(operation_id_value) => Ok(operation_id_value),
        Err(application_error) => {
            let module = envelope.operation.unsigned.module.as_str();
            let action = envelope.operation.unsigned.action.as_str();
            let reject_refund = module == "TrafficPayment" && action == "Refund";
            let reject_member_reservation =
                module == "TrafficPayment" && action == "ReserveSession";
            let reject_policy_update = module == "NetworkEscrow" && action == "SetSpendingPolicy";
            if reject_refund || reject_member_reservation || reject_policy_update {
                return Err(application_error);
            }
            stage_consensus_candidate(paths, envelope, now).map_err(|_| application_error)
        }
    }
}

fn stage_consensus_candidate(
    paths: &DataPaths,
    envelope: crate::consensus::PendingOperationEnvelope,
    now: i64,
) -> Result<String> {
    let operation = envelope.operation;
    let public_key_bytes = STANDARD
        .decode(&envelope.public_key)
        .map_err(|_| Error::msg("operation public key is not valid base64"))?;
    if address_from_public_key(&public_key_bytes) != operation.unsigned.signer {
        return Err(Error::msg("operation public key does not match signer"));
    }
    verify_operation(&operation, &envelope.public_key)?;
    if operation.unsigned.protocol_version != PROTOCOL_VERSION
        || now > operation.unsigned.valid_until
    {
        return Err(Error::msg("consensus candidate is invalid or expired"));
    }
    if !matches!(
        (
            operation.unsigned.module.as_str(),
            operation.unsigned.action.as_str()
        ),
        ("Asset", "Transfer")
            | (
                "NetworkRegistry",
                "CreateNetwork" | "RevokeMember" | "IssueMember"
            )
            | ("NetworkEscrow", "FundNetwork" | "SetSpendingPolicy")
            | ("TrafficPayment", "ReserveSession" | "Refund" | "Settle")
            | (
                "Governance",
                "SetParameters"
                    | "PauseEmission"
                    | "ResumeEmission"
                    | "CreateProposal"
                    | "VoteProposal"
                    | "ValidatorVoteProposal"
                    | "VetoTreasuryProposal"
                    | "FinalizeProposal"
                    | "ExecuteProposal"
            )
            | (
                "NodeRegistry",
                "RegisterNode"
                    | "UpdateRewardIp"
                    | "UpdatePrice"
                    | "DrainNode"
                    | "WithdrawServiceBond"
            )
            | ("NodeEmissionController", "ClaimNodeReward")
            | (
                "StakeVault",
                "BondValidator"
                    | "ExitValidator"
                    | "WithdrawValidatorBond"
                    | "BondGovernance"
                    | "ExitGovernance"
                    | "WithdrawGovernanceBond"
            )
            | ("Availability", "AttestProbe")
    ) {
        return Err(Error::msg("unsupported consensus candidate action"));
    }
    let operation_bytes = serde_json::to_vec(&operation)?;
    if operation_bytes.len() > 256 * 1024 {
        return Err(Error::msg("consensus candidate exceeds 256 KiB"));
    }
    let operation_id_value = operation_id(&operation)?;
    let created_at = operation
        .unsigned
        .valid_until
        .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS);
    if paths.operation_exists(&operation_id_value)? {
        return Ok(operation_id_value);
    }
    paths.with_active_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg("consensus candidate targets another ledger"));
        }
        if ledger.consensus.proposal.is_some() || ledger.consensus.valid_proposal.is_some() {
            return Err(Error::msg(
                "consensus candidate pool is frozen for a proposal",
            ));
        }
        if ledger.operations.contains_key(&operation_id_value) {
            return Ok(operation_id_value.clone());
        }
        if ledger.pending_operation_ids.iter().any(|pending_id| {
            ledger.operations.get(pending_id).is_some_and(|pending| {
                pending.signer == operation.unsigned.signer
                    && pending.nonce == operation.unsigned.account_nonce
            })
        }) {
            return Err(Error::msg(
                "another pending operation already uses this signer nonce",
            ));
        }
        if operation.unsigned.module == "NetworkRegistry"
            && operation.unsigned.action == "IssueMember"
        {
            let network_commitment =
                payload_str(&operation.unsigned.payload, "network_commitment")?;
            let member_name = payload_str(&operation.unsigned.payload, "member_name")?;
            let serial = operation
                .unsigned
                .payload
                .get("credential")
                .and_then(|credential| credential.get("serial"))
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::msg("member credential serial is invalid"))?;
            let conflict = ledger.pending_operation_ids.iter().any(|pending_id| {
                ledger.operations.get(pending_id).is_some_and(|pending| {
                    pending.kind == "NetworkRegistry.IssueMember"
                        && pending
                            .payload
                            .get("network_commitment")
                            .and_then(Value::as_str)
                            == Some(network_commitment)
                        && (pending.payload.get("member_name").and_then(Value::as_str)
                            == Some(member_name)
                            || pending
                                .payload
                                .get("credential")
                                .and_then(|credential| credential.get("serial"))
                                .and_then(Value::as_u64)
                                == Some(serial))
                })
            });
            if conflict {
                return Err(Error::msg(
                    "another pending member issue already uses this name or serial",
                ));
            }
        }
        if operation.unsigned.module == "NetworkRegistry"
            && operation.unsigned.action == "CreateNetwork"
        {
            let alias = payload_str(&operation.unsigned.payload, "alias")?;
            if ledger
                .finalized_checkpoint
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.network_aliases.contains_key(alias))
            {
                return Err(Error::msg(format!(
                    "network alias '{alias}' already exists in finalized state"
                )));
            }
        }
        if ledger.pending_operation_ids.len() >= MAX_BLOCK_OPERATIONS {
            return Err(Error::msg("consensus candidate pool is full"));
        }
        let finalized_nonce = ledger
            .finalized_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.accounts.get(&operation.unsigned.signer))
            .map_or(0, |account| account.nonce);
        if operation.unsigned.account_nonce <= finalized_nonce
            || operation.unsigned.account_nonce > finalized_nonce.saturating_add(64)
        {
            return Err(Error::msg(
                "consensus candidate nonce is outside the 64-operation pending window",
            ));
        }
        let account = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &account.public_key {
            Some(existing) if existing != &envelope.public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => account.public_key = Some(envelope.public_key.clone()),
            _ => {}
        }
        let fee_quote = fee::validate_envelope(ledger, &operation.unsigned)?;
        ensure_operation_fee_payable(ledger, &operation, fee_quote.fee)?;
        let block_units = pending_fee_units(ledger)
            .checked_add(fee::operation_fee_units(
                &operation.unsigned.module,
                &operation.unsigned.action,
                &operation.unsigned.payload,
            ))
            .ok_or_else(|| Error::msg("pending operation fee units overflow"))?;
        if block_units > ledger.settings.fee_policy.max_units_per_block {
            return Err(Error::msg(
                "consensus candidate exceeds the fee-unit block limit",
            ));
        }
        ledger.operations.insert(
            operation_id_value.clone(),
            OperationRecord {
                operation_id: operation_id_value.clone(),
                kind: format!(
                    "{}.{}",
                    operation.unsigned.module, operation.unsigned.action
                ),
                signer: operation.unsigned.signer.clone(),
                nonce: operation.unsigned.account_nonce,
                created_at,
                status: OperationStatus::Pending,
                error: None,
                payload: operation.unsigned.payload.clone(),
                signature: operation.signature.clone(),
                block_height: None,
                signed_operation: Some(operation),
                fee_payer: None,
                fee_charged: 0,
                fee_burned: 0,
                fee_to_treasury: 0,
            },
        );
        ledger
            .pending_operation_ids
            .push(operation_id_value.clone());
        sort_pending_operation_ids(ledger);
        Ok(operation_id_value)
    })
}

fn submit_signed_governance_operation(
    paths: &DataPaths,
    public_key: &str,
    operation: SignedOperation,
    now: i64,
) -> Result<()> {
    let public_key_bytes = STANDARD
        .decode(public_key)
        .map_err(|_| Error::msg("operation public key is not valid base64"))?;
    if address_from_public_key(&public_key_bytes) != operation.unsigned.signer {
        return Err(Error::msg("operation public key does not match signer"));
    }
    verify_operation(&operation, public_key)?;
    if operation.unsigned.protocol_version != PROTOCOL_VERSION
        || operation.unsigned.module != "Governance"
        || now > operation.unsigned.valid_until
    {
        return Err(Error::msg(
            "signed governance operation is invalid or expired",
        ));
    }
    let executed_at = operation
        .unsigned
        .valid_until
        .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS);
    let operation_id_value = operation_id(&operation)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg(
                "signed governance operation targets another ledger",
            ));
        }
        if ledger.operations.contains_key(&operation_id_value) {
            return Ok(());
        }
        let signer = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &signer.public_key {
            Some(existing) if existing != public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => signer.public_key = Some(public_key.to_owned()),
            _ => {}
        }
        if operation.unsigned.account_nonce != signer.nonce + 1 {
            return Err(Error::msg("operation nonce is not the next account nonce"));
        }
        apply_replicated_governance_action(
            ledger,
            public_key,
            &operation,
            &operation_id_value,
            executed_at,
        )?;
        finalize_operation(ledger, &operation, &operation_id_value, executed_at)
    })
}

fn submit_signed_node_operation(
    paths: &DataPaths,
    public_key: &str,
    operation: SignedOperation,
    now: i64,
) -> Result<()> {
    let public_key_bytes = STANDARD
        .decode(public_key)
        .map_err(|_| Error::msg("operation public key is not valid base64"))?;
    if address_from_public_key(&public_key_bytes) != operation.unsigned.signer {
        return Err(Error::msg("operation public key does not match signer"));
    }
    verify_operation(&operation, public_key)?;
    if operation.unsigned.protocol_version != PROTOCOL_VERSION
        || now > operation.unsigned.valid_until
    {
        return Err(Error::msg("signed Node operation is invalid or expired"));
    }
    let executed_at = operation
        .unsigned
        .valid_until
        .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS);
    let operation_id_value = operation_id(&operation)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg("signed Node operation targets another ledger"));
        }
        if ledger.operations.contains_key(&operation_id_value) {
            return Ok(());
        }
        let signer = ledger
            .accounts
            .entry(operation.unsigned.signer.clone())
            .or_default();
        match &signer.public_key {
            Some(existing) if existing != public_key => {
                return Err(Error::msg("account public key mismatch"));
            }
            None => signer.public_key = Some(public_key.to_owned()),
            _ => {}
        }
        if operation.unsigned.account_nonce != signer.nonce + 1 {
            return Err(Error::msg("operation nonce is not the next account nonce"));
        }
        let payload = &operation.unsigned.payload;
        let mut protocol_fee = TrafficProtocolFee::default();
        match (
            operation.unsigned.module.as_str(),
            operation.unsigned.action.as_str(),
        ) {
            ("NodeRegistry", "RegisterNode") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                if node_id != ledger.next_node_id {
                    return Err(Error::msg("Node ID is not the next registry ID"));
                }
                if payload_str(payload, "owner_public_key")? != public_key {
                    return Err(Error::msg("registered Owner key does not match signer"));
                }
                let previous_node_id = payload.get("previous_node_id").and_then(Value::as_u64);
                validate_node_owner_registration(
                    ledger,
                    &operation.unsigned.signer,
                    public_key,
                    previous_node_id,
                )?;
                let reward_address = payload_str(payload, "reward_address")?.to_owned();
                let reward_public_key = payload_str(payload, "reward_public_key")?.to_owned();
                let reward_bytes = STANDARD
                    .decode(&reward_public_key)
                    .map_err(|_| Error::msg("Reward public key is invalid"))?;
                if address_from_public_key(&reward_bytes) != reward_address {
                    return Err(Error::msg("Reward public key does not match address"));
                }
                let reward_ip = payload_str(payload, "reward_ip")?.to_owned();
                let ip_slot =
                    validate_reward_ip_slot(&reward_ip, payload_str(payload, "ip_slot")?)?;
                let price_per_gib = validate_price_per_gib(parse_payload_u128(
                    payload,
                    "price_per_gib_base_units",
                )?)?;
                let endpoint = parse_wss_endpoint(payload_str(payload, "endpoint")?)?.to_string();
                ensure_node_endpoint_available(ledger, &endpoint, None)?;
                let registered_at = payload["registered_at"].as_i64().unwrap_or(executed_at);
                let (status, warmup_until, active_since) =
                    initial_node_lifecycle(node_id, registered_at, ledger.settings.warmup_seconds)?;
                let record = NodeRecord {
                    node_id,
                    previous_node_id,
                    name: payload_str(payload, "name")?.to_owned(),
                    owner_address: operation.unsigned.signer.clone(),
                    owner_public_key: public_key.to_owned(),
                    relay_public_key: payload_str(payload, "relay_public_key")?.to_owned(),
                    reward_address: reward_address.clone(),
                    endpoint,
                    reward_ip,
                    ip_slot: ip_slot.clone(),
                    price_per_gib,
                    status,
                    registered_at,
                    warmup_until,
                    active_since,
                    last_heartbeat: None,
                    last_probe_success: None,
                    probe_success_count: 0,
                    last_relay_receipt_at: None,
                    eligible_seconds_by_epoch: BTreeMap::new(),
                    total_eligible_seconds: 0,
                    service_bond: 0,
                    service_bond_unlock_at: None,
                    governance_bond: 0,
                    governance_bonded_at: None,
                    governance_exit_requested_at: None,
                    governance_bond_unlock_at: None,
                    offline_slashed_at: None,
                    offline_slashed_service_bond: 0,
                    offline_slashed_vesting_reward: 0,
                    claimable_reward: 0,
                    reward_vesting_buckets: Vec::new(),
                    validator: false,
                    validator_signature_rate_bps: 0,
                    validator_bond: 0,
                    validator_candidate_since: None,
                    validator_last_epoch: None,
                    validator_consecutive_epochs: 0,
                    validator_exit_requested_at: None,
                    validator_bond_unlock_at: None,
                };
                ledger
                    .accounts
                    .entry(reward_address)
                    .or_default()
                    .public_key = Some(reward_public_key);
                if node_id == 1 {
                    if ledger.genesis_authority.is_some() {
                        return Err(Error::msg("Genesis authority already exists"));
                    }
                    ledger.genesis_authority = Some(GenesisAuthority {
                        node_id,
                        owner_address: operation.unsigned.signer.clone(),
                        owner_public_key: public_key.to_owned(),
                        established_at: registered_at,
                    });
                } else if ledger.genesis_authority.is_none() {
                    return Err(Error::msg("Genesis authority is missing"));
                }
                ledger.nodes.insert(node_id, record);
                bind_ip_slot_if_available(ledger, &ip_slot, node_id, now);
                ledger.next_node_id += 1;
            }
            ("NodeRegistry", "UpdateRewardIp") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                apply_reward_ip_update(
                    ledger,
                    node_id,
                    payload_str(payload, "endpoint")?,
                    payload_str(payload, "reward_ip")?,
                    payload_str(payload, "ip_slot")?,
                    now,
                )?;
            }
            ("NodeRegistry", "UpdatePrice") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                apply_node_price_update(
                    ledger,
                    node_id,
                    parse_payload_u128(payload, "price_per_gib_base_units")?,
                )?;
            }
            ("NodeRegistry", "DrainNode") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                ensure_node_can_drain(ledger.nodes.get(&node_id).expect("Node exists"))?;
                ledger.nodes.get_mut(&node_id).unwrap().status = NodeStatus::Draining;
            }
            ("NodeRegistry", "WithdrawServiceBond") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let declared_reward_address = payload_str(payload, "reward_address")?;
                let node = ledger.nodes.get(&node_id).expect("Node exists");
                if node.status != NodeStatus::Exited {
                    return Err(Error::msg(
                        "Service Bond can only be withdrawn after the Node has exited",
                    ));
                }
                let unlock_at = node
                    .service_bond_unlock_at
                    .ok_or_else(|| Error::msg("Service Bond is not pending unlock"))?;
                if now < unlock_at {
                    return Err(Error::msg(format!(
                        "Service Bond remains locked until {unlock_at}"
                    )));
                }
                if amount == 0 || amount != node.service_bond {
                    return Err(Error::msg("Service Bond withdrawal amount is invalid"));
                }
                if declared_reward_address != node.reward_address {
                    return Err(Error::msg(
                        "Service Bond reward address does not match Node",
                    ));
                }
                let reward_address = node.reward_address.clone();
                let node = ledger.nodes.get_mut(&node_id).expect("Node exists");
                node.service_bond = 0;
                node.service_bond_unlock_at = None;
                let account = ledger.accounts.entry(reward_address.clone()).or_default();
                account.balance = account
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
                add_history(ledger, &reward_address, &operation_id_value);
            }
            ("NodeEmissionController", "ClaimNodeReward") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let node = ledger.nodes.get_mut(&node_id).unwrap();
                if amount == 0 || amount > node.claimable_reward {
                    return Err(Error::msg("claim amount exceeds unlocked Node reward"));
                }
                node.claimable_reward -= amount;
                let reward_address = node.reward_address.clone();
                ledger
                    .accounts
                    .entry(reward_address.clone())
                    .or_default()
                    .balance += amount;
                add_history(ledger, &reward_address, &operation_id_value);
            }
            ("StakeVault", "BondGovernance") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let bonded_at = payload["bonded_at"]
                    .as_i64()
                    .ok_or_else(|| Error::msg("Governance Bond timestamp is invalid"))?;
                if bonded_at != executed_at {
                    return Err(Error::msg("Governance Bond timestamp is not deterministic"));
                }
                let node = ledger
                    .nodes
                    .get(&node_id)
                    .ok_or_else(|| Error::msg("Node is missing"))?;
                if node.reward_address != operation.unsigned.signer {
                    return Err(Error::msg("Governance Bond signer is not Reward account"));
                }
                if matches!(
                    node.status,
                    NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
                ) {
                    return Err(Error::msg(
                        "Governance Bond cannot be added while the Node is draining, exited, or suspended",
                    ));
                }
                if node.governance_exit_requested_at.is_some() {
                    return Err(Error::msg(
                        "Governance exit is pending; withdraw the old bond before bonding again",
                    ));
                }
                if amount == 0
                    || node.governance_bond.saturating_add(amount)
                        < ledger.settings.required_governance_bond
                {
                    return Err(Error::msg(
                        "Governance Bond must reach the current required amount",
                    ));
                }
                if ledger.accounts[&operation.unsigned.signer].balance < amount {
                    return Err(Error::msg("insufficient Governance Bond balance"));
                }
                ledger
                    .accounts
                    .get_mut(&operation.unsigned.signer)
                    .unwrap()
                    .balance -= amount;
                let node = ledger.nodes.get_mut(&node_id).unwrap();
                node.governance_bond = node
                    .governance_bond
                    .checked_add(amount)
                    .ok_or_else(|| Error::msg("Governance Bond overflow"))?;
                node.governance_bonded_at = Some(bonded_at);
            }
            ("StakeVault", "ExitGovernance") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let unlock_at = payload["unlock_at"]
                    .as_i64()
                    .ok_or_else(|| Error::msg("Governance Bond unlock time is invalid"))?;
                let expected_unlock_at = executed_at
                    .checked_add(ledger.settings.governance_bond_unlock_seconds)
                    .ok_or_else(|| Error::msg("Governance Bond unlock timestamp overflow"))?;
                let node = ledger.nodes.get_mut(&node_id).unwrap();
                if node.governance_bond == 0 {
                    return Err(Error::msg("node has no Governance Bond"));
                }
                if node.governance_exit_requested_at.is_some() {
                    return Err(Error::msg("Governance exit is already pending"));
                }
                if unlock_at != expected_unlock_at {
                    return Err(Error::msg("Governance Bond unlock timestamp is invalid"));
                }
                node.governance_exit_requested_at = Some(executed_at);
                node.governance_bond_unlock_at = Some(unlock_at);
            }
            ("StakeVault", "WithdrawGovernanceBond") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let declared_reward_address = payload_str(payload, "reward_address")?;
                let node = ledger.nodes.get(&node_id).expect("Node exists");
                let unlock_at = node
                    .governance_bond_unlock_at
                    .ok_or_else(|| Error::msg("Governance exit has not been requested"))?;
                if executed_at < unlock_at {
                    return Err(Error::msg(format!(
                        "Governance Bond remains locked until {unlock_at}"
                    )));
                }
                if amount == 0 || node.governance_bond != amount {
                    return Err(Error::msg("Governance Bond is not withdrawable"));
                }
                if declared_reward_address != node.reward_address {
                    return Err(Error::msg(
                        "Governance Bond reward address does not match Node",
                    ));
                }
                let reward_address = node.reward_address.clone();
                let node = ledger.nodes.get_mut(&node_id).expect("Node exists");
                node.governance_bond = 0;
                node.governance_bonded_at = None;
                node.governance_exit_requested_at = None;
                node.governance_bond_unlock_at = None;
                let account = ledger.accounts.entry(reward_address.clone()).or_default();
                account.balance = account
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
                add_history(ledger, &reward_address, &operation_id_value);
            }
            ("StakeVault", "BondValidator") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let node = ledger
                    .nodes
                    .get(&node_id)
                    .ok_or_else(|| Error::msg("Node is missing"))?;
                if node.reward_address != operation.unsigned.signer {
                    return Err(Error::msg("Validator Bond signer is not Reward account"));
                }
                if ledger.accounts[&operation.unsigned.signer].balance < amount {
                    return Err(Error::msg("insufficient Validator Bond balance"));
                }
                ledger
                    .accounts
                    .get_mut(&operation.unsigned.signer)
                    .unwrap()
                    .balance -= amount;
                let node = ledger.nodes.get_mut(&node_id).unwrap();
                node.validator_bond += amount;
                if node.validator_bond >= ledger.settings.validator_bond
                    && node.validator_candidate_since.is_none()
                {
                    node.validator_candidate_since = Some(executed_at);
                }
                refresh_validator_committee(ledger, executed_at)?;
            }
            ("StakeVault", "ExitValidator") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let unlock_at = payload["unlock_at"]
                    .as_i64()
                    .ok_or_else(|| Error::msg("Validator unlock time is invalid"))?;
                let expected_unlock_at = executed_at
                    .checked_add(VALIDATOR_BOND_UNLOCK_SECONDS)
                    .ok_or_else(|| Error::msg("Validator Bond unlock timestamp overflow"))?;
                let node = ledger.nodes.get_mut(&node_id).unwrap();
                if node.validator_bond == 0 {
                    return Err(Error::msg("node has no Validator Bond"));
                }
                if node.validator_exit_requested_at.is_some() {
                    return Err(Error::msg("validator exit is already pending"));
                }
                if unlock_at != expected_unlock_at {
                    return Err(Error::msg("Validator Bond unlock timestamp is invalid"));
                }
                node.validator_exit_requested_at = Some(executed_at);
                node.validator_bond_unlock_at = Some(unlock_at);
            }
            ("StakeVault", "WithdrawValidatorBond") => {
                let node_id = payload["node_id"]
                    .as_u64()
                    .ok_or_else(|| Error::msg("Node ID is invalid"))?;
                ensure_replicated_node_owner(
                    ledger,
                    node_id,
                    &operation.unsigned.signer,
                    public_key,
                )?;
                let amount = parse_payload_u128(payload, "amount_base_units")?;
                let declared_reward_address = payload_str(payload, "reward_address")?;
                let node = ledger.nodes.get(&node_id).expect("Node exists");
                let unlock_at = node
                    .validator_bond_unlock_at
                    .ok_or_else(|| Error::msg("validator exit has not been requested"))?;
                if now < unlock_at {
                    return Err(Error::msg(format!(
                        "Validator Bond remains locked until {unlock_at}"
                    )));
                }
                if node.validator || amount == 0 || node.validator_bond != amount {
                    return Err(Error::msg("Validator Bond is not withdrawable"));
                }
                if declared_reward_address != node.reward_address {
                    return Err(Error::msg(
                        "Validator Bond reward address does not match Node",
                    ));
                }
                let reward_address = node.reward_address.clone();
                let node = ledger.nodes.get_mut(&node_id).expect("Node exists");
                node.validator_bond = 0;
                node.validator_candidate_since = None;
                node.validator_exit_requested_at = None;
                node.validator_bond_unlock_at = None;
                let account = ledger.accounts.entry(reward_address.clone()).or_default();
                account.balance = account
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
                add_history(ledger, &reward_address, &operation_id_value);
            }
            ("Availability", "AttestProbe") => {
                apply_availability_attestation(
                    ledger,
                    public_key,
                    &operation,
                    &operation_id_value,
                    executed_at,
                )?;
            }
            ("TrafficPayment", "Settle") => {
                let checkpoint: SenderCheckpoint = serde_json::from_value(
                    payload
                        .get("sender_checkpoint")
                        .cloned()
                        .ok_or_else(|| Error::msg("traffic SenderCheckpoint is missing"))?,
                )?;
                let receipt: ReceiverReceipt = serde_json::from_value(
                    payload
                        .get("receiver_receipt")
                        .cloned()
                        .ok_or_else(|| Error::msg("traffic ReceiverReceipt is missing"))?,
                )?;
                protocol_fee = apply_traffic_settlement(
                    ledger,
                    &operation.unsigned.signer,
                    public_key,
                    &operation_id_value,
                    &checkpoint,
                    &receipt,
                    executed_at,
                )?;
            }
            _ => return Err(Error::msg("unsupported signed Node operation")),
        }
        finalize_operation(ledger, &operation, &operation_id_value, executed_at)?;
        if protocol_fee.charged > 0 {
            let record = ledger
                .operations
                .get_mut(&operation_id_value)
                .expect("finalized operation record exists");
            record.fee_charged = record
                .fee_charged
                .checked_add(protocol_fee.charged)
                .ok_or_else(|| Error::msg("operation fee record overflow"))?;
            record.fee_burned = record
                .fee_burned
                .checked_add(protocol_fee.burned)
                .ok_or_else(|| Error::msg("operation burn fee record overflow"))?;
            record.fee_to_treasury = record
                .fee_to_treasury
                .checked_add(protocol_fee.to_treasury)
                .ok_or_else(|| Error::msg("operation treasury fee record overflow"))?;
        }
        Ok(())
    })
}

fn apply_availability_attestation(
    ledger: &mut LedgerState,
    public_key: &str,
    operation: &SignedOperation,
    operation_id_value: &str,
    executed_at: i64,
) -> Result<()> {
    let payload = &operation.unsigned.payload;
    let target_node_id = payload["target_node_id"]
        .as_u64()
        .ok_or_else(|| Error::msg("availability target Node ID is invalid"))?;
    let verifier_node_id = payload["verifier_node_id"]
        .as_u64()
        .ok_or_else(|| Error::msg("availability verifier Node ID is invalid"))?;
    let slot = payload["slot"]
        .as_i64()
        .ok_or_else(|| Error::msg("availability slot is invalid"))?;
    let epoch = payload["epoch"]
        .as_u64()
        .ok_or_else(|| Error::msg("availability Epoch is invalid"))?;
    let context = epoch_context(ledger, epoch)?.clone();
    if executed_at > context.submission_deadline {
        return Err(Error::msg(
            "availability attestation missed its Epoch finality deadline",
        ));
    }
    let role: AvailabilityVerifierRole = serde_json::from_value(
        payload
            .get("role")
            .cloned()
            .ok_or_else(|| Error::msg("availability verifier role is missing"))?,
    )?;
    let ticket_signature = payload["ticket_signature"]
        .as_str()
        .ok_or_else(|| Error::msg("availability Probe Ticket signature is invalid"))?;
    let response: ProbePayload = serde_json::from_value(
        payload
            .get("probe")
            .cloned()
            .ok_or_else(|| Error::msg("availability Probe response is missing"))?,
    )?;
    let verifier = ledger
        .nodes
        .get(&verifier_node_id)
        .ok_or_else(|| Error::msg("availability verifier Node is missing"))?;
    if verifier.owner_address != operation.unsigned.signer
        || verifier.owner_public_key != public_key
    {
        return Err(Error::msg(
            "availability attestation signer is not the selected Node Owner",
        ));
    }
    if response.node_id != target_node_id {
        return Err(Error::msg(
            "availability Probe response identifies another target Node",
        ));
    }
    verify_bytes(
        &verifier.owner_public_key,
        &availability_ticket_message(
            &ledger.ledger_id,
            epoch,
            slot,
            target_node_id,
            verifier_node_id,
            role,
        ),
        ticket_signature,
    )?;
    verify_node_probe_payload(ledger, &response)?;
    let slot_seconds = context.settings.availability_slot_seconds;
    let (slot_start, slot_end) = availability_slot_bounds(&context, slot)?;
    let scheduled_at = availability_scheduled_at(ticket_signature, slot_start, slot_seconds, role)?;
    if context.availability_mode == AvailabilityMode::Node1Trusted {
        if (executed_at - response.timestamp).abs() > 30 {
            return Err(Error::msg(
                "trusted Node 1 Probe observation is outside the 30 second operation window",
            ));
        }
    } else if response.timestamp < scheduled_at.saturating_sub(2)
        || response.timestamp > scheduled_at.saturating_add(10)
        || executed_at < scheduled_at.saturating_sub(2)
        || executed_at > scheduled_at.saturating_add(20)
    {
        return Err(Error::msg(
            "availability Probe observation is outside its signed Ticket window",
        ));
    }
    if response.timestamp < slot_start || response.timestamp >= slot_end {
        return Err(Error::msg(
            "availability Probe timestamp does not belong to the declared slot",
        ));
    }
    let set = availability_verifier_set(ledger, &context, target_node_id, slot);
    let selected = match role {
        AvailabilityVerifierRole::Primary => &set.primary_ids,
        AvailabilityVerifierRole::Audit => &set.auditor_ids,
    };
    if !selected.contains(&verifier_node_id) {
        return Err(Error::msg(
            "availability attestation signer was not selected for this target, slot, and role",
        ));
    }
    let expected_challenge = availability_challenge(ticket_signature);
    if response.challenge != expected_challenge {
        return Err(Error::msg(
            "availability Probe challenge is not deterministic for this slot",
        ));
    }
    let key = availability_slot_key(epoch, target_node_id, slot);
    let (ready_to_credit, first_credit, attestation_operation_ids) = {
        let record = ledger
            .availability_slots
            .entry(key.clone())
            .or_insert_with(|| AvailabilitySlotRecord {
                epoch,
                target_node_id,
                slot,
                mode: set.mode,
                selected_primary_ids: set.primary_ids.clone(),
                primary_operation_ids: BTreeMap::new(),
                primary_quorum: set.primary_quorum,
                audit_required: set.audit_required,
                selected_auditor_ids: set.auditor_ids.clone(),
                audit_operation_ids: BTreeMap::new(),
                audit_quorum: set.audit_quorum,
                credited_seconds: 0,
                credited_at: None,
            });
        if record.mode != set.mode
            || record.selected_primary_ids != set.primary_ids
            || record.primary_quorum != set.primary_quorum
            || record.audit_required != set.audit_required
            || record.selected_auditor_ids != set.auditor_ids
            || record.audit_quorum != set.audit_quorum
        {
            return Err(Error::msg(
                "availability verifier selection changed within a slot",
            ));
        }
        let operations = match role {
            AvailabilityVerifierRole::Primary => &mut record.primary_operation_ids,
            AvailabilityVerifierRole::Audit => &mut record.audit_operation_ids,
        };
        if operations
            .insert(verifier_node_id, operation_id_value.to_owned())
            .is_some()
        {
            return Err(Error::msg(
                "availability verifier already attested this target, slot, and role",
            ));
        }
        let primary_ready = record.primary_operation_ids.len() >= record.primary_quorum as usize;
        let audit_ready = !record.audit_required
            || record.audit_operation_ids.len() >= record.audit_quorum as usize;
        let mut operation_ids = record
            .primary_operation_ids
            .values()
            .cloned()
            .collect::<Vec<_>>();
        operation_ids.extend(record.audit_operation_ids.values().cloned());
        (
            primary_ready && audit_ready,
            record.credited_at.is_none(),
            operation_ids,
        )
    };
    if !ready_to_credit {
        return Ok(());
    }

    let latest_probe_timestamp = attestation_operation_ids
        .iter()
        .filter_map(|attestation_id| {
            if attestation_id == operation_id_value {
                Some(response.timestamp)
            } else {
                ledger
                    .operations
                    .get(attestation_id)
                    .and_then(|record| record.payload.get("probe"))
                    .and_then(|probe| probe.get("timestamp"))
                    .and_then(Value::as_i64)
            }
        })
        .max()
        .unwrap_or(response.timestamp);

    let (warmup_until, target_ip_slot, target_status) = ledger
        .nodes
        .get(&target_node_id)
        .map(|node| (node.warmup_until, node.ip_slot.clone(), node.status))
        .ok_or_else(|| Error::msg("availability target Node is missing"))?;
    let eligible_start = slot_start.max(context.started_at).max(warmup_until);
    let eligible_end = slot_end.min(context.ended_at);
    let serviceable = !matches!(
        target_status,
        NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
    );
    let owns_ip_slot = serviceable
        && bind_ip_slot_if_available(
            ledger,
            &target_ip_slot,
            target_node_id,
            latest_probe_timestamp,
        )
        && node_owns_ip_slot_at(ledger, target_node_id, latest_probe_timestamp);
    let node = ledger
        .nodes
        .get_mut(&target_node_id)
        .ok_or_else(|| Error::msg("availability target Node is missing"))?;
    let credited_seconds = if first_credit
        && !ledger.governance.emission_paused
        && serviceable
        && owns_ip_slot
        && eligible_end > eligible_start
    {
        (eligible_end - eligible_start) as u64
    } else {
        0
    };
    if first_credit && serviceable && owns_ip_slot {
        node.last_probe_success = Some(latest_probe_timestamp);
        node.probe_success_count = node.probe_success_count.saturating_add(1);
        if eligible_end > eligible_start {
            node.status = NodeStatus::Active;
            node.active_since.get_or_insert(eligible_start);
        }
    }
    if credited_seconds > 0 {
        let epoch_seconds = node.eligible_seconds_by_epoch.entry(epoch).or_default();
        *epoch_seconds = epoch_seconds.saturating_add(credited_seconds);
        node.total_eligible_seconds = node.total_eligible_seconds.saturating_add(credited_seconds);
    }
    if !first_credit {
        if serviceable {
            node.last_probe_success = Some(
                node.last_probe_success
                    .unwrap_or(latest_probe_timestamp)
                    .max(latest_probe_timestamp),
            );
        }
        return Ok(());
    }
    let record = ledger
        .availability_slots
        .get_mut(&key)
        .expect("availability slot exists");
    record.credited_seconds = credited_seconds;
    record.credited_at = Some(slot_end);
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct TrafficProtocolFee {
    charged: u128,
    burned: u128,
    to_treasury: u128,
}

fn apply_traffic_settlement(
    ledger: &mut LedgerState,
    signer_address: &str,
    signer_public_key: &str,
    operation_id_value: &str,
    checkpoint: &SenderCheckpoint,
    receipt: &ReceiverReceipt,
    executed_at: i64,
) -> Result<TrafficProtocolFee> {
    if checkpoint.protocol_version != PROTOCOL_VERSION
        || receipt.protocol_version != PROTOCOL_VERSION
        || checkpoint.ledger_id != ledger.ledger_id
        || receipt.ledger_id != ledger.ledger_id
    {
        return Err(Error::msg(
            "traffic receipt targets another protocol or ledger",
        ));
    }
    if checkpoint.node_id != receipt.node_id
        || checkpoint.authorization_id != receipt.authorization_id
        || checkpoint.session_id != receipt.session_id
        || checkpoint.direction != receipt.direction
        || checkpoint.sequence != receipt.sequence
        || checkpoint.cumulative_sent_bytes != receipt.cumulative_received_bytes
        || checkpoint.transcript_hash != receipt.transcript_hash
    {
        return Err(Error::msg(
            "traffic sender checkpoint and receiver receipt do not describe the same prefix",
        ));
    }
    if !checkpoint.final_checkpoint
        && (checkpoint.sequence == 0 || checkpoint.cumulative_sent_bytes == 0)
    {
        return Err(Error::msg(
            "traffic settlement cannot contain an empty prefix",
        ));
    }
    let expected_checkpoint_hash = sender_checkpoint_hash(checkpoint)?;
    if receipt.sender_checkpoint_hash != expected_checkpoint_hash {
        return Err(Error::msg(
            "traffic ReceiverReceipt does not bind the submitted SenderCheckpoint",
        ));
    }
    let authorization = ledger
        .payment_authorizations
        .get(&checkpoint.authorization_id)
        .cloned()
        .ok_or_else(|| Error::msg("traffic payment authorization was not found"))?;
    if authorization.refunded_at.is_some() || authorization.reserved_remaining == 0 {
        return Err(Error::msg(
            "traffic payment authorization is no longer claimable",
        ));
    }
    if authorization.node_id != checkpoint.node_id
        || authorization.session_id != checkpoint.session_id
    {
        return Err(Error::msg(
            "traffic receipt does not match its payment authorization",
        ));
    }
    if executed_at > authorization.claim_until
        || checkpoint.checkpoint_at < authorization.created_at
        || receipt.received_at < checkpoint.checkpoint_at
        || receipt.received_at.saturating_sub(checkpoint.checkpoint_at) > 30
        || receipt.received_at > authorization.valid_until
    {
        return Err(Error::msg(
            "traffic receipt is outside its authorized time window",
        ));
    }
    let node = ledger
        .nodes
        .get(&authorization.node_id)
        .cloned()
        .ok_or_else(|| Error::msg("traffic settlement Node is missing"))?;
    if node.owner_address != signer_address || node.owner_public_key != signer_public_key {
        return Err(Error::msg(
            "only the authorized Node Owner can submit traffic settlement",
        ));
    }
    let (expected_sender, expected_receiver) = match checkpoint.direction {
        RelayDirection::SenderToReceiver => (
            authorization.sender_member_id.as_str(),
            authorization.receiver_member_id.as_str(),
        ),
        RelayDirection::ReceiverToSender => (
            authorization.receiver_member_id.as_str(),
            authorization.sender_member_id.as_str(),
        ),
    };
    if checkpoint.sender_member_id != expected_sender
        || receipt.receiver_member_id != expected_receiver
    {
        return Err(Error::msg(
            "traffic receipt member roles do not match the authorization",
        ));
    }
    let network = ledger
        .networks
        .get(&authorization.network_commitment)
        .ok_or_else(|| Error::msg("traffic payment Network is missing"))?;
    let sender = network
        .members
        .values()
        .find(|member| member.member_id == expected_sender)
        .ok_or_else(|| Error::msg("traffic sender Member is missing"))?;
    let receiver = network
        .members
        .values()
        .find(|member| member.member_id == expected_receiver)
        .ok_or_else(|| Error::msg("traffic receiver Member is missing"))?;
    let member_was_valid = |member: &MemberRecord, timestamp: i64| {
        member.issued_at <= timestamp
            && timestamp < member.expires_at
            && member
                .revoked_at
                .is_none_or(|revoked_at| timestamp < revoked_at)
    };
    if !member_was_valid(sender, checkpoint.checkpoint_at)
        || !member_was_valid(receiver, receipt.received_at)
    {
        return Err(Error::msg(
            "traffic receipt uses an invalid or revoked Member",
        ));
    }
    verify_bytes(
        &sender.public_key,
        &sender_checkpoint_signing_bytes(checkpoint)?,
        &checkpoint.sender_signature,
    )?;
    verify_bytes(
        &receiver.public_key,
        &receiver_receipt_signing_bytes(receipt)?,
        &receipt.receiver_signature,
    )?;
    let previous = authorization
        .directions
        .get(&checkpoint.direction)
        .cloned()
        .unwrap_or_default();
    let moved_backwards = checkpoint.sequence < previous.settled_sequence
        || checkpoint.cumulative_sent_bytes < previous.settled_payload_bytes;
    let did_not_advance = checkpoint.sequence == previous.settled_sequence
        && checkpoint.cumulative_sent_bytes == previous.settled_payload_bytes;
    if moved_backwards || (!checkpoint.final_checkpoint && did_not_advance) || previous.finalized {
        return Err(Error::msg(
            "traffic settlement is not a strictly newer prefix",
        ));
    }
    let numerator = u128::from(checkpoint.cumulative_sent_bytes)
        .checked_mul(authorization.price_per_gib)
        .ok_or_else(|| Error::msg("traffic settlement amount overflow"))?;
    let gib = 1024_u128 * 1024 * 1024;
    let total_owed = numerator
        .checked_add(gib - 1)
        .ok_or_else(|| Error::msg("traffic settlement rounding overflow"))?
        / gib;
    let amount = total_owed
        .checked_sub(previous.settled_amount)
        .ok_or_else(|| Error::msg("traffic settlement amount moved backwards"))?;
    let newly_settled_bytes = checkpoint
        .cumulative_sent_bytes
        .checked_sub(previous.settled_payload_bytes)
        .ok_or_else(|| Error::msg("traffic settlement bytes moved backwards"))?;
    if amount > authorization.reserved_remaining {
        return Err(Error::msg(
            "traffic settlement exceeds the remaining payment authorization",
        ));
    }
    let receipt_hash = sha256_full_id("receiver-receipt", &serde_json::to_vec(receipt)?);
    let authorization = ledger
        .payment_authorizations
        .get_mut(&checkpoint.authorization_id)
        .expect("validated authorization");
    authorization.reserved_remaining -= amount;
    authorization.settled_amount = authorization
        .settled_amount
        .checked_add(amount)
        .ok_or_else(|| Error::msg("traffic settled amount overflow"))?;
    authorization.directions.insert(
        checkpoint.direction,
        TrafficDirectionSettlement {
            settled_sequence: checkpoint.sequence,
            settled_payload_bytes: checkpoint.cumulative_sent_bytes,
            settled_amount: previous
                .settled_amount
                .checked_add(amount)
                .ok_or_else(|| Error::msg("traffic direction amount overflow"))?,
            settled_transcript_hash: Some(checkpoint.transcript_hash.clone()),
            last_receipt_hash: Some(receipt_hash),
            last_receipt_at: Some(receipt.received_at),
            finalized: checkpoint.final_checkpoint,
        },
    );
    let released = if authorization
        .directions
        .values()
        .all(|direction| direction.finalized)
    {
        let released = authorization.reserved_remaining;
        authorization.reserved_remaining = 0;
        authorization.closed_at = Some(executed_at);
        released
    } else {
        0
    };
    if released > 0 {
        let network = ledger
            .networks
            .get_mut(&authorization.network_commitment)
            .expect("validated payment Network");
        network.escrow_balance = network
            .escrow_balance
            .checked_add(released)
            .ok_or_else(|| Error::msg("Network Fund overflow while closing Relay session"))?;
    }
    ledger.total_settled_traffic_bytes = ledger
        .total_settled_traffic_bytes
        .checked_add(u128::from(newly_settled_bytes))
        .ok_or_else(|| Error::msg("total settled traffic overflow"))?;
    let protocol_fee = amount
        .checked_mul(u128::from(authorization.traffic_protocol_fee_bps))
        .ok_or_else(|| Error::msg("traffic protocol fee overflow"))?
        / BPS_DENOMINATOR;
    let to_treasury = protocol_fee
        .checked_mul(u128::from(authorization.traffic_treasury_share_bps))
        .ok_or_else(|| Error::msg("traffic Treasury fee overflow"))?
        / BPS_DENOMINATOR;
    let burned = protocol_fee - to_treasury;
    let node_income = amount - protocol_fee;
    ledger.treasury = ledger
        .treasury
        .checked_add(to_treasury)
        .ok_or_else(|| Error::msg("Treasury balance overflow"))?;
    ledger.burned = ledger
        .burned
        .checked_add(burned)
        .ok_or_else(|| Error::msg("burn counter overflow"))?;
    let reward_address = node.reward_address;
    ledger
        .accounts
        .entry(reward_address.clone())
        .or_default()
        .balance = ledger.accounts[&reward_address]
        .balance
        .checked_add(node_income)
        .ok_or_else(|| Error::msg("Node traffic income overflow"))?;
    let node = ledger
        .nodes
        .get_mut(&checkpoint.node_id)
        .expect("validated Node");
    node.last_relay_receipt_at = Some(
        node.last_relay_receipt_at
            .unwrap_or(receipt.received_at)
            .max(receipt.received_at),
    );
    add_history(ledger, &reward_address, operation_id_value);
    Ok(TrafficProtocolFee {
        charged: protocol_fee,
        burned,
        to_treasury,
    })
}

pub fn payment_authorization(
    paths: &DataPaths,
    authorization_id: &str,
) -> Result<PaymentAuthorizationRecord> {
    paths
        .read_ledger()?
        .payment_authorizations
        .get(authorization_id)
        .cloned()
        .ok_or_else(|| Error::msg("payment authorization was not found"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayAuthorizationView {
    pub ledger_id: String,
    pub authorization: PaymentAuthorizationRecord,
    pub sender_public_key: String,
    pub receiver_public_key: String,
    pub finalized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentAuthorizationStatusView {
    pub authorization_id: String,
    pub session_id: String,
    pub status: OperationStatus,
    pub block_height: Option<u64>,
    pub authorization: Option<PaymentAuthorizationRecord>,
}

pub fn payment_authorization_status(
    paths: &DataPaths,
    authorization_id_or_session_id: &str,
) -> Result<PaymentAuthorizationStatusView> {
    let ledger = paths.read_ledger()?;
    let authorization = ledger
        .payment_authorizations
        .get(authorization_id_or_session_id)
        .or_else(|| {
            ledger
                .payment_authorizations
                .values()
                .find(|authorization| authorization.session_id == authorization_id_or_session_id)
        });
    if let Some(authorization) = authorization {
        let operation = ledger.operations.get(&authorization.authorization_id);
        return Ok(PaymentAuthorizationStatusView {
            authorization_id: authorization.authorization_id.clone(),
            session_id: authorization.session_id.clone(),
            status: operation
                .map(|operation| operation.status.clone())
                .unwrap_or(OperationStatus::Finalized),
            block_height: operation.and_then(|operation| operation.block_height),
            authorization: Some(authorization.clone()),
        });
    }

    let operation = ledger
        .operations
        .get(authorization_id_or_session_id)
        .filter(|operation| operation.kind == "TrafficPayment.ReserveSession")
        .or_else(|| {
            ledger.operations.values().find(|operation| {
                operation.kind == "TrafficPayment.ReserveSession"
                    && operation.payload.get("session_id").and_then(Value::as_str)
                        == Some(authorization_id_or_session_id)
            })
        })
        .ok_or_else(|| Error::msg("payment authorization was not found"))?;
    let session_id = payload_str(&operation.payload, "session_id")?.to_owned();
    Ok(PaymentAuthorizationStatusView {
        authorization_id: operation.operation_id.clone(),
        session_id,
        status: operation.status.clone(),
        block_height: operation.block_height,
        authorization: None,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentHistoryView {
    pub network: String,
    pub network_commitment: String,
    pub fund_balance: u128,
    pub total_settled: u128,
    pub total_reserved: u128,
    pub authorizations: Vec<PaymentAuthorizationRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsettledPaymentView {
    pub session: UnsettledRelaySession,
    pub authorization: PaymentAuthorizationRecord,
}

pub fn unsettled_payments(
    paths: &DataPaths,
    network_alias: Option<&str>,
    member: Option<&str>,
    node_id: Option<u64>,
) -> Result<Vec<UnsettledPaymentView>> {
    let ledger = paths.read_ledger()?;
    let commitment = network_alias
        .map(|alias| resolve_network(&ledger, alias))
        .transpose()?;
    let member_id = match (&commitment, member) {
        (Some(commitment), Some(member)) => {
            let network = ledger.networks.get(commitment).expect("resolved Network");
            Some(
                network
                    .members
                    .get(member)
                    .or_else(|| {
                        network
                            .members
                            .values()
                            .find(|record| record.member_id == member)
                    })
                    .map(|record| record.member_id.clone())
                    .ok_or_else(|| Error::msg("unsettled payment Member was not found"))?,
            )
        }
        (None, Some(_)) => {
            return Err(Error::msg(
                "an unsettled payment Member filter requires a Network",
            ));
        }
        (_, None) => None,
    };
    let mut unsettled = paths
        .unsettled_relay_sessions()?
        .into_iter()
        .filter_map(|session| {
            let authorization = ledger
                .payment_authorizations
                .get(&session.authorization_id)?;
            (authorization.refunded_at.is_none()
                && authorization.closed_at.is_none()
                && authorization.reserved_remaining > 0
                && commitment
                    .as_ref()
                    .is_none_or(|value| authorization.network_commitment == *value)
                && node_id.is_none_or(|value| authorization.node_id == value)
                && member_id.as_ref().is_none_or(|value| {
                    authorization.sender_member_id == *value
                        || authorization.receiver_member_id == *value
                }))
            .then(|| UnsettledPaymentView {
                session,
                authorization: authorization.clone(),
            })
        })
        .collect::<Vec<_>>();
    unsettled.sort_by_key(|item| std::cmp::Reverse(item.session.disconnected_at));
    Ok(unsettled)
}

pub fn payment_history(
    paths: &DataPaths,
    network_alias: &str,
    member: Option<&str>,
    limit: usize,
) -> Result<PaymentHistoryView> {
    let ledger = paths.read_ledger()?;
    let commitment = resolve_network(&ledger, network_alias)?;
    let network = ledger.networks.get(&commitment).expect("resolved Network");
    let member_id = member
        .map(|member| {
            network
                .members
                .get(member)
                .or_else(|| {
                    network
                        .members
                        .values()
                        .find(|record| record.member_id == member)
                })
                .map(|record| record.member_id.clone())
                .ok_or_else(|| Error::msg("payment history member was not found"))
        })
        .transpose()?;
    let mut authorizations: Vec<_> = ledger
        .payment_authorizations
        .values()
        .filter(|authorization| {
            authorization.network_commitment == commitment
                && member_id.as_ref().is_none_or(|member_id| {
                    authorization.sender_member_id == *member_id
                        || authorization.receiver_member_id == *member_id
                        || authorization.initiator_member_id == *member_id
                })
        })
        .cloned()
        .collect();
    let total_settled = authorizations.iter().try_fold(0_u128, |total, item| {
        total
            .checked_add(item.settled_amount)
            .ok_or_else(|| Error::msg("payment history settled total overflow"))
    })?;
    let total_reserved = authorizations.iter().try_fold(0_u128, |total, item| {
        total
            .checked_add(item.reserved_remaining)
            .ok_or_else(|| Error::msg("payment history reservation total overflow"))
    })?;
    authorizations.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.authorization_id.cmp(&left.authorization_id))
    });
    authorizations.truncate(limit.min(1_000));
    Ok(PaymentHistoryView {
        network: network.alias.clone(),
        network_commitment: commitment,
        fund_balance: network.escrow_balance,
        total_settled,
        total_reserved,
        authorizations,
    })
}

pub fn relay_authorization_view(
    paths: &DataPaths,
    authorization_id_or_session_id: &str,
) -> Result<RelayAuthorizationView> {
    let ledger = paths.read_ledger()?;
    let authorization = ledger
        .payment_authorizations
        .get(authorization_id_or_session_id)
        .or_else(|| {
            ledger
                .payment_authorizations
                .values()
                .find(|authorization| authorization.session_id == authorization_id_or_session_id)
        })
        .cloned()
        .ok_or_else(|| Error::msg("payment authorization was not found"))?;
    let network = ledger
        .networks
        .get(&authorization.network_commitment)
        .ok_or_else(|| Error::msg("payment authorization Network is missing"))?;
    let public_key = |member_id: &str| {
        network
            .members
            .values()
            .find(|member| member.member_id == member_id)
            .map(|member| member.public_key.clone())
            .ok_or_else(|| Error::msg("payment authorization Member is missing"))
    };
    let finalized = ledger
        .operations
        .get(&authorization.authorization_id)
        .is_some_and(|record| matches!(record.status, OperationStatus::Finalized));
    Ok(RelayAuthorizationView {
        ledger_id: ledger.ledger_id,
        sender_public_key: public_key(&authorization.sender_member_id)?,
        receiver_public_key: public_key(&authorization.receiver_member_id)?,
        authorization,
        finalized,
    })
}

pub fn validate_relay_open(
    paths: &DataPaths,
    authorization_id: &str,
    node_id: u64,
    network_id: &str,
    source_member_id: &str,
    destination_member_id: &str,
    now: i64,
) -> Result<RelayAuthorizationView> {
    let view = validate_relay_open_participants(
        paths,
        authorization_id,
        node_id,
        network_id,
        source_member_id,
        destination_member_id,
    )?;
    if now < view.authorization.created_at || now >= view.authorization.valid_until {
        return Err(Error::msg("payment authorization is not active"));
    }
    Ok(view)
}

pub fn validate_relay_recovery_open(
    paths: &DataPaths,
    authorization_id: &str,
    node_id: u64,
    network_id: &str,
    source_member_id: &str,
    destination_member_id: &str,
    now: i64,
) -> Result<RelayAuthorizationView> {
    let view = validate_relay_open_participants(
        paths,
        authorization_id,
        node_id,
        network_id,
        source_member_id,
        destination_member_id,
    )?;
    if now < view.authorization.created_at || now >= view.authorization.claim_until {
        return Err(Error::msg(
            "payment authorization recovery window has expired",
        ));
    }
    Ok(view)
}

fn validate_relay_open_participants(
    paths: &DataPaths,
    authorization_id: &str,
    node_id: u64,
    network_id: &str,
    source_member_id: &str,
    destination_member_id: &str,
) -> Result<RelayAuthorizationView> {
    let view = relay_authorization_view(paths, authorization_id)?;
    let authorization = &view.authorization;
    if !view.finalized {
        return Err(Error::msg("payment authorization is not finalized"));
    }
    if authorization.node_id != node_id
        || authorization.network_id != network_id
        || authorization.sender_member_id != source_member_id
        || authorization.receiver_member_id != destination_member_id
    {
        return Err(Error::msg(
            "payment authorization does not match this Relay channel",
        ));
    }
    if authorization.refunded_at.is_some() || authorization.reserved_remaining == 0 {
        return Err(Error::msg("payment authorization is not active"));
    }
    Ok(view)
}

pub fn submit_traffic_settlement(
    paths: &DataPaths,
    node_name: &str,
    password: &str,
    checkpoint: SenderCheckpoint,
    receipt: ReceiverReceipt,
    now: i64,
) -> Result<String> {
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(node_name)?)?;
    let ledger = paths.read_ledger()?;
    let nonce = ledger
        .accounts
        .get(&owner_file.address)
        .map_or(1, |account| account.nonce.saturating_add(1));
    let payload = json!({
        "sender_checkpoint": checkpoint,
        "receiver_receipt": receipt,
    });
    let fee_quote = fee::quote(&ledger, "TrafficPayment", "Settle", &payload)?;
    let operation = sign_public_operation(
        &owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: &ledger.ledger_id,
            module: "TrafficPayment",
            action: "Settle",
            nonce,
            valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            max_fee_base_units: fee_quote.recommended_max_fee,
            fee_policy_version: fee_quote.policy_version,
            payload,
        },
    )?;
    let operation_id_value = operation_id(&operation)?;
    submit_signed_node_operation(paths, &owner_file.public_key, operation, now)?;
    Ok(operation_id_value)
}

pub fn abandon_traffic_authorization(
    paths: &DataPaths,
    node_name: &str,
    password: &str,
    authorization_id: &str,
    now: i64,
) -> Result<String> {
    abandon_traffic_authorization_with_note(
        paths,
        node_name,
        password,
        authorization_id,
        "node abandoned interrupted Relay session",
        now,
    )
}

pub fn abandon_traffic_authorization_with_note(
    paths: &DataPaths,
    node_name: &str,
    password: &str,
    authorization_id: &str,
    note: &str,
    now: i64,
) -> Result<String> {
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(node_name)?)?;
    let ledger = paths.read_ledger()?;
    let authorization = ledger
        .payment_authorizations
        .get(authorization_id)
        .ok_or_else(|| Error::msg("payment authorization was not found"))?;
    let node = ledger
        .nodes
        .get(&authorization.node_id)
        .ok_or_else(|| Error::msg("serving Node was not found"))?;
    if node.name != node_name || node.owner_address != owner_file.address {
        return Err(Error::msg(
            "payment authorization does not belong to this Node",
        ));
    }
    if authorization.refunded_at.is_some()
        || authorization.closed_at.is_some()
        || authorization.reserved_remaining == 0
    {
        return Err(Error::msg("payment authorization is already closed"));
    }
    let nonce = ledger
        .accounts
        .get(&owner_file.address)
        .map_or(1, |account| account.nonce.saturating_add(1));
    let payload = json!({
        "authorization_id": authorization_id,
        "note": note,
    });
    let fee_quote = fee::quote(&ledger, "TrafficPayment", "Refund", &payload)?;
    let operation = sign_public_operation(
        &owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: &ledger.ledger_id,
            module: "TrafficPayment",
            action: "Refund",
            nonce,
            valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            max_fee_base_units: fee_quote.recommended_max_fee,
            fee_policy_version: fee_quote.policy_version,
            payload,
        },
    )?;
    let operation_id_value = operation_id(&operation)?;
    submit_signed_network_operation(paths, &owner_file.public_key, operation, now)?;
    paths.remove_unsettled_relay_session(authorization_id)?;
    Ok(operation_id_value)
}

pub fn account_history(
    paths: &DataPaths,
    address: &str,
    limit: usize,
) -> Result<Vec<OperationRecord>> {
    validate_address(address)?;
    let ledger = paths.read_ledger()?;
    let Some(account) = ledger.accounts.get(address) else {
        return Ok(Vec::new());
    };
    Ok(account
        .operation_ids
        .iter()
        .rev()
        .take(limit)
        .filter_map(|id| ledger.operations.get(id).cloned())
        .collect())
}

pub fn create_network(
    paths: &DataPaths,
    account_name: &str,
    password: &str,
    alias: &str,
    now: i64,
) -> Result<NetworkRecord> {
    validate_name(alias)?;
    let keyfile = account_keyfile(paths, account_name)?;
    let key_pair = decrypt_key(&keyfile, password)?;
    let network_bytes = random_bytes::<32>()?;
    let network_id = URL_SAFE_NO_PAD.encode(network_bytes);
    let commitment = sha256_id("net", &network_bytes);
    paths.with_ledger_mut(|ledger| {
        if ledger.network_aliases.contains_key(alias) {
            return Err(Error::msg(format!(
                "network alias '{alias}' already exists"
            )));
        }
        ensure_account(ledger, &keyfile)?;
        let nonce = ledger.accounts[&keyfile.address].nonce + 1;
        let payload = json!({"network_commitment": commitment, "alias": alias});
        let signed = sign_operation(
            ledger,
            (&keyfile, &key_pair),
            "NetworkRegistry",
            "CreateNetwork",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &keyfile.public_key)?;
        let record = NetworkRecord {
            network_id: network_id.clone(),
            commitment: commitment.clone(),
            alias: alias.to_owned(),
            owner_address: keyfile.address.clone(),
            owner_public_key: keyfile.public_key.clone(),
            created_at: now,
            escrow_balance: 0,
            next_member_serial: 1,
            members: BTreeMap::new(),
            spending_policy: Default::default(),
        };
        ledger
            .network_aliases
            .insert(alias.to_owned(), commitment.clone());
        ledger.networks.insert(commitment.clone(), record.clone());
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(record)
    })
}

pub fn fund_network(
    paths: &DataPaths,
    account_name: &str,
    password: &str,
    network_alias: &str,
    amount_text: &str,
    now: i64,
) -> Result<String> {
    let amount = parse_mrk(amount_text)?;
    if amount == 0 {
        return Err(Error::msg("fund amount must be greater than zero"));
    }
    let keyfile = account_keyfile(paths, account_name)?;
    let key_pair = decrypt_key(&keyfile, password)?;
    paths.with_ledger_mut(|ledger| {
        let commitment = resolve_network(ledger, network_alias)?;
        let network = ledger.networks.get(&commitment).expect("resolved network");
        if network.owner_address != keyfile.address {
            return Err(Error::msg(
                "only the Network Owner account can fund this local network",
            ));
        }
        let sender = ledger
            .accounts
            .get(&keyfile.address)
            .cloned()
            .unwrap_or_default();
        if sender.balance < amount {
            return Err(Error::msg(format!(
                "insufficient spendable MRK: available {}, required {}",
                format_mrk(sender.balance),
                format_mrk(amount)
            )));
        }
        let nonce = sender.nonce + 1;
        let payload = json!({
            "network_commitment": commitment,
            "amount_base_units": amount.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&keyfile, &key_pair),
            "NetworkEscrow",
            "FundNetwork",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &keyfile.public_key)?;
        ledger
            .accounts
            .get_mut(&keyfile.address)
            .expect("owner account")
            .balance -= amount;
        ledger
            .networks
            .get_mut(&commitment)
            .expect("network")
            .escrow_balance += amount;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(operation_id)
    })
}

pub fn issue_member(
    paths: &DataPaths,
    account_name: &str,
    password: &str,
    network_alias: &str,
    member_name: &str,
    valid_days: i64,
    now: i64,
) -> Result<(MemberCredential, std::path::PathBuf)> {
    validate_name(member_name)?;
    if !(1..=365).contains(&valid_days) {
        return Err(Error::msg(
            "member credential validity must be between 1 and 365 days",
        ));
    }
    let owner_file = account_keyfile(paths, account_name)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let member_file = generate_keyfile(password)?;
    let member_id = hex_lower(&random_bytes::<16>()?);
    let expires_at = now + valid_days * 86_400;
    let credential = paths.with_ledger_mut(|ledger| {
        let commitment = resolve_network(ledger, network_alias)?;
        let network = ledger.networks.get_mut(&commitment).expect("network");
        if network.owner_address != owner_file.address {
            return Err(Error::msg("only the Network Owner can issue members"));
        }
        if network.members.contains_key(member_name) {
            return Err(Error::msg(format!("member '{member_name}' already exists")));
        }
        let serial = network.next_member_serial;
        network.next_member_serial += 1;
        let mut credential = MemberCredential {
            version: PROTOCOL_VERSION,
            network_id: network.network_id.clone(),
            member_id: member_id.clone(),
            member_public_key: member_file.public_key.clone(),
            permissions: vec![
                "connect".to_owned(),
                "send".to_owned(),
                "receive".to_owned(),
            ],
            max_connections: 1,
            serial,
            issued_at: now,
            expires_at,
            owner_signature: String::new(),
        };
        credential.owner_signature =
            sign_bytes(&owner_key, &credential_signing_bytes(&credential)?);
        network.members.insert(
            member_name.to_owned(),
            MemberRecord {
                name: member_name.to_owned(),
                member_id: member_id.clone(),
                public_key: member_file.public_key.clone(),
                serial,
                issued_at: now,
                expires_at,
                revoked_at: None,
                credential_signature: credential.owner_signature.clone(),
            },
        );
        Ok(credential)
    })?;
    let key_path = paths.member_key_path(network_alias, member_name)?;
    paths.write_keyfile(&key_path, &member_file)?;
    let credential_path = paths.member_credential_path(network_alias, member_name)?;
    if let Some(parent) = credential_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_json(&credential_path, &credential)?;
    Ok((credential, credential_path))
}

pub fn create_member_hello(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
    password: &str,
    challenge: &ChallengePayload,
    now: i64,
) -> Result<HelloPayload> {
    let credential: MemberCredential =
        read_json(&paths.member_credential_path(network_name, member_name)?)?;
    let keyfile = paths.read_keyfile(&paths.member_key_path(network_name, member_name)?)?;
    if keyfile.public_key != credential.member_public_key {
        return Err(Error::Crypto(
            "member credential and member keystore do not match",
        ));
    }
    let key = decrypt_key(&keyfile, password)?;
    let proof = sign_bytes(&key, &hello_signing_bytes(challenge, &credential, now)?);
    Ok(HelloPayload {
        credential,
        timestamp: now,
        proof,
    })
}

pub fn member_credential(
    paths: &DataPaths,
    network_name: &str,
    member_name: &str,
) -> Result<MemberCredential> {
    read_json(&paths.member_credential_path(network_name, member_name)?)
}

#[derive(Clone, Debug)]
pub struct AuthenticatedMember {
    pub network_id: String,
    pub member_id: String,
    pub max_connections: u32,
}

pub fn authenticate_member(
    paths: &DataPaths,
    challenge: &ChallengePayload,
    hello: &HelloPayload,
    now: i64,
) -> Result<AuthenticatedMember> {
    if (now - hello.timestamp).abs() > 30 {
        return Err(Error::msg(
            "member HELLO timestamp is outside the 30 second window",
        ));
    }
    let credential = &hello.credential;
    if credential.version != PROTOCOL_VERSION {
        return Err(Error::msg("unsupported member credential version"));
    }
    if now < credential.issued_at || now >= credential.expires_at {
        return Err(Error::msg("member credential is not currently valid"));
    }
    for permission in ["connect", "send", "receive"] {
        if !credential.permissions.iter().any(|item| item == permission) {
            return Err(Error::msg(format!(
                "member credential is missing '{permission}' permission"
            )));
        }
    }
    let ledger = paths.read_ledger()?;
    let network = ledger
        .networks
        .values()
        .find(|network| network.network_id == credential.network_id)
        .ok_or_else(|| Error::msg("member credential references an unknown network"))?;
    verify_bytes(
        &network.owner_public_key,
        &credential_signing_bytes(credential)?,
        &credential.owner_signature,
    )?;
    let member = network
        .members
        .values()
        .find(|member| member.serial == credential.serial)
        .ok_or_else(|| Error::msg("member credential serial is unknown"))?;
    if member.revoked_at.is_some()
        || member.member_id != credential.member_id
        || member.public_key != credential.member_public_key
        || member.credential_signature != credential.owner_signature
    {
        return Err(Error::msg(
            "member credential is revoked or does not match registry",
        ));
    }
    verify_bytes(
        &credential.member_public_key,
        &hello_signing_bytes(challenge, credential, hello.timestamp)?,
        &hello.proof,
    )?;
    Ok(AuthenticatedMember {
        network_id: credential.network_id.clone(),
        member_id: credential.member_id.clone(),
        max_connections: credential.max_connections,
    })
}

pub fn revoke_member(
    paths: &DataPaths,
    account_name: &str,
    password: &str,
    network_alias: &str,
    serial: u64,
    now: i64,
) -> Result<String> {
    let owner_file = account_keyfile(paths, account_name)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let commitment = resolve_network(ledger, network_alias)?;
        let network = ledger.networks.get(&commitment).expect("network");
        if network.owner_address != owner_file.address {
            return Err(Error::msg("only the Network Owner can revoke members"));
        }
        let member_name = network
            .members
            .iter()
            .find_map(|(name, member)| (member.serial == serial).then(|| name.clone()))
            .ok_or_else(|| Error::msg(format!("member serial {serial} not found")))?;
        if network.members[&member_name].revoked_at.is_some() {
            return Err(Error::msg(format!(
                "member serial {serial} is already revoked"
            )));
        }
        let sender = ledger
            .accounts
            .get(&owner_file.address)
            .cloned()
            .unwrap_or_default();
        let payload = json!({"network_commitment": commitment, "serial": serial});
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NetworkRegistry",
            "RevokeMember",
            sender.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        ledger
            .networks
            .get_mut(&commitment)
            .expect("network")
            .members
            .get_mut(&member_name)
            .expect("member")
            .revoked_at = Some(now);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(operation_id)
    })
}

pub fn init_node(paths: &DataPaths, name: &str, password: &str) -> Result<LocalNodeConfig> {
    init_node_with_storage_mode(paths, name, password, NodeStorageMode::Full)
}

pub fn init_node_with_storage_mode(
    paths: &DataPaths,
    name: &str,
    password: &str,
    storage_mode: NodeStorageMode,
) -> Result<LocalNodeConfig> {
    init_node_with_storage_mode_and_ledger_id(paths, name, password, storage_mode, None)
}

pub fn init_node_with_storage_mode_and_ledger_id(
    paths: &DataPaths,
    name: &str,
    password: &str,
    storage_mode: NodeStorageMode,
    ledger_id: Option<&str>,
) -> Result<LocalNodeConfig> {
    validate_name(name)?;
    if let Some(ledger_id) = ledger_id {
        crate::storage::validate_ledger_id(ledger_id)?;
    }
    let directory = paths.node_dir(name)?;
    if directory.exists() {
        return Err(Error::msg(format!("node '{name}' already exists")));
    }
    validate_keystore_password(password)?;
    let owner = generate_keyfile(password)?;
    let relay = generate_keyfile(password)?;
    let reward = generate_keyfile(password)?;
    let config = LocalNodeConfig {
        version: PROTOCOL_VERSION,
        name: name.to_owned(),
        owner_address: owner.address.clone(),
        relay_address: relay.address.clone(),
        reward_address: reward.address.clone(),
        node_id: None,
        storage_mode,
        bootstrap_peer: None,
        trusted_checkpoint_root: None,
        trusted_checkpoint_height: None,
        bootstrap_allow_insecure_local: false,
        bootstrap_tls_ca: None,
        relay_auto_abandon: Default::default(),
    };
    std::fs::create_dir(&directory)?;
    let write_result = (|| {
        paths.write_keyfile(&paths.node_owner_key_path(name)?, &owner)?;
        paths.write_keyfile(&paths.node_relay_key_path(name)?, &relay)?;
        paths.write_keyfile(&paths.node_reward_key_path(name)?, &reward)?;
        paths.write_node_config(&config)?;
        paths.initialize_ledger(ledger_id)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(config)
}

fn latest_bootstrap_snapshot(paths: &DataPaths) -> Result<BootstrapSnapshot> {
    let ledger = paths.read_active_ledger()?;
    let checkpoint = ledger
        .finalized_checkpoint
        .as_ref()
        .ok_or_else(|| Error::msg("chain has no finalized checkpoint to bootstrap from"))?;
    let mut checkpoint = (**checkpoint).clone();
    checkpoint.finalized_checkpoint = None;
    let state_root = ledger_state_root(&checkpoint)?;
    let height = chain_height(&checkpoint);
    if height == 0 {
        return Err(Error::msg("chain has not finalized its first block"));
    }
    Ok(BootstrapSnapshot {
        ledger_id: checkpoint.ledger_id.clone(),
        height,
        state_root,
        checkpoint,
    })
}

pub fn bootstrap_snapshot(paths: &DataPaths) -> Result<BootstrapSnapshot> {
    let snapshot = latest_bootstrap_snapshot(paths)?;
    paths.store_bootstrap_checkpoint(
        snapshot.height,
        &snapshot.checkpoint,
        BOOTSTRAP_CHECKPOINT_RETENTION,
    )?;
    Ok(snapshot)
}

pub fn bootstrap_checkpoints(paths: &DataPaths) -> Result<Vec<BootstrapCheckpointView>> {
    paths
        .bootstrap_checkpoints()?
        .into_iter()
        .map(|(height, mut checkpoint)| {
            checkpoint.finalized_checkpoint = None;
            if chain_height(&checkpoint) != height {
                return Err(Error::msg(format!(
                    "retained bootstrap checkpoint at height {height} has inconsistent metadata"
                )));
            }
            let finalized_at = chain_tip_timestamp(&checkpoint).ok_or_else(|| {
                Error::msg(format!(
                    "retained bootstrap checkpoint at height {height} has no finalized timestamp"
                ))
            })?;
            Ok(BootstrapCheckpointView {
                height,
                finalized_at,
                state_root: ledger_state_root(&checkpoint)?,
            })
        })
        .collect()
}

pub fn bootstrap_snapshot_at(paths: &DataPaths, height: u64) -> Result<BootstrapSnapshot> {
    let latest = latest_bootstrap_snapshot(paths)?;
    if height == latest.height {
        paths.store_bootstrap_checkpoint(
            latest.height,
            &latest.checkpoint,
            BOOTSTRAP_CHECKPOINT_RETENTION,
        )?;
        return Ok(latest);
    }
    if height > latest.height {
        return Err(Error::msg(format!(
            "bootstrap checkpoint height {height} is ahead of the finalized height {}",
            latest.height
        )));
    }
    let mut checkpoint = paths.bootstrap_checkpoint(height)?.ok_or_else(|| {
        Error::msg(format!(
            "bootstrap checkpoint at height {height} is not retained; inspect the latest {BOOTSTRAP_CHECKPOINT_RETENTION} retained checkpoints with 'mrk node block checkpoints' on the peer or its /explorer/checkpoints page"
        ))
    })?;
    checkpoint.finalized_checkpoint = None;
    if chain_height(&checkpoint) != height {
        return Err(Error::msg(
            "retained bootstrap checkpoint has inconsistent height metadata",
        ));
    }
    Ok(BootstrapSnapshot {
        ledger_id: checkpoint.ledger_id.clone(),
        height,
        state_root: ledger_state_root(&checkpoint)?,
        checkpoint,
    })
}

pub struct BootstrapInstallRequest<'a> {
    pub name: &'a str,
    pub peer: &'a str,
    pub expected_height: u64,
    pub expected_state_root: &'a str,
    pub allow_insecure_local: bool,
    pub tls_ca: Option<&'a std::path::Path>,
}

pub fn install_bootstrap_snapshot(
    paths: &DataPaths,
    request: BootstrapInstallRequest<'_>,
    snapshot: BootstrapSnapshot,
) -> Result<BootstrapInstallReport> {
    let peer = normalize_websocket_url(request.peer, RPC_PATH)?;
    if peer.path() != RPC_PATH {
        return Err(Error::msg(format!(
            "bootstrap peer path must be {RPC_PATH}"
        )));
    }
    let peer = peer.to_string();
    if !request.expected_state_root.starts_with("state_") || request.expected_state_root.len() != 70
    {
        return Err(Error::msg(
            "trusted checkpoint root must be a full state_ SHA-256 identifier",
        ));
    }
    if snapshot.height != request.expected_height {
        return Err(Error::msg(format!(
            "downloaded checkpoint height {} does not match trusted height {}",
            snapshot.height, request.expected_height
        )));
    }
    if snapshot.state_root != request.expected_state_root {
        return Err(Error::msg(format!(
            "downloaded checkpoint root {} does not match trusted root {}",
            snapshot.state_root, request.expected_state_root
        )));
    }
    let mut checkpoint = snapshot.checkpoint;
    checkpoint.finalized_checkpoint = None;
    if checkpoint.version != PROTOCOL_VERSION
        || checkpoint.ledger_id != snapshot.ledger_id
        || chain_height(&checkpoint) != snapshot.height
        || ledger_state_root(&checkpoint)? != snapshot.state_root
        || !checkpoint.pending_operation_ids.is_empty()
        || checkpoint.genesis_authority.is_none()
    {
        return Err(Error::msg(
            "downloaded bootstrap checkpoint metadata or state root is invalid",
        ));
    }
    let local = paths.read_ledger()?;
    if !local.blocks.is_empty()
        || !local.pending_operation_ids.is_empty()
        || local.genesis_authority.is_some()
        || !local.nodes.is_empty()
    {
        return Err(Error::msg(
            "bootstrap requires an initialized Node with an otherwise empty local chain",
        ));
    }
    let original_config = paths.read_node_config(request.name)?;
    if let Some(node_id) = original_config.node_id
        && let Some(checkpoint_node) = checkpoint.nodes.get(&node_id)
    {
        let owner_file = paths.read_keyfile(&paths.node_owner_key_path(request.name)?)?;
        if checkpoint_node.owner_address != original_config.owner_address
            || checkpoint_node.owner_address != owner_file.address
            || checkpoint_node.owner_public_key != owner_file.public_key
        {
            return Err(Error::msg(format!(
                "trusted bootstrap checkpoint assigns Node {node_id} to a different Owner"
            )));
        }
    }
    let finalized = checkpoint.clone();
    paths.store_bootstrap_checkpoint(
        snapshot.height,
        &finalized,
        BOOTSTRAP_CHECKPOINT_RETENTION,
    )?;
    checkpoint.finalized_checkpoint = Some(Box::new(finalized));
    paths.with_ledger_mut(|ledger| {
        *ledger = checkpoint;
        Ok(())
    })?;
    let mut config = original_config.clone();
    config.bootstrap_peer = Some(peer.clone());
    config.trusted_checkpoint_root = Some(request.expected_state_root.to_owned());
    config.trusted_checkpoint_height = Some(request.expected_height);
    config.bootstrap_allow_insecure_local = request.allow_insecure_local;
    config.bootstrap_tls_ca = request
        .tls_ca
        .map(|path| path.to_string_lossy().into_owned());
    if let Err(error) = paths.write_node_config(&config) {
        paths.with_ledger_mut(|ledger| {
            *ledger = local;
            Ok(())
        })?;
        let _ = paths.write_node_config(&original_config);
        return Err(error);
    }
    Ok(BootstrapInstallReport {
        ledger_id: snapshot.ledger_id,
        height: snapshot.height,
        state_root: snapshot.state_root,
        peer,
    })
}

pub fn backup_ledger(
    paths: &DataPaths,
    output: Option<&std::path::Path>,
    now: i64,
) -> Result<LedgerBackupReport> {
    let ledger = paths.read_ledger()?;
    verify_blockchain_inner(&ledger)?;
    let height = chain_height(&ledger);
    let state_root = ledger_state_root(&ledger)?;
    let payload = LedgerBackupPayload {
        format_version: 1,
        created_at: now,
        ledger_id: ledger.ledger_id.clone(),
        height,
        state_root: state_root.clone(),
        ledger,
    };
    let checksum = sha256_full_id("backup", &serde_json::to_vec(&payload)?);
    let backup = LedgerBackup {
        checksum: checksum.clone(),
        payload,
    };
    let path = output.map_or_else(
        || {
            paths
                .root
                .join("backups")
                .join(format!("mrk-{height}-{now}.json"))
        },
        std::path::Path::to_path_buf,
    );
    if path.exists() {
        return Err(Error::msg(format!(
            "refusing to overwrite existing backup {}",
            path.display()
        )));
    }
    atomic_write_json(&path, &backup)?;
    let persisted: LedgerBackup = serde_json::from_slice(&std::fs::read(&path)?)?;
    let persisted_checksum = sha256_full_id("backup", &serde_json::to_vec(&persisted.payload)?);
    if persisted.checksum != checksum
        || persisted_checksum != checksum
        || persisted.payload.state_root != state_root
        || ledger_state_root(&persisted.payload.ledger)? != state_root
    {
        return Err(Error::msg(
            "backup verification failed after writing the file",
        ));
    }
    let bytes = std::fs::metadata(&path)?.len();
    Ok(LedgerBackupReport {
        path: path.to_string_lossy().into_owned(),
        height,
        state_root,
        checksum,
        bytes,
    })
}

pub fn verify_ledger_backup(
    path: &std::path::Path,
    expected_state_root: Option<&str>,
) -> Result<LedgerBackupReport> {
    read_verified_ledger_backup(path, expected_state_root).map(|(_, report)| report)
}

fn read_verified_ledger_backup(
    path: &std::path::Path,
    expected_state_root: Option<&str>,
) -> Result<(LedgerBackup, LedgerBackupReport)> {
    let bytes = std::fs::read(path)?;
    let backup: LedgerBackup = serde_json::from_slice(&bytes)?;
    if backup.payload.format_version != 1 {
        return Err(Error::msg(format!(
            "unsupported backup format version {}",
            backup.payload.format_version
        )));
    }
    let checksum = sha256_full_id("backup", &serde_json::to_vec(&backup.payload)?);
    if backup.checksum != checksum {
        return Err(Error::msg("backup payload checksum does not match"));
    }
    if backup.payload.ledger_id != backup.payload.ledger.ledger_id {
        return Err(Error::msg(
            "backup ledger ID does not match its payload metadata",
        ));
    }
    if backup.payload.height != chain_height(&backup.payload.ledger) {
        return Err(Error::msg("backup height does not match its ledger"));
    }
    let state_root = ledger_state_root(&backup.payload.ledger)?;
    if backup.payload.state_root != state_root {
        return Err(Error::msg("backup state root does not match its ledger"));
    }
    if let Some(expected) = expected_state_root
        && expected != state_root
    {
        return Err(Error::msg(format!(
            "backup state root {state_root} does not match expected root {expected}"
        )));
    }
    verify_blockchain_inner(&backup.payload.ledger)?;
    let report = LedgerBackupReport {
        path: path.to_string_lossy().into_owned(),
        height: backup.payload.height,
        state_root,
        checksum,
        bytes: bytes.len() as u64,
    };
    Ok((backup, report))
}

pub fn restore_ledger_backup(
    paths: &DataPaths,
    node_name: &str,
    path: &std::path::Path,
    expected_state_root: &str,
) -> Result<LedgerBackupReport> {
    let (backup, report) = read_verified_ledger_backup(path, Some(expected_state_root))?;
    let config = paths.read_node_config(node_name)?;
    let restored_node_id = preferred_owner_node_id(&backup.payload.ledger, &config.owner_address);
    paths.with_ledger_mut(|ledger| {
        *ledger = backup.payload.ledger;
        Ok(())
    })?;
    let mut config = config;
    config.node_id = restored_node_id;
    paths.write_node_config(&config)?;
    Ok(report)
}

fn preferred_owner_node_id(ledger: &LedgerState, owner_address: &str) -> Option<u64> {
    ledger
        .nodes
        .iter()
        .filter(|(_, node)| node.owner_address == owner_address)
        .max_by_key(|(node_id, node)| (node.status != NodeStatus::Exited, **node_id))
        .map(|(node_id, _)| *node_id)
}

pub fn reconcile_local_node_registration(paths: &DataPaths, name: &str) -> Result<Option<u64>> {
    let mut config = paths.read_node_config(name)?;
    let ledger = paths.read_ledger()?;
    let node_id = preferred_owner_node_id(&ledger, &config.owner_address);
    if config.node_id != node_id {
        config.node_id = node_id;
        paths.write_node_config(&config)?;
    }
    Ok(node_id)
}

pub fn ensure_runtime_compatibility(paths: &DataPaths, name: &str) -> Result<()> {
    let config = paths.read_node_config(name)?;
    let ledger = paths.read_ledger()?;
    if config.version != PROTOCOL_VERSION || ledger.version != PROTOCOL_VERSION {
        return Err(Error::msg(format!(
            "unsupported on-disk version: Node config {}, Ledger {}; this binary requires {}. Back up the data directory and use an explicit upgrade tool",
            config.version, ledger.version, PROTOCOL_VERSION
        )));
    }
    Ok(())
}

fn validate_node_owner_registration(
    ledger: &LedgerState,
    owner_address: &str,
    owner_public_key: &str,
    previous_node_id: Option<u64>,
) -> Result<()> {
    if let Some(active) = ledger
        .nodes
        .values()
        .find(|node| node.owner_address == owner_address && node.status != NodeStatus::Exited)
    {
        return Err(Error::msg(format!(
            "Owner already controls non-EXITED Node {}",
            active.node_id
        )));
    }
    let latest_node_id = ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| (node.owner_address == owner_address).then_some(*node_id))
        .max();
    match (latest_node_id, previous_node_id) {
        (None, None) => return Ok(()),
        (None, Some(_)) => return Err(Error::msg("previous Node does not exist for this Owner")),
        (Some(_), None) => {
            return Err(Error::msg(
                "Owner has prior Node history; join must continue from its latest Node ID",
            ));
        }
        (Some(latest), Some(previous)) if latest != previous => {
            return Err(Error::msg(format!(
                "Node join must reference latest Owner Node {latest}"
            )));
        }
        (Some(_), Some(_)) => {}
    }
    let previous_node_id = previous_node_id.expect("matched previous Node");
    if previous_node_id == 1 {
        return Err(Error::msg("Genesis Node 1 cannot join under a new Node ID"));
    }
    let previous = ledger
        .nodes
        .get(&previous_node_id)
        .expect("latest Owner Node exists");
    if previous.owner_public_key != owner_public_key {
        return Err(Error::msg("previous Node Owner key does not match signer"));
    }
    if previous.status != NodeStatus::Exited {
        return Err(Error::msg(format!(
            "Node {previous_node_id} must be EXITED before its Owner can join again"
        )));
    }
    if previous.claimable_reward != 0
        || !previous.reward_vesting_buckets.is_empty()
        || previous.service_bond != 0
        || previous.governance_bond != 0
        || previous.validator_bond != 0
    {
        return Err(Error::msg(format!(
            "Node {previous_node_id} still has rewards or Bond balances; settle them before joining again"
        )));
    }
    Ok(())
}

pub fn join_node(
    paths: &DataPaths,
    name: &str,
    password: &str,
    endpoint: &str,
    price_text: Option<&str>,
    now: i64,
) -> Result<NodeRecord> {
    let mut config = paths.read_node_config(name)?;
    let previous_node_id = config.node_id;
    let endpoint = parse_wss_endpoint(endpoint)?.to_string();
    let reward_ip = resolve_endpoint_public_ip(&endpoint)?;
    let ip_slot = ip_slot(reward_ip);
    let requested_price_per_gib = price_text
        .map(parse_mrk)
        .transpose()?
        .map(validate_price_per_gib)
        .transpose()?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let relay_file = paths.read_keyfile(&paths.node_relay_key_path(name)?)?;
    let reward_file = paths.read_keyfile(&paths.node_reward_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let node = paths.with_ledger_mut(|ledger| {
        let price_per_gib =
            requested_price_per_gib.unwrap_or_else(|| network_median_price_per_gib(ledger, now));
        ensure_account(ledger, &owner_file)?;
        ensure_account(ledger, &reward_file)?;
        validate_node_owner_registration(
            ledger,
            &owner_file.address,
            &owner_file.public_key,
            previous_node_id,
        )?;
        ensure_node_endpoint_available(ledger, &endpoint, None)?;
        let node_id = ledger.next_node_id;
        ledger.next_node_id += 1;
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({
            "node_id": node_id,
            "previous_node_id": previous_node_id,
            "name": name,
            "owner_public_key": owner_file.public_key,
            "endpoint": endpoint.clone(),
            "reward_ip": reward_ip.to_string(),
            "ip_slot": ip_slot,
            "relay_public_key": relay_file.public_key,
            "reward_address": reward_file.address,
            "reward_public_key": reward_file.public_key,
            "registered_at": now,
            "price_per_gib_base_units": price_per_gib.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeRegistry",
            "RegisterNode",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let (status, warmup_until, active_since) =
            initial_node_lifecycle(node_id, now, ledger.settings.warmup_seconds)?;
        let record = NodeRecord {
            node_id,
            previous_node_id,
            name: name.to_owned(),
            owner_address: owner_file.address.clone(),
            owner_public_key: owner_file.public_key.clone(),
            relay_public_key: relay_file.public_key.clone(),
            reward_address: reward_file.address.clone(),
            endpoint: endpoint.clone(),
            reward_ip: reward_ip.to_string(),
            ip_slot: ip_slot.clone(),
            price_per_gib,
            status,
            registered_at: now,
            warmup_until,
            active_since,
            last_heartbeat: None,
            last_probe_success: None,
            probe_success_count: 0,
            last_relay_receipt_at: None,
            eligible_seconds_by_epoch: BTreeMap::new(),
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            governance_bond: 0,
            governance_bonded_at: None,
            governance_exit_requested_at: None,
            governance_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 0,
            reward_vesting_buckets: Vec::new(),
            validator: false,
            validator_signature_rate_bps: 0,
            validator_bond: 0,
            validator_candidate_since: None,
            validator_last_epoch: None,
            validator_consecutive_epochs: 0,
            validator_exit_requested_at: None,
            validator_bond_unlock_at: None,
        };
        if node_id == 1 {
            if ledger.genesis_authority.is_some() {
                return Err(Error::msg("Genesis Node authority is already established"));
            }
            ledger.genesis_authority = Some(GenesisAuthority {
                node_id,
                owner_address: owner_file.address.clone(),
                owner_public_key: owner_file.public_key.clone(),
                established_at: now,
            });
        } else if ledger.genesis_authority.is_none() {
            return Err(Error::msg(
                "ledger is missing its immutable Genesis Node authority",
            ));
        }
        ledger.nodes.insert(node_id, record.clone());
        bind_ip_slot_if_available(ledger, &ip_slot, node_id, now);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(record)
    })?;
    config.node_id = Some(node.node_id);
    paths.write_node_config(&config)?;
    Ok(node)
}

pub fn update_reward_ip(
    paths: &DataPaths,
    name: &str,
    password: &str,
    endpoint: &str,
    now: i64,
) -> Result<(String, NodeRecord)> {
    let endpoint = parse_wss_endpoint(endpoint)?.to_string();
    let reward_ip = resolve_endpoint_public_ip(&endpoint)?;
    let new_ip_slot = ip_slot(reward_ip);
    let reward_ip = reward_ip.to_string();
    let payload_endpoint = endpoint.clone();
    let payload_reward_ip = reward_ip.clone();
    let payload_ip_slot = new_ip_slot.clone();
    submit_node_registry_update(
        paths,
        name,
        password,
        "UpdateRewardIp",
        now,
        move |node_id| {
            json!({
                "node_id": node_id,
                "endpoint": payload_endpoint,
                "reward_ip": payload_reward_ip,
                "ip_slot": payload_ip_slot,
            })
        },
        move |ledger, node_id| {
            apply_reward_ip_update(ledger, node_id, &endpoint, &reward_ip, &new_ip_slot, now)
        },
    )
}

pub fn update_node_price(
    paths: &DataPaths,
    name: &str,
    password: &str,
    price_text: &str,
    now: i64,
) -> Result<(String, NodeRecord)> {
    let price_per_gib = validate_price_per_gib(parse_mrk(price_text)?)?;
    submit_node_registry_update(
        paths,
        name,
        password,
        "UpdatePrice",
        now,
        move |node_id| {
            json!({
                "node_id": node_id,
                "price_per_gib_base_units": price_per_gib.to_string(),
            })
        },
        move |ledger, node_id| apply_node_price_update(ledger, node_id, price_per_gib),
    )
}

fn submit_node_registry_update<P, A>(
    paths: &DataPaths,
    name: &str,
    password: &str,
    action: &str,
    now: i64,
    payload: P,
    apply: A,
) -> Result<(String, NodeRecord)>
where
    P: FnOnce(u64) -> Value,
    A: FnOnce(&mut LedgerState, u64) -> Result<()>,
{
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_replicated_node_owner(ledger, node_id, &owner_file.address, &owner_file.public_key)
            .map_err(|_| Error::msg("Node Owner key does not match the registry"))?;
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = payload(node_id);
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeRegistry",
            action,
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        apply(ledger, node_id)?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok((operation_id, ledger.nodes[&node_id].clone()))
    })
}

fn initial_node_lifecycle(
    node_id: u64,
    registered_at: i64,
    warmup_seconds: i64,
) -> Result<(NodeStatus, i64, Option<i64>)> {
    if node_id == 1 {
        return Ok((NodeStatus::Active, registered_at, Some(registered_at)));
    }
    let warmup_until = registered_at
        .checked_add(warmup_seconds)
        .ok_or_else(|| Error::msg("Node warmup boundary overflow"))?;
    Ok((NodeStatus::WarmingUp, warmup_until, None))
}

pub fn verify_registered_endpoint(paths: &DataPaths, name: &str) -> Result<IpAddr> {
    let node = node_record(paths, name)?;
    let reward_ip = IpAddr::from_str(&node.reward_ip)
        .map_err(|_| Error::msg("registered node contains an invalid reward IP"))?;
    verify_endpoint_ip(&node.endpoint, reward_ip)?;
    Ok(reward_ip)
}

pub fn node_tick(paths: &DataPaths, name: &str, now: i64) -> Result<NodeRecord> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    paths.with_active_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get_mut(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if !matches!(node.status, NodeStatus::Exited | NodeStatus::Suspended) {
            node.last_heartbeat = Some(now);
        }
        Ok(node.clone())
    })
}

pub fn node_rewards(paths: &DataPaths, name: &str) -> Result<NodeRewardsView> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let ledger = paths.read_ledger()?;
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
    let vesting_reward = node_vesting_reward(node)?;
    Ok(NodeRewardsView {
        node_id,
        status: node.status,
        epoch_eligible_seconds: node
            .eligible_seconds_by_epoch
            .get(&ledger.epoch_number)
            .copied()
            .unwrap_or_default(),
        total_eligible_seconds: node.total_eligible_seconds,
        service_bond: node.service_bond,
        service_bond_display: format_mrk(node.service_bond),
        service_bond_unlock_at: node.service_bond_unlock_at,
        offline_slashed_at: node.offline_slashed_at,
        offline_slashed_service_bond: node.offline_slashed_service_bond,
        offline_slashed_service_bond_display: format_mrk(node.offline_slashed_service_bond),
        offline_slashed_vesting_reward: node.offline_slashed_vesting_reward,
        offline_slashed_vesting_reward_display: format_mrk(node.offline_slashed_vesting_reward),
        claimable_reward: node.claimable_reward,
        claimable_reward_display: format_mrk(node.claimable_reward),
        vesting_reward,
        vesting_reward_display: format_mrk(vesting_reward),
        vesting_bucket_count: node.reward_vesting_buckets.len(),
    })
}

pub fn claim_node_rewards(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<(String, u128)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let claimable = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?
            .claimable_reward;
        if claimable == 0 {
            return Err(Error::msg("node has no claimable MRK reward"));
        }
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": claimable.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeEmissionController",
            "ClaimNodeReward",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        ledger
            .nodes
            .get_mut(&node_id)
            .expect("node")
            .claimable_reward -= claimable;
        let reward_address = ledger
            .nodes
            .get(&node_id)
            .expect("node")
            .reward_address
            .clone();
        ledger
            .accounts
            .entry(reward_address.clone())
            .or_default()
            .balance += claimable;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &reward_address, &operation_id);
        Ok((operation_id, claimable))
    })
}

pub fn drain_node(paths: &DataPaths, name: &str, password: &str, now: i64) -> Result<String> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        ensure_node_can_drain(node)?;
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({"node_id": node_id});
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeRegistry",
            "DrainNode",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        ledger.nodes.get_mut(&node_id).expect("node").status = NodeStatus::Draining;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(operation_id)
    })
}

pub fn withdraw_service_bond(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<(String, u128)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        if node.status != NodeStatus::Exited {
            return Err(Error::msg(
                "Service Bond can only be withdrawn after the Node has exited",
            ));
        }
        let unlock_at = node
            .service_bond_unlock_at
            .ok_or_else(|| Error::msg("Service Bond is not pending unlock"))?;
        if now < unlock_at {
            return Err(Error::msg(format!(
                "Service Bond remains locked until {unlock_at}"
            )));
        }
        let amount = node.service_bond;
        if amount == 0 {
            return Err(Error::msg("node has no Service Bond to withdraw"));
        }
        let reward_address = node.reward_address.clone();
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": amount.to_string(),
            "reward_address": reward_address,
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeRegistry",
            "WithdrawServiceBond",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let node = ledger.nodes.get_mut(&node_id).expect("Node exists");
        node.service_bond = 0;
        node.service_bond_unlock_at = None;
        let account = ledger.accounts.entry(reward_address.clone()).or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &reward_address, &operation_id);
        Ok((operation_id, amount))
    })
}

pub fn node_probe_response(
    paths: &DataPaths,
    name: &str,
    password: &str,
    challenge: &str,
) -> Result<ProbePayload> {
    if challenge.len() < 16 || challenge.len() > 512 {
        return Err(Error::msg(
            "probe challenge must contain between 16 and 512 characters",
        ));
    }
    let config = paths.read_node_config(name)?;
    let keyfile = paths.read_keyfile(&paths.node_relay_key_path(name)?)?;
    let key = decrypt_key(&keyfile, password)?;
    let timestamp = Utc::now().timestamp();
    let payload = format!(
        "mrk-probe-v1:{}:{timestamp}:{challenge}",
        config.node_id.unwrap_or_default()
    );
    Ok(ProbePayload {
        protocol: "mrk-probe-v1".to_owned(),
        node_id: config.node_id.unwrap_or_default(),
        relay_public_key: keyfile.public_key,
        timestamp,
        challenge: challenge.to_owned(),
        signature: sign_bytes(&key, payload.as_bytes()),
    })
}

fn epoch_context(ledger: &LedgerState, epoch: u64) -> Result<&EpochContext> {
    ledger
        .epoch_contexts
        .get(&epoch)
        .ok_or_else(|| Error::msg(format!("Epoch {epoch} is no longer accepting operations")))
}

fn availability_slot_key(epoch: u64, target_node_id: u64, slot: i64) -> String {
    format!("{epoch}:{target_node_id}:{slot}")
}

fn availability_slot_bounds(context: &EpochContext, slot: i64) -> Result<(i64, i64)> {
    if slot < 0 {
        return Err(Error::msg("availability slot is outside its Epoch"));
    }
    let slot_start = slot
        .checked_mul(context.settings.availability_slot_seconds)
        .and_then(|offset| context.started_at.checked_add(offset))
        .ok_or_else(|| Error::msg("availability slot timestamp overflow"))?;
    let slot_end = slot_start
        .checked_add(context.settings.availability_slot_seconds)
        .ok_or_else(|| Error::msg("availability slot end overflow"))?;
    if slot_start < context.started_at || slot_end > context.ended_at {
        return Err(Error::msg("availability slot is outside its Epoch"));
    }
    Ok((slot_start, slot_end))
}

fn active_availability_slot(context: &EpochContext, timestamp: i64) -> Result<Option<i64>> {
    let slot_seconds = context.settings.availability_slot_seconds;
    if slot_seconds <= 0 {
        return Err(Error::msg("availability slot duration is invalid"));
    }
    if timestamp < context.started_at || timestamp >= context.ended_at {
        return Ok(None);
    }
    let slot = timestamp
        .checked_sub(context.started_at)
        .ok_or_else(|| Error::msg("availability timestamp overflow"))?
        .div_euclid(slot_seconds);
    availability_slot_bounds(context, slot)?;
    Ok(Some(slot))
}

#[derive(Clone, Debug)]
struct AvailabilityVerifierSet {
    mode: AvailabilityMode,
    primary_ids: Vec<u64>,
    primary_quorum: u32,
    audit_required: bool,
    auditor_ids: Vec<u64>,
    audit_quorum: u32,
}

fn availability_verifier_set(
    ledger: &LedgerState,
    context: &EpochContext,
    target_node_id: u64,
    slot: i64,
) -> AvailabilityVerifierSet {
    if context.availability_mode == AvailabilityMode::Node1Trusted {
        return AvailabilityVerifierSet {
            mode: AvailabilityMode::Node1Trusted,
            primary_ids: ledger
                .nodes
                .contains_key(&1)
                .then_some(1)
                .into_iter()
                .collect(),
            primary_quorum: 1,
            audit_required: false,
            auditor_ids: Vec::new(),
            audit_quorum: 0,
        };
    }
    if context.validator_ids.len() < MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS {
        return AvailabilityVerifierSet {
            mode: AvailabilityMode::MultiValidator,
            primary_ids: Vec::new(),
            primary_quorum: context.settings.availability_quorum,
            audit_required: false,
            auditor_ids: Vec::new(),
            audit_quorum: 0,
        };
    }
    let mut candidates = context
        .validator_ids
        .iter()
        .copied()
        .filter(|node_id| *node_id != target_node_id)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|node_id| {
        sha256_full_id(
            "availability-primary-selector-v1",
            format!(
                "{}:{}:{target_node_id}:{slot}:{node_id}",
                ledger.ledger_id, context.epoch
            )
            .as_bytes(),
        )
    });
    let primary_count = context.settings.availability_verifier_count as usize;
    if candidates.len() < primary_count
        || context.settings.availability_quorum > context.settings.availability_verifier_count
    {
        return AvailabilityVerifierSet {
            mode: AvailabilityMode::MultiValidator,
            primary_ids: Vec::new(),
            primary_quorum: context.settings.availability_quorum,
            audit_required: false,
            auditor_ids: Vec::new(),
            audit_quorum: 0,
        };
    }
    let mut primary_ids = candidates[..primary_count].to_vec();
    primary_ids.sort_unstable();
    let audit_sampled = deterministic_mod(
        "availability-audit-sample-v1",
        format!(
            "{}:{}:{target_node_id}:{slot}",
            ledger.ledger_id, context.epoch
        )
        .as_bytes(),
        10_000,
    ) < u64::from(context.settings.availability_audit_rate_bps);
    let mut auditor_candidates = candidates
        .into_iter()
        .filter(|node_id| !primary_ids.contains(node_id))
        .collect::<Vec<_>>();
    auditor_candidates.sort_by_key(|node_id| {
        sha256_full_id(
            "availability-auditor-selector-v1",
            format!(
                "{}:{}:{target_node_id}:{slot}:{node_id}",
                ledger.ledger_id, context.epoch
            )
            .as_bytes(),
        )
    });
    let auditor_count = context.settings.availability_auditor_count as usize;
    let audit_required = audit_sampled
        && context.validator_ids.len() >= MIN_AUDITED_AVAILABILITY_VALIDATORS
        && auditor_candidates.len() >= auditor_count
        && context.settings.availability_audit_quorum
            <= context.settings.availability_auditor_count;
    let mut auditor_ids = if audit_required {
        auditor_candidates[..auditor_count].to_vec()
    } else {
        Vec::new()
    };
    auditor_ids.sort_unstable();
    AvailabilityVerifierSet {
        mode: AvailabilityMode::MultiValidator,
        primary_ids,
        primary_quorum: context.settings.availability_quorum,
        audit_required,
        auditor_ids,
        audit_quorum: if audit_required {
            context.settings.availability_audit_quorum
        } else {
            0
        },
    }
}

fn deterministic_mod(domain: &str, bytes: &[u8], modulus: u64) -> u64 {
    debug_assert!(modulus > 0);
    let hash = sha256_full_id(domain, bytes);
    let suffix = &hash[hash.len() - 16..];
    u64::from_str_radix(suffix, 16).expect("SHA-256 suffix is hexadecimal") % modulus
}

fn availability_role_text(role: AvailabilityVerifierRole) -> &'static str {
    match role {
        AvailabilityVerifierRole::Primary => "PRIMARY",
        AvailabilityVerifierRole::Audit => "AUDIT",
    }
}

fn availability_ticket_message(
    ledger_id: &str,
    epoch: u64,
    slot: i64,
    target_node_id: u64,
    verifier_node_id: u64,
    role: AvailabilityVerifierRole,
) -> Vec<u8> {
    format!(
        "mrk-availability-ticket-v1:{ledger_id}:{epoch}:{slot}:{target_node_id}:{verifier_node_id}:{}",
        availability_role_text(role)
    )
    .into_bytes()
}

fn availability_challenge(ticket_signature: &str) -> String {
    sha256_full_id("availability-challenge-v1", ticket_signature.as_bytes())
}

fn availability_scheduled_at(
    ticket_signature: &str,
    slot_start: i64,
    slot_seconds: i64,
    role: AvailabilityVerifierRole,
) -> Result<i64> {
    if slot_seconds < 60 {
        return Err(Error::msg(
            "Availability requires slots of at least 60 seconds",
        ));
    }
    let (start_offset, end_offset) = match role {
        AvailabilityVerifierRole::Primary => (2_i64, slot_seconds / 2 - 10),
        AvailabilityVerifierRole::Audit => (slot_seconds / 2 + 2, slot_seconds - 10),
    };
    let width = u64::try_from(end_offset - start_offset + 1)
        .map_err(|_| Error::msg("availability Probe scheduling window is invalid"))?;
    let offset = start_offset
        + i64::try_from(deterministic_mod(
            "availability-schedule-v1",
            ticket_signature.as_bytes(),
            width,
        ))
        .expect("schedule offset fits in i64");
    slot_start
        .checked_add(offset)
        .ok_or_else(|| Error::msg("availability Probe schedule overflow"))
}

fn build_availability_probe_request(
    ledger: &LedgerState,
    context: &EpochContext,
    target_node_id: u64,
    verifier_node_id: u64,
    role: AvailabilityVerifierRole,
    slot: i64,
    owner_key: &Ed25519KeyPair,
) -> Result<AvailabilityProbeRequest> {
    let ticket_signature = sign_bytes(
        owner_key,
        &availability_ticket_message(
            &ledger.ledger_id,
            context.epoch,
            slot,
            target_node_id,
            verifier_node_id,
            role,
        ),
    );
    let (slot_start, _) = availability_slot_bounds(context, slot)?;
    let scheduled_at = availability_scheduled_at(
        &ticket_signature,
        slot_start,
        context.settings.availability_slot_seconds,
        role,
    )?;
    let target = ledger
        .nodes
        .get(&target_node_id)
        .cloned()
        .ok_or_else(|| Error::msg("Probe target Node is not registered"))?;
    Ok(AvailabilityProbeRequest {
        target,
        verifier_node_id,
        epoch: context.epoch,
        slot,
        role,
        challenge: availability_challenge(&ticket_signature),
        ticket_signature,
        scheduled_at,
    })
}

pub fn availability_probe_request(
    paths: &DataPaths,
    verifier_name: &str,
    password: &str,
    target_node_id: u64,
    now: i64,
) -> Result<AvailabilityProbeRequest> {
    let verifier_node_id = paths
        .read_node_config(verifier_name)?
        .node_id
        .ok_or_else(|| Error::msg("Probe verifier Node is not registered"))?;
    let ledger = paths.read_ledger()?;
    let context = epoch_context(&ledger, ledger.epoch_number)?;
    let slot = active_availability_slot(context, now)?
        .ok_or_else(|| Error::msg("availability timestamp is outside the current Epoch"))?;
    let set = availability_verifier_set(&ledger, context, target_node_id, slot);
    let role = if set.primary_ids.contains(&verifier_node_id) {
        AvailabilityVerifierRole::Primary
    } else if set.auditor_ids.contains(&verifier_node_id) {
        AvailabilityVerifierRole::Audit
    } else {
        return Err(Error::msg(format!(
            "Node {verifier_node_id} is not selected to Probe Node {target_node_id} in availability slot {slot}"
        )));
    };
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(verifier_name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let mut request = build_availability_probe_request(
        &ledger,
        context,
        target_node_id,
        verifier_node_id,
        role,
        slot,
        &owner_key,
    )?;
    if set.mode == AvailabilityMode::Node1Trusted {
        request.scheduled_at = now;
    }
    if now > request.scheduled_at.saturating_add(10) {
        return Err(Error::msg(format!(
            "Probe Ticket window ended at {}; current time is {now}",
            request.scheduled_at.saturating_add(10),
        )));
    }
    Ok(request)
}

pub fn availability_probe_requests(
    paths: &DataPaths,
    verifier_name: &str,
    signer: &AvailabilityTicketSigner,
    now: i64,
    limit: usize,
) -> Result<Vec<AvailabilityProbeRequest>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let verifier_node_id = paths
        .read_node_config(verifier_name)?
        .node_id
        .ok_or_else(|| Error::msg("Probe verifier Node is not registered"))?;
    let ledger = paths.read_ledger()?;
    if signer.node_id != verifier_node_id {
        return Err(Error::msg(
            "Availability Ticket signer does not match the local Node",
        ));
    }
    let context = epoch_context(&ledger, ledger.epoch_number)?;
    let Some(slot) = active_availability_slot(context, now)? else {
        return Ok(Vec::new());
    };
    let mut requests = ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| {
            if matches!(
                node.status,
                NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
            ) {
                return None;
            }
            let set = availability_verifier_set(&ledger, context, *node_id, slot);
            let role = if set.primary_ids.contains(&verifier_node_id) {
                AvailabilityVerifierRole::Primary
            } else if set.auditor_ids.contains(&verifier_node_id) {
                AvailabilityVerifierRole::Audit
            } else {
                return None;
            };
            let already_submitted = ledger
                .availability_slots
                .get(&availability_slot_key(context.epoch, *node_id, slot))
                .is_some_and(|record| match role {
                    AvailabilityVerifierRole::Primary => {
                        record.primary_operation_ids.contains_key(&verifier_node_id)
                    }
                    AvailabilityVerifierRole::Audit => {
                        record.audit_operation_ids.contains_key(&verifier_node_id)
                    }
                });
            if already_submitted {
                return None;
            }
            let mut request = build_availability_probe_request(
                &ledger,
                context,
                *node_id,
                verifier_node_id,
                role,
                slot,
                &signer.owner_key,
            )
            .ok()?;
            if set.mode == AvailabilityMode::Node1Trusted {
                request.scheduled_at = now;
            }
            Some(request).filter(|request| {
                now >= request.scheduled_at && now <= request.scheduled_at.saturating_add(10)
            })
        })
        .collect::<Vec<_>>();
    requests.sort_by_key(|request| {
        sha256_full_id(
            "availability-work",
            format!(
                "{}:{slot}:{verifier_node_id}:{}:{}",
                ledger.ledger_id,
                request.target.node_id,
                availability_role_text(request.role)
            )
            .as_bytes(),
        )
    });
    requests.truncate(limit);
    Ok(requests)
}

pub fn submit_node_probe_attestation(
    paths: &DataPaths,
    verifier_name: &str,
    password: &str,
    request: AvailabilityAttestationRequest,
) -> Result<AvailabilitySubmissionView> {
    let config = paths.read_node_config(verifier_name)?;
    let verifier_node_id = config
        .node_id
        .ok_or_else(|| Error::msg("Probe verifier Node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(verifier_name)?)?;
    let ledger = paths.read_ledger()?;
    let nonce = ledger
        .accounts
        .get(&owner_file.address)
        .map_or(1, |account| account.nonce.saturating_add(1));
    let payload = json!({
        "target_node_id": request.response.node_id,
        "verifier_node_id": verifier_node_id,
        "slot": request.slot,
        "epoch": request.epoch,
        "role": request.role,
        "ticket_signature": request.ticket_signature,
        "probe": request.response,
    });
    let fee_quote = fee::quote(&ledger, "Availability", "AttestProbe", &payload)?;
    let operation = sign_public_operation(
        &owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: &ledger.ledger_id,
            module: "Availability",
            action: "AttestProbe",
            nonce,
            valid_until: request.now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            max_fee_base_units: fee_quote.recommended_max_fee,
            fee_policy_version: fee_quote.policy_version,
            payload,
        },
    )?;
    let operation_id_value = operation_id(&operation)?;
    submit_signed_node_operation(paths, &owner_file.public_key, operation, request.now)?;
    let ledger = paths.read_ledger()?;
    let key = availability_slot_key(
        request.epoch,
        ledger.operations[&operation_id_value].payload["target_node_id"]
            .as_u64()
            .expect("validated target"),
        request.slot,
    );
    let record = ledger
        .availability_slots
        .get(&key)
        .ok_or_else(|| Error::msg("availability attestation was not recorded"))?;
    Ok(AvailabilitySubmissionView {
        operation_id: operation_id_value,
        target_node_id: record.target_node_id,
        verifier_node_id,
        slot: request.slot,
        role: request.role,
        primary_attestation_count: record.primary_operation_ids.len(),
        primary_quorum: record.primary_quorum,
        audit_required: record.audit_required,
        audit_attestation_count: record.audit_operation_ids.len(),
        audit_quorum: record.audit_quorum,
        credited_seconds: record.credited_seconds,
    })
}

fn verify_node_probe_payload(ledger: &LedgerState, response: &ProbePayload) -> Result<()> {
    if response.protocol != "mrk-probe-v1" {
        return Err(Error::msg("unsupported node Probe protocol"));
    }
    if response.challenge.len() < 16 || response.challenge.len() > 512 {
        return Err(Error::msg("node Probe challenge has an invalid length"));
    }
    let node = ledger
        .nodes
        .get(&response.node_id)
        .ok_or_else(|| Error::msg("node Probe references an unknown node"))?;
    if node.relay_public_key != response.relay_public_key {
        return Err(Error::msg("node Probe Relay key does not match registry"));
    }
    let payload = format!(
        "mrk-probe-v1:{}:{}:{}",
        response.node_id, response.timestamp, response.challenge
    );
    verify_bytes(
        &node.relay_public_key,
        payload.as_bytes(),
        &response.signature,
    )
}

pub fn node_record(paths: &DataPaths, name: &str) -> Result<NodeRecord> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    node_record_by_id_if_present(paths, node_id)?
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))
}

pub fn node_record_by_id(paths: &DataPaths, node_id: u64) -> Result<NodeRecord> {
    node_record_by_id_if_present(paths, node_id)?
        .ok_or_else(|| Error::msg(format!("node {node_id} is not registered")))
}

pub fn node_record_by_id_if_present(paths: &DataPaths, node_id: u64) -> Result<Option<NodeRecord>> {
    Ok(paths.read_active_ledger()?.nodes.get(&node_id).cloned())
}

pub fn registry_node_by_id(paths: &DataPaths, node_id: u64, now: i64) -> Result<RegistryNodeView> {
    let ledger = paths.read_ledger()?;
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg(format!("node {node_id} is not registered")))?;
    Ok(registry_node_view(node, &ledger, now))
}

pub fn registry_nodes(
    paths: &DataPaths,
    status: Option<NodeStatus>,
    availability: Option<RegistryNodeAvailability>,
    validator_only: bool,
    cursor: Option<u64>,
    limit: usize,
    now: i64,
) -> Result<RegistryNodeListView> {
    validate_registry_page_limit(limit)?;
    let ledger = paths.read_ledger()?;
    let mut nodes = ledger
        .nodes
        .range((
            std::ops::Bound::Excluded(cursor.unwrap_or(0)),
            std::ops::Bound::Unbounded,
        ))
        .filter_map(|(_, node)| {
            let view = registry_node_view(node, &ledger, now);
            (status.is_none_or(|status| node.status == status)
                && availability.is_none_or(|availability| view.availability == Some(availability))
                && (!validator_only || node.validator))
                .then_some(view)
        })
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = nodes.len() > limit;
    nodes.truncate(limit);
    let next_cursor = has_more.then(|| nodes.last().expect("non-empty page").node_id);
    Ok(RegistryNodeListView { nodes, next_cursor })
}

pub fn discover_relays(
    paths: &DataPaths,
    cursor: Option<u64>,
    limit: usize,
    now: i64,
) -> Result<RelayDiscoveryListView> {
    validate_registry_page_limit(limit)?;
    let ledger = paths.read_ledger()?;
    let validity = ledger.settings.probe_validity_seconds;
    let mut relays = ledger
        .nodes
        .range((
            std::ops::Bound::Excluded(cursor.unwrap_or(0)),
            std::ops::Bound::Unbounded,
        ))
        .filter_map(|(_, node)| {
            let last_probe_success = node.last_probe_success?;
            let probe_is_fresh = validity >= 0
                && last_probe_success <= now
                && now.saturating_sub(last_probe_success) <= validity;
            let owns_ip_slot = ledger
                .ip_slots
                .get(&node.ip_slot)
                .is_some_and(|slot| slot.node_id == node.node_id && slot.released_at.is_none());
            (node.status == NodeStatus::Active && probe_is_fresh && owns_ip_slot).then(|| {
                RelayDiscoveryView {
                    node_id: node.node_id,
                    endpoint: node.endpoint.clone(),
                    reward_ip: node.reward_ip.clone(),
                    price_per_gib_base_units: node.price_per_gib.to_string(),
                    price_per_gib_display: format_mrk(node.price_per_gib),
                    last_probe_success,
                    probe_valid_until: last_probe_success.saturating_add(validity),
                    validator: node.validator,
                }
            })
        })
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = relays.len() > limit;
    relays.truncate(limit);
    let next_cursor = has_more.then(|| relays.last().expect("non-empty page").node_id);
    Ok(RelayDiscoveryListView {
        relays,
        next_cursor,
    })
}

fn validate_registry_page_limit(limit: usize) -> Result<()> {
    if !(1..=1_000).contains(&limit) {
        return Err(Error::msg("page limit must be between 1 and 1000"));
    }
    Ok(())
}

fn registry_node_view(node: &NodeRecord, ledger: &LedgerState, now: i64) -> RegistryNodeView {
    let settings = &ledger.settings;
    let owns_ip_slot = ledger
        .ip_slots
        .get(&node.ip_slot)
        .is_some_and(|slot| slot.node_id == node.node_id && slot.released_at.is_none());
    let ip_slot_unavailable = ledger.ip_slots.get(&node.ip_slot).is_some_and(|slot| {
        !owns_ip_slot
            && !slot.released_at.is_some_and(|released_at| {
                now >= released_at
                    && now.saturating_sub(released_at) >= settings.ip_reuse_cooldown_seconds
            })
    });
    let probe_valid_until = node
        .last_probe_success
        .map(|timestamp| timestamp.saturating_add(settings.probe_validity_seconds));
    let lifecycle_is_serviceable =
        matches!(node.status, NodeStatus::WarmingUp | NodeStatus::Active);
    let offline_exit_at = lifecycle_is_serviceable.then(|| {
        node.last_probe_success
            .unwrap_or(node.registered_at)
            .saturating_add(settings.offline_slash_seconds)
    });
    let availability = if !lifecycle_is_serviceable {
        None
    } else if offline_exit_at.is_some_and(|exit_at| now >= exit_at) {
        Some(RegistryNodeAvailability::ExitPending)
    } else if ip_slot_unavailable {
        Some(RegistryNodeAvailability::IpSlotUnavailable)
    } else if !owns_ip_slot || node.last_probe_success.is_none() {
        Some(RegistryNodeAvailability::Unverified)
    } else if probe_valid_until.is_some_and(|valid_until| {
        node.last_probe_success
            .is_some_and(|timestamp| timestamp <= now)
            && now <= valid_until
    }) {
        Some(RegistryNodeAvailability::Online)
    } else {
        Some(RegistryNodeAvailability::ProbeStale)
    };
    let ip_slot_reusable_at = (!owns_ip_slot)
        .then(|| ledger.ip_slots.get(&node.ip_slot)?.released_at)
        .flatten()
        .map(|released_at| released_at.saturating_add(settings.ip_reuse_cooldown_seconds))
        .filter(|reusable_at| *reusable_at > now);
    RegistryNodeView {
        node_id: node.node_id,
        previous_node_id: node.previous_node_id,
        name: node.name.clone(),
        owner_address: node.owner_address.clone(),
        owner_public_key: node.owner_public_key.clone(),
        relay_public_key: node.relay_public_key.clone(),
        reward_address: node.reward_address.clone(),
        endpoint: node.endpoint.clone(),
        reward_ip: node.reward_ip.clone(),
        price_per_gib_base_units: node.price_per_gib.to_string(),
        price_per_gib_display: format_mrk(node.price_per_gib),
        status: node.status,
        registered_at: node.registered_at,
        warmup_until: node.warmup_until,
        active_since: node.active_since,
        last_probe_success: node.last_probe_success,
        probe_success_count: node.probe_success_count,
        availability,
        probe_valid_until,
        offline_exit_at,
        owns_ip_slot,
        ip_slot_reusable_at,
        service_bond_base_units: node.service_bond.to_string(),
        service_bond_display: format_mrk(node.service_bond),
        service_bond_unlock_at: node.service_bond_unlock_at,
        governance_bond_base_units: node.governance_bond.to_string(),
        governance_bond_display: format_mrk(node.governance_bond),
        governance_bonded_at: node.governance_bonded_at,
        governance_exit_requested_at: node.governance_exit_requested_at,
        governance_bond_unlock_at: node.governance_bond_unlock_at,
        offline_slashed_at: node.offline_slashed_at,
        validator: node.validator,
        validator_candidate: node.validator_candidate_since.is_some()
            && node.validator_exit_requested_at.is_none()
            && node.validator_bond >= settings.validator_bond,
    }
}

pub fn governance_bond_status(
    paths: &DataPaths,
    name: &str,
    now: i64,
) -> Result<GovernanceBondStatusView> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let ledger = paths.read_ledger()?;
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
    Ok(GovernanceBondStatusView {
        node_id,
        eligible: governance_node_is_eligible(&ledger, node_id, now),
        governance_bond: node.governance_bond,
        governance_bond_display: format_mrk(node.governance_bond),
        required_bond: ledger.settings.required_governance_bond,
        required_bond_display: format_mrk(ledger.settings.required_governance_bond),
        bonded_at: node.governance_bonded_at,
        matures_at: governance_bond_matures_at(node, &ledger.settings),
        exit_requested_at: node.governance_exit_requested_at,
        bond_unlock_at: node.governance_bond_unlock_at,
    })
}

pub fn bond_governance(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<GovernanceBondReceipt> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let reward_file = paths.read_keyfile(&paths.node_reward_key_path(name)?)?;
    let reward_key = decrypt_key(&reward_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_account(ledger, &reward_file)?;
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != config.owner_address || node.reward_address != reward_file.address
        {
            return Err(Error::msg("local Node keys do not match the Node registry"));
        }
        if matches!(
            node.status,
            NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
        ) {
            return Err(Error::msg(
                "Governance Bond cannot be added while the Node is draining, exited, or suspended",
            ));
        }
        if node.governance_exit_requested_at.is_some() {
            return Err(Error::msg(
                "Governance exit is pending; withdraw the old bond before bonding again",
            ));
        }
        let needed = ledger
            .settings
            .required_governance_bond
            .saturating_sub(node.governance_bond);
        if needed == 0 {
            return Err(Error::msg("node already has the required Governance Bond"));
        }
        let reward_account = ledger
            .accounts
            .get(&reward_file.address)
            .cloned()
            .unwrap_or_default();
        if reward_account.balance < needed {
            return Err(Error::msg(format!(
                "insufficient spendable MRK for Governance Bond: available {}, required {}",
                format_mrk(reward_account.balance),
                format_mrk(needed)
            )));
        }
        let matures_at = now
            .checked_add(ledger.settings.governance_bond_maturity_seconds)
            .ok_or_else(|| Error::msg("Governance Bond maturity timestamp overflow"))?;
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": needed.to_string(),
            "bonded_at": now,
        });
        let signed = sign_operation(
            ledger,
            (&reward_file, &reward_key),
            "StakeVault",
            "BondGovernance",
            reward_account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &reward_file.public_key)?;
        ledger
            .accounts
            .get_mut(&reward_file.address)
            .expect("reward account")
            .balance -= needed;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.governance_bond = node
            .governance_bond
            .checked_add(needed)
            .ok_or_else(|| Error::msg("Governance Bond overflow"))?;
        node.governance_bonded_at = Some(now);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        let node = ledger.nodes.get(&node_id).expect("node");
        Ok(GovernanceBondReceipt {
            operation_id,
            status: OperationStatus::Pending,
            node_id,
            bonded: needed,
            bonded_display: format_mrk(needed),
            total_governance_bond: node.governance_bond,
            total_governance_bond_display: format_mrk(node.governance_bond),
            bonded_at: now,
            matures_at,
        })
    })
}

pub fn request_governance_exit(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<String> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        if node.governance_bond == 0 {
            return Err(Error::msg("node has no Governance Bond"));
        }
        if node.governance_exit_requested_at.is_some() {
            return Err(Error::msg("Governance exit is already pending"));
        }
        let account = ledger.accounts[&owner_file.address].clone();
        let unlock_at = now
            .checked_add(ledger.settings.governance_bond_unlock_seconds)
            .ok_or_else(|| Error::msg("Governance Bond unlock timestamp overflow"))?;
        let payload = json!({"node_id": node_id, "unlock_at": unlock_at});
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "StakeVault",
            "ExitGovernance",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.governance_exit_requested_at = Some(now);
        node.governance_bond_unlock_at = Some(unlock_at);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(operation_id)
    })
}

pub fn withdraw_governance_bond(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<(String, u128)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        let unlock_at = node
            .governance_bond_unlock_at
            .ok_or_else(|| Error::msg("Governance exit has not been requested"))?;
        if now < unlock_at {
            return Err(Error::msg(format!(
                "Governance Bond remains locked until {unlock_at}"
            )));
        }
        let amount = node.governance_bond;
        if amount == 0 {
            return Err(Error::msg("node has no Governance Bond to withdraw"));
        }
        let reward_address = node.reward_address.clone();
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": amount.to_string(),
            "reward_address": reward_address,
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "StakeVault",
            "WithdrawGovernanceBond",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.governance_bond = 0;
        node.governance_bonded_at = None;
        node.governance_exit_requested_at = None;
        node.governance_bond_unlock_at = None;
        let account = ledger.accounts.entry(reward_address.clone()).or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &reward_address, &operation_id);
        Ok((operation_id, amount))
    })
}

pub fn validator_status(paths: &DataPaths, name: &str) -> Result<ValidatorStatusView> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let ledger = paths.read_ledger()?;
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
    Ok(ValidatorStatusView {
        node_id,
        candidate: node.validator_candidate_since.is_some()
            && node.validator_exit_requested_at.is_none()
            && node.validator_bond >= ledger.settings.validator_bond,
        active_validator: node.validator,
        validator_bond: node.validator_bond,
        validator_bond_display: format_mrk(node.validator_bond),
        required_bond: ledger.settings.validator_bond,
        required_bond_display: format_mrk(ledger.settings.validator_bond),
        candidate_since: node.validator_candidate_since,
        last_validator_epoch: node.validator_last_epoch,
        consecutive_epochs: node.validator_consecutive_epochs,
        exit_requested_at: node.validator_exit_requested_at,
        bond_unlock_at: node.validator_bond_unlock_at,
    })
}

pub fn join_validator_pool(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<ValidatorBondReceipt> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let reward_file = paths.read_keyfile(&paths.node_reward_key_path(name)?)?;
    let reward_key = decrypt_key(&reward_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_account(ledger, &reward_file)?;
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != config.owner_address || node.reward_address != reward_file.address
        {
            return Err(Error::msg("local Node keys do not match the Node registry"));
        }
        if node.validator_exit_requested_at.is_some() {
            return Err(Error::msg(
                "validator exit is pending; withdraw the old bond before joining again",
            ));
        }
        let needed = ledger
            .settings
            .validator_bond
            .saturating_sub(node.validator_bond);
        if needed == 0 {
            return Err(Error::msg("node already has the required Validator Bond"));
        }
        let reward_account = ledger
            .accounts
            .get(&reward_file.address)
            .cloned()
            .unwrap_or_default();
        if reward_account.balance < needed {
            return Err(Error::msg(format!(
                "insufficient spendable MRK for Validator Bond: available {}, required {}",
                format_mrk(reward_account.balance),
                format_mrk(needed)
            )));
        }
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": needed.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&reward_file, &reward_key),
            "StakeVault",
            "BondValidator",
            reward_account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &reward_file.public_key)?;
        ledger
            .accounts
            .get_mut(&reward_file.address)
            .expect("reward account")
            .balance -= needed;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.validator_bond += needed;
        if node.validator_bond >= ledger.settings.validator_bond
            && node.validator_candidate_since.is_none()
        {
            node.validator_candidate_since = Some(now);
        }
        finalize_operation(ledger, &signed, &operation_id, now)?;
        refresh_validator_committee(ledger, now)?;
        let node = ledger.nodes.get(&node_id).expect("node");
        Ok(ValidatorBondReceipt {
            operation_id,
            status: OperationStatus::Pending,
            node_id,
            bonded: needed,
            bonded_display: format_mrk(needed),
            total_validator_bond: node.validator_bond,
            total_validator_bond_display: format_mrk(node.validator_bond),
            candidate: node.validator_candidate_since.is_some(),
        })
    })
}

pub fn request_validator_exit(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<String> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        if node.validator_bond == 0 {
            return Err(Error::msg("node has no Validator Bond"));
        }
        if node.validator_exit_requested_at.is_some() {
            return Err(Error::msg("validator exit is already pending"));
        }
        let account = ledger.accounts[&owner_file.address].clone();
        let unlock_at = now
            .checked_add(VALIDATOR_BOND_UNLOCK_SECONDS)
            .ok_or_else(|| Error::msg("Validator Bond unlock timestamp overflow"))?;
        let payload = json!({"node_id": node_id, "unlock_at": unlock_at});
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "StakeVault",
            "ExitValidator",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.validator_exit_requested_at = Some(now);
        node.validator_bond_unlock_at = Some(unlock_at);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(operation_id)
    })
}

pub fn withdraw_validator_bond(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<(String, u128)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        let unlock_at = node
            .validator_bond_unlock_at
            .ok_or_else(|| Error::msg("validator exit has not been requested"))?;
        if now < unlock_at {
            return Err(Error::msg(format!(
                "Validator Bond remains locked until {unlock_at}"
            )));
        }
        if node.validator {
            return Err(Error::msg(
                "Validator Bond cannot be withdrawn while the node is in the active committee",
            ));
        }
        let amount = node.validator_bond;
        if amount == 0 {
            return Err(Error::msg("node has no Validator Bond to withdraw"));
        }
        let reward_address = node.reward_address.clone();
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "node_id": node_id,
            "amount_base_units": amount.to_string(),
            "reward_address": reward_address,
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "StakeVault",
            "WithdrawValidatorBond",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let node = ledger.nodes.get_mut(&node_id).expect("node");
        node.validator_bond = 0;
        node.validator_candidate_since = None;
        node.validator_exit_requested_at = None;
        node.validator_bond_unlock_at = None;
        let account = ledger.accounts.entry(reward_address.clone()).or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| Error::msg("Reward account balance overflow"))?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &reward_address, &operation_id);
        Ok((operation_id, amount))
    })
}

pub fn validator_committee(paths: &DataPaths, now: i64) -> Result<ValidatorCommitteeView> {
    let ledger = paths.read_ledger()?;
    let candidates = validator_candidate_node_ids(&ledger, now);
    let active = ledger.consensus.active_validators.clone();
    let set_hash = validator_set_hash(&ledger, &active)?;
    let next_height = next_block_height(&ledger);
    let proposer = consensus_proposer(&active, next_height, ledger.consensus.round);
    let rotation_interval = u64::from(ledger.settings.validator_rotation_interval_epochs.max(1));
    let next_scheduled_rotation_epoch = ledger
        .consensus
        .last_selection_epoch
        .map_or(ledger.epoch_number, |epoch| {
            epoch.saturating_add(rotation_interval)
        });
    Ok(ValidatorCommitteeView {
        epoch: ledger.epoch_number,
        validator_set_hash: set_hash,
        active_validator_ids: active.clone(),
        candidate_node_ids: candidates,
        max_active_validators: ledger.settings.max_active_validators,
        max_rotations_per_selection: ledger.settings.max_validator_rotations,
        rotation_interval_epochs: ledger.settings.validator_rotation_interval_epochs,
        last_selection_epoch: ledger.consensus.last_selection_epoch,
        next_scheduled_rotation_epoch,
        quorum: consensus_quorum(active.len()),
        next_height,
        current_round: ledger.consensus.round,
        proposer_node_id: proposer,
    })
}

fn validator_candidate_node_ids(ledger: &LedgerState, now: i64) -> Vec<u64> {
    let governance_eligible = governance_eligible_node_ids(ledger, now)
        .into_iter()
        .collect::<BTreeSet<_>>();
    ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| {
            (governance_eligible.contains(node_id)
                && node.validator_bond >= ledger.settings.validator_bond
                && node.validator_candidate_since.is_some()
                && node.validator_exit_requested_at.is_none())
            .then_some(*node_id)
        })
        .collect()
}

fn refresh_validator_committee(ledger: &mut LedgerState, now: i64) -> Result<()> {
    fallback_to_node1_availability_if_needed(ledger);
    let current_candidates = validator_candidate_node_ids(ledger, now);
    let bootstrap_expansion = !multi_validator_ready(ledger, now)
        && ledger.consensus.proposal.is_none()
        && current_candidates.len() <= ledger.settings.max_active_validators as usize
        && current_candidates != ledger.consensus.active_validators;
    let candidate_set = current_candidates.iter().copied().collect::<BTreeSet<_>>();
    let forced_reselection = ledger
        .consensus
        .active_validators
        .iter()
        .any(|node_id| !candidate_set.contains(node_id));
    let rotation_interval = u64::from(ledger.settings.validator_rotation_interval_epochs.max(1));
    let scheduled_selection_due = ledger
        .consensus
        .last_selection_epoch
        .is_none_or(|last_epoch| {
            ledger.epoch_number.saturating_sub(last_epoch) >= rotation_interval
        });
    let selection_due = ledger.consensus.active_validators.is_empty()
        || scheduled_selection_due
        || bootstrap_expansion;
    let selection_due = selection_due || forced_reselection;
    if !selection_due {
        return Ok(());
    }
    let candidates = current_candidates;
    let max_active = ledger.settings.max_active_validators.clamp(1, 31) as usize;
    let max_rotations = ledger.settings.max_validator_rotations.min(10) as usize;
    let previous = ledger.consensus.active_validators.clone();
    let candidate_set = candidates.iter().copied().collect::<BTreeSet<_>>();
    let mut selected = previous
        .iter()
        .copied()
        .filter(|node_id| candidate_set.contains(node_id))
        .collect::<Vec<_>>();

    if candidates.len() <= max_active {
        selected = candidates.clone();
    } else if selected.is_empty() {
        let mut initial = candidates.clone();
        initial.sort_by_key(|node_id| {
            let node = &ledger.nodes[node_id];
            (node.validator_candidate_since.unwrap_or(i64::MAX), *node_id)
        });
        selected = initial.into_iter().take(max_active).collect();
    } else {
        let selected_set = selected.iter().copied().collect::<BTreeSet<_>>();
        let mut waiting = candidates
            .iter()
            .copied()
            .filter(|node_id| !selected_set.contains(node_id))
            .collect::<Vec<_>>();
        waiting.sort_by_key(|node_id| {
            let node = &ledger.nodes[node_id];
            (
                node.validator_last_epoch.unwrap_or(0),
                node.validator_candidate_since.unwrap_or(i64::MAX),
                *node_id,
            )
        });
        if selected.len() == max_active && !waiting.is_empty() {
            selected.sort_by_key(|node_id| {
                let node = &ledger.nodes[node_id];
                (
                    std::cmp::Reverse(node.validator_consecutive_epochs),
                    *node_id,
                )
            });
            let rotations = max_rotations.min(waiting.len()).min(selected.len());
            selected.drain(..rotations);
        }
        let selected_set = selected.iter().copied().collect::<BTreeSet<_>>();
        for node_id in waiting {
            if selected.len() >= max_active {
                break;
            }
            if !selected_set.contains(&node_id) && !selected.contains(&node_id) {
                selected.push(node_id);
            }
        }
    }
    selected.sort_unstable();
    let previous_set = previous.iter().copied().collect::<BTreeSet<_>>();
    let selected_set = selected.iter().copied().collect::<BTreeSet<_>>();
    for (node_id, node) in &mut ledger.nodes {
        let is_selected = selected_set.contains(node_id);
        node.validator = is_selected;
        if is_selected {
            node.validator_consecutive_epochs = if previous_set.contains(node_id) {
                node.validator_consecutive_epochs.saturating_add(1)
            } else {
                1
            };
            node.validator_last_epoch = Some(ledger.epoch_number);
        } else {
            node.validator_consecutive_epochs = 0;
        }
    }
    ledger.consensus.active_validators = selected;
    ledger.consensus.last_selection_epoch = Some(ledger.epoch_number);
    ledger.consensus.height = next_block_height(ledger);
    ledger.consensus.round = 0;
    ledger.consensus.round_started_at = Some(now);
    ledger.consensus.proposal = None;
    ledger.consensus.valid_proposal = None;
    ledger.consensus.valid_round = None;
    ledger.consensus.prevotes.clear();
    ledger.consensus.precommits.clear();
    ledger.consensus.locks.clear();
    fallback_to_node1_availability_if_needed(ledger);
    Ok(())
}

fn fallback_to_node1_availability_if_needed(ledger: &mut LedgerState) {
    if ledger.consensus.active_validators.len() < MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS {
        ledger.availability_mode = AvailabilityMode::Node1Trusted;
    }
}

fn validator_set_hash(ledger: &LedgerState, validators: &[u64]) -> Result<String> {
    validator_set_hash_for_epoch(ledger, ledger.epoch_number, validators)
}

fn validator_set_hash_for_epoch(
    ledger: &LedgerState,
    epoch: u64,
    validators: &[u64],
) -> Result<String> {
    let entries = validators
        .iter()
        .map(|node_id| {
            let node = ledger
                .nodes
                .get(node_id)
                .ok_or_else(|| Error::msg(format!("Validator Node {node_id} is missing")))?;
            Ok(json!({
                "node_id": node_id,
                "owner_address": node.owner_address,
                "owner_public_key": node.owner_public_key,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(sha256_full_id(
        "vset",
        &serde_json::to_vec(&json!({
            "ledger_id": ledger.ledger_id,
            "epoch": epoch,
            "validators": entries,
        }))?,
    ))
}

fn consensus_quorum(validator_count: usize) -> usize {
    if validator_count == 0 {
        0
    } else {
        (2 * validator_count) / 3 + 1
    }
}

fn consensus_proposer(validators: &[u64], height: u64, round: u32) -> Option<u64> {
    if validators.is_empty() {
        return None;
    }
    let index = ((height.saturating_sub(1) + u64::from(round)) % validators.len() as u64) as usize;
    validators.get(index).copied()
}

fn consensus_value_id(block: &BlockRecord) -> String {
    sha256_full_id(
        "consensus-value",
        format!(
            "{}:{}:{}",
            block.height,
            block.state_root,
            block.operation_ids.join(",")
        )
        .as_bytes(),
    )
}

fn multi_validator_ready(ledger: &LedgerState, now: i64) -> bool {
    governance_eligible_node_ids(ledger, now).len() >= MULTI_VALIDATOR_NODE_THRESHOLD
        && ledger.consensus.active_validators.len() >= MIN_ACTIVE_VALIDATORS
}

pub fn consensus_status(paths: &DataPaths, now: i64) -> Result<ConsensusStatusView> {
    let ledger = paths.read_active_ledger()?;
    let active = ledger.consensus.active_validators.clone();
    let height = next_block_height(&ledger);
    let set_hash = validator_set_hash(&ledger, &active)?;
    let multi_validator = multi_validator_ready(&ledger, now);
    let next_block_at = multi_validator
        .then(|| next_block_timestamp(&ledger))
        .flatten();
    let round_started_at = multi_validator
        .then(|| consensus_timer_started_at(&ledger, ledger.consensus.round_started_at))
        .flatten();
    Ok(ConsensusStatusView {
        mode: if multi_validator {
            "MULTI_VALIDATOR".to_owned()
        } else {
            "NODE1_SINGLE_PRODUCER".to_owned()
        },
        height,
        round: ledger.consensus.round,
        round_started_at,
        next_block_at,
        proposer_node_id: multi_validator
            .then(|| consensus_proposer(&active, height, ledger.consensus.round))
            .flatten(),
        proposal_block_hash: multi_validator
            .then(|| {
                ledger
                    .consensus
                    .proposal
                    .as_ref()
                    .map(|proposal| proposal.block.block_hash.clone())
            })
            .flatten(),
        prevote_count: if multi_validator {
            ledger.consensus.prevotes.len()
        } else {
            0
        },
        precommit_count: if multi_validator {
            ledger.consensus.precommits.len()
        } else {
            0
        },
        prevote_validator_ids: if multi_validator {
            ledger.consensus.prevotes.keys().copied().collect()
        } else {
            Vec::new()
        },
        precommit_validator_ids: if multi_validator {
            ledger.consensus.precommits.keys().copied().collect()
        } else {
            Vec::new()
        },
        quorum: if multi_validator {
            consensus_quorum(active.len())
        } else {
            0
        },
        active_validator_ids: active,
        validator_set_hash: set_hash,
        locked_validators: ledger.consensus.locks.clone(),
    })
}

pub fn create_consensus_hello(
    paths: &DataPaths,
    name: &str,
    password: &str,
    challenge: &crate::consensus::ConsensusChallenge,
    now: i64,
) -> Result<crate::consensus::ConsensusHello> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    if challenge.protocol != crate::consensus::CONSENSUS_PROTOCOL {
        return Err(Error::msg("unsupported consensus challenge protocol"));
    }
    if (now - challenge.timestamp).abs() > 30 {
        return Err(Error::msg("consensus challenge timestamp is stale"));
    }
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let ledger = paths.read_ledger()?;
    let server = ledger
        .nodes
        .get(&challenge.server_node_id)
        .ok_or_else(|| Error::msg("consensus challenge references an unknown server Node"))?;
    if server.owner_public_key != challenge.server_owner_public_key {
        return Err(Error::msg(
            "consensus challenge Owner key does not match the Node registry",
        ));
    }
    verify_bytes(
        &server.owner_public_key,
        &crate::consensus::challenge_signing_bytes(challenge),
        &challenge.signature,
    )?;
    ensure_active_validator_identity(&ledger, node_id, &owner_file)?;
    Ok(crate::consensus::ConsensusHello {
        protocol: crate::consensus::CONSENSUS_PROTOCOL.to_owned(),
        validator_node_id: node_id,
        timestamp: now,
        signature: sign_bytes(
            &owner_key,
            &crate::consensus::hello_signing_bytes(challenge, node_id, now),
        ),
    })
}

pub fn create_consensus_challenge(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<crate::consensus::ConsensusChallenge> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let ledger = paths.read_ledger()?;
    ensure_active_validator_identity(&ledger, node_id, &owner_file)?;
    let mut challenge = crate::consensus::ConsensusChallenge {
        protocol: crate::consensus::CONSENSUS_PROTOCOL.to_owned(),
        challenge: hex_lower(&random_bytes::<32>()?),
        server_node_id: node_id,
        server_owner_public_key: owner_file.public_key,
        timestamp: now,
        signature: String::new(),
    };
    challenge.signature = sign_bytes(
        &owner_key,
        &crate::consensus::challenge_signing_bytes(&challenge),
    );
    Ok(challenge)
}

pub fn authenticate_consensus_peer(
    paths: &DataPaths,
    challenge: &crate::consensus::ConsensusChallenge,
    hello: &crate::consensus::ConsensusHello,
    now: i64,
) -> Result<u64> {
    if challenge.protocol != crate::consensus::CONSENSUS_PROTOCOL
        || hello.protocol != crate::consensus::CONSENSUS_PROTOCOL
        || (now - challenge.timestamp).abs() > 30
        || (now - hello.timestamp).abs() > 30
    {
        return Err(Error::msg("invalid or stale consensus peer handshake"));
    }
    let ledger = paths.read_ledger()?;
    let validator = ledger
        .nodes
        .get(&hello.validator_node_id)
        .ok_or_else(|| Error::msg("consensus peer references an unknown Node"))?;
    if !ledger
        .consensus
        .active_validators
        .contains(&hello.validator_node_id)
    {
        return Err(Error::msg("consensus peer is not an active Validator"));
    }
    verify_bytes(
        &validator.owner_public_key,
        &crate::consensus::hello_signing_bytes(challenge, hello.validator_node_id, hello.timestamp),
        &hello.signature,
    )?;
    Ok(hello.validator_node_id)
}

pub fn submit_consensus_proposal(
    paths: &DataPaths,
    block: BlockRecord,
    now: i64,
) -> Result<ConsensusSubmissionView> {
    paths.with_active_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        if let Some(existing) = &ledger.consensus.proposal {
            if existing.block.block_hash == block.block_hash {
                return Ok(ConsensusSubmissionView {
                    accepted: true,
                    duplicate: true,
                    double_sign_detected: false,
                    finalized_block: None,
                });
            }
            return Err(Error::msg(
                "a conflicting proposal already exists for this height and round",
            ));
        }
        verify_multi_validator_proposal(ledger, &block, now)?;
        let post_state = consensus_post_state(ledger, &block)?;
        ledger.consensus.height = block.height;
        ledger.consensus.round_started_at = Some(now);
        ledger.consensus.proposal = Some(ConsensusProposal {
            block,
            proposed_at: now,
            post_state: Some(Box::new(post_state)),
        });
        Ok(ConsensusSubmissionView {
            accepted: true,
            duplicate: false,
            double_sign_detected: false,
            finalized_block: None,
        })
    })
}

pub fn submit_consensus_vote(
    paths: &DataPaths,
    vote: ConsensusVote,
    now: i64,
) -> Result<ConsensusSubmissionView> {
    let submission = paths.with_active_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        if (now - vote.timestamp).abs() > 60 {
            return Err(Error::msg("consensus vote timestamp is stale"));
        }
        verify_consensus_vote(ledger, &vote)?;
        let existing = match vote.vote_type {
            ConsensusVoteType::Prevote => ledger.consensus.prevotes.get(&vote.validator_node_id),
            ConsensusVoteType::Precommit => {
                ledger.consensus.precommits.get(&vote.validator_node_id)
            }
        }
        .cloned();
        if let Some(existing) = existing {
            if existing.block_hash == vote.block_hash {
                return Ok(ConsensusSubmissionView {
                    accepted: true,
                    duplicate: true,
                    double_sign_detected: false,
                    finalized_block: None,
                });
            }
            ledger
                .consensus
                .double_sign_evidence
                .push(DoubleSignEvidence {
                    validator_node_id: vote.validator_node_id,
                    height: vote.height,
                    round: vote.round,
                    vote_type: vote.vote_type.clone(),
                    first_vote: existing,
                    conflicting_vote: vote.clone(),
                    recorded_at: now,
                });
            let validator = ledger
                .nodes
                .get_mut(&vote.validator_node_id)
                .expect("verified Validator");
            validator.validator_bond = 0;
            validator.validator_candidate_since = None;
            validator.validator_signature_rate_bps = 0;
            // Slashing is application state and changes the state root. A proposal
            // signed before the evidence arrived can no longer be finalized with
            // that old root, so invalidate this round and repropose the new state.
            ledger.consensus.proposal = None;
            ledger.consensus.valid_proposal = None;
            ledger.consensus.valid_round = None;
            ledger.consensus.prevotes.clear();
            ledger.consensus.precommits.clear();
            ledger.consensus.locks.clear();
            return Ok(ConsensusSubmissionView {
                accepted: false,
                duplicate: false,
                double_sign_detected: true,
                finalized_block: None,
            });
        }
        match vote.vote_type {
            ConsensusVoteType::Prevote => {
                ledger
                    .consensus
                    .prevotes
                    .insert(vote.validator_node_id, vote.clone());
                let matching = ledger
                    .consensus
                    .prevotes
                    .values()
                    .filter(|candidate| candidate.block_hash == vote.block_hash)
                    .count();
                if matching == consensus_quorum(ledger.consensus.active_validators.len()) {
                    ledger.consensus.round_started_at = Some(now);
                }
            }
            ConsensusVoteType::Precommit => {
                if let Some(target) = &vote.block_hash {
                    ledger
                        .consensus
                        .locks
                        .insert(vote.validator_node_id, target.clone());
                }
                ledger
                    .consensus
                    .precommits
                    .insert(vote.validator_node_id, vote.clone());
            }
        }
        let finalized_block = if matches!(vote.vote_type, ConsensusVoteType::Precommit) {
            if let Some(target) = vote.block_hash.as_deref() {
                finalize_consensus_block_if_quorum(ledger, target)?
            } else {
                None
            }
        } else {
            None
        };
        Ok(ConsensusSubmissionView {
            accepted: true,
            duplicate: false,
            double_sign_detected: false,
            finalized_block,
        })
    })?;
    if submission.finalized_block.is_some() {
        persist_latest_bootstrap_checkpoint(paths)?;
    }
    Ok(submission)
}

pub fn propose_consensus_block(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<BlockRecord> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_active_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        ensure_active_validator_identity(ledger, node_id, &owner_file)?;
        ensure_consensus_block_is_due(ledger, now)?;
        let height = next_block_height(ledger);
        let round = ledger.consensus.round;
        let expected = consensus_proposer(&ledger.consensus.active_validators, height, round)
            .ok_or_else(|| Error::msg("active Validator committee is empty"))?;
        if node_id != expected {
            return Err(Error::msg(format!(
                "Node {node_id} is not proposer for height {height} round {round}; expected Node {expected}"
            )));
        }
        if ledger.consensus.proposal.is_some() {
            return Err(Error::msg("a proposal already exists for the current round"));
        }
        if ledger.pending_operation_ids.len() > MAX_BLOCK_OPERATIONS {
            return Err(Error::msg(format!(
                "pending operation count exceeds the {MAX_BLOCK_OPERATIONS} operation block limit"
            )));
        }
        let active = ledger.consensus.active_validators.clone();
        let set_hash = validator_set_hash(ledger, &active)?;
        let (operation_ids, simulated, state_root) =
            if let Some(valid) = &ledger.consensus.valid_proposal {
                if valid.block.height != height {
                    return Err(Error::msg(
                        "consensus valid value belongs to another height",
                    ));
                }
                let post_state = valid
                    .post_state
                    .as_ref()
                    .ok_or_else(|| Error::msg("consensus valid value has no post-state"))?;
                (
                    valid.block.operation_ids.clone(),
                    (**post_state).clone(),
                    valid.block.state_root.clone(),
                )
            } else {
                let candidates = ledger.pending_operation_ids.clone();
                let (simulated, operation_ids) = prepare_block_operations(
                    ledger,
                    &candidates,
                    height,
                    now,
                    true,
                )?;
                let state_root = ledger_state_root(&simulated)?;
                (operation_ids, simulated, state_root)
            };
        let payload = MultiValidatorBlockSigningPayload {
            version: MULTI_VALIDATOR_BLOCK_VERSION,
            ledger_id: ledger.ledger_id.clone(),
            height,
            previous_block_hash: chain_tip_hash(ledger)
                .unwrap_or(GENESIS_PREVIOUS_BLOCK_HASH)
                .to_owned(),
            timestamp: now,
            producer_node_id: node_id,
            producer_owner_address: owner_file.address.clone(),
            operation_ids,
            state_root,
            consensus_mode: BlockConsensusMode::MultiValidator,
            consensus_round: round,
            validator_set_hash: set_hash,
            validator_epoch: ledger.epoch_number,
            validator_node_ids: active,
        };
        let signing_bytes = serde_json::to_vec(&payload)?;
        let block = BlockRecord {
            version: payload.version,
            ledger_id: payload.ledger_id,
            height: payload.height,
            previous_block_hash: payload.previous_block_hash,
            timestamp: payload.timestamp,
            producer_node_id: payload.producer_node_id,
            producer_owner_address: payload.producer_owner_address,
            operation_ids: payload.operation_ids,
            state_root: payload.state_root,
            block_hash: sha256_full_id("blk", &signing_bytes),
            producer_signature: sign_bytes(&owner_key, &signing_bytes),
            consensus_mode: payload.consensus_mode,
            consensus_round: payload.consensus_round,
            validator_set_hash: payload.validator_set_hash,
            commit_signatures: Vec::new(),
            validator_epoch: payload.validator_epoch,
            validator_node_ids: payload.validator_node_ids,
        };
        verify_multi_validator_proposal(ledger, &block, now)?;
        ledger.consensus.height = height;
        ledger.consensus.round_started_at = Some(now);
        ledger.consensus.proposal = Some(ConsensusProposal {
            block: block.clone(),
            proposed_at: now,
            post_state: Some(Box::new(simulated)),
        });
        Ok(block)
    })
}

pub fn cast_consensus_vote(
    paths: &DataPaths,
    name: &str,
    password: &str,
    vote_type: ConsensusVoteType,
    block_hash: Option<String>,
    now: i64,
) -> Result<(ConsensusVote, Option<BlockRecord>)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_active_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        ensure_active_validator_identity(ledger, node_id, &owner_file)?;
        let height = next_block_height(ledger);
        let round = ledger.consensus.round;
        let active = ledger.consensus.active_validators.clone();
        let set_hash = validator_set_hash(ledger, &active)?;
        if let Some(target) = &block_hash {
            let proposal = ledger
                .consensus
                .proposal
                .as_ref()
                .ok_or_else(|| Error::msg("cannot vote for a block without a proposal"))?;
            if proposal.block.block_hash != *target {
                return Err(Error::msg("vote block hash does not match the current proposal"));
            }
            // The proposal was fully executed and verified before it entered consensus state.
            // Re-executing it here would make later votes depend on non-consensus wall-clock
            // updates such as heartbeats that may have happened after PROPOSE.
            verify_stored_consensus_proposal(ledger, &proposal.block)?;
        }
        if let Some(locked) = ledger.consensus.locks.get(&node_id)
            && block_hash.as_deref() != Some(locked.as_str())
        {
            let same_valid_value = block_hash.as_ref().is_some_and(|_| {
                ledger
                    .consensus
                    .valid_proposal
                    .as_ref()
                    .zip(ledger.consensus.proposal.as_ref())
                    .is_some_and(|(valid, current)| {
                        consensus_value_id(&valid.block) == consensus_value_id(&current.block)
                    })
            });
            if !same_valid_value {
                return Err(Error::msg(format!(
                    "Validator Node {node_id} is locked on {locked} and cannot vote for another value"
                )));
            }
        }
        if matches!(vote_type, ConsensusVoteType::Precommit) {
            let prevote_count = ledger
                .consensus
                .prevotes
                .values()
                .filter(|vote| vote.block_hash == block_hash)
                .count();
            if prevote_count < consensus_quorum(active.len()) {
                return Err(Error::msg(
                    "PRECOMMIT requires more than two-thirds matching PREVOTEs",
                ));
            }
        }
        let payload = ConsensusVoteSigningPayload {
            ledger_id: ledger.ledger_id.clone(),
            height,
            round,
            vote_type: vote_type.clone(),
            block_hash: block_hash.clone(),
            validator_set_hash: set_hash,
            validator_node_id: node_id,
            timestamp: now,
        };
        let signing_bytes = serde_json::to_vec(&payload)?;
        let vote = ConsensusVote {
            ledger_id: payload.ledger_id,
            height: payload.height,
            round: payload.round,
            vote_type: payload.vote_type,
            block_hash: payload.block_hash,
            validator_set_hash: payload.validator_set_hash,
            validator_node_id: payload.validator_node_id,
            timestamp: payload.timestamp,
            signature: sign_bytes(&owner_key, &signing_bytes),
        };
        verify_consensus_vote(ledger, &vote)?;
        let votes = match vote_type {
            ConsensusVoteType::Prevote => &mut ledger.consensus.prevotes,
            ConsensusVoteType::Precommit => &mut ledger.consensus.precommits,
        };
        if let Some(existing) = votes.get(&node_id) {
            if existing.block_hash == vote.block_hash {
                return Ok((existing.clone(), None));
            }
            return Err(Error::msg(format!(
                "Validator Node {node_id} attempted a conflicting {:?} at height {height} round {round}",
                vote_type
            )));
        }
        votes.insert(node_id, vote.clone());
        if matches!(vote_type, ConsensusVoteType::Prevote) {
            let matching = ledger
                .consensus
                .prevotes
                .values()
                .filter(|candidate| candidate.block_hash == vote.block_hash)
                .count();
            if matching == consensus_quorum(active.len()) {
                ledger.consensus.round_started_at = Some(now);
            }
        }
        if matches!(vote_type, ConsensusVoteType::Precommit)
            && let Some(target) = &block_hash
        {
            ledger.consensus.locks.insert(node_id, target.clone());
        }
        let finalized = if matches!(vote_type, ConsensusVoteType::Precommit) {
            if let Some(target) = block_hash.as_deref() {
                finalize_consensus_block_if_quorum(ledger, target)?
            } else {
                None
            }
        } else {
            None
        };
        Ok((vote, finalized))
    })
}

pub fn advance_consensus_round(paths: &DataPaths, now: i64) -> Result<u32> {
    paths.with_active_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        let started =
            consensus_timer_started_at(ledger, ledger.consensus.round_started_at).unwrap_or(now);
        let multiplier = 1_i64
            .checked_shl(ledger.consensus.round.min(5))
            .unwrap_or(32);
        let timeout = ledger
            .settings
            .consensus_round_timeout_seconds
            .saturating_mul(multiplier)
            .min(60);
        if now.saturating_sub(started) < timeout {
            return Err(Error::msg(format!(
                "consensus round timeout has not elapsed; requires {timeout}s"
            )));
        }
        if let Some(proposal) = &ledger.consensus.proposal {
            let matching_prevotes = ledger
                .consensus
                .prevotes
                .values()
                .filter(|vote| vote.block_hash.as_deref() == Some(&proposal.block.block_hash))
                .count();
            if matching_prevotes >= consensus_quorum(ledger.consensus.active_validators.len()) {
                ledger.consensus.valid_proposal = Some(proposal.clone());
                ledger.consensus.valid_round = Some(ledger.consensus.round);
            }
        }
        ledger.consensus.round = ledger.consensus.round.saturating_add(1);
        ledger.consensus.round_started_at = Some(now);
        ledger.consensus.proposal = None;
        ledger.consensus.prevotes.clear();
        ledger.consensus.precommits.clear();
        Ok(ledger.consensus.round)
    })
}

pub fn restart_consensus_timer(paths: &DataPaths, now: i64) -> Result<()> {
    paths.with_active_ledger_mut(|ledger| {
        if ledger.consensus.proposal.is_none() {
            ledger.consensus.round_started_at = consensus_timer_started_at(ledger, Some(now));
        }
        Ok(())
    })
}

fn ensure_multi_validator_mode(ledger: &LedgerState, now: i64) -> Result<()> {
    let eligible_count = governance_eligible_node_ids(ledger, now).len();
    if eligible_count < MULTI_VALIDATOR_NODE_THRESHOLD {
        return Err(Error::msg(format!(
            "multi-Validator consensus requires at least {MULTI_VALIDATOR_NODE_THRESHOLD} Governance-Eligible Nodes; current count is {eligible_count}"
        )));
    }
    if ledger.consensus.active_validators.is_empty() {
        return Err(Error::msg(
            "multi-Validator consensus has no active Validator committee",
        ));
    }
    if ledger.consensus.active_validators.len() < MIN_ACTIVE_VALIDATORS {
        return Err(Error::msg(format!(
            "multi-Validator consensus requires at least {MIN_ACTIVE_VALIDATORS} Active Validators; current count is {} and Node 1 remains the block producer",
            ledger.consensus.active_validators.len()
        )));
    }
    Ok(())
}

fn ensure_consensus_block_is_due(ledger: &LedgerState, now: i64) -> Result<()> {
    if block_is_due(ledger, now) {
        return Ok(());
    }
    let next = next_block_timestamp(ledger).expect("a block that is not due has a chain tip");
    Err(Error::msg(format!(
        "next block is not due until timestamp {next} under block-interval-seconds={}",
        ledger.settings.block_interval_seconds
    )))
}

fn reset_multi_validator_consensus_if_node1_mode(ledger: &mut LedgerState, now: i64) {
    if multi_validator_ready(ledger, now) {
        return;
    }
    ledger.consensus.height = next_block_height(ledger);
    ledger.consensus.round = 0;
    ledger.consensus.round_started_at = None;
    ledger.consensus.proposal = None;
    ledger.consensus.valid_proposal = None;
    ledger.consensus.valid_round = None;
    ledger.consensus.prevotes.clear();
    ledger.consensus.precommits.clear();
    ledger.consensus.locks.clear();
}

fn verify_stored_consensus_proposal(ledger: &LedgerState, block: &BlockRecord) -> Result<()> {
    let stored = ledger
        .consensus
        .proposal
        .as_ref()
        .ok_or_else(|| Error::msg("consensus has no stored proposal"))?;
    if stored.block.block_hash != block.block_hash
        || block.height != next_block_height(ledger)
        || block.consensus_round != ledger.consensus.round
        || block.validator_epoch != ledger.epoch_number
        || block.validator_node_ids != ledger.consensus.active_validators
        || block.validator_set_hash
            != validator_set_hash(ledger, &ledger.consensus.active_validators)?
    {
        return Err(Error::msg(
            "stored consensus proposal no longer matches the active height, round or Validator set",
        ));
    }
    Ok(())
}

fn ensure_active_validator_identity(
    ledger: &LedgerState,
    node_id: u64,
    owner_file: &EncryptedKeyFile,
) -> Result<()> {
    if !ledger.consensus.active_validators.contains(&node_id) {
        return Err(Error::msg(format!(
            "Node {node_id} is not in the active Validator committee"
        )));
    }
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("Validator Node is missing from the registry"))?;
    if node.owner_address != owner_file.address || node.owner_public_key != owner_file.public_key {
        return Err(Error::msg(
            "Validator Owner key does not match the registry",
        ));
    }
    Ok(())
}

fn verify_multi_validator_proposal(
    ledger: &LedgerState,
    block: &BlockRecord,
    now: i64,
) -> Result<()> {
    if block.version != MULTI_VALIDATOR_BLOCK_VERSION
        || block.consensus_mode != BlockConsensusMode::MultiValidator
        || block.ledger_id != ledger.ledger_id
        || block.height != next_block_height(ledger)
        || block.consensus_round != ledger.consensus.round
        || block.validator_epoch != ledger.epoch_number
        || block.validator_node_ids != ledger.consensus.active_validators
    {
        return Err(Error::msg(
            "multi-Validator proposal has invalid consensus metadata",
        ));
    }
    if block.timestamp > now + 30 || block.timestamp < now - 60 {
        return Err(Error::msg(
            "proposal timestamp is outside the allowed window",
        ));
    }
    ensure_consensus_block_is_due(ledger, now)?;
    if next_block_timestamp(ledger).is_some_and(|earliest| block.timestamp < earliest) {
        return Err(Error::msg(
            "proposal timestamp is earlier than the configured block interval",
        ));
    }
    let expected_previous = chain_tip_hash(ledger).unwrap_or(GENESIS_PREVIOUS_BLOCK_HASH);
    if block.previous_block_hash != expected_previous {
        return Err(Error::msg("proposal does not extend the finalized chain"));
    }
    let expected_set_hash = validator_set_hash(ledger, &ledger.consensus.active_validators)?;
    if block.validator_set_hash != expected_set_hash {
        return Err(Error::msg("proposal Validator set hash is invalid"));
    }
    let expected_proposer = consensus_proposer(
        &ledger.consensus.active_validators,
        block.height,
        block.consensus_round,
    )
    .ok_or_else(|| Error::msg("active Validator committee is empty"))?;
    if block.producer_node_id != expected_proposer {
        return Err(Error::msg(
            "proposal was signed by the wrong round proposer",
        ));
    }
    let proposer = ledger
        .nodes
        .get(&expected_proposer)
        .ok_or_else(|| Error::msg("proposal Validator is missing"))?;
    if block.producer_owner_address != proposer.owner_address {
        return Err(Error::msg("proposal producer identity is invalid"));
    }
    if ledger.finalized_checkpoint.is_none() && block.operation_ids != ledger.pending_operation_ids
    {
        return Err(Error::msg("proposal operation ordering is invalid"));
    }
    let positions = block
        .operation_ids
        .iter()
        .map(|id| {
            ledger
                .pending_operation_ids
                .iter()
                .position(|pending| pending == id)
                .ok_or_else(|| {
                    Error::msg(format!(
                        "proposal operation {id} is not in the local pending pool"
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    if positions.windows(2).any(|window| window[0] >= window[1]) {
        return Err(Error::msg(
            "proposal operations are not in canonical pending order",
        ));
    }
    let simulated = consensus_post_state(ledger, block)?;
    if block.state_root != ledger_state_root(&simulated)? {
        return Err(Error::msg(
            "proposal state root does not match local execution",
        ));
    }
    let payload = multi_validator_block_signing_payload(block);
    let signing_bytes = serde_json::to_vec(&payload)?;
    if block.block_hash != sha256_full_id("blk", &signing_bytes) {
        return Err(Error::msg(
            "proposal block hash does not match its contents",
        ));
    }
    verify_bytes(
        &proposer.owner_public_key,
        &signing_bytes,
        &block.producer_signature,
    )
}

fn consensus_post_state(ledger: &LedgerState, block: &BlockRecord) -> Result<LedgerState> {
    let mut simulated = prepare_block_operations(
        ledger,
        &block.operation_ids,
        block.height,
        block.timestamp,
        false,
    )?
    .0;
    simulated.consensus.proposal = None;
    simulated.consensus.valid_proposal = None;
    simulated.consensus.valid_round = None;
    simulated.consensus.prevotes.clear();
    simulated.consensus.precommits.clear();
    simulated.consensus.locks.clear();
    simulated.finalized_checkpoint = None;
    Ok(simulated)
}

fn prepare_block_operations(
    ledger: &LedgerState,
    operation_ids: &[String],
    height: u64,
    timestamp: i64,
    skip_invalid: bool,
) -> Result<(LedgerState, Vec<String>)> {
    if ledger.finalized_checkpoint.is_some() {
        return replay_block_operations(ledger, operation_ids, height, timestamp, skip_invalid);
    }

    // Before the first finalized checkpoint there is no independent base state to replay.
    // Preserve the legacy bootstrap behavior; every later Node 1 and Validator block goes
    // through the same deterministic replay path above.
    let mut simulated = ledger.clone();
    advance_epochs_for_block(&mut simulated, timestamp)?;
    for operation_id_value in operation_ids {
        let operation = simulated
            .operations
            .get_mut(operation_id_value)
            .ok_or_else(|| Error::msg("pending operation is missing from the ledger"))?;
        operation.status = OperationStatus::Finalized;
        operation.block_height = Some(height);
    }
    settle_finalized_epochs_for_block(&mut simulated, timestamp)?;
    finalize_offline_nodes(&mut simulated, timestamp)?;
    finalize_draining_nodes(&mut simulated, timestamp)?;
    simulated.pending_operation_ids.clear();
    Ok((simulated, operation_ids.to_vec()))
}

fn replay_block_operations(
    ledger: &LedgerState,
    operation_ids: &[String],
    height: u64,
    timestamp: i64,
    skip_invalid: bool,
) -> Result<(LedgerState, Vec<String>)> {
    let checkpoint = ledger
        .finalized_checkpoint
        .as_ref()
        .ok_or_else(|| Error::msg("deterministic execution requires a finalized checkpoint"))?;
    let mut base = (**checkpoint).clone();
    base.finalized_checkpoint = None;
    base.blocks = ledger.blocks.clone();
    base.pruned_through_height = ledger.pruned_through_height;
    base.pruned_tip_hash = ledger.pruned_tip_hash.clone();
    base.pruned_tip_timestamp = ledger.pruned_tip_timestamp;
    base.pruned_operation_count = ledger.pruned_operation_count;
    base.operation_history_from_height = ledger.operation_history_from_height;
    base.operations = ledger
        .operations
        .iter()
        .filter(|(_, operation)| {
            matches!(
                operation.status,
                OperationStatus::Finalized | OperationStatus::Rejected
            )
        })
        .map(|(id, operation)| (id.clone(), operation.clone()))
        .collect();
    for (address, account) in &mut base.accounts {
        account.operation_ids = ledger
            .accounts
            .get(address)
            .map(|current| {
                current
                    .operation_ids
                    .iter()
                    .filter(|id| base.operations.contains_key(*id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
    }
    for (node_id, node) in &mut base.nodes {
        node.last_heartbeat = ledger
            .nodes
            .get(node_id)
            .and_then(|current| current.last_heartbeat);
    }
    base.pending_operation_ids.clear();
    base.consensus.proposal = None;
    base.consensus.valid_proposal = None;
    base.consensus.valid_round = None;
    base.consensus.prevotes.clear();
    base.consensus.precommits.clear();
    base.consensus.locks.clear();
    advance_epochs_for_block(&mut base, timestamp)?;

    let replay = DataPaths::in_memory_with_ledger(base)?;
    let mut accepted = Vec::with_capacity(operation_ids.len());
    for operation_id_value in operation_ids {
        let record = ledger.operations.get(operation_id_value).ok_or_else(|| {
            Error::msg(format!(
                "proposal operation {operation_id_value} is unavailable"
            ))
        })?;
        let operation = record.signed_operation.clone().ok_or_else(|| {
            Error::msg(format!(
                "proposal operation {operation_id_value} has no signed envelope"
            ))
        })?;
        let public_key = ledger
            .accounts
            .get(&operation.unsigned.signer)
            .and_then(|account| account.public_key.clone())
            .ok_or_else(|| {
                Error::msg(format!(
                    "proposal operation {operation_id_value} signer key is unavailable"
                ))
            })?;
        let envelope = crate::consensus::PendingOperationEnvelope {
            public_key,
            operation,
        };
        match submit_consensus_operation_strict(&replay, envelope.clone(), timestamp) {
            Ok(id) => accepted.push(id),
            Err(error) => {
                match finalize_rejected_consensus_operation(
                    &replay,
                    envelope,
                    timestamp,
                    &error.to_string(),
                ) {
                    Ok(id) => accepted.push(id),
                    Err(_) if skip_invalid => {}
                    Err(rejection_error) => {
                        return Err(Error::msg(format!(
                            "proposal operation {operation_id_value} failed deterministic execution: {error}; fee-only rejection failed: {rejection_error}"
                        )));
                    }
                }
            }
        }
    }
    let mut state = replay.read_ledger()?;
    for operation_id_value in &accepted {
        let operation = state
            .operations
            .get_mut(operation_id_value)
            .expect("accepted replay operation exists");
        if matches!(operation.status, OperationStatus::Pending) {
            operation.status = OperationStatus::Finalized;
        }
        operation.block_height = Some(height);
    }
    settle_finalized_epochs_for_block(&mut state, timestamp)?;
    finalize_offline_nodes(&mut state, timestamp)?;
    finalize_draining_nodes(&mut state, timestamp)?;
    state.pending_operation_ids.clear();
    Ok((state, accepted))
}

fn verify_consensus_vote(ledger: &LedgerState, vote: &ConsensusVote) -> Result<()> {
    if vote.ledger_id != ledger.ledger_id
        || vote.height != next_block_height(ledger)
        || vote.round != ledger.consensus.round
        || vote.validator_set_hash
            != validator_set_hash(ledger, &ledger.consensus.active_validators)?
        || !ledger
            .consensus
            .active_validators
            .contains(&vote.validator_node_id)
    {
        return Err(Error::msg(
            "consensus vote has invalid height, round or Validator set",
        ));
    }
    let validator = ledger
        .nodes
        .get(&vote.validator_node_id)
        .ok_or_else(|| Error::msg("consensus vote references a missing Validator"))?;
    let payload = ConsensusVoteSigningPayload {
        ledger_id: vote.ledger_id.clone(),
        height: vote.height,
        round: vote.round,
        vote_type: vote.vote_type.clone(),
        block_hash: vote.block_hash.clone(),
        validator_set_hash: vote.validator_set_hash.clone(),
        validator_node_id: vote.validator_node_id,
        timestamp: vote.timestamp,
    };
    verify_bytes(
        &validator.owner_public_key,
        &serde_json::to_vec(&payload)?,
        &vote.signature,
    )
}

fn verify_consensus_vote_historical(ledger: &LedgerState, vote: &ConsensusVote) -> Result<()> {
    if vote.ledger_id != ledger.ledger_id {
        return Err(Error::msg(
            "historical consensus vote has the wrong ledger domain",
        ));
    }
    let validator = ledger
        .nodes
        .get(&vote.validator_node_id)
        .ok_or_else(|| Error::msg("historical vote Validator is missing"))?;
    let payload = ConsensusVoteSigningPayload {
        ledger_id: vote.ledger_id.clone(),
        height: vote.height,
        round: vote.round,
        vote_type: vote.vote_type.clone(),
        block_hash: vote.block_hash.clone(),
        validator_set_hash: vote.validator_set_hash.clone(),
        validator_node_id: vote.validator_node_id,
        timestamp: vote.timestamp,
    };
    verify_bytes(
        &validator.owner_public_key,
        &serde_json::to_vec(&payload)?,
        &vote.signature,
    )
}

fn finalize_consensus_block_if_quorum(
    ledger: &mut LedgerState,
    block_hash: &str,
) -> Result<Option<BlockRecord>> {
    let quorum = consensus_quorum(ledger.consensus.active_validators.len());
    let matching = ledger
        .consensus
        .precommits
        .values()
        .filter(|vote| vote.block_hash.as_deref() == Some(block_hash))
        .cloned()
        .collect::<Vec<_>>();
    if matching.len() < quorum {
        return Ok(None);
    }
    let proposal = ledger
        .consensus
        .proposal
        .as_ref()
        .filter(|proposal| proposal.block.block_hash == block_hash)
        .ok_or_else(|| Error::msg("PRECOMMIT quorum references an unknown proposal"))?;
    let mut block = proposal.block.clone();
    let post_state = proposal
        .post_state
        .clone()
        .ok_or_else(|| Error::msg("proposal is missing its verified post-state"))?;
    for vote in &matching {
        verify_consensus_vote(ledger, vote)?;
    }
    if ledger.finalized_checkpoint.is_none() && ledger.pending_operation_ids != block.operation_ids
    {
        return Err(Error::msg(
            "pending operation order changed after the block proposal",
        ));
    }
    block.commit_signatures = matching;
    *ledger = *post_state;
    ledger.blocks.push(block.clone());
    ledger.consensus.height = block.height + 1;
    ledger.consensus.round = 0;
    ledger.consensus.round_started_at = None;
    ledger.consensus.proposal = None;
    ledger.consensus.valid_proposal = None;
    ledger.consensus.valid_round = None;
    ledger.consensus.prevotes.clear();
    ledger.consensus.precommits.clear();
    ledger.consensus.locks.clear();
    update_finalized_checkpoint(ledger);
    Ok(Some(block))
}

fn multi_validator_block_signing_payload(block: &BlockRecord) -> MultiValidatorBlockSigningPayload {
    MultiValidatorBlockSigningPayload {
        version: block.version,
        ledger_id: block.ledger_id.clone(),
        height: block.height,
        previous_block_hash: block.previous_block_hash.clone(),
        timestamp: block.timestamp,
        producer_node_id: block.producer_node_id,
        producer_owner_address: block.producer_owner_address.clone(),
        operation_ids: block.operation_ids.clone(),
        state_root: block.state_root.clone(),
        consensus_mode: block.consensus_mode.clone(),
        consensus_round: block.consensus_round,
        validator_set_hash: block.validator_set_hash.clone(),
        validator_epoch: block.validator_epoch,
        validator_node_ids: block.validator_node_ids.clone(),
    }
}

pub fn block_status(paths: &DataPaths, now: i64) -> Result<BlockStatusView> {
    let ledger = paths.read_ledger()?;
    let (burned, total_settled_traffic_bytes) = finalized_network_totals(&ledger);
    let genesis = ledger
        .genesis_authority
        .clone()
        .or_else(|| legacy_genesis_authority(&ledger));
    let eligible_count = governance_eligible_node_ids(&ledger, now).len();
    let active_validator_count = ledger.consensus.active_validators.len();
    let availability_context = epoch_context(&ledger, ledger.epoch_number)?;
    let enabled = genesis.is_some() && !multi_validator_ready(&ledger, now);
    let pending_operation_count =
        if ledger.blocks.is_empty() && ledger.pending_operation_ids.is_empty() {
            ledger
                .operations
                .values()
                .filter(|operation| operation.block_height.is_none())
                .count()
        } else {
            ledger.pending_operation_ids.len()
        };
    Ok(BlockStatusView {
        mode: if enabled {
            "NODE1_SINGLE_PRODUCER".to_owned()
        } else if genesis.is_none() {
            "WAITING_FOR_GENESIS_NODE1".to_owned()
        } else {
            "MULTI_VALIDATOR".to_owned()
        },
        height: chain_height(&ledger),
        burned_base_units: burned.to_string(),
        burned_display: format_mrk(burned),
        total_settled_traffic_bytes: total_settled_traffic_bytes.to_string(),
        total_settled_traffic_display: format_bytes(total_settled_traffic_bytes),
        last_block_hash: chain_tip_hash(&ledger).map(str::to_owned),
        last_block_at: chain_tip_timestamp(&ledger),
        pending_operation_count,
        producer_node_id: genesis.map(|authority| authority.node_id),
        node1_production_enabled: enabled,
        governance_eligible_count: eligible_count,
        threshold: MULTI_VALIDATOR_NODE_THRESHOLD,
        active_validator_count,
        minimum_active_validators: MIN_ACTIVE_VALIDATORS,
        availability_mode: availability_context.availability_mode,
        availability_earning_enabled: availability_context.availability_mode
            == AvailabilityMode::Node1Trusted
            || availability_context.validator_ids.len()
                >= MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        minimum_decentralized_availability_validators: MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        pruned_through_height: ledger.pruned_through_height,
        retained_block_count: ledger.blocks.len(),
        retained_operation_count: ledger.operations.len(),
    })
}

fn finalized_network_totals(ledger: &LedgerState) -> (u128, u128) {
    ledger
        .finalized_checkpoint
        .as_deref()
        .map_or((0, 0), |checkpoint| {
            (checkpoint.burned, checkpoint.total_settled_traffic_bytes)
        })
}

fn format_bytes(bytes: u128) -> String {
    const UNITS: [&str; 9] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let mut unit = 0;
    let mut scale = 1_u128;
    while unit + 1 < UNITS.len() && bytes >= scale * 1_024 {
        unit += 1;
        scale *= 1_024;
    }
    if unit == 0 {
        return format!("{bytes} B");
    }
    let whole = bytes / scale;
    let hundredths = (bytes % scale) * 100 / scale;
    if hundredths == 0 {
        format!("{whole} {}", UNITS[unit])
    } else if hundredths.is_multiple_of(10) {
        format!("{whole}.{} {}", hundredths / 10, UNITS[unit])
    } else {
        format!("{whole}.{hundredths:02} {}", UNITS[unit])
    }
}

pub fn block_by_height(paths: &DataPaths, height: u64) -> Result<BlockRecord> {
    paths.stored_block(height)
}

pub fn blocks(
    paths: &DataPaths,
    before_height: Option<u64>,
    limit: usize,
) -> Result<BlockListView> {
    let (blocks, next_cursor) =
        paths.stored_blocks_descending(before_height, limit.clamp(1, 100))?;
    Ok(BlockListView {
        blocks: blocks
            .into_iter()
            .map(|block| BlockSummaryView {
                height: block.height,
                block_hash: block.block_hash,
                timestamp: block.timestamp,
                producer_node_id: block.producer_node_id,
                operation_count: block.operation_ids.len(),
                consensus_mode: block.consensus_mode,
            })
            .collect(),
        next_cursor,
    })
}

pub fn block_operations(
    paths: &DataPaths,
    height: u64,
    cursor: usize,
    limit: usize,
) -> Result<BlockOperationListView> {
    let block = block_by_height(paths, height)?;
    let limit = limit.clamp(1, 100);
    let end = cursor.saturating_add(limit).min(block.operation_ids.len());
    let operation_ids = block.operation_ids.get(cursor..end).unwrap_or_default();
    let operations = paths.stored_operations(operation_ids)?;
    let next = cursor.saturating_add(operations.len());
    Ok(BlockOperationListView {
        operations,
        next_cursor: (next < block.operation_ids.len()).then_some(next as u64),
    })
}

pub fn produce_node1_block(
    paths: &DataPaths,
    name: &str,
    password: &str,
    allow_empty: bool,
    now: i64,
) -> Result<BlockRecord> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let block = paths.with_active_ledger_mut(|ledger| {
        let genesis = ensure_genesis_authority(ledger)?;
        if node_id != genesis.node_id
            || config.owner_address != genesis.owner_address
            || owner_file.address != genesis.owner_address
            || owner_file.public_key != genesis.owner_public_key
        {
            return Err(Error::msg(
                "only the immutable Genesis Node 1 Owner key may produce bootstrap blocks",
            ));
        }
        let eligible_count = governance_eligible_node_ids(ledger, now).len();
        let active_validator_count = ledger.consensus.active_validators.len();
        if eligible_count >= MULTI_VALIDATOR_NODE_THRESHOLD
            && active_validator_count >= MIN_ACTIVE_VALIDATORS
        {
            return Err(Error::msg(format!(
                "Node 1 block production is disabled at {eligible_count} Governance-Eligible Nodes and {active_validator_count} Active Validators; multi-Validator consensus is required"
            )));
        }
        reset_multi_validator_consensus_if_node1_mode(ledger, now);
        if ledger.pending_operation_ids.is_empty() && !allow_empty {
            return Err(Error::msg("there are no pending operations to include"));
        }
        if ledger.pending_operation_ids.len() > MAX_BLOCK_OPERATIONS {
            return Err(Error::msg(format!(
                "pending operation count exceeds the {MAX_BLOCK_OPERATIONS} operation block limit; an explicit legacy snapshot migration is required"
            )));
        }
        if chain_tip_timestamp(ledger).is_some_and(|timestamp| now < timestamp) {
            return Err(Error::msg("block timestamp cannot move backwards"));
        }
        let height = next_block_height(ledger);
        let candidates = ledger.pending_operation_ids.clone();
        let (mut committed, operation_ids) =
            prepare_block_operations(ledger, &candidates, height, now, true)?;
        reset_multi_validator_consensus_if_node1_mode(&mut committed, now);
        refresh_validator_committee(&mut committed, now)?;
        let state_root = ledger_state_root(&committed)?;
        let payload = BlockSigningPayload {
            version: PROTOCOL_VERSION,
            ledger_id: ledger.ledger_id.clone(),
            height,
            previous_block_hash: chain_tip_hash(ledger)
                .unwrap_or(GENESIS_PREVIOUS_BLOCK_HASH)
                .to_owned(),
            timestamp: now,
            producer_node_id: node_id,
            producer_owner_address: owner_file.address.clone(),
            operation_ids,
            state_root,
        };
        let signing_bytes = serde_json::to_vec(&payload)?;
        let block = BlockRecord {
            version: payload.version,
            ledger_id: payload.ledger_id,
            height: payload.height,
            previous_block_hash: payload.previous_block_hash,
            timestamp: payload.timestamp,
            producer_node_id: payload.producer_node_id,
            producer_owner_address: payload.producer_owner_address,
            operation_ids: payload.operation_ids,
            state_root: payload.state_root,
            block_hash: sha256_full_id("blk", &signing_bytes),
            producer_signature: sign_bytes(&owner_key, &signing_bytes),
            consensus_mode: crate::model::BlockConsensusMode::Node1,
            consensus_round: 0,
            validator_set_hash: String::new(),
            commit_signatures: Vec::new(),
            validator_epoch: 0,
            validator_node_ids: Vec::new(),
        };
        verify_bytes(
            &genesis.owner_public_key,
            &signing_bytes,
            &block.producer_signature,
        )?;
        committed.blocks.push(block.clone());
        update_finalized_checkpoint(&mut committed);
        *ledger = committed;
        Ok(block)
    })?;
    persist_latest_bootstrap_checkpoint(paths)?;
    Ok(block)
}

pub fn produce_node1_block_if_due(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<Option<BlockRecord>> {
    let config = paths.read_node_config(name)?;
    if config.node_id != Some(1) {
        return Ok(None);
    }
    let ledger = paths.read_active_ledger()?;
    let genesis_exists = ledger.genesis_authority.is_some() || ledger.nodes.contains_key(&1);
    if !genesis_exists || multi_validator_ready(&ledger, now) {
        return Ok(None);
    }
    if !block_is_due(&ledger, now) {
        return Ok(None);
    }
    produce_node1_block(paths, name, password, true, now).map(Some)
}

pub fn verify_blockchain(paths: &DataPaths) -> Result<BlockVerificationReport> {
    let ledger = paths.read_ledger()?;
    match verify_blockchain_inner(&ledger) {
        Ok((checked_operations, legacy_unverified_operations)) => Ok(BlockVerificationReport {
            ok: true,
            height: chain_height(&ledger),
            checked_operations,
            legacy_unverified_operations,
            pruned_through_height: ledger.pruned_through_height,
            pruned_operation_count: ledger.pruned_operation_count,
            detail: "block linkage, producer signatures, Validator commits and operation commitments are valid".to_owned(),
        }),
        Err(error) => Ok(BlockVerificationReport {
            ok: false,
            height: chain_height(&ledger),
            checked_operations: 0,
            legacy_unverified_operations: 0,
            pruned_through_height: ledger.pruned_through_height,
            pruned_operation_count: ledger.pruned_operation_count,
            detail: error.to_string(),
        }),
    }
}

fn verify_blockchain_inner(ledger: &LedgerState) -> Result<(usize, usize)> {
    if ledger.pending_operation_ids.len() > MAX_BLOCK_OPERATIONS {
        return Err(Error::msg(format!(
            "pending operation queue exceeds the {MAX_BLOCK_OPERATIONS} operation limit"
        )));
    }
    let genesis = ledger
        .genesis_authority
        .clone()
        .or_else(|| legacy_genesis_authority(ledger))
        .ok_or_else(|| Error::msg("Genesis Node 1 has not been registered"))?;
    let registered = ledger
        .nodes
        .get(&1)
        .ok_or_else(|| Error::msg("Genesis Node 1 is missing from the registry"))?;
    if genesis.node_id != 1
        || genesis.owner_address != registered.owner_address
        || genesis.owner_public_key != registered.owner_public_key
    {
        return Err(Error::msg(
            "Genesis authority does not match registered Node 1",
        ));
    }
    if ledger.pruned_through_height == 0
        && (ledger.pruned_tip_hash.is_some() || ledger.pruned_tip_timestamp.is_some())
    {
        return Err(Error::msg(
            "history checkpoint exists without a pruned prefix",
        ));
    }
    if ledger.pruned_through_height > 0
        && (ledger.pruned_tip_hash.is_none() || ledger.pruned_tip_timestamp.is_none())
    {
        return Err(Error::msg("pruned history checkpoint is incomplete"));
    }
    let mut previous_hash = ledger
        .pruned_tip_hash
        .clone()
        .unwrap_or_else(|| GENESIS_PREVIOUS_BLOCK_HASH.to_owned());
    let mut previous_timestamp = ledger.pruned_tip_timestamp.unwrap_or(i64::MIN);
    let mut included = BTreeSet::new();
    let mut checked_operations = 0_usize;
    let mut legacy_unverified = 0_usize;
    for (index, block) in ledger.blocks.iter().enumerate() {
        let expected_height = ledger.pruned_through_height + index as u64 + 1;
        if block.height != expected_height {
            return Err(Error::msg(format!(
                "block height mismatch at index {index}: expected {expected_height}, got {}",
                block.height
            )));
        }
        if block.ledger_id != ledger.ledger_id {
            return Err(Error::msg(format!(
                "block {} has an invalid protocol or ledger domain",
                block.height
            )));
        }
        if block.previous_block_hash != previous_hash {
            return Err(Error::msg(format!(
                "block {} does not link to its predecessor",
                block.height
            )));
        }
        if block.timestamp < previous_timestamp {
            return Err(Error::msg(format!(
                "block {} timestamp moves backwards",
                block.height
            )));
        }
        if block.operation_ids.len() > MAX_BLOCK_OPERATIONS {
            return Err(Error::msg(format!(
                "block {} exceeds the operation limit",
                block.height
            )));
        }
        if !block.state_root.starts_with("state_") || block.state_root.len() != 70 {
            return Err(Error::msg(format!(
                "block {} contains an invalid state root",
                block.height
            )));
        }
        match block.consensus_mode {
            BlockConsensusMode::Node1 => {
                if block.version != PROTOCOL_VERSION
                    || block.producer_node_id != 1
                    || block.producer_owner_address != genesis.owner_address
                {
                    return Err(Error::msg(format!(
                        "block {} is not a valid Genesis Node 1 block",
                        block.height
                    )));
                }
                let payload = block_signing_payload(block);
                let signing_bytes = serde_json::to_vec(&payload)?;
                if block.block_hash != sha256_full_id("blk", &signing_bytes) {
                    return Err(Error::msg(format!(
                        "block {} hash does not match its contents",
                        block.height
                    )));
                }
                verify_bytes(
                    &genesis.owner_public_key,
                    &signing_bytes,
                    &block.producer_signature,
                )?;
            }
            BlockConsensusMode::MultiValidator => {
                if block.version != MULTI_VALIDATOR_BLOCK_VERSION
                    || block.validator_node_ids.is_empty()
                {
                    return Err(Error::msg(format!(
                        "block {} has invalid multi-Validator metadata",
                        block.height
                    )));
                }
                let mut validators = block.validator_node_ids.clone();
                validators.sort_unstable();
                validators.dedup();
                if validators != block.validator_node_ids {
                    return Err(Error::msg(format!(
                        "block {} Validator list is not canonical",
                        block.height
                    )));
                }
                let expected_set_hash = validator_set_hash_for_epoch(
                    ledger,
                    block.validator_epoch,
                    &block.validator_node_ids,
                )?;
                if block.validator_set_hash != expected_set_hash {
                    return Err(Error::msg(format!(
                        "block {} Validator set hash is invalid",
                        block.height
                    )));
                }
                let expected_proposer = consensus_proposer(
                    &block.validator_node_ids,
                    block.height,
                    block.consensus_round,
                )
                .ok_or_else(|| Error::msg("multi-Validator block has no proposer"))?;
                let proposer = ledger.nodes.get(&expected_proposer).ok_or_else(|| {
                    Error::msg(format!("block {} proposer is missing", block.height))
                })?;
                if block.producer_node_id != expected_proposer
                    || block.producer_owner_address != proposer.owner_address
                {
                    return Err(Error::msg(format!(
                        "block {} was produced by the wrong Validator",
                        block.height
                    )));
                }
                let payload = multi_validator_block_signing_payload(block);
                let signing_bytes = serde_json::to_vec(&payload)?;
                if block.block_hash != sha256_full_id("blk", &signing_bytes) {
                    return Err(Error::msg(format!(
                        "block {} hash does not match its contents",
                        block.height
                    )));
                }
                verify_bytes(
                    &proposer.owner_public_key,
                    &signing_bytes,
                    &block.producer_signature,
                )?;
                let mut committers = BTreeSet::new();
                for vote in &block.commit_signatures {
                    if vote.height != block.height
                        || vote.round != block.consensus_round
                        || vote.vote_type != ConsensusVoteType::Precommit
                        || vote.block_hash.as_deref() != Some(block.block_hash.as_str())
                        || vote.validator_set_hash != block.validator_set_hash
                        || !block.validator_node_ids.contains(&vote.validator_node_id)
                        || !committers.insert(vote.validator_node_id)
                    {
                        return Err(Error::msg(format!(
                            "block {} contains an invalid or duplicate PRECOMMIT",
                            block.height
                        )));
                    }
                    verify_consensus_vote_historical(ledger, vote)?;
                }
                if committers.len() < consensus_quorum(block.validator_node_ids.len()) {
                    return Err(Error::msg(format!(
                        "block {} does not contain a greater-than-two-thirds PRECOMMIT quorum",
                        block.height
                    )));
                }
            }
        }
        for operation_id_value in &block.operation_ids {
            if !included.insert(operation_id_value.clone()) {
                return Err(Error::msg(format!(
                    "operation {operation_id_value} appears in more than one block"
                )));
            }
            let Some(operation) = ledger.operations.get(operation_id_value) else {
                if block.height < ledger.operation_history_from_height {
                    continue;
                }
                return Err(Error::msg(format!(
                    "block {} references missing operation {operation_id_value}",
                    block.height
                )));
            };
            checked_operations = checked_operations.saturating_add(1);
            if !matches!(
                operation.status,
                OperationStatus::Finalized | OperationStatus::Rejected
            ) || operation.block_height != Some(block.height)
            {
                return Err(Error::msg(format!(
                    "operation {operation_id_value} has inconsistent finality metadata"
                )));
            }
            if let Some(signed) = &operation.signed_operation {
                if operation_id(signed)? != *operation_id_value
                    || signed.signature != operation.signature
                    || signed.unsigned.payload != operation.payload
                    || format!("{}.{}", signed.unsigned.module, signed.unsigned.action)
                        != operation.kind
                {
                    return Err(Error::msg(format!(
                        "operation {operation_id_value} does not match its signed commitment"
                    )));
                }
                let public_key = ledger
                    .accounts
                    .get(&signed.unsigned.signer)
                    .and_then(|account| account.public_key.as_deref())
                    .ok_or_else(|| {
                        Error::msg(format!(
                            "operation {operation_id_value} signer key is missing"
                        ))
                    })?;
                verify_operation(signed, public_key)?;
            } else {
                legacy_unverified = legacy_unverified.saturating_add(1);
            }
        }
        previous_hash = block.block_hash.clone();
        previous_timestamp = block.timestamp;
    }
    for operation in ledger.operations.values() {
        if operation.block_height.is_some()
            && operation
                .block_height
                .is_some_and(|height| height > ledger.pruned_through_height)
            && !included.contains(&operation.operation_id)
        {
            return Err(Error::msg(format!(
                "operation {} claims block finality but is absent from the chain",
                operation.operation_id
            )));
        }
    }
    for operation_id_value in &ledger.pending_operation_ids {
        let operation = ledger.operations.get(operation_id_value).ok_or_else(|| {
            Error::msg(format!(
                "pending operation {operation_id_value} is missing from the ledger"
            ))
        })?;
        if !matches!(operation.status, OperationStatus::Pending) || operation.block_height.is_some()
        {
            return Err(Error::msg(format!(
                "pending operation {operation_id_value} has inconsistent status"
            )));
        }
    }
    Ok((checked_operations, legacy_unverified))
}

fn update_finalized_checkpoint(ledger: &mut LedgerState) {
    let mut checkpoint = ledger.clone();
    checkpoint.finalized_checkpoint = None;
    let height = chain_height(&checkpoint);
    let tip_hash = chain_tip_hash(&checkpoint).map(str::to_owned);
    let tip_timestamp = chain_tip_timestamp(&checkpoint);
    checkpoint.blocks.clear();
    checkpoint.pruned_through_height = height;
    checkpoint.pruned_tip_hash = tip_hash;
    checkpoint.pruned_tip_timestamp = tip_timestamp;
    checkpoint.operations.retain(|_, operation| {
        operation.block_height.is_none()
            || operation
                .block_height
                .is_some_and(|block_height| block_height == height)
    });
    for account in checkpoint.accounts.values_mut() {
        account
            .operation_ids
            .retain(|operation_id| checkpoint.operations.contains_key(operation_id));
    }
    ledger.finalized_checkpoint = Some(Box::new(checkpoint));
}

fn persist_latest_bootstrap_checkpoint(paths: &DataPaths) -> Result<()> {
    let snapshot = latest_bootstrap_snapshot(paths)?;
    let previous = paths.latest_bootstrap_checkpoint()?;
    if !crate::checkpoint::should_persist(
        previous.as_ref().map(|(_, checkpoint)| checkpoint),
        &snapshot.checkpoint,
    ) {
        return Ok(());
    }
    paths.store_bootstrap_checkpoint(
        snapshot.height,
        &snapshot.checkpoint,
        BOOTSTRAP_CHECKPOINT_RETENTION,
    )
}

fn block_signing_payload(block: &BlockRecord) -> BlockSigningPayload {
    BlockSigningPayload {
        version: block.version,
        ledger_id: block.ledger_id.clone(),
        height: block.height,
        previous_block_hash: block.previous_block_hash.clone(),
        timestamp: block.timestamp,
        producer_node_id: block.producer_node_id,
        producer_owner_address: block.producer_owner_address.clone(),
        operation_ids: block.operation_ids.clone(),
        state_root: block.state_root.clone(),
    }
}

pub fn create_governance_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    kind: GovernanceProposalKind,
    title: &str,
    action: GovernanceProposalAction,
    now: i64,
) -> Result<GovernanceProposalRecord> {
    let title = title.trim();
    if title.is_empty() || title.len() > 128 {
        return Err(Error::msg(
            "governance proposal title must contain between 1 and 128 characters",
        ));
    }
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let reward_file = paths.read_keyfile(&paths.node_reward_key_path(name)?)?;
    let reward_key = decrypt_key(&reward_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_proposal_node_threshold(ledger, &kind, now)?;
        validate_governance_proposal_action(&kind, &action, ledger, now)?;
        let eligible = governance_eligible_node_ids(ledger, now);
        if !eligible.contains(&node_id) {
            return Err(Error::msg(
                "only a Governance-Eligible Node may create a proposal",
            ));
        }
        let treasury_spend = matches!(action, GovernanceProposalAction::TreasurySpend { .. });
        if treasury_spend && !treasury_governance_node_ids(ledger, now).contains(&node_id) {
            return Err(Error::msg(
                "TreasurySpend proposals require 180 days of cumulative eligible Node service",
            ));
        }
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("proposal Node is missing"))?;
        if node.reward_address != reward_file.address {
            return Err(Error::msg("Node Reward key does not match the registry"));
        }
        ensure_account(ledger, &reward_file)?;
        let reward_account = ledger.accounts[&reward_file.address].clone();
        if reward_account.balance < GOVERNANCE_PROPOSAL_BOND {
            return Err(Error::msg(format!(
                "insufficient spendable MRK for Proposal Bond: available {}, required {}",
                format_mrk(reward_account.balance),
                format_mrk(GOVERNANCE_PROPOSAL_BOND)
            )));
        }
        let power_snapshot = if treasury_spend {
            treasury_governance_power_snapshot(ledger, now)?
        } else {
            governance_power_snapshot(ledger, now)?
        };
        let validator_snapshot = if treasury_spend {
            let validators = ledger.consensus.active_validators.clone();
            if validators.len() < MIN_ACTIVE_VALIDATORS {
                return Err(Error::msg(format!(
                    "TreasurySpend requires at least {MIN_ACTIVE_VALIDATORS} Active Validators"
                )));
            }
            validators
        } else {
            Vec::new()
        };
        let total_power = power_snapshot.values().copied().sum::<u128>();
        let proposal_id = ledger.governance.next_proposal_id.max(1);
        let (voting_seconds, timelock_seconds) = match kind {
            GovernanceProposalKind::Standard => {
                (STANDARD_VOTING_SECONDS, STANDARD_TIMELOCK_SECONDS)
            }
            GovernanceProposalKind::Critical => {
                (CRITICAL_VOTING_SECONDS, CRITICAL_TIMELOCK_SECONDS)
            }
        };
        let voting_ends_at = now + voting_seconds;
        let execute_after = voting_ends_at + timelock_seconds;
        let payload = json!({
            "proposal_id": proposal_id,
            "kind": kind,
            "title": title,
            "action": action,
            "snapshot_epoch": ledger.epoch_number,
            "power_snapshot": power_snapshot,
            "validator_snapshot": validator_snapshot,
            "voting_ends_at": voting_ends_at,
            "execute_after": execute_after,
            "proposal_bond_base_units": GOVERNANCE_PROPOSAL_BOND.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&reward_file, &reward_key),
            "Governance",
            "CreateProposal",
            reward_account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &reward_file.public_key)?;
        ledger
            .accounts
            .get_mut(&reward_file.address)
            .expect("reward account")
            .balance -= GOVERNANCE_PROPOSAL_BOND;
        let record = GovernanceProposalRecord {
            proposal_id,
            proposer_node_id: node_id,
            proposer_reward_address: reward_file.address.clone(),
            kind,
            title: title.to_owned(),
            action,
            created_at: now,
            voting_ends_at,
            execute_after,
            status: GovernanceProposalStatus::Voting,
            snapshot_epoch: ledger.epoch_number,
            power_snapshot,
            total_power,
            votes: BTreeMap::new(),
            validator_snapshot,
            validator_votes: BTreeMap::new(),
            timelock_vetoes: BTreeMap::new(),
            proposal_bond: GOVERNANCE_PROPOSAL_BOND,
            finalized_at: None,
            executed_at: None,
        };
        ledger
            .governance
            .proposals
            .insert(proposal_id, record.clone());
        ledger.governance.next_proposal_id = proposal_id.saturating_add(1);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        Ok(record)
    })
}

pub fn vote_governance_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    proposal_id: u64,
    choice: GovernanceVoteChoice,
    now: i64,
) -> Result<(String, GovernanceTallyView)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_node_identity(ledger, node_id, &owner_file)?;
        let proposal = ledger
            .governance
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| Error::msg(format!("governance proposal {proposal_id} not found")))?;
        ensure_governance_proposal_node_threshold(ledger, &proposal.kind, now)?;
        if proposal.status != GovernanceProposalStatus::Voting || now >= proposal.voting_ends_at {
            return Err(Error::msg("governance proposal is not accepting votes"));
        }
        let power = proposal
            .power_snapshot
            .get(&node_id)
            .copied()
            .ok_or_else(|| Error::msg("Node was not Governance-Eligible at proposal snapshot"))?;
        if proposal.votes.contains_key(&node_id) {
            return Err(Error::msg("Node has already voted on this proposal"));
        }
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "proposal_id": proposal_id,
            "node_id": node_id,
            "choice": choice,
            "snapshot_power": power.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            "VoteProposal",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal")
            .votes
            .insert(
                node_id,
                GovernanceVoteRecord {
                    node_id,
                    choice,
                    power,
                    operation_id: operation_id.clone(),
                    voted_at: now,
                },
            );
        finalize_operation(ledger, &signed, &operation_id, now)?;
        let tally = governance_tally(
            ledger
                .governance
                .proposals
                .get(&proposal_id)
                .expect("proposal"),
        );
        Ok((operation_id, tally))
    })
}

pub fn validator_vote_governance_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    proposal_id: u64,
    choice: GovernanceVoteChoice,
    now: i64,
) -> Result<(String, GovernanceTallyView)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_node_identity(ledger, node_id, &owner_file)?;
        let proposal = ledger
            .governance
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| Error::msg(format!("governance proposal {proposal_id} not found")))?;
        ensure_governance_proposal_node_threshold(ledger, &proposal.kind, now)?;
        if !matches!(
            proposal.action,
            GovernanceProposalAction::TreasurySpend { .. }
        ) {
            return Err(Error::msg(
                "Validator approval is required only for TreasurySpend proposals",
            ));
        }
        if proposal.status != GovernanceProposalStatus::Voting || now >= proposal.voting_ends_at {
            return Err(Error::msg(
                "governance proposal is not accepting Validator votes",
            ));
        }
        if !proposal.validator_snapshot.contains(&node_id) {
            return Err(Error::msg(
                "Node was not an Active Validator at proposal snapshot",
            ));
        }
        if proposal.validator_votes.contains_key(&node_id) {
            return Err(Error::msg("Validator has already voted on this proposal"));
        }
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "proposal_id": proposal_id,
            "validator_node_id": node_id,
            "choice": choice,
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            "ValidatorVoteProposal",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal")
            .validator_votes
            .insert(
                node_id,
                GovernanceValidatorVoteRecord {
                    node_id,
                    choice,
                    operation_id: operation_id.clone(),
                    voted_at: now,
                },
            );
        finalize_operation(ledger, &signed, &operation_id, now)?;
        let tally = governance_tally(
            ledger
                .governance
                .proposals
                .get(&proposal_id)
                .expect("proposal"),
        );
        Ok((operation_id, tally))
    })
}

pub fn veto_treasury_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    proposal_id: u64,
    now: i64,
) -> Result<(String, GovernanceTallyView)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_node_identity(ledger, node_id, &owner_file)?;
        let proposal = ledger
            .governance
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| Error::msg(format!("governance proposal {proposal_id} not found")))?;
        ensure_governance_proposal_node_threshold(ledger, &proposal.kind, now)?;
        if !matches!(
            proposal.action,
            GovernanceProposalAction::TreasurySpend { .. }
        ) {
            return Err(Error::msg(
                "timelock veto applies only to TreasurySpend proposals",
            ));
        }
        if proposal.status != GovernanceProposalStatus::Passed || now >= proposal.execute_after {
            return Err(Error::msg(
                "TreasurySpend vetoes are accepted only during the execution timelock",
            ));
        }
        let power = proposal
            .power_snapshot
            .get(&node_id)
            .copied()
            .ok_or_else(|| Error::msg("Node was not in the mature governance snapshot"))?;
        if proposal.timelock_vetoes.contains_key(&node_id) {
            return Err(Error::msg("Node has already vetoed this proposal"));
        }
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "proposal_id": proposal_id,
            "node_id": node_id,
            "snapshot_power": power.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            "VetoTreasuryProposal",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let proposal = ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal");
        proposal.timelock_vetoes.insert(
            node_id,
            GovernanceVoteRecord {
                node_id,
                choice: GovernanceVoteChoice::No,
                power,
                operation_id: operation_id.clone(),
                voted_at: now,
            },
        );
        let veto_power = proposal
            .timelock_vetoes
            .values()
            .map(|vote| vote.power)
            .sum::<u128>();
        if veto_power.saturating_mul(3) > proposal.total_power {
            proposal.status = GovernanceProposalStatus::Cancelled;
            proposal.finalized_at = Some(now);
        }
        finalize_operation(ledger, &signed, &operation_id, now)?;
        let tally = governance_tally(
            ledger
                .governance
                .proposals
                .get(&proposal_id)
                .expect("proposal"),
        );
        Ok((operation_id, tally))
    })
}

pub fn finalize_governance_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    proposal_id: u64,
    now: i64,
) -> Result<(String, GovernanceTallyView)> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_node_identity(ledger, node_id, &owner_file)?;
        let tally = {
            let proposal = ledger
                .governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| {
                    Error::msg(format!("governance proposal {proposal_id} not found"))
                })?;
            ensure_governance_proposal_node_threshold(ledger, &proposal.kind, now)?;
            if proposal.status != GovernanceProposalStatus::Voting {
                return Err(Error::msg("governance proposal is already finalized"));
            }
            if now < proposal.voting_ends_at {
                return Err(Error::msg(format!(
                    "governance voting remains open until {}",
                    proposal.voting_ends_at
                )));
            }
            governance_tally(proposal)
        };
        let passed = governance_tally_passed(
            ledger
                .governance
                .proposals
                .get(&proposal_id)
                .expect("proposal"),
            &tally,
        );
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({
            "proposal_id": proposal_id,
            "result": if passed { "PASSED" } else { "REJECTED" },
            "yes_power": tally.yes_power.to_string(),
            "no_power": tally.no_power.to_string(),
            "abstain_power": tally.abstain_power.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            "FinalizeProposal",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        let proposal = ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal");
        proposal.status = if passed {
            GovernanceProposalStatus::Passed
        } else {
            GovernanceProposalStatus::Rejected
        };
        proposal.finalized_at = Some(now);
        let quorum_reached = tally.participation_power.saturating_mul(2) >= proposal.total_power;
        let burn =
            if !passed && proposal.kind == GovernanceProposalKind::Standard && !quorum_reached {
                proposal.proposal_bond / 5
            } else {
                0
            };
        let refund = proposal.proposal_bond - burn;
        let refund_address = proposal.proposer_reward_address.clone();
        proposal.proposal_bond = 0;
        ledger.treasury += burn;
        ledger
            .accounts
            .entry(refund_address.clone())
            .or_default()
            .balance += refund;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        add_history(ledger, &refund_address, &operation_id);
        let mut finalized_tally = tally;
        finalized_tally.status = if passed {
            GovernanceProposalStatus::Passed
        } else {
            GovernanceProposalStatus::Rejected
        };
        Ok((operation_id, finalized_tally))
    })
}

pub fn execute_governance_proposal(
    paths: &DataPaths,
    name: &str,
    password: &str,
    proposal_id: u64,
    now: i64,
) -> Result<GovernanceReceipt> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        ensure_distributed_governance_mode(ledger, now)?;
        ensure_governance_node_identity(ledger, node_id, &owner_file)?;
        let proposal = ledger
            .governance
            .proposals
            .get(&proposal_id)
            .ok_or_else(|| Error::msg(format!("governance proposal {proposal_id} not found")))?;
        ensure_governance_proposal_node_threshold(ledger, &proposal.kind, now)?;
        if proposal.status != GovernanceProposalStatus::Passed {
            return Err(Error::msg("only a passed proposal can execute"));
        }
        if now < proposal.execute_after {
            return Err(Error::msg(format!(
                "proposal timelock remains active until {}",
                proposal.execute_after
            )));
        }
        let action = proposal.action.clone();
        let account = ledger.accounts[&owner_file.address].clone();
        let payload = json!({"proposal_id": proposal_id, "action": action});
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            "ExecuteProposal",
            account.nonce + 1,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload.clone(),
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        apply_governance_proposal_action(ledger, &action, now)?;
        let proposal = ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal");
        proposal.status = GovernanceProposalStatus::Executed;
        proposal.executed_at = Some(now);
        finalize_operation(ledger, &signed, &operation_id, now)?;
        if let GovernanceProposalAction::TreasurySpend {
            recipient,
            amount,
            reference_hash,
        } = &action
        {
            ledger.treasury_spends.push(TreasurySpendRecord {
                proposal_id,
                operation_id: operation_id.clone(),
                recipient: recipient.clone(),
                amount: *amount,
                reference_hash: reference_hash.clone(),
                executed_at: now,
            });
            add_history(ledger, recipient, &operation_id);
        }
        ledger.governance.last_action_at = Some(now);
        ledger.governance.actions.push(GovernanceActionRecord {
            operation_id: operation_id.clone(),
            action: "ExecuteProposal".to_owned(),
            signer_node_id: node_id,
            executed_at: now,
            payload: payload.clone(),
        });
        Ok(GovernanceReceipt {
            operation_id,
            status: OperationStatus::Pending,
            action: "ExecuteProposal".to_owned(),
            signer_node_id: node_id,
            executed_at: now,
            payload,
        })
    })
}

pub fn governance_proposal(
    paths: &DataPaths,
    proposal_id: u64,
) -> Result<(GovernanceProposalRecord, GovernanceTallyView)> {
    let proposal = paths
        .read_ledger()?
        .governance
        .proposals
        .get(&proposal_id)
        .cloned()
        .ok_or_else(|| Error::msg(format!("governance proposal {proposal_id} not found")))?;
    let tally = governance_tally(&proposal);
    Ok((proposal, tally))
}

pub fn governance_proposals(paths: &DataPaths) -> Result<Vec<GovernanceProposalRecord>> {
    Ok(paths
        .read_ledger()?
        .governance
        .proposals
        .into_values()
        .collect())
}

fn ensure_distributed_governance_mode(ledger: &LedgerState, now: i64) -> Result<()> {
    let eligible_count = governance_eligible_node_ids(ledger, now).len();
    if eligible_count < GOVERNANCE_NODE_THRESHOLD {
        return Err(Error::msg(format!(
            "distributed governance requires at least {GOVERNANCE_NODE_THRESHOLD} Governance-Eligible Nodes; current count is {eligible_count}"
        )));
    }
    Ok(())
}

fn governance_proposal_node_threshold(kind: &GovernanceProposalKind) -> usize {
    match kind {
        GovernanceProposalKind::Standard => GOVERNANCE_NODE_THRESHOLD,
        GovernanceProposalKind::Critical => CRITICAL_GOVERNANCE_NODE_THRESHOLD,
    }
}

fn ensure_governance_proposal_node_threshold(
    ledger: &LedgerState,
    kind: &GovernanceProposalKind,
    now: i64,
) -> Result<()> {
    let eligible_count = governance_eligible_node_ids(ledger, now).len();
    let threshold = governance_proposal_node_threshold(kind);
    if eligible_count < threshold {
        return Err(Error::msg(format!(
            "{} governance requires at least {threshold} Governance-Eligible Nodes; current count is {eligible_count}",
            match kind {
                GovernanceProposalKind::Standard => "STANDARD",
                GovernanceProposalKind::Critical => "CRITICAL",
            }
        )));
    }
    Ok(())
}

fn ensure_governance_node_identity(
    ledger: &LedgerState,
    node_id: u64,
    owner_file: &EncryptedKeyFile,
) -> Result<()> {
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("governance Node is missing"))?;
    if node.owner_address != owner_file.address || node.owner_public_key != owner_file.public_key {
        return Err(Error::msg(
            "Governance Node Owner key does not match the registry",
        ));
    }
    Ok(())
}

fn governance_power_snapshot(ledger: &LedgerState, now: i64) -> Result<BTreeMap<u64, u128>> {
    let eligible = governance_eligible_node_ids(ledger, now);
    if eligible.len() < GOVERNANCE_NODE_THRESHOLD {
        return Err(Error::msg(
            "not enough Governance-Eligible Nodes for a snapshot",
        ));
    }
    governance_power_snapshot_for_nodes(ledger, &eligible)
}

fn treasury_governance_node_ids(ledger: &LedgerState, now: i64) -> Vec<u64> {
    governance_eligible_node_ids(ledger, now)
        .into_iter()
        .filter(|node_id| {
            ledger.nodes[node_id].total_eligible_seconds >= TREASURY_MATURE_SERVICE_SECONDS
        })
        .collect()
}

fn treasury_governance_power_snapshot(
    ledger: &LedgerState,
    now: i64,
) -> Result<BTreeMap<u64, u128>> {
    let mature = treasury_governance_node_ids(ledger, now);
    if mature.len() < CRITICAL_GOVERNANCE_NODE_THRESHOLD {
        return Err(Error::msg(format!(
            "TreasurySpend requires at least {CRITICAL_GOVERNANCE_NODE_THRESHOLD} Governance-Eligible Nodes with 180 days of service; current count is {}",
            mature.len()
        )));
    }
    governance_power_snapshot_for_nodes(ledger, &mature)
}

fn governance_power_snapshot_for_nodes(
    ledger: &LedgerState,
    node_ids: &[u64],
) -> Result<BTreeMap<u64, u128>> {
    let raw = node_ids
        .iter()
        .map(|node_id| {
            let node = &ledger.nodes[node_id];
            let age_days = (node.total_eligible_seconds / 86_400).clamp(1, 180) as u128;
            (*node_id, age_days)
        })
        .collect::<BTreeMap<_, _>>();
    let max_raw = raw.values().copied().max().unwrap_or(1);
    let node_count = raw.len() as u128;
    let max_share_bps = 100_u128.max(10_000_u128.div_ceil(node_count));
    let mut low = 1_u128;
    let mut high = max_raw;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let total = raw.values().map(|power| (*power).min(mid)).sum::<u128>();
        if total.saturating_mul(max_share_bps) >= mid.saturating_mul(10_000) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(raw
        .into_iter()
        .map(|(node_id, power)| (node_id, power.min(low)))
        .collect())
}

fn governance_tally(proposal: &GovernanceProposalRecord) -> GovernanceTallyView {
    let mut yes = 0_u128;
    let mut no = 0_u128;
    let mut abstain = 0_u128;
    for vote in proposal.votes.values() {
        match vote.choice {
            GovernanceVoteChoice::Yes => yes += vote.power,
            GovernanceVoteChoice::No => no += vote.power,
            GovernanceVoteChoice::Abstain => abstain += vote.power,
        }
    }
    let mut validator_yes = 0_usize;
    let mut validator_no = 0_usize;
    let mut validator_abstain = 0_usize;
    for vote in proposal.validator_votes.values() {
        match vote.choice {
            GovernanceVoteChoice::Yes => validator_yes += 1,
            GovernanceVoteChoice::No => validator_no += 1,
            GovernanceVoteChoice::Abstain => validator_abstain += 1,
        }
    }
    let timelock_veto_power = proposal
        .timelock_vetoes
        .values()
        .map(|vote| vote.power)
        .sum();
    GovernanceTallyView {
        proposal_id: proposal.proposal_id,
        status: proposal.status.clone(),
        total_power: proposal.total_power,
        yes_power: yes,
        no_power: no,
        abstain_power: abstain,
        participation_power: yes + no + abstain,
        validator_total: proposal.validator_snapshot.len(),
        validator_yes,
        validator_no,
        validator_abstain,
        validator_quorum: governance_validator_quorum(proposal.validator_snapshot.len()),
        timelock_veto_power,
        voting_ends_at: proposal.voting_ends_at,
        execute_after: proposal.execute_after,
    }
}

fn governance_tally_passed(
    proposal: &GovernanceProposalRecord,
    tally: &GovernanceTallyView,
) -> bool {
    match proposal.kind {
        GovernanceProposalKind::Standard => {
            tally.participation_power.saturating_mul(2) >= proposal.total_power
                && tally.yes_power.saturating_mul(3)
                    >= (tally.yes_power + tally.no_power).saturating_mul(2)
                && tally.yes_power.saturating_mul(2) > proposal.total_power
        }
        GovernanceProposalKind::Critical => {
            let node_approval =
                tally.yes_power.saturating_mul(3) >= proposal.total_power.saturating_mul(2);
            if matches!(
                proposal.action,
                GovernanceProposalAction::TreasurySpend { .. }
            ) {
                node_approval
                    && tally.validator_total >= MIN_ACTIVE_VALIDATORS
                    && tally.validator_yes >= tally.validator_quorum
            } else {
                node_approval
            }
        }
    }
}

fn governance_validator_quorum(validator_count: usize) -> usize {
    validator_count.saturating_mul(2).div_ceil(3)
}

fn validate_governance_proposal_action(
    kind: &GovernanceProposalKind,
    action: &GovernanceProposalAction,
    ledger: &LedgerState,
    now: i64,
) -> Result<()> {
    match action {
        GovernanceProposalAction::SetParameters {
            changes,
            effective_epoch,
        } => {
            validate_governance_parameter_batch(ledger, changes, *effective_epoch)?;
            if changes
                .keys()
                .any(|parameter| governance_parameter_is_critical(parameter))
                && *kind != GovernanceProposalKind::Critical
            {
                return Err(Error::msg("parameter batch requires a CRITICAL proposal"));
            }
        }
        GovernanceProposalAction::PauseEmission { reason } => {
            if reason.trim().is_empty() || reason.len() > 256 {
                return Err(Error::msg(
                    "pause reason must contain between 1 and 256 characters",
                ));
            }
        }
        GovernanceProposalAction::ResumeEmission => {}
        GovernanceProposalAction::TreasurySpend {
            recipient,
            amount,
            reference_hash,
        } => {
            if *kind != GovernanceProposalKind::Critical {
                return Err(Error::msg("TreasurySpend requires a CRITICAL proposal"));
            }
            validate_address(recipient)?;
            validate_treasury_reference_hash(reference_hash)?;
            validate_treasury_spend_amount(ledger, *amount, now)?;
        }
    }
    Ok(())
}

fn apply_replicated_governance_action(
    ledger: &mut LedgerState,
    public_key: &str,
    operation: &SignedOperation,
    operation_id_value: &str,
    executed_at: i64,
) -> Result<()> {
    let payload = &operation.unsigned.payload;
    match operation.unsigned.action.as_str() {
        "SetParameters" | "PauseEmission" | "ResumeEmission" => {
            let genesis = ensure_genesis_authority(ledger)?;
            if genesis.owner_address != operation.unsigned.signer
                || genesis.owner_public_key != public_key
                || governance_eligible_node_ids(ledger, executed_at).len()
                    >= NODE1_DIRECT_GOVERNANCE_END_THRESHOLD
            {
                return Err(Error::msg("direct governance signer or mode is invalid"));
            }
            cancel_governance_proposals_below_threshold(ledger, executed_at);
            match operation.unsigned.action.as_str() {
                "SetParameters" => {
                    let changes: BTreeMap<String, String> =
                        serde_json::from_value(payload.get("changes").cloned().ok_or_else(
                            || Error::msg("governance parameter changes are missing"),
                        )?)?;
                    let effective_epoch = payload
                        .get("effective_epoch")
                        .and_then(serde_json::Value::as_u64);
                    apply_governance_parameter_batch(ledger, &changes, effective_epoch)?;
                }
                "PauseEmission" => {
                    if ledger.governance.emission_paused {
                        return Err(Error::msg("node emission is already paused"));
                    }
                    ledger.governance.emission_paused = true;
                    ledger.governance.pause_reason =
                        Some(payload_str(payload, "reason")?.to_owned());
                    reset_active_heartbeats(ledger, executed_at);
                }
                "ResumeEmission" => {
                    if !ledger.governance.emission_paused {
                        return Err(Error::msg("node emission is not paused"));
                    }
                    ledger.governance.emission_paused = false;
                    ledger.governance.pause_reason = None;
                    reset_active_heartbeats(ledger, executed_at);
                }
                _ => unreachable!(),
            }
            ledger.governance.last_action_at = Some(executed_at);
            ledger.governance.actions.push(GovernanceActionRecord {
                operation_id: operation_id_value.to_owned(),
                action: operation.unsigned.action.clone(),
                signer_node_id: genesis.node_id,
                executed_at,
                payload: payload.clone(),
            });
        }
        "CreateProposal" => {
            ensure_distributed_governance_mode(ledger, executed_at)?;
            let proposal_id = payload["proposal_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("proposal ID is invalid"))?;
            if proposal_id != ledger.governance.next_proposal_id.max(1) {
                return Err(Error::msg("proposal ID is not the next ID"));
            }
            let proposer_node_id = ledger
                .nodes
                .values()
                .find(|node| node.reward_address == operation.unsigned.signer)
                .map(|node| node.node_id)
                .ok_or_else(|| Error::msg("proposal signer is not a Node Reward account"))?;
            let kind: GovernanceProposalKind = serde_json::from_value(payload["kind"].clone())?;
            let action: GovernanceProposalAction =
                serde_json::from_value(payload["action"].clone())?;
            ensure_governance_proposal_node_threshold(ledger, &kind, executed_at)?;
            validate_governance_proposal_action(&kind, &action, ledger, executed_at)?;
            let power_snapshot: BTreeMap<u64, u128> =
                serde_json::from_value(payload["power_snapshot"].clone())?;
            let validator_snapshot: Vec<u64> =
                serde_json::from_value(payload["validator_snapshot"].clone())?;
            let expected_power = if matches!(action, GovernanceProposalAction::TreasurySpend { .. })
            {
                treasury_governance_power_snapshot(ledger, executed_at)?
            } else {
                governance_power_snapshot(ledger, executed_at)?
            };
            if power_snapshot != expected_power
                || (matches!(action, GovernanceProposalAction::TreasurySpend { .. })
                    && validator_snapshot != ledger.consensus.active_validators)
            {
                return Err(Error::msg("proposal snapshots are not deterministic"));
            }
            if ledger.accounts[&operation.unsigned.signer].balance < GOVERNANCE_PROPOSAL_BOND {
                return Err(Error::msg("insufficient Proposal Bond"));
            }
            ledger
                .accounts
                .get_mut(&operation.unsigned.signer)
                .expect("signer")
                .balance -= GOVERNANCE_PROPOSAL_BOND;
            let snapshot_epoch = payload["snapshot_epoch"]
                .as_u64()
                .ok_or_else(|| Error::msg("proposal snapshot epoch is invalid"))?;
            if snapshot_epoch != ledger.epoch_number {
                return Err(Error::msg("proposal snapshot epoch does not match"));
            }
            let record = GovernanceProposalRecord {
                proposal_id,
                proposer_node_id,
                proposer_reward_address: operation.unsigned.signer.clone(),
                kind,
                title: payload_str(payload, "title")?.to_owned(),
                action,
                created_at: executed_at,
                voting_ends_at: payload["voting_ends_at"]
                    .as_i64()
                    .ok_or_else(|| Error::msg("voting end is invalid"))?,
                execute_after: payload["execute_after"]
                    .as_i64()
                    .ok_or_else(|| Error::msg("execution time is invalid"))?,
                status: GovernanceProposalStatus::Voting,
                snapshot_epoch,
                total_power: power_snapshot.values().copied().sum(),
                power_snapshot,
                votes: BTreeMap::new(),
                validator_snapshot,
                validator_votes: BTreeMap::new(),
                timelock_vetoes: BTreeMap::new(),
                proposal_bond: GOVERNANCE_PROPOSAL_BOND,
                finalized_at: None,
                executed_at: None,
            };
            ledger.governance.proposals.insert(proposal_id, record);
            ledger.governance.next_proposal_id = proposal_id.saturating_add(1);
        }
        "VoteProposal" => {
            let proposal_id = payload["proposal_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("proposal ID is invalid"))?;
            let node_id = payload["node_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("vote Node ID is invalid"))?;
            ensure_replicated_node_owner(ledger, node_id, &operation.unsigned.signer, public_key)?;
            let choice: GovernanceVoteChoice = serde_json::from_value(payload["choice"].clone())?;
            let proposal_kind = ledger
                .governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?
                .kind
                .clone();
            ensure_governance_proposal_node_threshold(ledger, &proposal_kind, executed_at)?;
            let proposal = ledger
                .governance
                .proposals
                .get_mut(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?;
            let power = proposal
                .power_snapshot
                .get(&node_id)
                .copied()
                .ok_or_else(|| Error::msg("Node is absent from proposal snapshot"))?;
            if proposal.status != GovernanceProposalStatus::Voting
                || executed_at >= proposal.voting_ends_at
                || proposal.votes.contains_key(&node_id)
            {
                return Err(Error::msg("proposal is not accepting this vote"));
            }
            proposal.votes.insert(
                node_id,
                GovernanceVoteRecord {
                    node_id,
                    choice,
                    power,
                    operation_id: operation_id_value.to_owned(),
                    voted_at: executed_at,
                },
            );
        }
        "ValidatorVoteProposal" => {
            let proposal_id = payload["proposal_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("proposal ID is invalid"))?;
            let node_id = payload["validator_node_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("Validator Node ID is invalid"))?;
            ensure_replicated_node_owner(ledger, node_id, &operation.unsigned.signer, public_key)?;
            let choice: GovernanceVoteChoice = serde_json::from_value(payload["choice"].clone())?;
            let proposal_kind = ledger
                .governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?
                .kind
                .clone();
            ensure_governance_proposal_node_threshold(ledger, &proposal_kind, executed_at)?;
            let proposal = ledger
                .governance
                .proposals
                .get_mut(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?;
            if proposal.status != GovernanceProposalStatus::Voting
                || !proposal.validator_snapshot.contains(&node_id)
                || proposal.validator_votes.contains_key(&node_id)
            {
                return Err(Error::msg("proposal is not accepting this Validator vote"));
            }
            proposal.validator_votes.insert(
                node_id,
                GovernanceValidatorVoteRecord {
                    node_id,
                    choice,
                    operation_id: operation_id_value.to_owned(),
                    voted_at: executed_at,
                },
            );
        }
        action => {
            return apply_replicated_governance_terminal_action(
                ledger,
                public_key,
                operation,
                operation_id_value,
                executed_at,
                action,
            );
        }
    }
    Ok(())
}

fn ensure_replicated_node_owner(
    ledger: &LedgerState,
    node_id: u64,
    signer: &str,
    public_key: &str,
) -> Result<()> {
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg("Node is missing"))?;
    if node.owner_address != signer || node.owner_public_key != public_key {
        return Err(Error::msg("operation signer does not match Node Owner"));
    }
    Ok(())
}

fn ensure_node_can_drain(node: &NodeRecord) -> Result<()> {
    if matches!(node.status, NodeStatus::Draining | NodeStatus::Exited) {
        return Err(Error::msg("node is already draining or exited"));
    }
    if node.validator
        || node.validator_bond > 0
        || node.validator_candidate_since.is_some()
        || node.validator_exit_requested_at.is_some()
        || node.validator_bond_unlock_at.is_some()
    {
        return Err(Error::msg(
            "Validator role and Validator Bond must be fully exited and withdrawn before draining the Node",
        ));
    }
    if node.governance_bond > 0
        || node.governance_bonded_at.is_some()
        || node.governance_exit_requested_at.is_some()
        || node.governance_bond_unlock_at.is_some()
    {
        return Err(Error::msg(
            "Governance Bond must be fully exited and withdrawn before draining the Node",
        ));
    }
    Ok(())
}

fn apply_replicated_governance_terminal_action(
    ledger: &mut LedgerState,
    public_key: &str,
    operation: &SignedOperation,
    operation_id_value: &str,
    executed_at: i64,
    action_name: &str,
) -> Result<()> {
    let payload = &operation.unsigned.payload;
    let proposal_id = payload["proposal_id"]
        .as_u64()
        .ok_or_else(|| Error::msg("proposal ID is invalid"))?;
    let proposal_kind = ledger
        .governance
        .proposals
        .get(&proposal_id)
        .ok_or_else(|| Error::msg("governance proposal is missing"))?
        .kind
        .clone();
    ensure_governance_proposal_node_threshold(ledger, &proposal_kind, executed_at)?;
    match action_name {
        "VetoTreasuryProposal" => {
            let node_id = payload["node_id"]
                .as_u64()
                .ok_or_else(|| Error::msg("veto Node ID is invalid"))?;
            ensure_replicated_node_owner(ledger, node_id, &operation.unsigned.signer, public_key)?;
            let proposal = ledger
                .governance
                .proposals
                .get_mut(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?;
            let power = proposal
                .power_snapshot
                .get(&node_id)
                .copied()
                .ok_or_else(|| Error::msg("Node is absent from veto snapshot"))?;
            if proposal.status != GovernanceProposalStatus::Passed
                || executed_at >= proposal.execute_after
                || proposal.timelock_vetoes.contains_key(&node_id)
            {
                return Err(Error::msg("proposal is not accepting this veto"));
            }
            proposal.timelock_vetoes.insert(
                node_id,
                GovernanceVoteRecord {
                    node_id,
                    choice: GovernanceVoteChoice::No,
                    power,
                    operation_id: operation_id_value.to_owned(),
                    voted_at: executed_at,
                },
            );
            let veto_power = proposal
                .timelock_vetoes
                .values()
                .map(|vote| vote.power)
                .sum::<u128>();
            if veto_power.saturating_mul(10) >= proposal.total_power {
                proposal.status = GovernanceProposalStatus::Rejected;
                proposal.finalized_at = Some(executed_at);
                let refund = proposal.proposal_bond;
                proposal.proposal_bond = 0;
                ledger
                    .accounts
                    .entry(proposal.proposer_reward_address.clone())
                    .or_default()
                    .balance += refund;
            }
        }
        "FinalizeProposal" => {
            let proposal = ledger
                .governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?;
            if proposal.status != GovernanceProposalStatus::Voting
                || executed_at < proposal.voting_ends_at
            {
                return Err(Error::msg("proposal cannot be finalized now"));
            }
            let tally = governance_tally(proposal);
            let passed = governance_tally_passed(proposal, &tally);
            let proposal = ledger.governance.proposals.get_mut(&proposal_id).unwrap();
            proposal.status = if passed {
                GovernanceProposalStatus::Passed
            } else {
                GovernanceProposalStatus::Rejected
            };
            proposal.finalized_at = Some(executed_at);
            let quorum_reached =
                tally.participation_power.saturating_mul(2) >= proposal.total_power;
            let burn = if !passed
                && proposal.kind == GovernanceProposalKind::Standard
                && !quorum_reached
            {
                proposal.proposal_bond / 5
            } else {
                0
            };
            let refund = proposal.proposal_bond - burn;
            proposal.proposal_bond = 0;
            ledger.burned = ledger
                .burned
                .checked_add(burn)
                .ok_or_else(|| Error::msg("burn counter overflow"))?;
            ledger
                .accounts
                .entry(proposal.proposer_reward_address.clone())
                .or_default()
                .balance += refund;
        }
        "ExecuteProposal" => {
            let action: GovernanceProposalAction =
                serde_json::from_value(payload["action"].clone())?;
            let proposal = ledger
                .governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| Error::msg("governance proposal is missing"))?;
            if proposal.status != GovernanceProposalStatus::Passed
                || executed_at < proposal.execute_after
                || proposal.action != action
            {
                return Err(Error::msg("proposal cannot execute this action"));
            }
            apply_governance_proposal_action(ledger, &action, executed_at)?;
            let proposal = ledger.governance.proposals.get_mut(&proposal_id).unwrap();
            proposal.status = GovernanceProposalStatus::Executed;
            proposal.executed_at = Some(executed_at);
            if let GovernanceProposalAction::TreasurySpend {
                recipient,
                amount,
                reference_hash,
            } = action
            {
                ledger.treasury_spends.push(TreasurySpendRecord {
                    proposal_id,
                    operation_id: operation_id_value.to_owned(),
                    recipient: recipient.clone(),
                    amount,
                    reference_hash,
                    executed_at,
                });
                add_history(ledger, &recipient, operation_id_value);
            }
        }
        _ => {
            return Err(Error::msg(format!(
                "unsupported signed governance action {action_name}"
            )));
        }
    }
    Ok(())
}

fn governance_parameter_is_critical(parameter: &str) -> bool {
    matches!(
        parameter,
        "epoch-seconds"
            | "epoch-mint-amount"
            | "reward-immediate-bps"
            | "reward-vesting-seconds"
            | "service-bond-unlock-seconds"
            | "offline-slash-seconds"
            | "warmup-seconds"
            | "validator-weight-bps"
            | "validator-signature-threshold-bps"
            | "governance-bond"
            | "governance-bond-maturity-seconds"
            | "governance-bond-unlock-seconds"
            | "validator-bond"
            | "max-active-validators"
            | "max-validator-rotations"
            | "validator-rotation-interval-epochs"
            | "consensus-round-timeout-seconds"
            | "availability-slot-seconds"
            | "availability-verifier-count"
            | "availability-quorum"
            | "availability-audit-rate-bps"
            | "availability-auditor-count"
            | "availability-audit-quorum"
            | "base-fee-per-unit"
            | "fee-min-multiplier-bps"
            | "fee-max-multiplier-bps"
            | "fee-target-units-per-epoch"
            | "fee-max-units-per-block"
            | "fee-adjustment-denominator"
            | "traffic-protocol-fee-bps"
            | "traffic-treasury-share-bps"
    )
}

fn governance_parameter_is_fee_policy(parameter: &str) -> bool {
    FEE_GOVERNANCE_PARAMETERS.contains(&parameter)
}

fn apply_governance_proposal_action(
    ledger: &mut LedgerState,
    action: &GovernanceProposalAction,
    now: i64,
) -> Result<()> {
    match action {
        GovernanceProposalAction::SetParameters {
            changes,
            effective_epoch,
        } => {
            apply_governance_parameter_batch(ledger, changes, *effective_epoch)?;
        }
        GovernanceProposalAction::PauseEmission { reason } => {
            if ledger.governance.emission_paused {
                return Err(Error::msg("node emission is already paused"));
            }
            ledger.governance.emission_paused = true;
            ledger.governance.pause_reason = Some(reason.clone());
            reset_active_heartbeats(ledger, now);
        }
        GovernanceProposalAction::ResumeEmission => {
            if !ledger.governance.emission_paused {
                return Err(Error::msg("node emission is not paused"));
            }
            ledger.governance.emission_paused = false;
            ledger.governance.pause_reason = None;
            reset_active_heartbeats(ledger, now);
        }
        GovernanceProposalAction::TreasurySpend {
            recipient, amount, ..
        } => {
            validate_address(recipient)?;
            validate_treasury_spend_amount(ledger, *amount, now)?;
            ledger.treasury -= *amount;
            let account = ledger.accounts.entry(recipient.clone()).or_default();
            account.balance = account
                .balance
                .checked_add(*amount)
                .ok_or_else(|| Error::msg("treasury recipient balance overflow"))?;
        }
    }
    Ok(())
}

fn validate_treasury_spend_amount(ledger: &LedgerState, amount: u128, now: i64) -> Result<()> {
    let treasury_balance = ledger.treasury;
    if amount == 0 {
        return Err(Error::msg("TreasurySpend amount must be greater than zero"));
    }
    if amount > treasury_balance {
        return Err(Error::msg(
            "TreasurySpend exceeds the available treasury balance",
        ));
    }
    let limit = treasury_balance.saturating_mul(TREASURY_SINGLE_SPEND_BPS) / 10_000;
    if amount > limit {
        return Err(Error::msg(format!(
            "TreasurySpend exceeds the 1% single-proposal limit of {}",
            format_mrk(limit)
        )));
    }
    let ninety_day_spent = treasury_spent_since(ledger, now - 90 * 86_400)?;
    let ninety_day_limit = treasury_balance.saturating_mul(TREASURY_NINETY_DAY_SPEND_BPS) / 10_000;
    if ninety_day_spent.saturating_add(amount) > ninety_day_limit {
        return Err(Error::msg(format!(
            "TreasurySpend exceeds the rolling 90-day 2% limit of {} (already spent {})",
            format_mrk(ninety_day_limit),
            format_mrk(ninety_day_spent)
        )));
    }
    let annual_spent = treasury_spent_since(ledger, now - 365 * 86_400)?;
    let annual_limit = treasury_balance.saturating_mul(TREASURY_ANNUAL_SPEND_BPS) / 10_000;
    if annual_spent.saturating_add(amount) > annual_limit {
        return Err(Error::msg(format!(
            "TreasurySpend exceeds the rolling 365-day 5% limit of {} (already spent {})",
            format_mrk(annual_limit),
            format_mrk(annual_spent)
        )));
    }
    Ok(())
}

fn treasury_spent_since(ledger: &LedgerState, since: i64) -> Result<u128> {
    ledger
        .treasury_spends
        .iter()
        .filter(|spend| spend.executed_at > since)
        .try_fold(0_u128, |total, spend| total.checked_add(spend.amount))
        .ok_or_else(|| Error::msg("treasury rolling spend calculation overflow"))
}

fn validate_treasury_reference_hash(reference_hash: &str) -> Result<()> {
    let Some(digest) = reference_hash.strip_prefix("sha256:") else {
        return Err(Error::msg(
            "treasury reference must use the form sha256:<64 lowercase hex characters>",
        ));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::msg(
            "treasury reference must use the form sha256:<64 lowercase hex characters>",
        ));
    }
    Ok(())
}

fn cancel_governance_proposals_below_threshold(ledger: &mut LedgerState, now: i64) {
    let eligible_count = governance_eligible_node_ids(ledger, now).len();
    let cancellable = ledger
        .governance
        .proposals
        .iter()
        .filter_map(|(proposal_id, proposal)| {
            (matches!(
                proposal.status,
                GovernanceProposalStatus::Voting | GovernanceProposalStatus::Passed
            ) && eligible_count < governance_proposal_node_threshold(&proposal.kind))
            .then_some(*proposal_id)
        })
        .collect::<Vec<_>>();
    for proposal_id in cancellable {
        let proposal = ledger
            .governance
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal");
        proposal.status = GovernanceProposalStatus::Cancelled;
        proposal.finalized_at = Some(now);
        let refund = proposal.proposal_bond;
        proposal.proposal_bond = 0;
        ledger
            .accounts
            .entry(proposal.proposer_reward_address.clone())
            .or_default()
            .balance += refund;
    }
}

pub fn governance_status(paths: &DataPaths, now: i64) -> Result<GovernanceStatusView> {
    let ledger = paths.read_ledger()?;
    let genesis = ledger
        .genesis_authority
        .clone()
        .or_else(|| legacy_genesis_authority(&ledger));
    let eligible = governance_eligible_node_ids(&ledger, now);
    let direct = eligible.len() < NODE1_DIRECT_GOVERNANCE_END_THRESHOLD;
    let current_epoch_ends_at = ledger
        .epoch_started_at
        .checked_add(ledger.epoch_seconds_snapshot)
        .ok_or_else(|| Error::msg("Epoch boundary overflow"))?;
    let availability_mode = epoch_context(&ledger, ledger.epoch_number)?.availability_mode;
    let parameters = governance_parameter_views(&ledger);
    Ok(GovernanceStatusView {
        mode: if eligible.len() < GOVERNANCE_NODE_THRESHOLD {
            "NODE1_DIRECT".to_owned()
        } else if direct {
            "HYBRID".to_owned()
        } else {
            "NODE_VOTING".to_owned()
        },
        threshold: GOVERNANCE_NODE_THRESHOLD,
        critical_threshold: CRITICAL_GOVERNANCE_NODE_THRESHOLD,
        node1_direct_end_threshold: NODE1_DIRECT_GOVERNANCE_END_THRESHOLD,
        governance_eligible_count: eligible.len(),
        governance_eligible_node_ids: eligible,
        genesis_node_id: genesis.as_ref().map(|authority| authority.node_id),
        genesis_owner_address: genesis.map(|authority| authority.owner_address),
        node1_direct_actions_enabled: direct,
        emission_paused: ledger.governance.emission_paused,
        pause_reason: ledger.governance.pause_reason.clone(),
        current_epoch_number: ledger.epoch_number,
        current_epoch_started_at: ledger.epoch_started_at,
        current_epoch_ends_at,
        current_epoch_seconds: ledger.epoch_seconds_snapshot,
        current_epoch_mint_amount: ledger.epoch_mint_amount_snapshot,
        current_epoch_mint_amount_display: format_mrk(ledger.epoch_mint_amount_snapshot),
        current_reward_immediate_bps: ledger.reward_immediate_bps_snapshot,
        current_reward_vesting_seconds: ledger.reward_vesting_seconds_snapshot,
        availability_mode,
        availability_activated_at: ledger.availability_activated_at,
        availability_activated_epoch: ledger.availability_activated_epoch,
        minimum_decentralized_availability_validators: MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        settings: ledger.settings,
        scheduled_parameter_changes: ledger.scheduled_parameter_changes,
        parameters,
        last_action_at: ledger.governance.last_action_at,
    })
}

fn governance_parameter_views(ledger: &LedgerState) -> Vec<GovernanceParameterView> {
    let settings = &ledger.settings;
    let fee = &settings.fee_policy;
    let mut parameters = Vec::with_capacity(37);
    let mut push = |name: &str, category: &str, current_value: String, configured_value: String| {
        let scheduled_changes = ledger
            .scheduled_parameter_changes
            .iter()
            .filter_map(|(effective_epoch, changes)| {
                changes
                    .get(name)
                    .map(|value| ScheduledGovernanceParameterView {
                        effective_epoch: *effective_epoch,
                        value: value.clone(),
                    })
            })
            .collect();
        parameters.push(GovernanceParameterView {
            name: name.to_owned(),
            category: category.to_owned(),
            governance: if governance_parameter_is_critical(name) {
                "CRITICAL"
            } else {
                "STANDARD"
            }
            .to_owned(),
            current_value,
            configured_value,
            scheduled_changes,
        });
    };

    push(
        "epoch-seconds",
        "Emission",
        ledger.epoch_seconds_snapshot.to_string(),
        settings.epoch_seconds.to_string(),
    );
    push(
        "epoch-mint-amount",
        "Emission",
        format_mrk(ledger.epoch_mint_amount_snapshot),
        format_mrk(settings.epoch_mint_amount),
    );
    push(
        "reward-immediate-bps",
        "Emission",
        ledger.reward_immediate_bps_snapshot.to_string(),
        settings.reward_immediate_bps.to_string(),
    );
    push(
        "reward-vesting-seconds",
        "Emission",
        ledger.reward_vesting_seconds_snapshot.to_string(),
        settings.reward_vesting_seconds.to_string(),
    );
    push(
        "validator-weight-bps",
        "Emission",
        settings.validator_weight_bps.to_string(),
        settings.validator_weight_bps.to_string(),
    );
    push(
        "validator-signature-threshold-bps",
        "Emission",
        settings.validator_signature_threshold_bps.to_string(),
        settings.validator_signature_threshold_bps.to_string(),
    );
    push(
        "service-bond",
        "Node lifecycle",
        format_mrk(settings.required_service_bond),
        format_mrk(settings.required_service_bond),
    );
    push(
        "service-bond-unlock-seconds",
        "Node lifecycle",
        settings.service_bond_unlock_seconds.to_string(),
        settings.service_bond_unlock_seconds.to_string(),
    );
    push(
        "offline-slash-seconds",
        "Node lifecycle",
        settings.offline_slash_seconds.to_string(),
        settings.offline_slash_seconds.to_string(),
    );
    push(
        "warmup-seconds",
        "Node lifecycle",
        settings.warmup_seconds.to_string(),
        settings.warmup_seconds.to_string(),
    );
    push(
        "heartbeat-grace-seconds",
        "Node lifecycle",
        settings.heartbeat_grace_seconds.to_string(),
        settings.heartbeat_grace_seconds.to_string(),
    );
    push(
        "ip-reuse-cooldown-seconds",
        "Node lifecycle",
        settings.ip_reuse_cooldown_seconds.to_string(),
        settings.ip_reuse_cooldown_seconds.to_string(),
    );
    push(
        "probe-validity-seconds",
        "Availability",
        settings.probe_validity_seconds.to_string(),
        settings.probe_validity_seconds.to_string(),
    );
    push(
        "availability-slot-seconds",
        "Availability",
        settings.availability_slot_seconds.to_string(),
        settings.availability_slot_seconds.to_string(),
    );
    push(
        "availability-verifier-count",
        "Availability",
        settings.availability_verifier_count.to_string(),
        settings.availability_verifier_count.to_string(),
    );
    push(
        "availability-quorum",
        "Availability",
        settings.availability_quorum.to_string(),
        settings.availability_quorum.to_string(),
    );
    push(
        "availability-audit-rate-bps",
        "Availability",
        settings.availability_audit_rate_bps.to_string(),
        settings.availability_audit_rate_bps.to_string(),
    );
    push(
        "availability-auditor-count",
        "Availability",
        settings.availability_auditor_count.to_string(),
        settings.availability_auditor_count.to_string(),
    );
    push(
        "availability-audit-quorum",
        "Availability",
        settings.availability_audit_quorum.to_string(),
        settings.availability_audit_quorum.to_string(),
    );
    push(
        "governance-min-service-seconds",
        "Governance",
        settings.governance_min_service_seconds.to_string(),
        settings.governance_min_service_seconds.to_string(),
    );
    push(
        "governance-bond",
        "Governance",
        format_mrk(settings.required_governance_bond),
        format_mrk(settings.required_governance_bond),
    );
    push(
        "governance-bond-maturity-seconds",
        "Governance",
        settings.governance_bond_maturity_seconds.to_string(),
        settings.governance_bond_maturity_seconds.to_string(),
    );
    push(
        "governance-bond-unlock-seconds",
        "Governance",
        settings.governance_bond_unlock_seconds.to_string(),
        settings.governance_bond_unlock_seconds.to_string(),
    );
    push(
        "block-interval-seconds",
        "Consensus",
        settings.block_interval_seconds.to_string(),
        settings.block_interval_seconds.to_string(),
    );
    push(
        "validator-bond",
        "Consensus",
        format_mrk(settings.validator_bond),
        format_mrk(settings.validator_bond),
    );
    push(
        "max-active-validators",
        "Consensus",
        settings.max_active_validators.to_string(),
        settings.max_active_validators.to_string(),
    );
    push(
        "max-validator-rotations",
        "Consensus",
        settings.max_validator_rotations.to_string(),
        settings.max_validator_rotations.to_string(),
    );
    push(
        "validator-rotation-interval-epochs",
        "Consensus",
        settings.validator_rotation_interval_epochs.to_string(),
        settings.validator_rotation_interval_epochs.to_string(),
    );
    push(
        "consensus-round-timeout-seconds",
        "Consensus",
        settings.consensus_round_timeout_seconds.to_string(),
        settings.consensus_round_timeout_seconds.to_string(),
    );
    push(
        "base-fee-per-unit",
        "Fees",
        format_mrk(fee.base_fee_per_unit),
        format_mrk(fee.base_fee_per_unit),
    );
    push(
        "fee-min-multiplier-bps",
        "Fees",
        fee.min_multiplier_bps.to_string(),
        fee.min_multiplier_bps.to_string(),
    );
    push(
        "fee-max-multiplier-bps",
        "Fees",
        fee.max_multiplier_bps.to_string(),
        fee.max_multiplier_bps.to_string(),
    );
    push(
        "fee-target-units-per-epoch",
        "Fees",
        fee.target_units_per_epoch.to_string(),
        fee.target_units_per_epoch.to_string(),
    );
    push(
        "fee-max-units-per-block",
        "Fees",
        fee.max_units_per_block.to_string(),
        fee.max_units_per_block.to_string(),
    );
    push(
        "fee-adjustment-denominator",
        "Fees",
        fee.adjustment_denominator.to_string(),
        fee.adjustment_denominator.to_string(),
    );
    push(
        "traffic-protocol-fee-bps",
        "Fees",
        fee.traffic_protocol_fee_bps.to_string(),
        fee.traffic_protocol_fee_bps.to_string(),
    );
    push(
        "traffic-treasury-share-bps",
        "Fees",
        fee.traffic_treasury_share_bps.to_string(),
        fee.traffic_treasury_share_bps.to_string(),
    );
    parameters
}

pub fn governance_set_parameter(
    paths: &DataPaths,
    name: &str,
    password: &str,
    parameter: &str,
    value: &str,
    now: i64,
) -> Result<GovernanceReceipt> {
    governance_set_parameters(
        paths,
        name,
        password,
        BTreeMap::from([(parameter.to_owned(), value.to_owned())]),
        now,
    )
}

pub fn governance_set_parameters(
    paths: &DataPaths,
    name: &str,
    password: &str,
    changes: BTreeMap<String, String>,
    now: i64,
) -> Result<GovernanceReceipt> {
    governance_set_parameters_at_epoch(paths, name, password, changes, None, now)
}

pub fn governance_set_parameters_at_epoch(
    paths: &DataPaths,
    name: &str,
    password: &str,
    changes: BTreeMap<String, String>,
    effective_epoch: Option<u64>,
    now: i64,
) -> Result<GovernanceReceipt> {
    execute_node1_governance(paths, name, password, "SetParameters", now, move |ledger| {
        let epoch_context_activation =
            apply_governance_parameter_batch(ledger, &changes, effective_epoch)?;
        let mut payload = json!({
            "changes": changes,
            "epoch_context_activation": epoch_context_activation,
        });
        if let Some(effective_epoch) = effective_epoch {
            payload["effective_epoch"] = json!(effective_epoch);
        }
        Ok(payload)
    })
}

pub fn governance_pause_emission(
    paths: &DataPaths,
    name: &str,
    password: &str,
    reason: &str,
    now: i64,
) -> Result<GovernanceReceipt> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 256 {
        return Err(Error::msg(
            "pause reason must contain between 1 and 256 characters",
        ));
    }
    let reason = reason.to_owned();
    execute_node1_governance(paths, name, password, "PauseEmission", now, move |ledger| {
        if ledger.governance.emission_paused {
            return Err(Error::msg("node emission is already paused"));
        }
        ledger.governance.emission_paused = true;
        ledger.governance.pause_reason = Some(reason.clone());
        reset_active_heartbeats(ledger, now);
        Ok(json!({"reason": reason}))
    })
}

pub fn governance_resume_emission(
    paths: &DataPaths,
    name: &str,
    password: &str,
    now: i64,
) -> Result<GovernanceReceipt> {
    execute_node1_governance(
        paths,
        name,
        password,
        "ResumeEmission",
        now,
        move |ledger| {
            if !ledger.governance.emission_paused {
                return Err(Error::msg("node emission is not paused"));
            }
            let previous_reason = ledger.governance.pause_reason.take();
            ledger.governance.emission_paused = false;
            reset_active_heartbeats(ledger, now);
            Ok(json!({"previous_reason": previous_reason}))
        },
    )
}

fn execute_node1_governance(
    paths: &DataPaths,
    name: &str,
    password: &str,
    action: &str,
    now: i64,
    apply: impl FnOnce(&mut LedgerState) -> Result<Value>,
) -> Result<GovernanceReceipt> {
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let genesis = ensure_genesis_authority(ledger)?;
        if node_id != genesis.node_id
            || config.owner_address != genesis.owner_address
            || owner_file.address != genesis.owner_address
            || owner_file.public_key != genesis.owner_public_key
        {
            return Err(Error::msg(
                "only the immutable Genesis Node 1 Owner key may execute direct governance",
            ));
        }
        let eligible_count = governance_eligible_node_ids(ledger, now).len();
        if eligible_count >= NODE1_DIRECT_GOVERNANCE_END_THRESHOLD {
            return Err(Error::msg(format!(
                "Node 1 direct governance is disabled at {eligible_count} Governance-Eligible Nodes; node voting is required"
            )));
        }
        cancel_governance_proposals_below_threshold(ledger, now);
        ensure_account(ledger, &owner_file)?;
        let payload = apply(ledger)?;
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "Governance",
            action,
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload.clone(),
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &genesis.owner_public_key)?;
        finalize_operation(ledger, &signed, &operation_id, now)?;
        ledger.governance.last_action_at = Some(now);
        ledger.governance.actions.push(GovernanceActionRecord {
            operation_id: operation_id.clone(),
            action: action.to_owned(),
            signer_node_id: node_id,
            executed_at: now,
            payload: payload.clone(),
        });
        Ok(GovernanceReceipt {
            operation_id,
            status: OperationStatus::Pending,
            action: action.to_owned(),
            signer_node_id: node_id,
            executed_at: now,
            payload,
        })
    })
}

fn legacy_genesis_authority(ledger: &LedgerState) -> Option<GenesisAuthority> {
    ledger.nodes.get(&1).map(|node| GenesisAuthority {
        node_id: 1,
        owner_address: node.owner_address.clone(),
        owner_public_key: node.owner_public_key.clone(),
        established_at: node.registered_at,
    })
}

fn ensure_genesis_authority(ledger: &mut LedgerState) -> Result<GenesisAuthority> {
    let authority = ledger
        .genesis_authority
        .clone()
        .or_else(|| legacy_genesis_authority(ledger))
        .ok_or_else(|| Error::msg("Genesis Node 1 has not been registered"))?;
    if authority.node_id != 1 {
        return Err(Error::msg("Genesis authority must reference Node ID 1"));
    }
    let node = ledger
        .nodes
        .get(&1)
        .ok_or_else(|| Error::msg("Genesis Node 1 is missing from the registry"))?;
    if node.owner_address != authority.owner_address
        || node.owner_public_key != authority.owner_public_key
    {
        return Err(Error::msg(
            "Genesis Node 1 authority does not match the registry",
        ));
    }
    ledger.genesis_authority = Some(authority.clone());
    Ok(authority)
}

fn governance_eligible_node_ids(ledger: &LedgerState, now: i64) -> Vec<u64> {
    ledger
        .nodes
        .keys()
        .filter_map(|node_id| {
            governance_node_is_eligible(ledger, *node_id, now).then_some(*node_id)
        })
        .collect()
}

fn governance_bond_matures_at(node: &NodeRecord, settings: &LedgerSettings) -> Option<i64> {
    node.governance_bonded_at?
        .checked_add(settings.governance_bond_maturity_seconds)
}

fn governance_bond_is_mature(node: &NodeRecord, settings: &LedgerSettings, now: i64) -> bool {
    if settings.required_governance_bond == 0 {
        return true;
    }
    node.governance_bond >= settings.required_governance_bond
        && node.governance_exit_requested_at.is_none()
        && governance_bond_matures_at(node, settings).is_some_and(|matures_at| now >= matures_at)
}

fn governance_node_is_eligible(ledger: &LedgerState, node_id: u64, now: i64) -> bool {
    let Some(node) = ledger.nodes.get(&node_id) else {
        return false;
    };
    let probe_fresh = node.last_probe_success.is_some_and(|timestamp| {
        timestamp <= now && now.saturating_sub(timestamp) <= ledger.settings.probe_validity_seconds
    });
    matches!(node.status, NodeStatus::Active)
        && node_owns_ip_slot_at(ledger, node_id, now)
        && node.service_bond >= ledger.settings.required_service_bond
        && node.total_eligible_seconds >= ledger.settings.governance_min_service_seconds
        && governance_bond_is_mature(node, &ledger.settings, now)
        && probe_fresh
}

fn reset_active_heartbeats(ledger: &mut LedgerState, now: i64) {
    for node in ledger.nodes.values_mut() {
        if matches!(node.status, NodeStatus::Active) {
            node.last_heartbeat = Some(now);
        }
    }
}

fn set_governance_parameter_value(
    settings: &mut LedgerSettings,
    parameter: &str,
    value: &str,
) -> Result<(String, String)> {
    fn integer(value: &str, parameter: &str, min: u64, max: u64) -> Result<u64> {
        let parsed = value
            .parse::<u64>()
            .map_err(|_| Error::msg(format!("{parameter} must be an unsigned integer")))?;
        if !(min..=max).contains(&parsed) {
            return Err(Error::msg(format!(
                "{parameter} must be between {min} and {max}"
            )));
        }
        Ok(parsed)
    }
    let result = match parameter {
        "epoch-seconds" => {
            let parsed = integer(value, parameter, 60, 31_536_000)? as i64;
            let old = settings.epoch_seconds;
            settings.epoch_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "epoch-mint-amount" => {
            let parsed = parse_mrk(value)?;
            if parsed == 0 || parsed > MAX_SUPPLY {
                return Err(Error::msg(
                    "epoch-mint-amount must be greater than zero and no more than MAX_SUPPLY",
                ));
            }
            let old = settings.epoch_mint_amount;
            settings.epoch_mint_amount = parsed;
            (format_mrk(old), format_mrk(parsed))
        }
        "reward-immediate-bps" => {
            let parsed = integer(value, parameter, 0, 10_000)? as u32;
            let old = settings.reward_immediate_bps;
            settings.reward_immediate_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "reward-vesting-seconds" => {
            let parsed = integer(value, parameter, 1, 10 * 365 * 86_400)? as i64;
            let old = settings.reward_vesting_seconds;
            settings.reward_vesting_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "validator-weight-bps" => {
            let parsed = integer(value, parameter, 10_000, 20_000)? as u32;
            let old = settings.validator_weight_bps;
            settings.validator_weight_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "validator-signature-threshold-bps" => {
            let parsed = integer(value, parameter, 5_000, 10_000)? as u32;
            let old = settings.validator_signature_threshold_bps;
            settings.validator_signature_threshold_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "service-bond" => {
            let parsed = parse_mrk(value)?;
            if parsed > MAX_SUPPLY {
                return Err(Error::msg("service-bond must not exceed MAX_SUPPLY"));
            }
            let old = settings.required_service_bond;
            settings.required_service_bond = parsed;
            (format_mrk(old), format_mrk(parsed))
        }
        "service-bond-unlock-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)? as i64;
            let old = settings.service_bond_unlock_seconds;
            settings.service_bond_unlock_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "offline-slash-seconds" => {
            let parsed = integer(value, parameter, 3_600, 365 * 86_400)? as i64;
            let old = settings.offline_slash_seconds;
            settings.offline_slash_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "warmup-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)? as i64;
            let old = settings.warmup_seconds;
            settings.warmup_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "heartbeat-grace-seconds" => {
            let parsed = integer(value, parameter, 10, 3_600)? as i64;
            let old = settings.heartbeat_grace_seconds;
            settings.heartbeat_grace_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "probe-validity-seconds" => {
            let parsed = integer(value, parameter, 30, 3_600)? as i64;
            let old = settings.probe_validity_seconds;
            settings.probe_validity_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-slot-seconds" => {
            let parsed = integer(value, parameter, 60, 300)? as i64;
            let old = settings.availability_slot_seconds;
            settings.availability_slot_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-verifier-count" => {
            let parsed = integer(value, parameter, 3, 30)? as u32;
            let old = settings.availability_verifier_count;
            settings.availability_verifier_count = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-quorum" => {
            let parsed = integer(value, parameter, 2, 21)? as u32;
            let old = settings.availability_quorum;
            settings.availability_quorum = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-audit-rate-bps" => {
            let parsed = integer(value, parameter, 0, 10_000)? as u32;
            let old = settings.availability_audit_rate_bps;
            settings.availability_audit_rate_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-auditor-count" => {
            let parsed = integer(value, parameter, 1, 10)? as u32;
            let old = settings.availability_auditor_count;
            settings.availability_auditor_count = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-audit-quorum" => {
            let parsed = integer(value, parameter, 1, 7)? as u32;
            let old = settings.availability_audit_quorum;
            settings.availability_audit_quorum = parsed;
            (old.to_string(), parsed.to_string())
        }
        "ip-reuse-cooldown-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)? as i64;
            let old = settings.ip_reuse_cooldown_seconds;
            settings.ip_reuse_cooldown_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "governance-min-service-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)?;
            let old = settings.governance_min_service_seconds;
            settings.governance_min_service_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "governance-bond" => {
            let parsed = parse_mrk(value)?;
            if parsed == 0 || parsed > MAX_SUPPLY {
                return Err(Error::msg(
                    "governance-bond must be greater than zero and no more than MAX_SUPPLY",
                ));
            }
            let old = settings.required_governance_bond;
            settings.required_governance_bond = parsed;
            (format_mrk(old), format_mrk(parsed))
        }
        "governance-bond-maturity-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)? as i64;
            let old = settings.governance_bond_maturity_seconds;
            settings.governance_bond_maturity_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "governance-bond-unlock-seconds" => {
            let parsed = integer(value, parameter, 0, 365 * 86_400)? as i64;
            let old = settings.governance_bond_unlock_seconds;
            settings.governance_bond_unlock_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "block-interval-seconds" => {
            let parsed = integer(value, parameter, 1, 300)? as i64;
            let old = settings.block_interval_seconds;
            settings.block_interval_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "validator-bond" => {
            let parsed = parse_mrk(value)?;
            if parsed == 0 || parsed > MAX_SUPPLY {
                return Err(Error::msg(
                    "validator-bond must be greater than zero and no more than MAX_SUPPLY",
                ));
            }
            let old = settings.validator_bond;
            settings.validator_bond = parsed;
            (format_mrk(old), format_mrk(parsed))
        }
        "max-active-validators" => {
            let parsed = integer(value, parameter, 7, 31)? as u32;
            let old = settings.max_active_validators;
            settings.max_active_validators = parsed;
            (old.to_string(), parsed.to_string())
        }
        "max-validator-rotations" => {
            let parsed = integer(value, parameter, 1, 10)? as u32;
            let old = settings.max_validator_rotations;
            settings.max_validator_rotations = parsed;
            (old.to_string(), parsed.to_string())
        }
        "validator-rotation-interval-epochs" => {
            let parsed = integer(value, parameter, 1, 10_000)? as u32;
            let old = settings.validator_rotation_interval_epochs;
            settings.validator_rotation_interval_epochs = parsed;
            (old.to_string(), parsed.to_string())
        }
        "consensus-round-timeout-seconds" => {
            let parsed = integer(value, parameter, 5, 30)? as i64;
            let old = settings.consensus_round_timeout_seconds;
            settings.consensus_round_timeout_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "base-fee-per-unit" => {
            let parsed = parse_mrk(value)?;
            if !(fee::MIN_BASE_FEE_PER_UNIT..=fee::MAX_BASE_FEE_PER_UNIT).contains(&parsed) {
                return Err(Error::msg(
                    "base-fee-per-unit must be between 0.0001 MRK and 0.1 MRK",
                ));
            }
            let old = settings.fee_policy.base_fee_per_unit;
            settings.fee_policy.base_fee_per_unit = parsed;
            (format_mrk(old), format_mrk(parsed))
        }
        "fee-min-multiplier-bps" => {
            let parsed = integer(value, parameter, 100, 10_000)? as u32;
            let old = settings.fee_policy.min_multiplier_bps;
            settings.fee_policy.min_multiplier_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "fee-max-multiplier-bps" => {
            let parsed = integer(value, parameter, 10_000, 100_000)? as u32;
            let old = settings.fee_policy.max_multiplier_bps;
            settings.fee_policy.max_multiplier_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "fee-target-units-per-epoch" => {
            let parsed = integer(value, parameter, 1, 1_000_000_000_000)?;
            let old = settings.fee_policy.target_units_per_epoch;
            settings.fee_policy.target_units_per_epoch = parsed;
            (old.to_string(), parsed.to_string())
        }
        "fee-max-units-per-block" => {
            let parsed = integer(value, parameter, 1_000, 1_000_000_000)?;
            let old = settings.fee_policy.max_units_per_block;
            settings.fee_policy.max_units_per_block = parsed;
            (old.to_string(), parsed.to_string())
        }
        "fee-adjustment-denominator" => {
            let parsed = integer(value, parameter, 8, 1_000)? as u32;
            let old = settings.fee_policy.adjustment_denominator;
            settings.fee_policy.adjustment_denominator = parsed;
            (old.to_string(), parsed.to_string())
        }
        "traffic-protocol-fee-bps" => {
            let parsed = integer(value, parameter, 0, 500)? as u32;
            let old = settings.fee_policy.traffic_protocol_fee_bps;
            settings.fee_policy.traffic_protocol_fee_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        "traffic-treasury-share-bps" => {
            let parsed = integer(value, parameter, 0, 10_000)? as u32;
            let old = settings.fee_policy.traffic_treasury_share_bps;
            settings.fee_policy.traffic_treasury_share_bps = parsed;
            (old.to_string(), parsed.to_string())
        }
        _ => {
            return Err(Error::msg(format!(
                "unsupported governance parameter '{parameter}'"
            )));
        }
    };
    Ok(result)
}

fn validate_governance_settings(settings: &LedgerSettings) -> Result<()> {
    if settings.epoch_seconds < settings.availability_slot_seconds
        || settings.epoch_seconds % settings.availability_slot_seconds != 0
    {
        return Err(Error::msg(
            "epoch-seconds must be a multiple of availability-slot-seconds",
        ));
    }
    if settings.probe_validity_seconds < settings.availability_slot_seconds {
        return Err(Error::msg(
            "probe-validity-seconds cannot be shorter than availability-slot-seconds",
        ));
    }
    if settings.availability_quorum > settings.availability_verifier_count {
        return Err(Error::msg(
            "availability-quorum cannot exceed availability-verifier-count",
        ));
    }
    if settings.availability_audit_quorum > settings.availability_auditor_count {
        return Err(Error::msg(
            "availability-audit-quorum cannot exceed availability-auditor-count",
        ));
    }
    if settings.max_validator_rotations > settings.max_active_validators / 3 {
        return Err(Error::msg(
            "max-validator-rotations cannot replace more than one-third of the committee",
        ));
    }
    if settings.fee_policy.min_multiplier_bps > settings.fee_policy.max_multiplier_bps {
        return Err(Error::msg(
            "fee-min-multiplier-bps cannot exceed fee-max-multiplier-bps",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn set_governance_parameter(
    settings: &mut LedgerSettings,
    parameter: &str,
    value: &str,
) -> Result<(String, String)> {
    let mut candidate = settings.clone();
    let result = set_governance_parameter_value(&mut candidate, parameter, value)?;
    validate_governance_settings(&candidate)?;
    *settings = candidate;
    Ok(result)
}

fn apply_governance_parameter_changes(
    settings: &LedgerSettings,
    changes: &BTreeMap<String, String>,
) -> Result<LedgerSettings> {
    if changes.is_empty() {
        return Err(Error::msg("parameter changes cannot be empty"));
    }
    let mut candidate = settings.clone();
    for (parameter, value) in changes {
        set_governance_parameter_value(&mut candidate, parameter, value)?;
    }
    if candidate.fee_policy != settings.fee_policy {
        let old_base = settings.fee_policy.base_fee_per_unit;
        let new_base = candidate.fee_policy.base_fee_per_unit;
        if new_base > old_base.saturating_mul(2) || new_base.saturating_mul(2) < old_base {
            return Err(Error::msg(
                "base-fee-per-unit may change by at most 2x or 50% per policy update",
            ));
        }
        candidate.fee_policy.version = settings
            .fee_policy
            .version
            .checked_add(1)
            .ok_or_else(|| Error::msg("fee policy version overflow"))?;
    }
    validate_governance_settings(&candidate)?;
    Ok(candidate)
}

fn validate_scheduled_governance_parameter_changes(
    mut settings: LedgerSettings,
    scheduled_changes: &BTreeMap<u64, BTreeMap<String, String>>,
    current_epoch: u64,
) -> Result<()> {
    for (epoch, changes) in scheduled_changes {
        if *epoch <= current_epoch {
            return Err(Error::msg(format!(
                "scheduled governance parameter epoch {epoch} is not after current epoch {current_epoch}"
            )));
        }
        settings = apply_governance_parameter_changes(&settings, changes)?;
    }
    Ok(())
}

fn validated_governance_parameter_schedule(
    ledger: &LedgerState,
    changes: &BTreeMap<String, String>,
    effective_epoch: Option<u64>,
) -> Result<(LedgerSettings, GovernanceParameterSchedule, u64)> {
    if changes.is_empty() {
        return Err(Error::msg("parameter changes cannot be empty"));
    }
    let changes_fee_policy = changes
        .keys()
        .any(|parameter| governance_parameter_is_fee_policy(parameter));
    if changes_fee_policy {
        if FEE_GOVERNANCE_PARAMETERS
            .iter()
            .any(|parameter| !changes.contains_key(*parameter))
        {
            return Err(Error::msg(
                "fee policy changes must provide the complete atomic fee parameter set",
            ));
        }
        let effective_epoch = effective_epoch.ok_or_else(|| {
            Error::msg("fee policy changes require an explicit future effective Epoch")
        })?;
        let earliest = ledger.epoch_number.saturating_add(2);
        if effective_epoch < earliest {
            return Err(Error::msg(format!(
                "fee policy changes cannot activate before Epoch {earliest}"
            )));
        }
    }
    let activate_at_epoch =
        effective_epoch.unwrap_or_else(|| ledger.epoch_number.saturating_add(1));
    let mut settings = ledger.settings.clone();
    let mut scheduled_changes = ledger.scheduled_parameter_changes.clone();
    if let Some(effective_epoch) = effective_epoch {
        if effective_epoch <= ledger.epoch_number {
            return Err(Error::msg(format!(
                "effective epoch must be greater than current epoch {}",
                ledger.epoch_number
            )));
        }
        scheduled_changes
            .entry(effective_epoch)
            .or_default()
            .extend(changes.clone());
    } else {
        settings = apply_governance_parameter_changes(&settings, changes)?;
    }
    validate_scheduled_governance_parameter_changes(
        settings.clone(),
        &scheduled_changes,
        ledger.epoch_number,
    )?;
    Ok((settings, scheduled_changes, activate_at_epoch))
}

fn validate_governance_parameter_batch(
    ledger: &LedgerState,
    changes: &BTreeMap<String, String>,
    effective_epoch: Option<u64>,
) -> Result<u64> {
    validated_governance_parameter_schedule(ledger, changes, effective_epoch)
        .map(|(_, _, activate_at_epoch)| activate_at_epoch)
}

fn apply_governance_parameter_batch(
    ledger: &mut LedgerState,
    changes: &BTreeMap<String, String>,
    effective_epoch: Option<u64>,
) -> Result<u64> {
    let (settings, scheduled_changes, activate_at_epoch) =
        validated_governance_parameter_schedule(ledger, changes, effective_epoch)?;
    ledger.settings = settings;
    ledger.scheduled_parameter_changes = scheduled_changes;
    Ok(activate_at_epoch)
}

fn ensure_account(ledger: &mut LedgerState, keyfile: &EncryptedKeyFile) -> Result<()> {
    let account = ledger.accounts.entry(keyfile.address.clone()).or_default();
    if let Some(existing) = &account.public_key {
        if existing != &keyfile.public_key {
            return Err(Error::Crypto("account public key mismatch"));
        }
    } else {
        account.public_key = Some(keyfile.public_key.clone());
    }
    Ok(())
}

fn finalize_operation(
    ledger: &mut LedgerState,
    operation: &SignedOperation,
    operation_id: &str,
    now: i64,
) -> Result<()> {
    reset_multi_validator_consensus_if_node1_mode(ledger, now);
    cancel_governance_proposals_below_threshold(ledger, now);
    if ledger.consensus.proposal.is_some() || ledger.consensus.valid_proposal.is_some() {
        return Err(Error::msg(
            "a consensus proposal is in progress; retry the operation after finality or a round change",
        ));
    }
    if ledger.pending_operation_ids.len() >= MAX_BLOCK_OPERATIONS {
        return Err(Error::msg(format!(
            "pending operation queue reached the {MAX_BLOCK_OPERATIONS} operation block limit"
        )));
    }
    let fee_charge = charge_operation_fee(ledger, operation)?;
    let account = ledger
        .accounts
        .get_mut(&operation.unsigned.signer)
        .ok_or_else(|| Error::msg("operation signer account does not exist"))?;
    if operation.unsigned.account_nonce != account.nonce + 1 {
        return Err(Error::msg("operation nonce is not the next account nonce"));
    }
    account.nonce = operation.unsigned.account_nonce;
    account.operation_ids.push(operation_id.to_owned());
    ledger.operations.insert(
        operation_id.to_owned(),
        OperationRecord {
            operation_id: operation_id.to_owned(),
            kind: format!(
                "{}.{}",
                operation.unsigned.module, operation.unsigned.action
            ),
            signer: operation.unsigned.signer.clone(),
            nonce: operation.unsigned.account_nonce,
            created_at: operation
                .unsigned
                .valid_until
                .saturating_sub(DEFAULT_OPERATION_VALIDITY_SECONDS),
            status: OperationStatus::Pending,
            error: None,
            payload: operation.unsigned.payload.clone(),
            signature: operation.signature.clone(),
            block_height: None,
            signed_operation: Some(operation.clone()),
            fee_payer: fee_charge.payer,
            fee_charged: fee_charge.charged,
            fee_burned: fee_charge.burned,
            fee_to_treasury: 0,
        },
    );
    ledger.pending_operation_ids.push(operation_id.to_owned());
    sort_pending_operation_ids(ledger);
    Ok(())
}

#[derive(Default)]
struct OperationFeeCharge {
    payer: Option<String>,
    charged: u128,
    burned: u128,
}

enum OperationFeePayer {
    Account(String),
    NetworkEscrow(String),
}

fn operation_fee_payer(
    ledger: &LedgerState,
    operation: &SignedOperation,
) -> Result<OperationFeePayer> {
    let payload = &operation.unsigned.payload;
    let node_reward_address = |node_id: u64| {
        ledger
            .nodes
            .get(&node_id)
            .map(|node| node.reward_address.clone())
            .ok_or_else(|| Error::msg("fee-paying Node is missing"))
    };
    match (
        operation.unsigned.module.as_str(),
        operation.unsigned.action.as_str(),
    ) {
        ("TrafficPayment", "ReserveSession") => Ok(OperationFeePayer::NetworkEscrow(
            payload_network_commitment(ledger, payload)?,
        )),
        ("NodeRegistry", "RegisterNode") => payload
            .get("reward_address")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .map(OperationFeePayer::Account)
            .ok_or_else(|| Error::msg("registration fee payer is invalid")),
        ("NodeRegistry" | "NodeEmissionController" | "StakeVault", _) => node_reward_address(
            payload
                .get("node_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::msg("fee-paying Node ID is invalid"))?,
        )
        .map(OperationFeePayer::Account),
        _ => Ok(OperationFeePayer::Account(
            operation.unsigned.signer.clone(),
        )),
    }
}

fn pending_fee_units(ledger: &LedgerState) -> u64 {
    ledger
        .pending_operation_ids
        .iter()
        .filter_map(|operation_id| ledger.operations.get(operation_id))
        .filter_map(|record| record.signed_operation.as_ref())
        .map(|operation| {
            fee::operation_fee_units(
                &operation.unsigned.module,
                &operation.unsigned.action,
                &operation.unsigned.payload,
            )
        })
        .fold(0_u64, u64::saturating_add)
}

fn ensure_operation_fee_payable(
    ledger: &LedgerState,
    operation: &SignedOperation,
    fee: u128,
) -> Result<()> {
    if fee == 0 {
        return Ok(());
    }
    let available = match operation_fee_payer(ledger, operation)? {
        OperationFeePayer::Account(address) => ledger
            .accounts
            .get(&address)
            .map_or(0, |account| account.balance),
        OperationFeePayer::NetworkEscrow(commitment) => ledger
            .networks
            .get(&commitment)
            .map_or(0, |network| network.escrow_balance),
    };
    if available < fee {
        return Err(Error::msg(format!(
            "insufficient MRK for operation fee: available {}, required {}",
            format_mrk(available),
            format_mrk(fee)
        )));
    }
    Ok(())
}

fn charge_operation_fee(
    ledger: &mut LedgerState,
    operation: &SignedOperation,
) -> Result<OperationFeeCharge> {
    let quote = fee::validate_envelope(ledger, &operation.unsigned)?;
    let block_units = pending_fee_units(ledger)
        .checked_add(quote.units)
        .ok_or_else(|| Error::msg("pending operation fee units overflow"))?;
    if block_units > ledger.settings.fee_policy.max_units_per_block {
        return Err(Error::msg(format!(
            "pending operation fee units exceed the per-block limit of {}",
            ledger.settings.fee_policy.max_units_per_block
        )));
    }
    if quote.fee == 0 {
        return Ok(OperationFeeCharge::default());
    }
    let payer = operation_fee_payer(ledger, operation)?;
    let payer_label = match payer {
        OperationFeePayer::Account(address) => {
            let account = ledger
                .accounts
                .get_mut(&address)
                .ok_or_else(|| Error::msg("operation fee payer account does not exist"))?;
            if account.balance < quote.fee {
                return Err(Error::msg(format!(
                    "insufficient MRK for operation fee: available {}, required {}",
                    format_mrk(account.balance),
                    format_mrk(quote.fee)
                )));
            }
            account.balance -= quote.fee;
            address
        }
        OperationFeePayer::NetworkEscrow(commitment) => {
            let network = ledger
                .networks
                .get_mut(&commitment)
                .ok_or_else(|| Error::msg("operation fee payer Network is missing"))?;
            if network.escrow_balance < quote.fee {
                return Err(Error::msg(format!(
                    "insufficient Network Escrow for operation fee: available {}, required {}",
                    format_mrk(network.escrow_balance),
                    format_mrk(quote.fee)
                )));
            }
            network.escrow_balance -= quote.fee;
            format!("network:{commitment}")
        }
    };
    ledger.burned = ledger
        .burned
        .checked_add(quote.fee)
        .ok_or_else(|| Error::msg("burn counter overflow"))?;
    ledger.fee_units_used_in_epoch = ledger
        .fee_units_used_in_epoch
        .checked_add(quote.units)
        .ok_or_else(|| Error::msg("Epoch fee units overflow"))?;
    Ok(OperationFeeCharge {
        payer: Some(payer_label),
        charged: quote.fee,
        burned: quote.fee,
    })
}

fn resolve_network(ledger: &LedgerState, alias_or_commitment: &str) -> Result<String> {
    if ledger.networks.contains_key(alias_or_commitment) {
        return Ok(alias_or_commitment.to_owned());
    }
    ledger
        .network_aliases
        .get(alias_or_commitment)
        .cloned()
        .ok_or_else(|| Error::msg(format!("network not found: {alias_or_commitment}")))
}

fn parse_wss_endpoint(endpoint: &str) -> Result<Url> {
    let url = normalize_websocket_url(endpoint, RELAY_PATH)?;
    if url.scheme() != "wss" {
        return Err(Error::msg("node endpoint must use wss://"));
    }
    if url.path() != RELAY_PATH {
        return Err(Error::msg(format!(
            "node endpoint path must be {RELAY_PATH}"
        )));
    }
    Ok(url)
}

fn resolve_endpoint_public_ip(endpoint: &str) -> Result<IpAddr> {
    let url = parse_wss_endpoint(endpoint)?;
    let host = url
        .host()
        .ok_or_else(|| Error::msg("node endpoint is missing its host"))?;
    let resolved = match host {
        Host::Ipv4(ip) => IpAddr::V4(ip),
        Host::Ipv6(ip) => IpAddr::V6(ip),
        Host::Domain(domain) => {
            let port = url.port_or_known_default().unwrap_or(443);
            let addresses = (domain, port)
                .to_socket_addrs()
                .map_err(|error| Error::msg(format!("could not resolve endpoint domain: {error}")))?
                .map(|address| address.ip())
                .filter(|ip| is_public_ip(*ip))
                .collect::<BTreeSet<_>>();
            addresses
                .iter()
                .copied()
                .find(IpAddr::is_ipv4)
                .or_else(|| addresses.iter().copied().next())
                .ok_or_else(|| {
                    Error::msg("endpoint domain does not resolve to a public IP address")
                })?
        }
    };
    if !is_public_ip(resolved) {
        return Err(Error::msg(
            "endpoint must resolve to a globally routable public address",
        ));
    }
    Ok(resolved)
}

fn verify_endpoint_ip(endpoint: &str, reward_ip: IpAddr) -> Result<()> {
    let url = parse_wss_endpoint(endpoint)?;
    let host = url
        .host()
        .ok_or_else(|| Error::msg("node endpoint is missing its host"))?;
    let matches = match host {
        Host::Ipv4(ip) => IpAddr::V4(ip) == reward_ip,
        Host::Ipv6(ip) => IpAddr::V6(ip) == reward_ip,
        Host::Domain(domain) => {
            let port = url.port_or_known_default().unwrap_or(443);
            (domain, port)
                .to_socket_addrs()
                .map_err(|error| Error::msg(format!("could not resolve endpoint domain: {error}")))?
                .any(|address| address.ip() == reward_ip)
        }
    };
    if !matches {
        return Err(Error::msg(format!(
            "endpoint no longer resolves to registered public IP {reward_ip}"
        )));
    }
    Ok(())
}

pub fn ip_slot(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("v4:{ip}"),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            format!(
                "v6:{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
        }
    }
}

fn validate_reward_ip_slot(reward_ip: &str, declared_slot: &str) -> Result<String> {
    let reward_ip =
        IpAddr::from_str(reward_ip).map_err(|_| Error::msg("registered reward IP is invalid"))?;
    if !is_public_ip(reward_ip) {
        return Err(Error::msg(
            "registered reward IP must be a globally routable public address",
        ));
    }
    let expected_slot = ip_slot(reward_ip);
    if declared_slot != expected_slot {
        return Err(Error::msg("registered IP slot does not match reward IP"));
    }
    Ok(expected_slot)
}

fn ip_slot_is_available(ledger: &LedgerState, slot_name: &str, at: i64) -> bool {
    ledger.ip_slots.get(slot_name).is_none_or(|slot| {
        slot.released_at.is_some_and(|released_at| {
            at >= released_at
                && at.saturating_sub(released_at) >= ledger.settings.ip_reuse_cooldown_seconds
        })
    })
}

fn bind_ip_slot_if_available(
    ledger: &mut LedgerState,
    slot_name: &str,
    node_id: u64,
    bound_at: i64,
) -> bool {
    if ledger
        .ip_slots
        .get(slot_name)
        .is_some_and(|slot| slot.node_id == node_id && slot.released_at.is_none())
    {
        return true;
    }
    if !ip_slot_is_available(ledger, slot_name, bound_at) {
        return false;
    }
    ledger.ip_slots.insert(
        slot_name.to_owned(),
        IpSlotRecord {
            node_id,
            bound_at,
            released_at: None,
        },
    );
    true
}

fn node_owns_ip_slot_at(ledger: &LedgerState, node_id: u64, observed_at: i64) -> bool {
    let Some(node) = ledger.nodes.get(&node_id) else {
        return false;
    };
    ledger.ip_slots.get(&node.ip_slot).is_some_and(|slot| {
        slot.node_id == node_id && slot.released_at.is_none() && slot.bound_at <= observed_at
    })
}

fn release_node_ip_slot(ledger: &mut LedgerState, node_id: u64, released_at: i64) {
    let Some(slot_name) = ledger.nodes.get(&node_id).map(|node| node.ip_slot.clone()) else {
        return;
    };
    if let Some(slot) = ledger.ip_slots.get_mut(&slot_name)
        && slot.node_id == node_id
        && slot.released_at.is_none()
    {
        slot.released_at = Some(released_at);
    }
}

fn ensure_node_endpoint_available(
    ledger: &LedgerState,
    endpoint: &str,
    current_node_id: Option<u64>,
) -> Result<()> {
    if let Some(node) = ledger.nodes.values().find(|node| {
        Some(node.node_id) != current_node_id
            && node.status != NodeStatus::Exited
            && node.endpoint == endpoint
    }) {
        return Err(Error::msg(format!(
            "WSS endpoint is already registered by Node {}",
            node.node_id
        )));
    }
    Ok(())
}

fn validate_price_per_gib(price_per_gib: u128) -> Result<u128> {
    if price_per_gib > MAX_SUPPLY {
        return Err(Error::msg("price per GiB must not exceed MAX_SUPPLY"));
    }
    Ok(price_per_gib)
}

fn network_median_price_per_gib(ledger: &LedgerState, now: i64) -> u128 {
    let mut prices = ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| {
            (node.status == NodeStatus::Active
                && node_owns_ip_slot_at(ledger, *node_id, now)
                && node.last_probe_success.is_some_and(|probe_at| {
                    probe_at <= now
                        && now.saturating_sub(probe_at) <= ledger.settings.probe_validity_seconds
                }))
            .then_some(node.price_per_gib)
        })
        .collect::<Vec<_>>();
    if prices.is_empty() {
        return DEFAULT_RELAY_PRICE_PER_GIB;
    }
    prices.sort_unstable();
    let midpoint = prices.len() / 2;
    if prices.len() % 2 == 1 {
        prices[midpoint]
    } else {
        let lower = prices[midpoint - 1];
        lower + (prices[midpoint] - lower) / 2
    }
}

fn apply_node_price_update(
    ledger: &mut LedgerState,
    node_id: u64,
    price_per_gib: u128,
) -> Result<()> {
    let price_per_gib = validate_price_per_gib(price_per_gib)?;
    let node = ledger
        .nodes
        .get_mut(&node_id)
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
    if matches!(node.status, NodeStatus::Draining | NodeStatus::Exited) {
        return Err(Error::msg(
            "price cannot be updated while the node is draining or exited",
        ));
    }
    node.price_per_gib = price_per_gib;
    Ok(())
}

fn apply_reward_ip_update(
    ledger: &mut LedgerState,
    node_id: u64,
    endpoint: &str,
    reward_ip: &str,
    declared_slot: &str,
    updated_at: i64,
) -> Result<()> {
    let endpoint = parse_wss_endpoint(endpoint)?.to_string();
    ensure_node_endpoint_available(ledger, &endpoint, Some(node_id))?;
    let new_slot = validate_reward_ip_slot(reward_ip, declared_slot)?;
    let warmup_seconds = if node_id == 1
        && governance_eligible_node_ids(ledger, updated_at).len()
            < NODE1_DIRECT_GOVERNANCE_END_THRESHOLD
    {
        0
    } else {
        ledger.settings.warmup_seconds
    };
    let warmup_until = updated_at
        .checked_add(warmup_seconds)
        .ok_or_else(|| Error::msg("Node reward IP warmup timestamp overflow"))?;
    let (old_slot, status) = ledger
        .nodes
        .get(&node_id)
        .map(|node| (node.ip_slot.clone(), node.status))
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
    if matches!(
        status,
        NodeStatus::Draining | NodeStatus::Exited | NodeStatus::Suspended
    ) {
        return Err(Error::msg(
            "reward IP cannot be updated while the node is draining, exited, or suspended",
        ));
    }

    if old_slot != new_slot {
        release_node_ip_slot(ledger, node_id, updated_at);
    }
    let node = ledger.nodes.get_mut(&node_id).expect("Node exists");
    node.endpoint = endpoint;
    node.reward_ip = reward_ip.to_owned();
    node.ip_slot = new_slot.clone();
    node.status = NodeStatus::WarmingUp;
    node.warmup_until = warmup_until;
    node.active_since = None;
    // Keep the previous finalized proof as the offline-slash clock until the new
    // address obtains its first successful proof. Status still prevents discovery,
    // rewards, governance, and Validator eligibility during warmup.

    let retained_binding = old_slot == new_slot
        && ledger
            .ip_slots
            .get(&new_slot)
            .is_some_and(|slot| slot.node_id == node_id && slot.released_at.is_none());
    if retained_binding {
        ledger.ip_slots.get_mut(&new_slot).unwrap().bound_at = updated_at;
    } else {
        bind_ip_slot_if_available(ledger, &new_slot, node_id, updated_at);
    }
    Ok(())
}

fn finalize_draining_nodes(ledger: &mut LedgerState, finalized_at: i64) -> Result<()> {
    let draining = ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| {
            matches!(node.status, NodeStatus::Draining).then_some(*node_id)
        })
        .collect::<Vec<_>>();
    for node_id in draining {
        let forfeited_reward =
            node_vesting_reward(ledger.nodes.get(&node_id).expect("draining Node exists"))?;
        let service_bond_unlock_at = if ledger.nodes[&node_id].service_bond > 0 {
            Some(
                finalized_at
                    .checked_add(ledger.settings.service_bond_unlock_seconds)
                    .ok_or_else(|| Error::msg("Service Bond unlock timestamp overflow"))?,
            )
        } else {
            None
        };
        ledger.treasury = ledger
            .treasury
            .checked_add(forfeited_reward)
            .ok_or_else(|| Error::msg("Treasury balance overflow"))?;
        release_node_ip_slot(ledger, node_id, finalized_at);
        let node = ledger
            .nodes
            .get_mut(&node_id)
            .expect("draining Node exists");
        node.status = NodeStatus::Exited;
        node.last_heartbeat = None;
        node.reward_vesting_buckets.clear();
        node.service_bond_unlock_at = service_bond_unlock_at;
    }
    Ok(())
}

fn finalize_offline_nodes(ledger: &mut LedgerState, finalized_at: i64) -> Result<()> {
    if ledger.settings.offline_slash_seconds < 0 {
        return Err(Error::msg("offline slash duration cannot be negative"));
    }
    let offline = ledger
        .nodes
        .iter()
        .filter_map(|(node_id, node)| {
            if !matches!(
                node.status,
                NodeStatus::WarmingUp | NodeStatus::Active | NodeStatus::Draining
            ) {
                return None;
            }
            let offline_since = node.last_probe_success.unwrap_or(node.registered_at);
            let slash_at = offline_since.checked_add(ledger.settings.offline_slash_seconds)?;
            (finalized_at >= slash_at).then_some(*node_id)
        })
        .collect::<Vec<_>>();

    if offline.is_empty() {
        return Ok(());
    }
    let offline_set = offline.iter().copied().collect::<BTreeSet<_>>();
    for node_id in offline {
        let node = ledger.nodes.get(&node_id).expect("offline Node exists");
        let slashed_service_bond = node.service_bond;
        let slashed_vesting_reward = node_vesting_reward(node)?;
        let total_slashed = slashed_service_bond
            .checked_add(slashed_vesting_reward)
            .ok_or_else(|| Error::msg("offline slash amount overflow"))?;
        ledger.treasury = ledger
            .treasury
            .checked_add(total_slashed)
            .ok_or_else(|| Error::msg("Treasury balance overflow"))?;
        release_node_ip_slot(ledger, node_id, finalized_at);
        let node = ledger.nodes.get_mut(&node_id).expect("offline Node exists");
        node.status = NodeStatus::Exited;
        node.last_heartbeat = None;
        node.service_bond = 0;
        node.service_bond_unlock_at = None;
        node.reward_vesting_buckets.clear();
        node.offline_slashed_at = Some(finalized_at);
        node.offline_slashed_service_bond = node
            .offline_slashed_service_bond
            .checked_add(slashed_service_bond)
            .ok_or_else(|| Error::msg("slashed Service Bond total overflow"))?;
        node.offline_slashed_vesting_reward = node
            .offline_slashed_vesting_reward
            .checked_add(slashed_vesting_reward)
            .ok_or_else(|| Error::msg("slashed vesting reward total overflow"))?;
        node.validator = false;
    }
    ledger
        .consensus
        .active_validators
        .retain(|node_id| !offline_set.contains(node_id));
    fallback_to_node1_availability_if_needed(ledger);
    Ok(())
}

fn new_epoch_context(ledger: &LedgerState) -> Result<EpochContext> {
    let ended_at = ledger
        .epoch_started_at
        .checked_add(ledger.epoch_seconds_snapshot)
        .ok_or_else(|| Error::msg("Epoch boundary overflow"))?;
    Ok(EpochContext {
        epoch: ledger.epoch_number,
        started_at: ledger.epoch_started_at,
        ended_at,
        submission_deadline: ended_at
            .checked_add(AVAILABILITY_FINALITY_GRACE_SECONDS)
            .ok_or_else(|| Error::msg("Epoch finality deadline overflow"))?,
        settings: ledger.settings.clone(),
        availability_mode: ledger.availability_mode,
        validator_ids: ledger.consensus.active_validators.clone(),
        validator_bonus_ids: Vec::new(),
        node1_single_producer: !multi_validator_ready(ledger, ledger.epoch_started_at),
    })
}

fn ensure_current_epoch_context(ledger: &mut LedgerState) -> Result<()> {
    if !ledger.epoch_contexts.contains_key(&ledger.epoch_number) {
        let context = new_epoch_context(ledger)?;
        ledger.epoch_contexts.insert(ledger.epoch_number, context);
    }
    Ok(())
}

fn close_current_epoch_context(ledger: &mut LedgerState) -> Result<()> {
    let context = epoch_context(ledger, ledger.epoch_number)?.clone();
    let validator_bonus_ids = context
        .validator_ids
        .iter()
        .copied()
        .filter(|node_id| {
            ledger.nodes.get(node_id).is_some_and(|node| {
                node.validator_signature_rate_bps
                    >= context.settings.validator_signature_threshold_bps
            })
        })
        .collect();
    ledger
        .epoch_contexts
        .get_mut(&ledger.epoch_number)
        .expect("current Epoch context exists")
        .validator_bonus_ids = validator_bonus_ids;
    Ok(())
}

/// Advances the protocol clock while keeping recently closed Epochs open for attestations.
fn advance_epochs_for_block(ledger: &mut LedgerState, block_timestamp: i64) -> Result<()> {
    ensure_current_epoch_context(ledger)?;
    loop {
        let epoch_end = epoch_context(ledger, ledger.epoch_number)?.ended_at;
        if block_timestamp < epoch_end {
            break;
        }
        let next_fee_multiplier = fee::next_epoch_multiplier(ledger)?;
        close_current_epoch_context(ledger)?;
        ledger.epoch_started_at = epoch_end;
        ledger.epoch_number = ledger
            .epoch_number
            .checked_add(1)
            .ok_or_else(|| Error::msg("Epoch number overflow"))?;
        if let Some(changes) = ledger
            .scheduled_parameter_changes
            .remove(&ledger.epoch_number)
        {
            ledger.settings = apply_governance_parameter_changes(&ledger.settings, &changes)?;
        }
        ledger.fee_multiplier_bps = next_fee_multiplier.clamp(
            ledger.settings.fee_policy.min_multiplier_bps,
            ledger.settings.fee_policy.max_multiplier_bps,
        );
        ledger.fee_units_used_in_epoch = 0;
        ledger.epoch_seconds_snapshot = ledger.settings.epoch_seconds;
        ledger.epoch_mint_amount_snapshot = ledger.settings.epoch_mint_amount;
        ledger.reward_immediate_bps_snapshot = ledger.settings.reward_immediate_bps;
        ledger.reward_vesting_seconds_snapshot = ledger.settings.reward_vesting_seconds;
        refresh_validator_committee(ledger, epoch_end)?;
        activate_multi_validator_availability_if_ready(ledger, epoch_end);
        let context = new_epoch_context(ledger)?;
        ledger.epoch_contexts.insert(ledger.epoch_number, context);
    }
    Ok(())
}

fn settle_finalized_epochs_for_block(ledger: &mut LedgerState, block_timestamp: i64) -> Result<()> {
    let epochs = ledger
        .epoch_contexts
        .values()
        .filter(|context| {
            context.epoch < ledger.epoch_number && block_timestamp >= context.submission_deadline
        })
        .map(|context| context.epoch)
        .collect::<Vec<_>>();
    for epoch in epochs {
        let context = epoch_context(ledger, epoch)?.clone();
        settle_one_epoch(ledger, &context)?;
        ledger.epoch_contexts.remove(&epoch);
        ledger
            .availability_slots
            .retain(|_, record| record.epoch != epoch);
    }
    Ok(())
}

#[cfg(test)]
fn settle_elapsed_epochs_for_block(ledger: &mut LedgerState, block_timestamp: i64) -> Result<()> {
    advance_epochs_for_block(ledger, block_timestamp)?;
    settle_finalized_epochs_for_block(ledger, block_timestamp)
}

fn activate_multi_validator_availability_if_ready(ledger: &mut LedgerState, activated_at: i64) {
    if ledger.availability_mode == AvailabilityMode::Node1Trusted
        && ledger.consensus.active_validators.len() >= MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS
    {
        ledger.availability_mode = AvailabilityMode::MultiValidator;
        ledger.availability_activated_at.get_or_insert(activated_at);
        ledger
            .availability_activated_epoch
            .get_or_insert(ledger.epoch_number);
    }
}

fn node_reward_weight_bps(node_id: u64, context: &EpochContext) -> u32 {
    if node_id == 1 && context.node1_single_producer {
        NODE1_SINGLE_PRODUCER_WEIGHT_BPS
    } else if context.validator_bonus_ids.contains(&node_id) {
        context.settings.validator_weight_bps
    } else {
        10_000
    }
}

fn settle_one_epoch(ledger: &mut LedgerState, context: &EpochContext) -> Result<()> {
    settle_reward_vesting(ledger, context.ended_at)?;
    let epoch_seconds = u64::try_from(context.settings.epoch_seconds)
        .map_err(|_| Error::msg("current Epoch duration must be positive"))?;
    let mut weights = BTreeMap::<u64, u128>::new();
    let mut total_weight = 0_u128;
    for (node_id, node) in &ledger.nodes {
        let eligible_seconds = node
            .eligible_seconds_by_epoch
            .get(&context.epoch)
            .copied()
            .unwrap_or_default();
        if eligible_seconds > epoch_seconds {
            return Err(Error::msg(
                "Node eligible seconds exceed the current Epoch duration",
            ));
        }
        let factor = node_reward_weight_bps(*node_id, context);
        let weight = u128::from(eligible_seconds) * u128::from(factor);
        if weight > 0 {
            weights.insert(*node_id, weight);
            total_weight = total_weight
                .checked_add(weight)
                .ok_or_else(|| Error::msg("total Node reward weight overflow"))?;
        }
    }
    if total_weight == 0 {
        for node in ledger.nodes.values_mut() {
            node.eligible_seconds_by_epoch.remove(&context.epoch);
        }
        return Ok(());
    }
    let budget = context
        .settings
        .epoch_mint_amount
        .min(ledger.pool_remaining);
    if budget == 0 {
        for node in ledger.nodes.values_mut() {
            node.eligible_seconds_by_epoch.remove(&context.epoch);
        }
        return Ok(());
    }
    let mut allocations = Vec::with_capacity(weights.len());
    let mut allocated = 0_u128;
    for (node_id, weight) in weights {
        let whole = (budget / total_weight)
            .checked_mul(weight)
            .ok_or_else(|| Error::msg("Node reward calculation overflow"))?;
        let fractional_numerator = (budget % total_weight)
            .checked_mul(weight)
            .ok_or_else(|| Error::msg("Node fractional reward calculation overflow"))?;
        let reward = whole
            .checked_add(fractional_numerator / total_weight)
            .ok_or_else(|| Error::msg("Node reward calculation overflow"))?;
        let remainder = fractional_numerator % total_weight;
        allocated = allocated
            .checked_add(reward)
            .ok_or_else(|| Error::msg("Node reward allocation overflow"))?;
        allocations.push((node_id, reward, remainder));
    }
    let leftover = budget
        .checked_sub(allocated)
        .ok_or_else(|| Error::msg("Node reward allocation exceeds Epoch budget"))?;
    allocations.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    let leftover_count = usize::try_from(leftover)
        .map_err(|_| Error::msg("Epoch reward remainder does not fit in memory"))?;
    if leftover_count > allocations.len() {
        return Err(Error::msg(
            "Epoch reward remainder exceeds active Node count",
        ));
    }
    for allocation in allocations.iter_mut().take(leftover_count) {
        allocation.1 += 1;
    }
    let required_bond = context.settings.required_service_bond;
    for (node_id, reward, _) in allocations {
        let node = ledger.nodes.get_mut(&node_id).expect("weighted node");
        let bond_needed = required_bond.saturating_sub(node.service_bond);
        let to_bond = reward.min(bond_needed);
        node.service_bond += to_bond;
        let reward_after_bond = reward - to_bond;
        let immediate = reward_after_bond
            .checked_mul(u128::from(context.settings.reward_immediate_bps))
            .ok_or_else(|| Error::msg("immediate Node reward calculation overflow"))?
            / BPS_DENOMINATOR;
        let vesting = reward_after_bond - immediate;
        node.claimable_reward = node
            .claimable_reward
            .checked_add(immediate)
            .ok_or_else(|| Error::msg("claimable Node reward overflow"))?;
        add_node_reward_vesting(
            node,
            vesting,
            context.ended_at,
            context.settings.reward_vesting_seconds,
            ledger.created_at,
        )?;
    }
    for node in ledger.nodes.values_mut() {
        node.eligible_seconds_by_epoch.remove(&context.epoch);
    }
    ledger.pool_remaining -= budget;
    ledger.lifetime_minted = ledger
        .lifetime_minted
        .checked_add(budget)
        .ok_or_else(|| Error::msg("lifetime minted amount overflow"))?;
    Ok(())
}

fn settle_reward_vesting(ledger: &mut LedgerState, epoch_end: i64) -> Result<()> {
    for node in ledger.nodes.values_mut() {
        settle_node_reward_vesting(node, epoch_end)?;
    }
    Ok(())
}

fn add_node_reward_vesting(
    node: &mut NodeRecord,
    amount: u128,
    starts_at: i64,
    vesting_seconds: i64,
    quantization_offset: i64,
) -> Result<()> {
    if vesting_seconds <= 0 {
        return Err(Error::msg("Node reward vesting duration must be positive"));
    }
    if amount == 0 {
        return Ok(());
    }

    let duration = u128::try_from(vesting_seconds)
        .map_err(|_| Error::msg("Node reward vesting duration is invalid"))?;
    let effective_step = REWARD_VESTING_STEP_SECONDS.min(vesting_seconds);
    let quantization = REWARD_VESTING_QUANTIZATION_SECONDS.min((effective_step / 2).max(1));
    let mut elapsed = 0_i64;
    let mut vested_so_far = 0_u128;
    while elapsed < vesting_seconds {
        elapsed = elapsed
            .checked_add(REWARD_VESTING_STEP_SECONDS)
            .ok_or_else(|| Error::msg("Node reward vesting step overflow"))?
            .min(vesting_seconds);
        let elapsed_u128 = u128::try_from(elapsed)
            .map_err(|_| Error::msg("Node reward vesting elapsed time is invalid"))?;
        let target_vested = multiply_ratio_floor(amount, elapsed_u128, duration)?;
        let tranche = target_vested
            .checked_sub(vested_so_far)
            .ok_or_else(|| Error::msg("Node reward vesting amount regressed"))?;
        vested_so_far = target_vested;
        if tranche == 0 {
            continue;
        }

        let vesting_at = starts_at
            .checked_add(elapsed)
            .ok_or_else(|| Error::msg("Node reward vesting boundary overflow"))?;
        let unlock_at = quantize_timestamp_up(vesting_at, quantization, quantization_offset)?;
        match node
            .reward_vesting_buckets
            .binary_search_by_key(&unlock_at, |bucket| bucket.unlock_at)
        {
            Ok(index) => {
                node.reward_vesting_buckets[index].amount = node.reward_vesting_buckets[index]
                    .amount
                    .checked_add(tranche)
                    .ok_or_else(|| Error::msg("Node reward vesting bucket overflow"))?;
            }
            Err(index) => node.reward_vesting_buckets.insert(
                index,
                RewardVestingBucket {
                    unlock_at,
                    amount: tranche,
                },
            ),
        }
    }
    Ok(())
}

fn multiply_ratio_floor(amount: u128, numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 || numerator > denominator {
        return Err(Error::msg("invalid Node reward vesting ratio"));
    }
    let whole = (amount / denominator)
        .checked_mul(numerator)
        .ok_or_else(|| Error::msg("Node reward vesting calculation overflow"))?;
    let fractional = (amount % denominator)
        .checked_mul(numerator)
        .ok_or_else(|| Error::msg("Node reward vesting calculation overflow"))?
        / denominator;
    whole
        .checked_add(fractional)
        .ok_or_else(|| Error::msg("Node reward vesting calculation overflow"))
}

fn quantize_timestamp_up(timestamp: i64, unit: i64, offset: i64) -> Result<i64> {
    if unit <= 0 {
        return Err(Error::msg(
            "Node reward vesting quantization must be positive",
        ));
    }
    let delta = timestamp
        .checked_sub(offset)
        .ok_or_else(|| Error::msg("Node reward vesting quantization overflow"))?;
    let quotient = delta.div_euclid(unit);
    let units = quotient
        .checked_add(i64::from(delta.rem_euclid(unit) != 0))
        .ok_or_else(|| Error::msg("Node reward vesting quantization overflow"))?;
    offset
        .checked_add(
            units
                .checked_mul(unit)
                .ok_or_else(|| Error::msg("Node reward vesting quantization overflow"))?,
        )
        .ok_or_else(|| Error::msg("Node reward vesting quantization overflow"))
}

fn settle_node_reward_vesting(node: &mut NodeRecord, epoch_end: i64) -> Result<()> {
    let matured = node
        .reward_vesting_buckets
        .partition_point(|bucket| bucket.unlock_at <= epoch_end);
    let released =
        node.reward_vesting_buckets[..matured]
            .iter()
            .try_fold(0_u128, |total, bucket| {
                total
                    .checked_add(bucket.amount)
                    .ok_or_else(|| Error::msg("matured Node reward overflow"))
            })?;
    node.claimable_reward = node
        .claimable_reward
        .checked_add(released)
        .ok_or_else(|| Error::msg("claimable Node reward overflow"))?;
    node.reward_vesting_buckets.drain(..matured);
    Ok(())
}

fn node_vesting_reward(node: &NodeRecord) -> Result<u128> {
    node.reward_vesting_buckets
        .iter()
        .try_fold(0_u128, |total, bucket| {
            total
                .checked_add(bucket.amount)
                .ok_or_else(|| Error::msg("Node vesting reward overflow"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AccountState;

    #[test]
    fn network_totals_use_only_finalized_state() {
        let mut ledger = LedgerState {
            burned: 25,
            total_settled_traffic_bytes: 5_000,
            ..LedgerState::default()
        };
        assert_eq!(finalized_network_totals(&ledger), (0, 0));

        let mut checkpoint = ledger.clone();
        checkpoint.burned = 10;
        checkpoint.total_settled_traffic_bytes = 2_048;
        checkpoint.finalized_checkpoint = None;
        ledger.finalized_checkpoint = Some(Box::new(checkpoint));
        assert_eq!(finalized_network_totals(&ledger), (10, 2_048));
    }

    #[test]
    fn settled_traffic_uses_compact_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1_024), "1 KiB");
        assert_eq!(format_bytes(1_610_612_736), "1.5 GiB");
    }

    fn reset_epoch_context(ledger: &mut LedgerState) {
        ledger.epoch_contexts.clear();
        let context = new_epoch_context(ledger).unwrap();
        ledger.epoch_contexts.insert(ledger.epoch_number, context);
    }

    fn eligible_seconds(node: &NodeRecord, epoch: u64) -> u64 {
        node.eligible_seconds_by_epoch
            .get(&epoch)
            .copied()
            .unwrap_or_default()
    }

    fn set_eligible_seconds(node: &mut NodeRecord, epoch: u64, seconds: u64) {
        node.eligible_seconds_by_epoch.insert(epoch, seconds);
    }

    #[test]
    fn governance_parameter_view_is_complete_and_shows_activation_layers() {
        let mut ledger = LedgerState {
            epoch_seconds_snapshot: 1_800,
            settings: LedgerSettings {
                epoch_seconds: 3_600,
                ..LedgerSettings::default()
            },
            ..LedgerState::default()
        };
        ledger.scheduled_parameter_changes.insert(
            3,
            BTreeMap::from([("epoch-seconds".to_owned(), "600".to_owned())]),
        );

        let parameters = governance_parameter_views(&ledger);
        assert_eq!(parameters.len(), 37);
        assert_eq!(
            parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            parameters.len()
        );
        let epoch = parameters
            .iter()
            .find(|parameter| parameter.name == "epoch-seconds")
            .unwrap();
        assert_eq!(epoch.current_value, "1800");
        assert_eq!(epoch.configured_value, "3600");
        assert_eq!(epoch.governance, "CRITICAL");
        assert_eq!(epoch.scheduled_changes[0].effective_epoch, 3);
        assert_eq!(epoch.scheduled_changes[0].value, "600");
        assert_eq!(
            parameters
                .iter()
                .find(|parameter| parameter.name == "service-bond")
                .unwrap()
                .governance,
            "STANDARD"
        );
        let node_lifecycle_positions = parameters
            .iter()
            .enumerate()
            .filter_map(|(position, parameter)| {
                (parameter.category == "Node lifecycle").then_some(position)
            })
            .collect::<Vec<_>>();
        assert!(
            node_lifecycle_positions
                .windows(2)
                .all(|positions| positions[1] == positions[0] + 1),
            "Node lifecycle parameters must remain contiguous"
        );
    }

    #[test]
    fn availability_worker_waits_when_ledger_epoch_is_not_current() {
        let context = EpochContext {
            epoch: 4,
            started_at: 100,
            ended_at: 220,
            submission_deadline: 250,
            settings: LedgerSettings {
                availability_slot_seconds: 60,
                ..LedgerSettings::default()
            },
            availability_mode: AvailabilityMode::Node1Trusted,
            validator_ids: Vec::new(),
            validator_bonus_ids: Vec::new(),
            node1_single_producer: true,
        };

        assert_eq!(active_availability_slot(&context, 99).unwrap(), None);
        assert_eq!(active_availability_slot(&context, 100).unwrap(), Some(0));
        assert_eq!(active_availability_slot(&context, 159).unwrap(), Some(0));
        assert_eq!(active_availability_slot(&context, 160).unwrap(), Some(1));
        assert_eq!(active_availability_slot(&context, 219).unwrap(), Some(1));
        assert_eq!(active_availability_slot(&context, 220).unwrap(), None);
        assert_eq!(active_availability_slot(&context, 280).unwrap(), None);
    }

    #[test]
    fn node1_reward_bonus_tracks_single_producer_mode_without_stacking() {
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 100,
            epoch_number: 1,
            ..LedgerState::default()
        };
        ledger.settings.required_service_bond = 0;
        ledger.settings.required_governance_bond = 0;
        ledger.settings.governance_min_service_seconds = 0;
        for node_id in 1..=MULTI_VALIDATOR_NODE_THRESHOLD as u64 {
            let mut node = availability_test_node(node_id);
            node.last_probe_success = Some(100);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(&mut ledger, &slot, node_id, 100));
        }
        ledger.consensus.active_validators = vec![1, 2, 3, 4];

        let mut context = new_epoch_context(&ledger).unwrap();
        assert!(!context.node1_single_producer);
        context.validator_bonus_ids = vec![1, 2];
        assert_eq!(node_reward_weight_bps(1, &context), 12_500);
        assert_eq!(node_reward_weight_bps(2, &context), 12_500);

        ledger.consensus.active_validators.pop();
        let mut fallback = new_epoch_context(&ledger).unwrap();
        assert!(fallback.node1_single_producer);
        fallback.validator_bonus_ids = vec![1, 2];
        assert_eq!(node_reward_weight_bps(1, &fallback), 20_000);
        assert_eq!(node_reward_weight_bps(2, &fallback), 12_500);
        assert_eq!(node_reward_weight_bps(3, &fallback), 10_000);
    }

    #[test]
    fn normalizes_public_ip_slots() {
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
        assert_eq!(ip_slot("1.1.1.1".parse().unwrap()), "v4:1.1.1.1");
        assert_eq!(
            ip_slot("2606:4700:4700::1111".parse().unwrap()),
            "v6:2606:4700:4700:0::/64"
        );
    }

    #[test]
    fn conflicting_ip_slot_has_only_one_governance_eligible_owner() {
        let mut ledger = LedgerState::default();
        ledger.settings.required_service_bond = 0;
        ledger.settings.governance_min_service_seconds = 0;
        ledger.settings.required_governance_bond = 0;
        let mut owner = availability_test_node(1);
        owner.last_probe_success = Some(100);
        let mut conflicting = availability_test_node(2);
        conflicting.reward_ip = owner.reward_ip.clone();
        conflicting.ip_slot = owner.ip_slot.clone();
        conflicting.last_probe_success = Some(100);
        let slot = owner.ip_slot.clone();
        ledger.nodes.insert(1, owner);
        ledger.nodes.insert(2, conflicting);
        assert!(bind_ip_slot_if_available(&mut ledger, &slot, 1, 0));
        assert!(!bind_ip_slot_if_available(&mut ledger, &slot, 2, 100));
        assert_eq!(governance_eligible_node_ids(&ledger, 100), vec![1]);
        release_node_ip_slot(&mut ledger, 1, 100);
        assert!(bind_ip_slot_if_available(&mut ledger, &slot, 2, 100));
        assert_eq!(governance_eligible_node_ids(&ledger, 100), vec![2]);
    }

    #[test]
    fn standard_governance_requires_an_absolute_yes_majority() {
        let proposal = GovernanceProposalRecord {
            proposal_id: 1,
            proposer_node_id: 1,
            proposer_reward_address: "reward1".to_owned(),
            kind: GovernanceProposalKind::Standard,
            title: "standard threshold".to_owned(),
            action: GovernanceProposalAction::ResumeEmission,
            created_at: 0,
            voting_ends_at: STANDARD_VOTING_SECONDS,
            execute_after: STANDARD_VOTING_SECONDS + STANDARD_TIMELOCK_SECONDS,
            status: GovernanceProposalStatus::Voting,
            snapshot_epoch: 0,
            power_snapshot: BTreeMap::new(),
            total_power: 50,
            votes: BTreeMap::new(),
            validator_snapshot: Vec::new(),
            validator_votes: BTreeMap::new(),
            timelock_vetoes: BTreeMap::new(),
            proposal_bond: GOVERNANCE_PROPOSAL_BOND,
            finalized_at: None,
            executed_at: None,
        };
        let tally = |yes, no, abstain| GovernanceTallyView {
            proposal_id: 1,
            status: GovernanceProposalStatus::Voting,
            total_power: 50,
            yes_power: yes,
            no_power: no,
            abstain_power: abstain,
            participation_power: yes + no + abstain,
            validator_total: 0,
            validator_yes: 0,
            validator_no: 0,
            validator_abstain: 0,
            validator_quorum: 0,
            timelock_veto_power: 0,
            voting_ends_at: STANDARD_VOTING_SECONDS,
            execute_after: STANDARD_VOTING_SECONDS + STANDARD_TIMELOCK_SECONDS,
        };

        assert!(!governance_tally_passed(&proposal, &tally(1, 0, 24)));
        assert!(!governance_tally_passed(&proposal, &tally(25, 0, 0)));
        assert!(governance_tally_passed(&proposal, &tally(26, 0, 0)));
        assert!(governance_tally_passed(&proposal, &tally(26, 13, 0)));
        assert!(!governance_tally_passed(&proposal, &tally(26, 14, 0)));
        assert!(governance_tally_passed(&proposal, &tally(34, 16, 0)));
    }

    #[test]
    fn bonded_roles_must_be_cleared_before_node_drain() {
        let mut node = availability_test_node(1);
        assert!(ensure_node_can_drain(&node).is_err());

        node.validator = false;
        node.validator_bond = 1;
        assert!(ensure_node_can_drain(&node).is_err());

        node.validator_bond = 0;
        node.validator_candidate_since = None;
        node.validator_exit_requested_at = None;
        node.validator_bond_unlock_at = None;
        assert!(ensure_node_can_drain(&node).is_ok());

        node.governance_bond = 1;
        node.governance_bonded_at = Some(0);
        assert!(ensure_node_can_drain(&node).is_err());

        node.governance_bond = 0;
        node.governance_bonded_at = None;
        assert!(ensure_node_can_drain(&node).is_ok());
    }

    #[test]
    fn owner_join_requires_latest_settled_exited_node() {
        let mut ledger = LedgerState::default();
        let mut previous = availability_test_node(2);
        previous.owner_address = "returning-owner".to_owned();
        previous.owner_public_key = "returning-key".to_owned();
        previous.status = NodeStatus::Exited;
        ledger.nodes.insert(2, previous);

        assert!(
            validate_node_owner_registration(&ledger, "returning-owner", "returning-key", Some(2))
                .is_ok()
        );
        assert!(
            validate_node_owner_registration(&ledger, "returning-owner", "returning-key", None)
                .is_err()
        );

        ledger.nodes.get_mut(&2).unwrap().claimable_reward = 1;
        assert!(
            validate_node_owner_registration(&ledger, "returning-owner", "returning-key", Some(2))
                .is_err()
        );
        ledger.nodes.get_mut(&2).unwrap().claimable_reward = 0;
        ledger.nodes.get_mut(&2).unwrap().status = NodeStatus::Active;
        assert!(
            validate_node_owner_registration(&ledger, "returning-owner", "returning-key", Some(2))
                .is_err()
        );
    }

    #[test]
    fn legacy_node_checkpoint_encoding_omits_an_empty_previous_node_id() {
        let mut node = availability_test_node(2);
        let legacy_compatible = serde_json::to_value(&node).unwrap();
        assert!(legacy_compatible.get("previous_node_id").is_none());

        node.previous_node_id = Some(1);
        let replacement = serde_json::to_value(&node).unwrap();
        assert_eq!(replacement["previous_node_id"], 1);
    }

    fn availability_test_node(node_id: u64) -> NodeRecord {
        NodeRecord {
            node_id,
            previous_node_id: None,
            name: format!("node{node_id}"),
            owner_address: format!("owner{node_id}"),
            owner_public_key: format!("owner-key{node_id}"),
            relay_public_key: format!("relay-key{node_id}"),
            reward_address: format!("reward{node_id}"),
            endpoint: format!("wss://{node_id}.example/v1/relay"),
            reward_ip: format!("9.8.7.{node_id}"),
            ip_slot: format!("v4:9.8.7.{node_id}"),
            price_per_gib: 0,
            status: NodeStatus::Active,
            registered_at: 0,
            warmup_until: 0,
            active_since: Some(0),
            last_heartbeat: None,
            last_probe_success: Some(0),
            probe_success_count: 1,
            last_relay_receipt_at: None,
            eligible_seconds_by_epoch: BTreeMap::new(),
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            governance_bond: 0,
            governance_bonded_at: None,
            governance_exit_requested_at: None,
            governance_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 0,
            reward_vesting_buckets: Vec::new(),
            validator: true,
            validator_signature_rate_bps: 10_000,
            validator_bond: 0,
            validator_candidate_since: None,
            validator_last_epoch: None,
            validator_consecutive_epochs: 0,
            validator_exit_requested_at: None,
            validator_bond_unlock_at: None,
        }
    }

    #[test]
    fn relay_price_median_uses_only_active_reachable_nodes() {
        let now = 1_000;
        let mut ledger = LedgerState::default();
        ledger.settings.probe_validity_seconds = 300;
        assert_eq!(
            network_median_price_per_gib(&ledger, now),
            DEFAULT_RELAY_PRICE_PER_GIB
        );

        for (node_id, price_per_gib) in [(1, 100), (2, 300), (3, 500)] {
            let mut node = availability_test_node(node_id);
            node.price_per_gib = price_per_gib;
            node.last_probe_success = Some(now);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(&mut ledger, &slot, node_id, now));
        }

        let mut warming = availability_test_node(4);
        warming.status = NodeStatus::WarmingUp;
        warming.price_per_gib = 200;
        warming.last_probe_success = Some(now);
        let warming_slot = warming.ip_slot.clone();
        ledger.nodes.insert(4, warming);
        assert!(bind_ip_slot_if_available(
            &mut ledger,
            &warming_slot,
            4,
            now
        ));

        let mut stale = availability_test_node(5);
        stale.price_per_gib = 400;
        stale.last_probe_success = Some(now - 301);
        let stale_slot = stale.ip_slot.clone();
        ledger.nodes.insert(5, stale);
        assert!(bind_ip_slot_if_available(&mut ledger, &stale_slot, 5, now));

        let mut unbound = availability_test_node(6);
        unbound.price_per_gib = 600;
        unbound.last_probe_success = Some(now);
        ledger.nodes.insert(6, unbound);

        assert_eq!(network_median_price_per_gib(&ledger, now), 300);

        ledger.nodes.get_mut(&3).unwrap().status = NodeStatus::Suspended;
        assert_eq!(network_median_price_per_gib(&ledger, now), 200);

        ledger.nodes.get_mut(&1).unwrap().status = NodeStatus::Suspended;
        ledger.nodes.get_mut(&2).unwrap().status = NodeStatus::Suspended;
        assert_eq!(
            network_median_price_per_gib(&ledger, now),
            DEFAULT_RELAY_PRICE_PER_GIB
        );
    }

    #[test]
    fn node1_reward_ip_update_skips_timed_warmup_only_before_fifty_eligible_nodes() {
        let updated_at = 1_000;
        let mut ledger = LedgerState::default();
        ledger.settings.warmup_seconds = 86_400;
        ledger.settings.required_service_bond = 0;
        ledger.settings.required_governance_bond = 0;
        ledger.settings.governance_min_service_seconds = 0;
        for node_id in 1..NODE1_DIRECT_GOVERNANCE_END_THRESHOLD as u64 {
            let mut node = availability_test_node(node_id);
            node.last_probe_success = Some(updated_at);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(
                &mut ledger,
                &slot,
                node_id,
                updated_at
            ));
        }

        let mut before_threshold = ledger.clone();
        apply_reward_ip_update(
            &mut before_threshold,
            1,
            "wss://node1-new.example/v1/relay",
            "1.1.1.1",
            "v4:1.1.1.1",
            updated_at,
        )
        .unwrap();
        let node1 = &before_threshold.nodes[&1];
        assert_eq!(node1.status, NodeStatus::WarmingUp);
        assert_eq!(node1.warmup_until, updated_at);
        assert_eq!(node1.active_since, None);

        let mut at_threshold = ledger.clone();
        let threshold_node_id = NODE1_DIRECT_GOVERNANCE_END_THRESHOLD as u64;
        let mut threshold_node = availability_test_node(threshold_node_id);
        threshold_node.last_probe_success = Some(updated_at);
        let threshold_slot = threshold_node.ip_slot.clone();
        at_threshold.nodes.insert(threshold_node_id, threshold_node);
        assert!(bind_ip_slot_if_available(
            &mut at_threshold,
            &threshold_slot,
            threshold_node_id,
            updated_at
        ));
        apply_reward_ip_update(
            &mut at_threshold,
            1,
            "wss://node1-new.example/v1/relay",
            "1.1.1.1",
            "v4:1.1.1.1",
            updated_at,
        )
        .unwrap();
        assert_eq!(
            at_threshold.nodes[&1].warmup_until,
            updated_at + ledger.settings.warmup_seconds
        );

        let mut ordinary_node = ledger;
        apply_reward_ip_update(
            &mut ordinary_node,
            2,
            "wss://node2-new.example/v1/relay",
            "8.8.8.8",
            "v4:8.8.8.8",
            updated_at,
        )
        .unwrap();
        assert_eq!(
            ordinary_node.nodes[&2].warmup_until,
            updated_at + ordinary_node.settings.warmup_seconds
        );
    }

    #[test]
    fn availability_trust_transition_falls_back_to_node1_and_recovers() {
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            epoch_seconds_snapshot: 300,
            ..LedgerState::default()
        };
        ledger.settings.epoch_seconds = 300;
        ledger.settings.governance_min_service_seconds = 0;
        ledger.settings.required_governance_bond = 0;
        ledger.settings.required_service_bond = 0;
        for node_id in 1..=7 {
            let mut node = availability_test_node(node_id);
            node.validator_bond = ledger.settings.validator_bond;
            node.validator_candidate_since = Some(0);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(&mut ledger, &slot, node_id, 0));
        }
        reset_epoch_context(&mut ledger);
        let trusted = availability_verifier_set(&ledger, epoch_context(&ledger, 0).unwrap(), 1, 0);
        assert_eq!(trusted.mode, AvailabilityMode::Node1Trusted);
        assert_eq!(trusted.primary_ids, vec![1]);
        assert_eq!(trusted.primary_quorum, 1);

        refresh_validator_committee(&mut ledger, 0).unwrap();
        assert_eq!(ledger.consensus.active_validators.len(), 7);
        assert_eq!(ledger.availability_mode, AvailabilityMode::Node1Trusted);
        settle_elapsed_epochs_for_block(&mut ledger, 299).unwrap();
        assert_eq!(ledger.availability_mode, AvailabilityMode::Node1Trusted);
        settle_elapsed_epochs_for_block(&mut ledger, 300).unwrap();
        assert_eq!(ledger.availability_mode, AvailabilityMode::MultiValidator);
        assert_eq!(ledger.availability_activated_at, Some(300));
        let decentralized = availability_verifier_set(
            &ledger,
            epoch_context(&ledger, ledger.epoch_number).unwrap(),
            1,
            5,
        );
        assert_eq!(decentralized.primary_ids.len(), 5);
        assert_eq!(decentralized.primary_quorum, 3);
        assert!(!decentralized.primary_ids.contains(&1));

        ledger.nodes.get_mut(&7).unwrap().status = NodeStatus::Suspended;
        for node_id in 1..=6 {
            ledger.nodes.get_mut(&node_id).unwrap().last_probe_success = Some(600);
        }
        settle_elapsed_epochs_for_block(&mut ledger, 600).unwrap();
        assert_eq!(ledger.consensus.active_validators.len(), 6);
        assert_eq!(ledger.availability_mode, AvailabilityMode::Node1Trusted);
        let fallback = availability_verifier_set(
            &ledger,
            epoch_context(&ledger, ledger.epoch_number).unwrap(),
            1,
            10,
        );
        assert_eq!(fallback.primary_ids, vec![1]);
        assert_eq!(fallback.primary_quorum, 1);

        ledger.nodes.get_mut(&7).unwrap().status = NodeStatus::Active;
        for node_id in 1..=7 {
            ledger.nodes.get_mut(&node_id).unwrap().last_probe_success = Some(900);
        }
        settle_elapsed_epochs_for_block(&mut ledger, 900).unwrap();
        assert_eq!(ledger.consensus.active_validators.len(), 7);
        assert_eq!(ledger.availability_mode, AvailabilityMode::MultiValidator);
        assert_eq!(ledger.availability_activated_at, Some(300));
        assert_eq!(ledger.availability_activated_epoch, Some(1));
    }

    #[test]
    fn thirty_one_seat_committee_respects_rotation_count_and_epoch_interval() {
        let mut ledger = LedgerState::default();
        ledger.settings.required_service_bond = 0;
        ledger.settings.governance_min_service_seconds = 0;
        ledger.settings.required_governance_bond = 0;
        ledger.settings.max_active_validators = 31;
        ledger.settings.max_validator_rotations = 10;
        ledger.settings.validator_rotation_interval_epochs = 3;
        for node_id in 1..=41 {
            let mut node = availability_test_node(node_id);
            node.validator = false;
            node.validator_bond = ledger.settings.validator_bond;
            node.validator_candidate_since = Some(0);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(&mut ledger, &slot, node_id, 0));
        }

        refresh_validator_committee(&mut ledger, 0).unwrap();
        let first = ledger.consensus.active_validators.clone();
        assert_eq!(first, (1..=31).collect::<Vec<_>>());

        ledger.epoch_number += 1;
        for node in ledger.nodes.values_mut() {
            node.last_probe_success = Some(1);
        }
        refresh_validator_committee(&mut ledger, 1).unwrap();
        assert_eq!(ledger.consensus.active_validators, first);
        assert_eq!(ledger.consensus.last_selection_epoch, Some(0));

        ledger.epoch_number += 1;
        refresh_validator_committee(&mut ledger, 2).unwrap();
        assert_eq!(ledger.consensus.active_validators, first);
        assert_eq!(ledger.consensus.last_selection_epoch, Some(0));

        ledger.epoch_number += 1;
        refresh_validator_committee(&mut ledger, 3).unwrap();
        let second = ledger.consensus.active_validators.clone();
        let first_set = first.iter().copied().collect::<BTreeSet<_>>();
        let second_set = second.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(first_set.intersection(&second_set).count(), 21);
        assert_eq!(second_set.difference(&first_set).count(), 10);
        assert_eq!(second, (11..=41).collect::<Vec<_>>());
        assert_eq!(ledger.consensus.last_selection_epoch, Some(3));

        ledger.nodes.get_mut(&11).unwrap().status = NodeStatus::Suspended;
        ledger.epoch_number += 1;
        refresh_validator_committee(&mut ledger, 4).unwrap();
        assert_eq!(ledger.consensus.active_validators.len(), 31);
        assert!(!ledger.consensus.active_validators.contains(&11));
        assert_eq!(ledger.consensus.last_selection_epoch, Some(4));
    }

    #[test]
    fn audited_slots_use_disjoint_primary_and_auditor_sets() {
        let mut ledger = LedgerState {
            availability_mode: AvailabilityMode::MultiValidator,
            ..LedgerState::default()
        };
        ledger.settings.availability_audit_rate_bps = 10_000;
        for node_id in 1..=9 {
            ledger
                .nodes
                .insert(node_id, availability_test_node(node_id));
        }
        ledger.consensus.active_validators = (1..=9).collect();
        reset_epoch_context(&mut ledger);
        let set = availability_verifier_set(&ledger, epoch_context(&ledger, 0).unwrap(), 1, 0);
        assert!(set.audit_required);
        assert_eq!(set.primary_ids.len(), 5);
        assert_eq!(set.auditor_ids.len(), 3);
        assert_eq!(set.audit_quorum, 2);
        assert!(!set.primary_ids.contains(&1));
        assert!(!set.auditor_ids.contains(&1));
        assert!(
            set.primary_ids
                .iter()
                .all(|node_id| !set.auditor_ids.contains(node_id))
        );
    }

    #[test]
    fn owner_signed_probe_tickets_separate_primary_and_audit_windows() {
        let password = "availability-test-password";
        let keyfile = generate_keyfile(password).unwrap();
        let key = decrypt_key(&keyfile, password).unwrap();
        let primary_ticket = sign_bytes(
            &key,
            &availability_ticket_message("ledger", 2, 10, 4, 7, AvailabilityVerifierRole::Primary),
        );
        verify_bytes(
            &keyfile.public_key,
            &availability_ticket_message("ledger", 2, 10, 4, 7, AvailabilityVerifierRole::Primary),
            &primary_ticket,
        )
        .unwrap();
        let audit_ticket = sign_bytes(
            &key,
            &availability_ticket_message("ledger", 2, 10, 4, 7, AvailabilityVerifierRole::Audit),
        );
        assert_ne!(primary_ticket, audit_ticket);
        let slot_start = 600;
        let primary_at = availability_scheduled_at(
            &primary_ticket,
            slot_start,
            60,
            AvailabilityVerifierRole::Primary,
        )
        .unwrap();
        let audit_at = availability_scheduled_at(
            &audit_ticket,
            slot_start,
            60,
            AvailabilityVerifierRole::Audit,
        )
        .unwrap();
        assert!((slot_start + 2..=slot_start + 20).contains(&primary_at));
        assert!((slot_start + 32..=slot_start + 50).contains(&audit_at));
    }

    #[test]
    fn audited_slot_credits_only_after_both_quorums() {
        let password = "availability-test-password";
        let verifier_file = generate_keyfile(password).unwrap();
        let verifier_key = decrypt_key(&verifier_file, password).unwrap();
        let relay_file = generate_keyfile(password).unwrap();
        let relay_key = decrypt_key(&relay_file, password).unwrap();
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            epoch_seconds_snapshot: 300,
            availability_mode: AvailabilityMode::MultiValidator,
            ..LedgerState::default()
        };
        ledger.settings.epoch_seconds = 300;
        ledger.settings.availability_slot_seconds = 60;
        ledger.settings.availability_audit_rate_bps = 10_000;
        ledger.settings.warmup_seconds = 0;
        ledger.settings.required_service_bond = 0;
        for node_id in 1..=9 {
            let mut node = availability_test_node(node_id);
            node.owner_address = verifier_file.address.clone();
            node.owner_public_key = verifier_file.public_key.clone();
            ledger.nodes.insert(node_id, node);
        }
        let mut target = availability_test_node(10);
        target.owner_address = "target-owner".to_owned();
        target.relay_public_key = relay_file.public_key.clone();
        target.eligible_seconds_by_epoch.clear();
        target.total_eligible_seconds = 0;
        ledger.nodes.insert(10, target);
        ledger.consensus.active_validators = (1..=9).collect();
        reset_epoch_context(&mut ledger);
        let set = availability_verifier_set(&ledger, epoch_context(&ledger, 0).unwrap(), 10, 0);
        assert!(set.audit_required);

        let apply = |ledger: &mut LedgerState,
                     verifier_node_id: u64,
                     role: AvailabilityVerifierRole,
                     operation_index: u64| {
            let ticket_signature = sign_bytes(
                &verifier_key,
                &availability_ticket_message(
                    &ledger.ledger_id,
                    ledger.epoch_number,
                    0,
                    10,
                    verifier_node_id,
                    role,
                ),
            );
            let challenge = availability_challenge(&ticket_signature);
            let timestamp = availability_scheduled_at(&ticket_signature, 0, 60, role).unwrap();
            let response = ProbePayload {
                protocol: "mrk-probe-v1".to_owned(),
                node_id: 10,
                relay_public_key: relay_file.public_key.clone(),
                timestamp,
                challenge: challenge.clone(),
                signature: sign_bytes(
                    &relay_key,
                    format!("mrk-probe-v1:10:{timestamp}:{challenge}").as_bytes(),
                ),
            };
            let operation = sign_public_operation(
                &verifier_file,
                password,
                PublicOperationSigningRequest {
                    ledger_id: &ledger.ledger_id,
                    module: "Availability",
                    action: "AttestProbe",
                    nonce: operation_index,
                    valid_until: 600,
                    max_fee_base_units: 0,
                    fee_policy_version: ledger.settings.fee_policy.version,
                    payload: json!({
                        "target_node_id": 10,
                        "verifier_node_id": verifier_node_id,
                        "slot": 0,
                        "epoch": 0,
                        "role": role,
                        "ticket_signature": ticket_signature,
                        "probe": response,
                    }),
                },
            )
            .unwrap();
            apply_availability_attestation(
                ledger,
                &verifier_file.public_key,
                &operation,
                &format!("attestation-{operation_index}"),
                timestamp,
            )
            .unwrap();
        };

        for (index, node_id) in set.primary_ids.iter().take(3).enumerate() {
            apply(
                &mut ledger,
                *node_id,
                AvailabilityVerifierRole::Primary,
                index as u64 + 1,
            );
        }
        assert_eq!(eligible_seconds(&ledger.nodes[&10], 0), 0);
        apply(
            &mut ledger,
            set.auditor_ids[0],
            AvailabilityVerifierRole::Audit,
            10,
        );
        assert_eq!(eligible_seconds(&ledger.nodes[&10], 0), 0);
        apply(
            &mut ledger,
            set.auditor_ids[1],
            AvailabilityVerifierRole::Audit,
            11,
        );
        assert_eq!(eligible_seconds(&ledger.nodes[&10], 0), 60);
        assert_eq!(ledger.nodes[&10].total_eligible_seconds, 60);
        let record = &ledger.availability_slots["0:10:0"];
        assert_eq!(record.primary_operation_ids.len(), 3);
        assert_eq!(record.audit_operation_ids.len(), 2);
        assert_eq!(record.credited_seconds, 60);
    }

    #[test]
    fn closed_epoch_accepts_attestations_until_its_finality_deadline() {
        let password = "availability-boundary-password";
        let owner_file = generate_keyfile(password).unwrap();
        let owner_key = decrypt_key(&owner_file, password).unwrap();
        let relay_file = generate_keyfile(password).unwrap();
        let relay_key = decrypt_key(&relay_file, password).unwrap();
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            epoch_seconds_snapshot: 60,
            ..LedgerState::default()
        };
        ledger.settings.epoch_seconds = 60;
        ledger.settings.availability_slot_seconds = 60;
        ledger.settings.required_service_bond = 0;
        ledger.settings.warmup_seconds = 0;
        let mut verifier = availability_test_node(1);
        verifier.owner_address = owner_file.address.clone();
        verifier.owner_public_key = owner_file.public_key.clone();
        ledger.nodes.insert(1, verifier);
        let mut target = availability_test_node(2);
        target.relay_public_key = relay_file.public_key.clone();
        let ip_slot = target.ip_slot.clone();
        ledger.nodes.insert(2, target);
        assert!(bind_ip_slot_if_available(&mut ledger, &ip_slot, 2, 0));
        reset_epoch_context(&mut ledger);

        let ticket_signature = sign_bytes(
            &owner_key,
            &availability_ticket_message(
                &ledger.ledger_id,
                0,
                0,
                2,
                1,
                AvailabilityVerifierRole::Primary,
            ),
        );
        let challenge = availability_challenge(&ticket_signature);
        let response_timestamp = 50;
        let response = ProbePayload {
            protocol: "mrk-probe-v1".to_owned(),
            node_id: 2,
            relay_public_key: relay_file.public_key.clone(),
            timestamp: response_timestamp,
            challenge: challenge.clone(),
            signature: sign_bytes(
                &relay_key,
                format!("mrk-probe-v1:2:{response_timestamp}:{challenge}").as_bytes(),
            ),
        };
        let operation = sign_public_operation(
            &owner_file,
            password,
            PublicOperationSigningRequest {
                ledger_id: &ledger.ledger_id,
                module: "Availability",
                action: "AttestProbe",
                nonce: 1,
                valid_until: 120,
                max_fee_base_units: 0,
                fee_policy_version: ledger.settings.fee_policy.version,
                payload: json!({
                    "target_node_id": 2,
                    "verifier_node_id": 1,
                    "slot": 0,
                    "epoch": 0,
                    "role": AvailabilityVerifierRole::Primary,
                    "ticket_signature": ticket_signature,
                    "probe": response,
                }),
            },
        )
        .unwrap();

        advance_epochs_for_block(&mut ledger, 61).unwrap();
        assert_eq!(ledger.epoch_number, 1);
        apply_availability_attestation(
            &mut ledger,
            &owner_file.public_key,
            &operation,
            "boundary-attestation",
            61,
        )
        .unwrap();
        assert_eq!(eligible_seconds(&ledger.nodes[&2], 0), 60);
        settle_finalized_epochs_for_block(&mut ledger, 89).unwrap();
        assert!(ledger.epoch_contexts.contains_key(&0));
        settle_finalized_epochs_for_block(&mut ledger, 90).unwrap();
        assert!(!ledger.epoch_contexts.contains_key(&0));
        assert_eq!(eligible_seconds(&ledger.nodes[&2], 0), 0);
        assert!(ledger.nodes[&2].claimable_reward > 0);
    }

    #[test]
    fn parameter_batches_validate_and_activate_as_one_epoch_configuration() {
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            ..LedgerState::default()
        };
        reset_epoch_context(&mut ledger);
        let original = ledger.settings.clone();
        let invalid = BTreeMap::from([
            ("epoch-seconds".to_owned(), "300".to_owned()),
            ("availability-slot-seconds".to_owned(), "70".to_owned()),
        ]);
        assert!(apply_governance_parameter_batch(&mut ledger, &invalid, None).is_err());
        assert_eq!(ledger.settings.epoch_seconds, original.epoch_seconds);
        assert_eq!(
            ledger.settings.availability_slot_seconds,
            original.availability_slot_seconds
        );

        let changes = BTreeMap::from([
            ("epoch-seconds".to_owned(), "300".to_owned()),
            ("epoch-mint-amount".to_owned(), "100MRK".to_owned()),
            ("availability-slot-seconds".to_owned(), "60".to_owned()),
        ]);
        assert_eq!(
            apply_governance_parameter_batch(&mut ledger, &changes, None).unwrap(),
            1
        );
        assert_eq!(ledger.settings.epoch_seconds, 300);
        assert_eq!(
            epoch_context(&ledger, 0).unwrap().settings.epoch_seconds,
            1_800
        );
        advance_epochs_for_block(&mut ledger, 1_800).unwrap();
        let context = epoch_context(&ledger, 1).unwrap();
        assert_eq!(context.settings.epoch_seconds, 300);
        assert_eq!(
            context.settings.epoch_mint_amount,
            100 * crate::amount::MRK_SCALE
        );
        assert_eq!(context.settings.availability_slot_seconds, 60);
    }

    #[test]
    fn epoch_transition_records_the_previous_finalized_account_ranking_index() {
        let root = std::env::temp_dir().join(format!(
            "mrk-account-ranking-{}",
            crate::crypto::hex_lower(&crate::crypto::random_bytes::<8>().unwrap())
        ));
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            epoch_seconds_snapshot: 60,
            ..LedgerState::default()
        };
        ledger.settings.epoch_seconds = 60;
        ledger.accounts.insert(
            "mrk1beta".to_owned(),
            AccountState {
                balance: 100,
                ..AccountState::default()
            },
        );
        for address in ["mrk1gamma", "mrk1alpha"] {
            ledger.accounts.insert(
                address.to_owned(),
                AccountState {
                    balance: 200,
                    ..AccountState::default()
                },
            );
        }
        reset_epoch_context(&mut ledger);
        let ledger_id = ledger.ledger_id.clone();
        let block = |height, previous: &str, block_hash: &str, timestamp| BlockRecord {
            version: PROTOCOL_VERSION,
            ledger_id: ledger_id.clone(),
            height,
            previous_block_hash: previous.to_owned(),
            timestamp,
            producer_node_id: 1,
            producer_owner_address: "mrk1owner".to_owned(),
            operation_ids: Vec::new(),
            state_root: format!("state_{height}"),
            block_hash: block_hash.to_owned(),
            producer_signature: "signature".to_owned(),
            consensus_mode: BlockConsensusMode::Node1,
            consensus_round: 0,
            validator_set_hash: String::new(),
            commit_signatures: Vec::new(),
            validator_epoch: 0,
            validator_node_ids: Vec::new(),
        };
        ledger.blocks.push(block(1, "GENESIS", "blk_epoch_0", 30));
        paths
            .with_ledger_mut(|stored| {
                *stored = ledger;
                Ok(())
            })
            .unwrap();

        paths
            .with_active_ledger_mut(|ledger| {
                advance_epochs_for_block(ledger, 60)?;
                ledger
                    .blocks
                    .push(block(2, "blk_epoch_0", "blk_epoch_1", 60));
                Ok(())
            })
            .unwrap();

        let first = account_rankings(&paths, None, 2).unwrap();
        assert_eq!(first.snapshot_epoch, 0);
        assert_eq!(first.snapshot_height, 1);
        assert_eq!(first.total_account_balance_base_units, "500");
        assert_eq!(first.accounts[0].address, "mrk1alpha");
        assert_eq!(first.accounts[1].address, "mrk1gamma");
        let cursor = first.next_cursor.unwrap();
        assert_eq!(
            account_rankings(&paths, Some(&cursor), 2).unwrap().accounts[0].address,
            "mrk1beta"
        );

        drop(paths);
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        assert_eq!(
            account_rankings(&paths, None, 10).unwrap().accounts[0].address,
            "mrk1alpha"
        );

        paths
            .with_ledger_mut(|ledger| {
                ledger.accounts.get_mut("mrk1beta").unwrap().balance = 1_000;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            account_rankings(&paths, None, 10)
                .unwrap()
                .total_account_balance_base_units,
            "500"
        );
        paths
            .with_active_ledger_mut(|ledger| {
                ledger
                    .blocks
                    .push(block(3, "blk_epoch_1", "blk_epoch_1_mid", 90));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            account_rankings(&paths, None, 10)
                .unwrap()
                .total_account_balance_base_units,
            "500"
        );
        paths
            .with_active_ledger_mut(|ledger| {
                advance_epochs_for_block(ledger, 120)?;
                ledger
                    .blocks
                    .push(block(4, "blk_epoch_1_mid", "blk_epoch_2", 120));
                Ok(())
            })
            .unwrap();
        assert!(account_rankings(&paths, Some(&cursor), 2).is_err());
        let refreshed = account_rankings(&paths, None, 10).unwrap();
        assert_eq!(refreshed.snapshot_epoch, 1);
        assert_eq!(refreshed.accounts[0].address, "mrk1beta");
        assert_eq!(refreshed.total_account_balance_base_units, "1400");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parameter_batches_can_be_scheduled_for_a_future_epoch() {
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            ..LedgerState::default()
        };
        reset_epoch_context(&mut ledger);
        let original = ledger.settings.clone();
        let changes = BTreeMap::from([
            ("epoch-seconds".to_owned(), "300".to_owned()),
            ("availability-slot-seconds".to_owned(), "60".to_owned()),
        ]);

        assert_eq!(
            apply_governance_parameter_batch(&mut ledger, &changes, Some(2)).unwrap(),
            2
        );
        assert_eq!(ledger.settings.epoch_seconds, original.epoch_seconds);
        assert_eq!(ledger.scheduled_parameter_changes[&2], changes);

        advance_epochs_for_block(&mut ledger, 1_800).unwrap();
        assert_eq!(ledger.epoch_number, 1);
        assert_eq!(ledger.settings.epoch_seconds, original.epoch_seconds);

        advance_epochs_for_block(&mut ledger, 3_600).unwrap();
        assert_eq!(ledger.epoch_number, 2);
        assert_eq!(ledger.settings.epoch_seconds, 300);
        assert_eq!(ledger.settings.availability_slot_seconds, 60);
        assert!(!ledger.scheduled_parameter_changes.contains_key(&2));
        assert_eq!(
            epoch_context(&ledger, 2).unwrap().settings.epoch_seconds,
            300
        );
    }

    #[test]
    fn fee_policy_updates_are_atomic_versioned_and_delayed_two_epochs() {
        let mut ledger = LedgerState {
            created_at: 0,
            epoch_started_at: 0,
            epoch_number: 0,
            ..LedgerState::default()
        };
        reset_epoch_context(&mut ledger);
        let incomplete = BTreeMap::from([("base-fee-per-unit".to_owned(), "0.002MRK".to_owned())]);
        assert!(apply_governance_parameter_batch(&mut ledger, &incomplete, Some(2)).is_err());

        let changes = BTreeMap::from([
            ("base-fee-per-unit".to_owned(), "0.002MRK".to_owned()),
            ("fee-min-multiplier-bps".to_owned(), "2500".to_owned()),
            ("fee-max-multiplier-bps".to_owned(), "100000".to_owned()),
            ("fee-target-units-per-epoch".to_owned(), "800000".to_owned()),
            ("fee-max-units-per-block".to_owned(), "12000".to_owned()),
            ("fee-adjustment-denominator".to_owned(), "8".to_owned()),
            ("traffic-protocol-fee-bps".to_owned(), "120".to_owned()),
            ("traffic-treasury-share-bps".to_owned(), "6000".to_owned()),
        ]);
        assert!(apply_governance_parameter_batch(&mut ledger, &changes, Some(1)).is_err());
        assert_eq!(
            apply_governance_parameter_batch(&mut ledger, &changes, Some(2)).unwrap(),
            2
        );
        assert_eq!(ledger.settings.fee_policy.version, 1);
        assert_eq!(
            ledger.settings.fee_policy.base_fee_per_unit,
            crate::amount::parse_mrk("0.001MRK").unwrap()
        );

        advance_epochs_for_block(&mut ledger, 1_800).unwrap();
        assert_eq!(ledger.settings.fee_policy.version, 1);
        advance_epochs_for_block(&mut ledger, 3_600).unwrap();
        assert_eq!(ledger.settings.fee_policy.version, 2);
        assert_eq!(
            ledger.settings.fee_policy.base_fee_per_unit,
            crate::amount::parse_mrk("0.002MRK").unwrap()
        );
        assert_eq!(ledger.settings.fee_policy.traffic_protocol_fee_bps, 120);
        assert_eq!(ledger.settings.fee_policy.traffic_treasury_share_bps, 6000);
    }

    #[test]
    fn parameter_schedule_rejects_stale_epochs_and_future_constraint_conflicts() {
        let mut ledger = LedgerState {
            epoch_number: 4,
            ..LedgerState::default()
        };
        let epoch_change = BTreeMap::from([("epoch-seconds".to_owned(), "300".to_owned())]);
        assert!(apply_governance_parameter_batch(&mut ledger, &epoch_change, Some(4)).is_err());
        apply_governance_parameter_batch(&mut ledger, &epoch_change, Some(6)).unwrap();

        let earlier_conflict =
            BTreeMap::from([("availability-slot-seconds".to_owned(), "120".to_owned())]);
        assert!(apply_governance_parameter_batch(&mut ledger, &earlier_conflict, Some(5)).is_err());
        assert!(!ledger.scheduled_parameter_changes.contains_key(&5));
        assert_eq!(ledger.scheduled_parameter_changes[&6], epoch_change);
    }

    #[test]
    fn governance_power_uses_only_age_and_dynamic_one_percent_cap() {
        let mut ledger = LedgerState::default();
        let mut node_ids = Vec::new();
        for node_id in 1..=120 {
            let mature = node_id <= 60;
            ledger.nodes.insert(
                node_id,
                NodeRecord {
                    node_id,
                    previous_node_id: None,
                    name: format!("node{node_id}"),
                    owner_address: format!("owner{node_id}"),
                    owner_public_key: format!("owner-key{node_id}"),
                    relay_public_key: format!("relay-key{node_id}"),
                    reward_address: format!("reward{node_id}"),
                    endpoint: "wss://1.1.1.1/v1/relay".to_owned(),
                    reward_ip: format!("9.8.7.{node_id}"),
                    ip_slot: format!("v4:9.8.7.{node_id}"),
                    price_per_gib: 0,
                    status: NodeStatus::Active,
                    registered_at: 0,
                    warmup_until: 0,
                    active_since: Some(0),
                    last_heartbeat: Some(0),
                    last_probe_success: Some(0),
                    probe_success_count: 1,
                    last_relay_receipt_at: None,
                    eligible_seconds_by_epoch: BTreeMap::new(),
                    total_eligible_seconds: if mature { 180 * 86_400 } else { 30 * 86_400 },
                    service_bond: if node_id == 1 {
                        10_000_000 * crate::amount::MRK_SCALE
                    } else {
                        100 * crate::amount::MRK_SCALE
                    },
                    service_bond_unlock_at: None,
                    governance_bond: 0,
                    governance_bonded_at: None,
                    governance_exit_requested_at: None,
                    governance_bond_unlock_at: None,
                    offline_slashed_at: None,
                    offline_slashed_service_bond: 0,
                    offline_slashed_vesting_reward: 0,
                    claimable_reward: 0,
                    reward_vesting_buckets: Vec::new(),
                    validator: node_id == 1,
                    validator_signature_rate_bps: 10_000,
                    validator_bond: if node_id == 1 {
                        50_000 * crate::amount::MRK_SCALE
                    } else {
                        0
                    },
                    validator_candidate_since: None,
                    validator_last_epoch: None,
                    validator_consecutive_epochs: 0,
                    validator_exit_requested_at: None,
                    validator_bond_unlock_at: None,
                },
            );
            node_ids.push(node_id);
        }
        let power = governance_power_snapshot_for_nodes(&ledger, &node_ids).unwrap();
        assert_eq!(
            power[&1], power[&2],
            "MRK and Validator status must not add power"
        );
        assert_eq!(power[&1], 45);
        assert_eq!(power[&61], 30);
        let total = power.values().sum::<u128>();
        assert!(power[&1] * 100 <= total, "one Node must not exceed 1%");
    }

    #[test]
    fn epoch_mints_fixed_budget_and_forms_bond_first() {
        let now = 1_700_000_000;
        let mut ledger = LedgerState {
            epoch_started_at: now,
            ..LedgerState::default()
        };
        ledger.settings.epoch_seconds = 60;
        ledger.epoch_seconds_snapshot = 60;
        ledger.settings.required_service_bond = 10;
        reset_epoch_context(&mut ledger);
        ledger.nodes.insert(
            1,
            NodeRecord {
                node_id: 1,
                previous_node_id: None,
                name: "n1".into(),
                owner_address: "owner".into(),
                owner_public_key: "key".into(),
                relay_public_key: "relay".into(),
                reward_address: "owner".into(),
                endpoint: "wss://1.1.1.1".into(),
                reward_ip: "1.1.1.1".into(),
                ip_slot: "v4:1.1.1.1".into(),
                price_per_gib: 0,
                status: NodeStatus::Active,
                registered_at: now,
                warmup_until: now,
                active_since: Some(now),
                last_heartbeat: Some(now + 60),
                last_probe_success: Some(now),
                probe_success_count: 1,
                last_relay_receipt_at: None,
                eligible_seconds_by_epoch: BTreeMap::from([(0, 60)]),
                total_eligible_seconds: 60,
                service_bond: 0,
                service_bond_unlock_at: None,
                governance_bond: 0,
                governance_bonded_at: None,
                governance_exit_requested_at: None,
                governance_bond_unlock_at: None,
                offline_slashed_at: None,
                offline_slashed_service_bond: 0,
                offline_slashed_vesting_reward: 0,
                claimable_reward: 0,
                reward_vesting_buckets: Vec::new(),
                validator: false,
                validator_signature_rate_bps: 0,
                validator_bond: 0,
                validator_candidate_since: None,
                validator_last_epoch: None,
                validator_consecutive_epochs: 0,
                validator_exit_requested_at: None,
                validator_bond_unlock_at: None,
            },
        );
        settle_elapsed_epochs_for_block(&mut ledger, now + 60).unwrap();
        assert_eq!(
            ledger.lifetime_minted,
            crate::amount::GENESIS_TREASURY_ALLOCATION,
            "closed Epoch rewards wait for the finality grace period"
        );
        settle_elapsed_epochs_for_block(&mut ledger, now + 90).unwrap();
        let node = &ledger.nodes[&1];
        let expected = 500 * crate::amount::MRK_SCALE;
        let reward_after_bond = expected - 10;
        let immediate = reward_after_bond * 2_500 / BPS_DENOMINATOR;
        let vesting = reward_after_bond - immediate;
        assert_eq!(node.service_bond, 10);
        assert_eq!(node.claimable_reward, immediate);
        assert_eq!(node_vesting_reward(node).unwrap(), vesting);
        assert_eq!(node.reward_vesting_buckets.len(), 180);
        assert_eq!(
            ledger.lifetime_minted,
            crate::amount::GENESIS_TREASURY_ALLOCATION + expected
        );
        ledger.settings.required_service_bond = 0;
        ledger.settings.epoch_seconds = 120;
        ledger.settings.epoch_mint_amount = 450 * crate::amount::MRK_SCALE;
        ledger.settings.reward_immediate_bps = 2_000;
        ledger.settings.reward_vesting_seconds = 1_000;
        set_eligible_seconds(ledger.nodes.get_mut(&1).unwrap(), 1, 60);
        let node_one_before = ledger.nodes[&1].claimable_reward;
        let mut node_two = ledger.nodes[&1].clone();
        node_two.node_id = 2;
        set_eligible_seconds(&mut node_two, 1, 30);
        node_two.total_eligible_seconds = 30;
        node_two.service_bond = 0;
        node_two.claimable_reward = 0;
        node_two.reward_vesting_buckets.clear();
        ledger.nodes.insert(2, node_two);
        settle_elapsed_epochs_for_block(&mut ledger, now + 120).unwrap();
        settle_elapsed_epochs_for_block(&mut ledger, now + 150).unwrap();
        let second_budget = 500 * crate::amount::MRK_SCALE;
        let node_two_reward = second_budget / 5;
        let node_one_reward = second_budget - node_two_reward;
        assert_eq!(
            ledger.nodes[&1].claimable_reward - node_one_before,
            node_one_reward * 2_500 / BPS_DENOMINATOR
        );
        assert_eq!(ledger.nodes[&2].service_bond, 10);
        assert_eq!(
            ledger.nodes[&2].claimable_reward,
            (node_two_reward - 10) * 2_500 / BPS_DENOMINATOR
        );
        assert_eq!(
            ledger.epoch_mint_amount_snapshot,
            450 * crate::amount::MRK_SCALE,
            "governance changes must become active in the next Epoch"
        );
        assert_eq!(ledger.epoch_seconds_snapshot, 120);
        assert_eq!(ledger.reward_immediate_bps_snapshot, 2_000);
        assert_eq!(ledger.reward_vesting_seconds_snapshot, 1_000);
        let epoch_number = ledger.epoch_number;
        set_eligible_seconds(ledger.nodes.get_mut(&1).unwrap(), epoch_number, 60);
        settle_elapsed_epochs_for_block(&mut ledger, now + 239).unwrap();
        assert_eq!(ledger.epoch_number, epoch_number);
        assert_eq!(eligible_seconds(&ledger.nodes[&1], epoch_number), 60);
    }

    #[test]
    fn reward_release_parameters_are_critical_and_bounded() {
        let mut settings = LedgerSettings::default();
        assert!(governance_parameter_is_critical("reward-immediate-bps"));
        assert!(governance_parameter_is_critical("reward-vesting-seconds"));
        assert!(governance_parameter_is_critical(
            "service-bond-unlock-seconds"
        ));
        assert!(governance_parameter_is_critical("offline-slash-seconds"));
        assert_eq!(
            set_governance_parameter(&mut settings, "reward-immediate-bps", "3000").unwrap(),
            ("2500".to_owned(), "3000".to_owned())
        );
        assert_eq!(settings.reward_immediate_bps, 3_000);
        assert!(set_governance_parameter(&mut settings, "reward-immediate-bps", "10001").is_err());
        assert_eq!(
            set_governance_parameter(&mut settings, "reward-vesting-seconds", "86400").unwrap(),
            ((180 * 86_400).to_string(), "86400".to_owned())
        );
        assert_eq!(settings.reward_vesting_seconds, 86_400);
        assert!(set_governance_parameter(&mut settings, "reward-vesting-seconds", "0").is_err());
        assert_eq!(
            set_governance_parameter(&mut settings, "service-bond-unlock-seconds", "86400")
                .unwrap(),
            ((30 * 86_400).to_string(), "86400".to_owned())
        );
        assert_eq!(settings.service_bond_unlock_seconds, 86_400);
        assert!(
            set_governance_parameter(
                &mut settings,
                "service-bond-unlock-seconds",
                &(365_i64 * 86_400 + 1).to_string(),
            )
            .is_err()
        );
        assert_eq!(
            set_governance_parameter(&mut settings, "offline-slash-seconds", "86400").unwrap(),
            ((7 * 86_400).to_string(), "86400".to_owned())
        );
        assert_eq!(settings.offline_slash_seconds, 86_400);
        assert!(set_governance_parameter(&mut settings, "offline-slash-seconds", "3599").is_err());
    }

    #[test]
    fn validator_rotation_interval_is_critical_and_bounded() {
        let mut settings = LedgerSettings::default();
        assert!(governance_parameter_is_critical(
            "validator-rotation-interval-epochs"
        ));
        assert_eq!(settings.validator_rotation_interval_epochs, 1);
        assert_eq!(
            set_governance_parameter(&mut settings, "validator-rotation-interval-epochs", "6",)
                .unwrap(),
            ("1".to_owned(), "6".to_owned())
        );
        assert_eq!(settings.validator_rotation_interval_epochs, 6);
        assert!(
            set_governance_parameter(&mut settings, "validator-rotation-interval-epochs", "0",)
                .is_err()
        );
        assert!(
            set_governance_parameter(&mut settings, "validator-rotation-interval-epochs", "10001",)
                .is_err()
        );
    }

    #[test]
    fn governance_bond_parameters_are_critical_and_bounded() {
        let mut settings = LedgerSettings::default();
        for parameter in [
            "governance-bond",
            "governance-bond-maturity-seconds",
            "governance-bond-unlock-seconds",
        ] {
            assert!(governance_parameter_is_critical(parameter));
        }
        assert_eq!(
            set_governance_parameter(&mut settings, "governance-bond", "12000MRK").unwrap(),
            ("10000 MRK".to_owned(), "12000 MRK".to_owned())
        );
        assert_eq!(
            settings.required_governance_bond,
            12_000 * crate::amount::MRK_SCALE
        );
        assert!(set_governance_parameter(&mut settings, "governance-bond", "0MRK").is_err());
        set_governance_parameter(&mut settings, "governance-bond-maturity-seconds", "5184000")
            .unwrap();
        set_governance_parameter(&mut settings, "governance-bond-unlock-seconds", "2592000")
            .unwrap();
        assert_eq!(settings.governance_bond_maturity_seconds, 60 * 86_400);
        assert_eq!(settings.governance_bond_unlock_seconds, 30 * 86_400);
    }

    #[test]
    fn availability_audit_parameters_are_critical_and_cross_checked() {
        let mut settings = LedgerSettings::default();
        for parameter in [
            "availability-audit-rate-bps",
            "availability-auditor-count",
            "availability-audit-quorum",
        ] {
            assert!(governance_parameter_is_critical(parameter));
        }
        assert_eq!(settings.availability_verifier_count, 5);
        assert_eq!(settings.availability_quorum, 3);
        assert_eq!(settings.availability_audit_rate_bps, 500);
        assert_eq!(settings.availability_auditor_count, 3);
        assert_eq!(settings.availability_audit_quorum, 2);
        set_governance_parameter(&mut settings, "availability-audit-rate-bps", "750").unwrap();
        assert_eq!(settings.availability_audit_rate_bps, 750);
        assert!(
            set_governance_parameter(&mut settings, "availability-audit-rate-bps", "10001")
                .is_err()
        );
        assert!(
            set_governance_parameter(&mut settings, "availability-auditor-count", "1").is_err()
        );
        assert!(set_governance_parameter(&mut settings, "availability-audit-quorum", "4").is_err());
        assert!(
            set_governance_parameter(&mut settings, "availability-slot-seconds", "59").is_err()
        );
        assert!(set_governance_parameter(&mut settings, "max-active-validators", "6").is_err());
    }

    #[test]
    fn reward_vesting_buckets_merge_by_quantized_unlock_time() {
        let mut node = NodeRecord {
            node_id: 1,
            previous_node_id: None,
            name: "n1".into(),
            owner_address: "owner".into(),
            owner_public_key: "key".into(),
            relay_public_key: "relay".into(),
            reward_address: "reward".into(),
            endpoint: "wss://1.1.1.1".into(),
            reward_ip: "1.1.1.1".into(),
            ip_slot: "v4:1.1.1.1".into(),
            price_per_gib: 0,
            status: NodeStatus::Active,
            registered_at: 0,
            warmup_until: 0,
            active_since: Some(0),
            last_heartbeat: None,
            last_probe_success: None,
            probe_success_count: 0,
            last_relay_receipt_at: None,
            eligible_seconds_by_epoch: BTreeMap::new(),
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            governance_bond: 0,
            governance_bonded_at: None,
            governance_exit_requested_at: None,
            governance_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 10,
            reward_vesting_buckets: Vec::new(),
            validator: false,
            validator_signature_rate_bps: 0,
            validator_bond: 0,
            validator_candidate_since: None,
            validator_last_epoch: None,
            validator_consecutive_epochs: 0,
            validator_exit_requested_at: None,
            validator_bond_unlock_at: None,
        };

        let vesting_seconds = 180 * REWARD_VESTING_STEP_SECONDS;
        add_node_reward_vesting(&mut node, 180, 60, vesting_seconds, 0).unwrap();
        add_node_reward_vesting(&mut node, 360, 120, vesting_seconds, 0).unwrap();
        assert_eq!(node.reward_vesting_buckets.len(), 180);
        assert_eq!(node_vesting_reward(&node).unwrap(), 540);
        assert!(
            node.reward_vesting_buckets
                .iter()
                .all(|bucket| bucket.amount == 3)
        );

        let first_unlock = node.reward_vesting_buckets[0].unlock_at;
        settle_node_reward_vesting(&mut node, first_unlock - 1).unwrap();
        assert_eq!(node.claimable_reward, 10);
        settle_node_reward_vesting(&mut node, first_unlock).unwrap();
        assert_eq!(node.claimable_reward, 13);
        assert_eq!(node_vesting_reward(&node).unwrap(), 537);

        let last_unlock = node.reward_vesting_buckets.last().unwrap().unlock_at;
        settle_node_reward_vesting(&mut node, last_unlock).unwrap();
        assert_eq!(node.claimable_reward, 550);
        assert_eq!(node_vesting_reward(&node).unwrap(), 0);
        assert!(node.reward_vesting_buckets.is_empty());
    }

    #[test]
    fn reward_vesting_cumulative_targets_preserve_small_amounts() {
        let mut node = availability_test_node(1);
        node.validator = false;
        add_node_reward_vesting(&mut node, 2, 0, 3 * REWARD_VESTING_STEP_SECONDS, 0).unwrap();
        assert_eq!(node.reward_vesting_buckets.len(), 2);
        assert_eq!(node_vesting_reward(&node).unwrap(), 2);
        assert!(
            node.reward_vesting_buckets
                .iter()
                .all(|bucket| bucket.amount == 1)
        );
    }

    #[test]
    fn short_reward_vesting_uses_a_matching_quantization_unit() {
        let mut node = availability_test_node(1);
        node.validator = false;
        add_node_reward_vesting(&mut node, 10, 100, 1, 0).unwrap();
        assert_eq!(
            node.reward_vesting_buckets,
            vec![RewardVestingBucket {
                unlock_at: 101,
                amount: 10,
            }]
        );
        settle_node_reward_vesting(&mut node, 100).unwrap();
        assert_eq!(node.claimable_reward, 0);
        settle_node_reward_vesting(&mut node, 101).unwrap();
        assert_eq!(node.claimable_reward, 10);
    }

    #[test]
    fn treasury_spending_enforces_single_and_rolling_limits() {
        let now = 1_800_000_000;
        let mut ledger = LedgerState::default();
        let one_percent = ledger.treasury / 100;
        assert!(validate_treasury_spend_amount(&ledger, one_percent, now).is_ok());
        assert!(validate_treasury_spend_amount(&ledger, one_percent + 1, now).is_err());

        ledger.treasury_spends.push(TreasurySpendRecord {
            proposal_id: 1,
            operation_id: "op_recent".to_owned(),
            recipient: "recipient".to_owned(),
            amount: ledger.treasury * 19 / 1_000,
            reference_hash: format!("sha256:{}", "a".repeat(64)),
            executed_at: now - 30 * 86_400,
        });
        assert!(
            validate_treasury_spend_amount(&ledger, ledger.treasury / 500, now).is_err(),
            "recent spend plus new amount must not exceed the rolling 2% limit"
        );

        ledger.treasury_spends.clear();
        ledger.treasury_spends.push(TreasurySpendRecord {
            proposal_id: 2,
            operation_id: "op_annual".to_owned(),
            recipient: "recipient".to_owned(),
            amount: ledger.treasury * 49 / 1_000,
            reference_hash: format!("sha256:{}", "b".repeat(64)),
            executed_at: now - 180 * 86_400,
        });
        assert!(
            validate_treasury_spend_amount(&ledger, ledger.treasury / 500, now).is_err(),
            "annual spend plus new amount must not exceed the rolling 5% limit"
        );
    }

    #[test]
    fn lite_pruning_preserves_chain_tip_and_future_height() {
        let root = std::env::temp_dir().join(format!(
            "mrk-lite-prune-{}",
            hex_lower(&random_bytes::<8>().unwrap())
        ));
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        let password = "lite-prune-test-password";
        let now = 1_900_000_000;
        init_node_with_storage_mode(&paths, "node1", password, NodeStorageMode::Lite).unwrap();
        join_node(
            &paths,
            "node1",
            password,
            "wss://1.1.1.1/v1/relay",
            Some("0.02MRK"),
            now,
        )
        .unwrap();
        produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
        for (offset, value) in [(2, "6"), (3, "7"), (4, "8")] {
            governance_set_parameter(
                &paths,
                "node1",
                password,
                "block-interval-seconds",
                value,
                now + offset,
            )
            .unwrap();
            produce_node1_block(&paths, "node1", password, false, now + offset).unwrap();
        }

        let report = paths
            .with_ledger_mut(|ledger| Ok(crate::store::prune_history(ledger, 2, 1)))
            .unwrap();
        assert_eq!(report.pruned_blocks, 2);
        assert_eq!(report.retained_blocks, 2);
        assert_eq!(report.pruned_through_height, 2);
        assert_eq!(
            paths.read_ledger().unwrap().operation_history_from_height,
            3
        );
        let retained = paths.read_ledger().unwrap();
        for block in &retained.blocks {
            for operation_id in &block.operation_ids {
                assert!(retained.operations.contains_key(operation_id));
            }
        }
        assert!(
            block_by_height(&paths, 1)
                .unwrap_err()
                .to_string()
                .contains("pruned")
        );
        assert_eq!(block_by_height(&paths, 3).unwrap().height, 3);
        let newest = blocks(&paths, None, 1).unwrap();
        assert_eq!(newest.blocks.len(), 1);
        assert_eq!(newest.blocks[0].height, 4);
        assert_eq!(newest.next_cursor, Some(4));
        let older = blocks(&paths, newest.next_cursor, 10).unwrap();
        assert_eq!(
            older
                .blocks
                .iter()
                .map(|block| block.height)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(older.next_cursor, None);
        let operations = block_operations(&paths, 4, 0, 100).unwrap();
        assert_eq!(
            operations.operations.len(),
            block_by_height(&paths, 4).unwrap().operation_ids.len()
        );
        let verification = verify_blockchain(&paths).unwrap();
        assert!(verification.ok, "{}", verification.detail);
        assert_eq!(verification.height, 4);
        let next = produce_node1_block(&paths, "node1", password, true, now + 10).unwrap();
        assert_eq!(next.height, 5);
        assert_eq!(
            next.previous_block_hash,
            block_by_height(&paths, 4).unwrap().block_hash
        );

        std::fs::remove_dir_all(root).unwrap();
    }
}
