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
    crypto::{
        EncryptedKeyFile, address_from_public_key, decrypt_key, generate_keyfile, hex_lower,
        random_bytes, sha256_full_id, sha256_id, sign_bytes, validate_address,
        validate_keystore_password, verify_bytes,
    },
    model::{
        AvailabilityMode, AvailabilitySlotRecord, AvailabilityVerifierRole, BlockConsensusMode,
        BlockRecord, ConsensusProposal, ConsensusVote, ConsensusVoteType,
        DEFAULT_OPERATION_VALIDITY_SECONDS, DoubleSignEvidence, GenesisAuthority,
        GovernanceActionRecord, GovernanceProposalAction, GovernanceProposalKind,
        GovernanceProposalRecord, GovernanceProposalStatus, GovernanceValidatorVoteRecord,
        GovernanceVoteChoice, GovernanceVoteRecord, IpSlotRecord, LedgerSettings, LedgerState,
        LocalNodeConfig, MemberCredential, MemberRecord, NetworkRecord, NodeRecord, NodeStatus,
        NodeStorageMode, OperationRecord, OperationStatus, PROTOCOL_VERSION,
        PaymentAuthorizationRecord, RelayDirection, RewardVestingSchedule, SignedOperation,
        TRANSFER_FEE, TrafficDirectionSettlement, TreasurySpendRecord, UnsignedOperation,
    },
    relay::{
        ChallengePayload, HelloPayload, ProbePayload, RELAY_PAYMENT_CLAIM_SECONDS, ReceiverReceipt,
        SenderCheckpoint, credential_signing_bytes, hello_signing_bytes,
        receiver_receipt_signing_bytes, sender_checkpoint_hash, sender_checkpoint_signing_bytes,
    },
    storage::{DataPaths, atomic_write_json, read_json, validate_name},
};

pub const GOVERNANCE_NODE_THRESHOLD: usize = 20;
pub const MIN_ACTIVE_VALIDATORS: usize = 4;
pub const MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS: usize = 7;
pub const MIN_AUDITED_AVAILABILITY_VALIDATORS: usize = 9;
pub const MAX_BLOCK_OPERATIONS: usize = 10_000;
const BPS_DENOMINATOR: u128 = 10_000;
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

#[derive(Clone, Debug, Serialize)]
pub struct BalanceView {
    pub address: String,
    pub balance: u128,
    pub balance_display: String,
    pub nonce: u64,
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
    pub vesting_schedule_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryNodeView {
    pub node_id: u64,
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
    pub service_bond_base_units: String,
    pub service_bond_display: String,
    pub service_bond_unlock_at: Option<i64>,
    pub offline_slashed_at: Option<i64>,
    pub validator: bool,
    pub validator_candidate: bool,
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
    pub governance_eligible_count: usize,
    pub governance_eligible_node_ids: Vec<u64>,
    pub genesis_node_id: Option<u64>,
    pub genesis_owner_address: Option<String>,
    pub node1_direct_actions_enabled: bool,
    pub emission_paused: bool,
    pub pause_reason: Option<String>,
    pub current_epoch_seconds: i64,
    pub current_epoch_mint_amount: u128,
    pub current_reward_immediate_bps: u32,
    pub current_reward_vesting_seconds: i64,
    pub availability_mode: AvailabilityMode,
    pub availability_activated_at: Option<i64>,
    pub availability_activated_epoch: Option<u64>,
    pub minimum_decentralized_availability_validators: usize,
    pub settings: LedgerSettings,
    pub last_action_at: Option<i64>,
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
pub struct BlockVerificationReport {
    pub ok: bool,
    pub height: u64,
    pub checked_operations: usize,
    pub legacy_unverified_operations: usize,
    pub pruned_through_height: u64,
    pub pruned_operation_count: u64,
    pub detail: String,
}

pub const LITE_RETAIN_BLOCKS: usize = 65_536;
pub const LITE_RETAIN_OPERATIONS: usize = 262_144;
pub const LITE_RETAIN_ACCOUNT_OPERATIONS: usize = 1_024;

#[derive(Clone, Debug, Default, Serialize)]
pub struct HistoryPruneReport {
    pub pruned_blocks: usize,
    pub pruned_operations: usize,
    pub pruned_account_history_entries: usize,
    pub pruned_through_height: u64,
    pub retained_blocks: usize,
    pub retained_operations: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusCatchUpChunk {
    pub tip_height: u64,
    pub blocks: Vec<BlockRecord>,
    pub operations: Vec<OperationRecord>,
    pub finalized_checkpoint: Option<Box<LedgerState>>,
}

fn chain_height(ledger: &LedgerState) -> u64 {
    ledger.pruned_through_height + ledger.blocks.len() as u64
}

fn next_block_height(ledger: &LedgerState) -> u64 {
    chain_height(ledger) + 1
}

fn chain_tip_hash(ledger: &LedgerState) -> Option<&str> {
    ledger
        .blocks
        .last()
        .map(|block| block.block_hash.as_str())
        .or(ledger.pruned_tip_hash.as_deref())
}

fn chain_tip_timestamp(ledger: &LedgerState) -> Option<i64> {
    ledger
        .blocks
        .last()
        .map(|block| block.timestamp)
        .or(ledger.pruned_tip_timestamp)
}

pub fn consensus_catch_up_chunk(
    paths: &DataPaths,
    from_height: u64,
    max_blocks: usize,
) -> Result<ConsensusCatchUpChunk> {
    let ledger = paths.read_ledger()?;
    let tip_height = chain_height(&ledger);
    if from_height > tip_height {
        return Err(Error::msg(format!(
            "requested catch-up height {from_height} is ahead of local tip {tip_height}"
        )));
    }
    if from_height < ledger.pruned_through_height {
        return Err(Error::msg(format!(
            "requested history was pruned through height {}",
            ledger.pruned_through_height
        )));
    }
    let blocks = ledger
        .blocks
        .iter()
        .filter(|block| block.height > from_height)
        .take(max_blocks.clamp(1, crate::consensus::MAX_CATCH_UP_BLOCKS))
        .cloned()
        .collect::<Vec<_>>();
    let operation_ids = blocks
        .iter()
        .flat_map(|block| block.operation_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let operations = operation_ids
        .iter()
        .map(|operation_id| {
            ledger.operations.get(operation_id).cloned().ok_or_else(|| {
                Error::msg(format!(
                    "catch-up block references pruned operation {operation_id}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let reached_tip = blocks.last().map_or(from_height == tip_height, |block| {
        block.height == tip_height
    });
    let finalized_checkpoint = if reached_tip {
        ledger
            .finalized_checkpoint
            .clone()
            .filter(|checkpoint| checkpoint.pruned_through_height == tip_height)
    } else {
        None
    };
    Ok(ConsensusCatchUpChunk {
        tip_height,
        blocks,
        operations,
        finalized_checkpoint,
    })
}

pub fn apply_consensus_catch_up(
    paths: &DataPaths,
    blocks: Vec<BlockRecord>,
    operations: Vec<OperationRecord>,
    finalized_checkpoint: LedgerState,
) -> Result<u64> {
    paths.with_ledger_mut(|ledger| {
        if blocks.is_empty() {
            return Ok(chain_height(ledger));
        }
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
    })
}

pub fn prune_lite_history(paths: &DataPaths, name: &str) -> Result<HistoryPruneReport> {
    let config = paths.read_node_config(name)?;
    let ledger = paths.read_ledger()?;
    if config.storage_mode != NodeStorageMode::Lite
        || (ledger.blocks.len() <= LITE_RETAIN_BLOCKS
            && ledger.operations.len() <= LITE_RETAIN_OPERATIONS
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
        Ok(prune_history_with_limits(
            ledger,
            LITE_RETAIN_BLOCKS,
            LITE_RETAIN_OPERATIONS,
            LITE_RETAIN_ACCOUNT_OPERATIONS,
        ))
    })?;
    if report.pruned_blocks > 0
        || report.pruned_operations > 0
        || report.pruned_account_history_entries > 0
    {
        paths.compact_chain_db()?;
    }
    Ok(report)
}

fn prune_history_with_limits(
    ledger: &mut LedgerState,
    retained_block_limit: usize,
    retained_operation_limit: usize,
    retained_account_operation_limit: usize,
) -> HistoryPruneReport {
    let mut report = HistoryPruneReport::default();
    let remove_blocks = ledger.blocks.len().saturating_sub(retained_block_limit);
    if remove_blocks > 0 {
        let checkpoint = ledger.blocks[remove_blocks - 1].clone();
        ledger.blocks.drain(..remove_blocks);
        ledger.pruned_through_height = checkpoint.height;
        ledger.pruned_tip_hash = Some(checkpoint.block_hash);
        ledger.pruned_tip_timestamp = Some(checkpoint.timestamp);
        report.pruned_blocks = remove_blocks;
    }

    // Retain complete operation histories for the newest suffix of blocks. A single
    // large block is retained whole even if it exceeds the configured target.
    let mut retained_operation_ids = ledger
        .pending_operation_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut retained_finalized = 0_usize;
    let mut operation_history_from_height = next_block_height(ledger);
    for block in ledger.blocks.iter().rev() {
        if retained_finalized > 0
            && retained_finalized.saturating_add(block.operation_ids.len())
                > retained_operation_limit
        {
            break;
        }
        retained_finalized = retained_finalized.saturating_add(block.operation_ids.len());
        retained_operation_ids.extend(block.operation_ids.iter().cloned());
        operation_history_from_height = block.height;
    }
    ledger.operation_history_from_height = operation_history_from_height;
    let before_operations = ledger.operations.len();
    ledger.operations.retain(|operation_id, operation| {
        matches!(operation.status, OperationStatus::Pending)
            || retained_operation_ids.contains(operation_id)
    });
    report.pruned_operations = before_operations.saturating_sub(ledger.operations.len());
    ledger.pruned_operation_count = ledger
        .pruned_operation_count
        .saturating_add(report.pruned_operations as u64);

    for account in ledger.accounts.values_mut() {
        let before = account.operation_ids.len();
        account
            .operation_ids
            .retain(|operation_id| ledger.operations.contains_key(operation_id));
        if account.operation_ids.len() > retained_account_operation_limit {
            let remove = account.operation_ids.len() - retained_account_operation_limit;
            account.operation_ids.drain(..remove);
        }
        report.pruned_account_history_entries = report
            .pruned_account_history_entries
            .saturating_add(before.saturating_sub(account.operation_ids.len()));
    }
    report.pruned_through_height = ledger.pruned_through_height;
    report.retained_blocks = ledger.blocks.len();
    report.retained_operations = ledger.operations.len();
    report
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
    pub max_rotations_per_epoch: u32,
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
    pub proposer_node_id: Option<u64>,
    pub proposal_block_hash: Option<String>,
    pub prevote_count: usize,
    pub precommit_count: usize,
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
        spending_enabled: mature_count >= GOVERNANCE_NODE_THRESHOLD
            && active_validator_count >= MIN_ACTIVE_VALIDATORS,
        single_spend_limit_bps: TREASURY_SINGLE_SPEND_BPS,
        current_single_spend_limit: limit,
        current_single_spend_limit_display: format_mrk(limit),
        mature_governance_node_count: mature_count,
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
    let total = amount
        .checked_add(TRANSFER_FEE)
        .ok_or_else(|| Error::msg("transfer total overflow"))?;
    let ledger = paths.read_ledger()?;
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
        fee: TRANSFER_FEE,
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
            "fixed_fee_base_units": preview.fee.to_string(),
        });
        let signed = sign_operation(
            ledger,
            (&keyfile, &key_pair),
            "MRKAsset",
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
            sender.balance -= preview.total;
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
        ledger.burned = ledger
            .burned
            .checked_add(preview.fee)
            .ok_or_else(|| Error::msg("burn counter overflow"))?;
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
}

pub struct PublicOperationSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub module: &'a str,
    pub action: &'a str,
    pub nonce: u64,
    pub valid_until: i64,
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
        module: "MRKAsset".to_owned(),
        action: "Transfer".to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: request.nonce,
        valid_until: request.valid_until,
        payload: json!({
            "to": request.to,
            "amount_base_units": amount.to_string(),
            "fixed_fee_base_units": TRANSFER_FEE.to_string(),
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
        || operation.unsigned.module != "MRKAsset"
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
    let fee = parse_payload_u128(&operation.unsigned.payload, "fixed_fee_base_units")?;
    if amount == 0 || fee != TRANSFER_FEE {
        return Err(Error::msg("signed transfer amount or fee is invalid"));
    }
    let total = amount
        .checked_add(fee)
        .ok_or_else(|| Error::msg("signed transfer total overflow"))?;
    let operation_id = operation_id(&operation)?;
    paths.with_ledger_mut(|ledger| {
        if operation.unsigned.ledger_id != ledger.ledger_id {
            return Err(Error::msg("signed transfer targets a different ledger"));
        }
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
        sender.balance -= total;
        ledger.accounts.entry(to.clone()).or_default().balance = ledger
            .accounts
            .get(&to)
            .map(|account| account.balance)
            .unwrap_or_default()
            .checked_add(amount)
            .ok_or_else(|| Error::msg("recipient balance overflow"))?;
        ledger.burned = ledger
            .burned
            .checked_add(fee)
            .ok_or_else(|| Error::msg("burn counter overflow"))?;
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
            payload: json!({
                "network": request.network.alias,
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

pub struct PaymentAuthorizationSigningRequest<'a> {
    pub ledger_id: &'a str,
    pub network: &'a NetworkRecord,
    pub node_id: u64,
    pub sender_member_name: &'a str,
    pub receiver_member_name: &'a str,
    pub max_amount_text: &'a str,
    pub valid_minutes: i64,
    pub nonce: u64,
    pub now: i64,
}

pub fn prepare_payment_authorization(
    owner_file: &EncryptedKeyFile,
    password: &str,
    request: PaymentAuthorizationSigningRequest<'_>,
) -> Result<(String, SignedOperation)> {
    if request.network.owner_address != owner_file.address {
        return Err(Error::msg(
            "only the Network Owner can authorize Relay payment",
        ));
    }
    if !(1..=30 * 24 * 60).contains(&request.valid_minutes) {
        return Err(Error::msg(
            "payment authorization validity must be between 1 minute and 30 days",
        ));
    }
    let sender = request
        .network
        .members
        .get(request.sender_member_name)
        .ok_or_else(|| Error::msg("payment sender Member was not found"))?;
    let receiver = request
        .network
        .members
        .get(request.receiver_member_name)
        .ok_or_else(|| Error::msg("payment receiver Member was not found"))?;
    let max_amount = parse_mrk(request.max_amount_text)?;
    if max_amount == 0 {
        return Err(Error::msg(
            "payment maximum amount must be greater than zero",
        ));
    }
    let session_id = hex_lower(&random_bytes::<32>()?);
    let authorization_valid_until = request
        .now
        .checked_add(request.valid_minutes.saturating_mul(60))
        .ok_or_else(|| Error::msg("payment authorization expiry overflow"))?;
    let operation = sign_public_operation(
        owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: request.ledger_id,
            module: "TrafficPayment",
            action: "Authorize",
            nonce: request.nonce,
            valid_until: request.now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: json!({
                "network": request.network.alias,
                "node_id": request.node_id,
                "sender_member_id": sender.member_id,
                "receiver_member_id": receiver.member_id,
                "session_id": session_id,
                "max_amount_base_units": max_amount.to_string(),
                "authorization_valid_until": authorization_valid_until,
            }),
        },
    )?;
    Ok((session_id, operation))
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
                };
                ledger.network_aliases.insert(alias, commitment.clone());
                ledger.networks.insert(commitment, record.clone());
                serde_json::to_value(record)?
            }
            ("NetworkEscrow", "FundNetwork") => {
                let alias = payload_str(&operation.unsigned.payload, "network")?;
                let commitment = resolve_network(ledger, alias)?;
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
            ("TrafficPayment", "Authorize") => {
                let alias = payload_str(&operation.unsigned.payload, "network")?;
                let commitment = resolve_network(ledger, alias)?;
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
                if session_id.len() != 64
                    || !session_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(Error::msg(
                        "payment Session ID must be 32-byte lowercase hex",
                    ));
                }
                if ledger
                    .payment_authorizations
                    .values()
                    .any(|authorization| authorization.session_id == session_id)
                {
                    return Err(Error::msg("payment Session ID is already in use"));
                }
                let max_amount =
                    parse_payload_u128(&operation.unsigned.payload, "max_amount_base_units")?;
                if max_amount == 0 {
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
                if authorization_valid_until <= submitted_at
                    || authorization_valid_until.saturating_sub(submitted_at) > 30 * 86_400
                {
                    return Err(Error::msg(
                        "payment authorization must expire within 30 days",
                    ));
                }
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
                let price_per_gib = node.price_per_gib;
                let network = ledger.networks.get_mut(&commitment).expect("network");
                if network.owner_address != operation.unsigned.signer
                    || network.owner_public_key != public_key
                {
                    return Err(Error::msg(
                        "only the Network Owner can authorize Relay payment",
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
                if network.escrow_balance < max_amount {
                    return Err(Error::msg("insufficient Network Escrow"));
                }
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
                    payer_address: operation.unsigned.signer.clone(),
                    node_id,
                    sender_member_id,
                    receiver_member_id,
                    session_id,
                    price_per_gib,
                    max_amount,
                    reserved_remaining: max_amount,
                    settled_amount: 0,
                    created_at: submitted_at,
                    valid_until: authorization_valid_until,
                    claim_until: authorization_valid_until
                        .saturating_add(RELAY_PAYMENT_CLAIM_SECONDS),
                    refunded_at: None,
                    directions,
                };
                ledger
                    .payment_authorizations
                    .insert(operation_id.clone(), record.clone());
                serde_json::to_value(record)?
            }
            ("TrafficPayment", "Refund") => {
                let authorization_id =
                    payload_str(&operation.unsigned.payload, "authorization_id")?.to_owned();
                let authorization = ledger
                    .payment_authorizations
                    .get_mut(&authorization_id)
                    .ok_or_else(|| Error::msg("payment authorization was not found"))?;
                if authorization.payer_address != operation.unsigned.signer {
                    return Err(Error::msg("only the payment owner can request a refund"));
                }
                if submitted_at <= authorization.claim_until {
                    return Err(Error::msg(
                        "payment authorization claim window is still open",
                    ));
                }
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
                let alias = payload_str(&operation.unsigned.payload, "network")?;
                let serial = operation
                    .unsigned
                    .payload
                    .get("serial")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::msg("member serial is invalid"))?;
                let commitment = resolve_network(ledger, alias)?;
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
                let alias = payload_str(&operation.unsigned.payload, "network")?;
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
                let commitment = resolve_network(ledger, alias)?;
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

pub fn operation(paths: &DataPaths, operation_id: &str) -> Result<OperationRecord> {
    paths
        .read_ledger()?
        .operations
        .get(operation_id)
        .cloned()
        .ok_or_else(|| Error::msg(format!("operation not found: {operation_id}")))
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
        ("MRKAsset", "Transfer") => {
            submit_signed_transfer(paths, &envelope.public_key, envelope.operation, now).map(|_| ())
        }
        ("NetworkRegistry", _)
        | ("NetworkEscrow", _)
        | ("TrafficPayment", "Authorize" | "Refund") => {
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

pub fn submit_consensus_operation(
    paths: &DataPaths,
    envelope: crate::consensus::PendingOperationEnvelope,
    now: i64,
) -> Result<String> {
    match submit_consensus_operation_strict(paths, envelope.clone(), now) {
        Ok(operation_id_value) => Ok(operation_id_value),
        Err(application_error) => {
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
        ("MRKAsset", "Transfer")
            | (
                "NetworkRegistry",
                "CreateNetwork" | "RevokeMember" | "IssueMember"
            )
            | ("NetworkEscrow", "FundNetwork")
            | ("TrafficPayment", "Authorize" | "Refund" | "Settle")
            | (
                "Governance",
                "SetParameter"
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
                "RegisterNode" | "UpdateRewardIp" | "DrainNode" | "WithdrawServiceBond"
            )
            | ("NodeEmissionController", "ClaimNodeReward")
            | (
                "StakeVault",
                "BondValidator" | "ExitValidator" | "WithdrawValidatorBond"
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
    paths.with_ledger_mut(|ledger| {
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
                payload: operation.unsigned.payload.clone(),
                signature: operation.signature.clone(),
                block_height: None,
                signed_operation: Some(operation),
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
                let price_per_gib = parse_payload_u128(payload, "price_per_gib_base_units")?;
                let registered_at = payload["registered_at"].as_i64().unwrap_or(executed_at);
                let (status, warmup_until, active_since) =
                    initial_node_lifecycle(node_id, registered_at, ledger.settings.warmup_seconds)?;
                let record = NodeRecord {
                    node_id,
                    name: payload_str(payload, "name")?.to_owned(),
                    owner_address: operation.unsigned.signer.clone(),
                    owner_public_key: public_key.to_owned(),
                    relay_public_key: payload_str(payload, "relay_public_key")?.to_owned(),
                    reward_address: reward_address.clone(),
                    endpoint: payload_str(payload, "endpoint")?.to_owned(),
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
                    epoch_eligible_seconds: 0,
                    total_eligible_seconds: 0,
                    service_bond: 0,
                    service_bond_unlock_at: None,
                    offline_slashed_at: None,
                    offline_slashed_service_bond: 0,
                    offline_slashed_vesting_reward: 0,
                    claimable_reward: 0,
                    reward_vesting_schedules: Vec::new(),
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
                apply_traffic_settlement(
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
        finalize_operation(ledger, &operation, &operation_id_value, executed_at)
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
    if epoch != ledger.epoch_number {
        return Err(Error::msg(
            "availability Probe Ticket belongs to another Epoch",
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
    let slot_seconds = ledger.settings.availability_slot_seconds;
    let scheduled_at = availability_scheduled_at(ticket_signature, slot, slot_seconds, role)?;
    if ledger.availability_mode == AvailabilityMode::Node1Trusted {
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
    if slot_seconds <= 0 || response.timestamp.div_euclid(slot_seconds) != slot {
        return Err(Error::msg(
            "availability Probe timestamp does not belong to the declared slot",
        ));
    }
    let set = availability_verifier_set(ledger, target_node_id, slot);
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
    let slot_start = slot
        .checked_mul(slot_seconds)
        .ok_or_else(|| Error::msg("availability slot timestamp overflow"))?;
    let slot_end = slot_start
        .checked_add(slot_seconds)
        .ok_or_else(|| Error::msg("availability slot end overflow"))?;
    if slot_end <= ledger.epoch_started_at {
        return Err(Error::msg(
            "availability slot belongs to an Epoch that is already settled",
        ));
    }
    let key = availability_slot_key(target_node_id, slot);
    let (ready_to_credit, first_credit, attestation_operation_ids) = {
        let record = ledger
            .availability_slots
            .entry(key.clone())
            .or_insert_with(|| AvailabilitySlotRecord {
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

    let epoch_end = ledger
        .epoch_started_at
        .checked_add(ledger.epoch_seconds_snapshot)
        .ok_or_else(|| Error::msg("availability Epoch boundary overflow"))?;
    let (warmup_until, target_ip_slot, target_status) = ledger
        .nodes
        .get(&target_node_id)
        .map(|node| (node.warmup_until, node.ip_slot.clone(), node.status))
        .ok_or_else(|| Error::msg("availability target Node is missing"))?;
    let eligible_start = slot_start.max(ledger.epoch_started_at).max(warmup_until);
    let eligible_end = slot_end.min(epoch_end);
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
        node.epoch_eligible_seconds = node.epoch_eligible_seconds.saturating_add(credited_seconds);
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

fn apply_traffic_settlement(
    ledger: &mut LedgerState,
    signer_address: &str,
    signer_public_key: &str,
    operation_id_value: &str,
    checkpoint: &SenderCheckpoint,
    receipt: &ReceiverReceipt,
    executed_at: i64,
) -> Result<()> {
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
    if checkpoint.sequence == 0 || checkpoint.cumulative_sent_bytes == 0 {
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
    if checkpoint.sequence <= previous.settled_sequence
        || checkpoint.cumulative_sent_bytes <= previous.settled_payload_bytes
    {
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
        },
    );
    let reward_address = node.reward_address;
    ledger
        .accounts
        .entry(reward_address.clone())
        .or_default()
        .balance = ledger.accounts[&reward_address]
        .balance
        .checked_add(amount)
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
    Ok(())
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

pub fn relay_authorization_view(
    paths: &DataPaths,
    authorization_id: &str,
) -> Result<RelayAuthorizationView> {
    let ledger = paths.read_ledger()?;
    let authorization = ledger
        .payment_authorizations
        .get(authorization_id)
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
        .get(authorization_id)
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
    if authorization.refunded_at.is_some()
        || authorization.reserved_remaining == 0
        || now < authorization.created_at
        || now >= authorization.valid_until
    {
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
    let operation = sign_public_operation(
        &owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: &ledger.ledger_id,
            module: "TrafficPayment",
            action: "Settle",
            nonce,
            valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: json!({
                "sender_checkpoint": checkpoint,
                "receiver_receipt": receipt,
            }),
        },
    )?;
    let operation_id_value = operation_id(&operation)?;
    submit_signed_node_operation(paths, &owner_file.public_key, operation, now)?;
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
    validate_name(name)?;
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
        bootstrap_allow_insecure_local: false,
        bootstrap_tls_ca: None,
    };
    std::fs::create_dir(&directory)?;
    let write_result = (|| {
        paths.write_keyfile(&paths.node_owner_key_path(name)?, &owner)?;
        paths.write_keyfile(&paths.node_relay_key_path(name)?, &relay)?;
        paths.write_keyfile(&paths.node_reward_key_path(name)?, &reward)?;
        paths.write_node_config(&config)
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(config)
}

pub fn bootstrap_snapshot(paths: &DataPaths) -> Result<BootstrapSnapshot> {
    let ledger = paths.read_ledger()?;
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

pub fn install_bootstrap_snapshot(
    paths: &DataPaths,
    name: &str,
    peer: &str,
    expected_state_root: &str,
    allow_insecure_local: bool,
    tls_ca: Option<&std::path::Path>,
    snapshot: BootstrapSnapshot,
) -> Result<BootstrapInstallReport> {
    if !expected_state_root.starts_with("state_") || expected_state_root.len() != 70 {
        return Err(Error::msg(
            "trusted checkpoint root must be a full state_ SHA-256 identifier",
        ));
    }
    if snapshot.state_root != expected_state_root {
        return Err(Error::msg(format!(
            "downloaded checkpoint root {} does not match trusted root {expected_state_root}",
            snapshot.state_root
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
    let original_config = paths.read_node_config(name)?;
    if original_config.node_id.is_some() {
        return Err(Error::msg(
            "registered Node cannot replace its chain by bootstrap",
        ));
    }
    let finalized = checkpoint.clone();
    checkpoint.finalized_checkpoint = Some(Box::new(finalized));
    paths.with_ledger_mut(|ledger| {
        *ledger = checkpoint;
        Ok(())
    })?;
    let mut config = original_config.clone();
    config.bootstrap_peer = Some(peer.to_owned());
    config.trusted_checkpoint_root = Some(expected_state_root.to_owned());
    config.bootstrap_allow_insecure_local = allow_insecure_local;
    config.bootstrap_tls_ca = tls_ca.map(|path| path.to_string_lossy().into_owned());
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
        peer: peer.to_owned(),
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
    let restored_node_id = backup
        .payload
        .ledger
        .nodes
        .iter()
        .find_map(|(node_id, node)| {
            (node.owner_address == config.owner_address).then_some(*node_id)
        });
    paths.with_ledger_mut(|ledger| {
        *ledger = backup.payload.ledger;
        Ok(())
    })?;
    let mut config = config;
    config.node_id = restored_node_id;
    paths.write_node_config(&config)?;
    Ok(report)
}

pub fn reconcile_local_node_registration(paths: &DataPaths, name: &str) -> Result<Option<u64>> {
    let mut config = paths.read_node_config(name)?;
    let ledger = paths.read_ledger()?;
    let node_id = ledger.nodes.iter().find_map(|(node_id, node)| {
        (node.owner_address == config.owner_address).then_some(*node_id)
    });
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

pub fn register_node(
    paths: &DataPaths,
    name: &str,
    password: &str,
    endpoint: &str,
    price_text: &str,
    now: i64,
) -> Result<NodeRecord> {
    let mut config = paths.read_node_config(name)?;
    if config.node_id.is_some() {
        return Err(Error::msg(format!("node '{name}' is already registered")));
    }
    let reward_ip = resolve_endpoint_public_ip(endpoint)?;
    let ip_slot = ip_slot(reward_ip);
    let price_per_gib = parse_mrk(price_text)?;
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let relay_file = paths.read_keyfile(&paths.node_relay_key_path(name)?)?;
    let reward_file = paths.read_keyfile(&paths.node_reward_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    let node = paths.with_ledger_mut(|ledger| {
        ensure_account(ledger, &owner_file)?;
        ensure_account(ledger, &reward_file)?;
        let node_id = ledger.next_node_id;
        ledger.next_node_id += 1;
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({
            "node_id": node_id,
            "name": name,
            "owner_public_key": owner_file.public_key,
            "endpoint": endpoint,
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
            name: name.to_owned(),
            owner_address: owner_file.address.clone(),
            owner_public_key: owner_file.public_key.clone(),
            relay_public_key: relay_file.public_key.clone(),
            reward_address: reward_file.address.clone(),
            endpoint: endpoint.to_owned(),
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
            epoch_eligible_seconds: 0,
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 0,
            reward_vesting_schedules: Vec::new(),
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
    let config = paths.read_node_config(name)?;
    let node_id = config
        .node_id
        .ok_or_else(|| Error::msg("node is not registered"))?;
    let reward_ip = resolve_endpoint_public_ip(endpoint)?;
    let new_ip_slot = ip_slot(reward_ip);
    let owner_file = paths.read_keyfile(&paths.node_owner_key_path(name)?)?;
    let owner_key = decrypt_key(&owner_file, password)?;
    paths.with_ledger_mut(|ledger| {
        let node = ledger
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::msg("registered node is missing from the ledger"))?;
        if node.owner_address != owner_file.address
            || node.owner_public_key != owner_file.public_key
        {
            return Err(Error::msg("Node Owner key does not match the registry"));
        }
        let nonce = ledger.accounts[&owner_file.address].nonce + 1;
        let payload = json!({
            "node_id": node_id,
            "endpoint": endpoint,
            "reward_ip": reward_ip.to_string(),
            "ip_slot": new_ip_slot,
        });
        let signed = sign_operation(
            ledger,
            (&owner_file, &owner_key),
            "NodeRegistry",
            "UpdateRewardIp",
            nonce,
            now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload,
        )?;
        let operation_id = operation_id(&signed)?;
        verify_operation(&signed, &owner_file.public_key)?;
        apply_reward_ip_update(
            ledger,
            node_id,
            endpoint,
            &reward_ip.to_string(),
            &new_ip_slot,
            now,
        )?;
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
    paths.with_ledger_mut(|ledger| {
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
        epoch_eligible_seconds: node.epoch_eligible_seconds,
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
        vesting_schedule_count: node.reward_vesting_schedules.len(),
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

fn availability_slot_key(target_node_id: u64, slot: i64) -> String {
    format!("{target_node_id}:{slot}")
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
    target_node_id: u64,
    slot: i64,
) -> AvailabilityVerifierSet {
    if ledger.availability_mode == AvailabilityMode::Node1Trusted {
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
    if ledger.consensus.active_validators.len() < MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS {
        return AvailabilityVerifierSet {
            mode: AvailabilityMode::MultiValidator,
            primary_ids: Vec::new(),
            primary_quorum: ledger.settings.availability_quorum,
            audit_required: false,
            auditor_ids: Vec::new(),
            audit_quorum: 0,
        };
    }
    let mut candidates = ledger
        .consensus
        .active_validators
        .iter()
        .copied()
        .filter(|node_id| *node_id != target_node_id)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|node_id| {
        sha256_full_id(
            "availability-primary-selector-v1",
            format!(
                "{}:{}:{target_node_id}:{slot}:{node_id}",
                ledger.ledger_id, ledger.epoch_number
            )
            .as_bytes(),
        )
    });
    let primary_count = ledger.settings.availability_verifier_count as usize;
    if candidates.len() < primary_count
        || ledger.settings.availability_quorum > ledger.settings.availability_verifier_count
    {
        return AvailabilityVerifierSet {
            mode: AvailabilityMode::MultiValidator,
            primary_ids: Vec::new(),
            primary_quorum: ledger.settings.availability_quorum,
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
            ledger.ledger_id, ledger.epoch_number
        )
        .as_bytes(),
        10_000,
    ) < u64::from(ledger.settings.availability_audit_rate_bps);
    let mut auditor_candidates = candidates
        .into_iter()
        .filter(|node_id| !primary_ids.contains(node_id))
        .collect::<Vec<_>>();
    auditor_candidates.sort_by_key(|node_id| {
        sha256_full_id(
            "availability-auditor-selector-v1",
            format!(
                "{}:{}:{target_node_id}:{slot}:{node_id}",
                ledger.ledger_id, ledger.epoch_number
            )
            .as_bytes(),
        )
    });
    let auditor_count = ledger.settings.availability_auditor_count as usize;
    let audit_required = audit_sampled
        && ledger.consensus.active_validators.len() >= MIN_AUDITED_AVAILABILITY_VALIDATORS
        && auditor_candidates.len() >= auditor_count
        && ledger.settings.availability_audit_quorum <= ledger.settings.availability_auditor_count;
    let mut auditor_ids = if audit_required {
        auditor_candidates[..auditor_count].to_vec()
    } else {
        Vec::new()
    };
    auditor_ids.sort_unstable();
    AvailabilityVerifierSet {
        mode: AvailabilityMode::MultiValidator,
        primary_ids,
        primary_quorum: ledger.settings.availability_quorum,
        audit_required,
        auditor_ids,
        audit_quorum: if audit_required {
            ledger.settings.availability_audit_quorum
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
    slot: i64,
    slot_seconds: i64,
    role: AvailabilityVerifierRole,
) -> Result<i64> {
    if slot_seconds < 60 {
        return Err(Error::msg(
            "Availability requires slots of at least 60 seconds",
        ));
    }
    let slot_start = slot
        .checked_mul(slot_seconds)
        .ok_or_else(|| Error::msg("availability slot timestamp overflow"))?;
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
            ledger.epoch_number,
            slot,
            target_node_id,
            verifier_node_id,
            role,
        ),
    );
    let scheduled_at = availability_scheduled_at(
        &ticket_signature,
        slot,
        ledger.settings.availability_slot_seconds,
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
        epoch: ledger.epoch_number,
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
    let slot = now.div_euclid(ledger.settings.availability_slot_seconds);
    let set = availability_verifier_set(&ledger, target_node_id, slot);
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
    let slot_seconds = ledger.settings.availability_slot_seconds;
    if slot_seconds <= 0 {
        return Err(Error::msg("availability slot duration is invalid"));
    }
    let slot = now.div_euclid(slot_seconds);
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
            let set = availability_verifier_set(&ledger, *node_id, slot);
            let role = if set.primary_ids.contains(&verifier_node_id) {
                AvailabilityVerifierRole::Primary
            } else if set.auditor_ids.contains(&verifier_node_id) {
                AvailabilityVerifierRole::Audit
            } else {
                return None;
            };
            let already_submitted = ledger
                .availability_slots
                .get(&availability_slot_key(*node_id, slot))
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
    let operation = sign_public_operation(
        &owner_file,
        password,
        PublicOperationSigningRequest {
            ledger_id: &ledger.ledger_id,
            module: "Availability",
            action: "AttestProbe",
            nonce,
            valid_until: request.now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: json!({
                "target_node_id": request.response.node_id,
                "verifier_node_id": verifier_node_id,
                "slot": request.slot,
                "epoch": request.epoch,
                "role": request.role,
                "ticket_signature": request.ticket_signature,
                "probe": request.response,
            }),
        },
    )?;
    let operation_id_value = operation_id(&operation)?;
    submit_signed_node_operation(paths, &owner_file.public_key, operation, request.now)?;
    let ledger = paths.read_ledger()?;
    let key = availability_slot_key(
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
    paths
        .read_ledger()?
        .nodes
        .get(&node_id)
        .cloned()
        .ok_or_else(|| Error::msg("registered node is missing from the ledger"))
}

pub fn node_record_by_id(paths: &DataPaths, node_id: u64) -> Result<NodeRecord> {
    paths
        .read_ledger()?
        .nodes
        .get(&node_id)
        .cloned()
        .ok_or_else(|| Error::msg(format!("node {node_id} is not registered")))
}

pub fn registry_node_by_id(paths: &DataPaths, node_id: u64) -> Result<RegistryNodeView> {
    let ledger = paths.read_ledger()?;
    let node = ledger
        .nodes
        .get(&node_id)
        .ok_or_else(|| Error::msg(format!("node {node_id} is not registered")))?;
    Ok(registry_node_view(node, &ledger.settings))
}

pub fn registry_nodes(
    paths: &DataPaths,
    status: Option<NodeStatus>,
    validator_only: bool,
    cursor: Option<u64>,
    limit: usize,
) -> Result<RegistryNodeListView> {
    validate_registry_page_limit(limit)?;
    let ledger = paths.read_ledger()?;
    let mut nodes = ledger
        .nodes
        .range((
            std::ops::Bound::Excluded(cursor.unwrap_or(0)),
            std::ops::Bound::Unbounded,
        ))
        .filter(|(_, node)| status.is_none_or(|status| node.status == status))
        .filter(|(_, node)| !validator_only || node.validator)
        .take(limit + 1)
        .map(|(_, node)| registry_node_view(node, &ledger.settings))
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

fn registry_node_view(node: &NodeRecord, settings: &LedgerSettings) -> RegistryNodeView {
    RegistryNodeView {
        node_id: node.node_id,
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
        service_bond_base_units: node.service_bond.to_string(),
        service_bond_display: format_mrk(node.service_bond),
        service_bond_unlock_at: node.service_bond_unlock_at,
        offline_slashed_at: node.offline_slashed_at,
        validator: node.validator,
        validator_candidate: node.validator_candidate_since.is_some()
            && node.validator_exit_requested_at.is_none()
            && node.validator_bond >= settings.validator_bond,
    }
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
    Ok(ValidatorCommitteeView {
        epoch: ledger.epoch_number,
        validator_set_hash: set_hash,
        active_validator_ids: active.clone(),
        candidate_node_ids: candidates,
        max_active_validators: ledger.settings.max_active_validators,
        max_rotations_per_epoch: ledger.settings.max_validator_rotations,
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
    let bootstrap_expansion = (governance_eligible_node_ids(ledger, now).len()
        < GOVERNANCE_NODE_THRESHOLD
        || ledger.consensus.active_validators.len() < MIN_ACTIVE_VALIDATORS)
        && ledger.consensus.proposal.is_none()
        && current_candidates.len() <= ledger.settings.max_active_validators as usize
        && current_candidates != ledger.consensus.active_validators;
    let selection_due = ledger.consensus.active_validators.is_empty()
        || ledger.consensus.last_selection_epoch != Some(ledger.epoch_number)
        || bootstrap_expansion;
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

pub fn consensus_status(paths: &DataPaths, now: i64) -> Result<ConsensusStatusView> {
    let ledger = paths.read_ledger()?;
    let active = ledger.consensus.active_validators.clone();
    let height = next_block_height(&ledger);
    let set_hash = validator_set_hash(&ledger, &active)?;
    let eligible_count = governance_eligible_node_ids(&ledger, now).len();
    let multi_validator =
        eligible_count >= GOVERNANCE_NODE_THRESHOLD && active.len() >= MIN_ACTIVE_VALIDATORS;
    let round_started_at = multi_validator
        .then(|| {
            ledger
                .consensus
                .round_started_at
                .or_else(|| chain_tip_timestamp(&ledger))
        })
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
    paths.with_ledger_mut(|ledger| {
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
    paths.with_ledger_mut(|ledger| {
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
    })
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
    paths.with_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        ensure_active_validator_identity(ledger, node_id, &owner_file)?;
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
        migrate_legacy_pending_operations(ledger);
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
    paths.with_ledger_mut(|ledger| {
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
    paths.with_ledger_mut(|ledger| {
        ensure_multi_validator_mode(ledger, now)?;
        let started = ledger
            .consensus
            .round_started_at
            .or_else(|| chain_tip_timestamp(ledger))
            .unwrap_or(now);
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
    paths.with_ledger_mut(|ledger| {
        if ledger.consensus.proposal.is_none() {
            ledger.consensus.round_started_at = Some(now);
        }
        Ok(())
    })
}

fn ensure_multi_validator_mode(ledger: &LedgerState, now: i64) -> Result<()> {
    let eligible_count = governance_eligible_node_ids(ledger, now).len();
    if eligible_count < GOVERNANCE_NODE_THRESHOLD {
        return Err(Error::msg(format!(
            "multi-Validator consensus requires at least {GOVERNANCE_NODE_THRESHOLD} Governance-Eligible Nodes; current count is {eligible_count}"
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

fn reset_multi_validator_consensus_if_node1_mode(ledger: &mut LedgerState, now: i64) {
    if governance_eligible_node_ids(ledger, now).len() >= GOVERNANCE_NODE_THRESHOLD
        && ledger.consensus.active_validators.len() >= MIN_ACTIVE_VALIDATORS
    {
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
    settle_elapsed_epochs_for_block(&mut simulated, timestamp)?;
    for operation_id_value in operation_ids {
        let operation = simulated
            .operations
            .get_mut(operation_id_value)
            .ok_or_else(|| Error::msg("pending operation is missing from the ledger"))?;
        operation.status = OperationStatus::Finalized;
        operation.block_height = Some(height);
    }
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
        .filter(|(_, operation)| matches!(operation.status, OperationStatus::Finalized))
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
    settle_elapsed_epochs_for_block(&mut base, timestamp)?;

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
        match submit_consensus_operation_strict(
            &replay,
            crate::consensus::PendingOperationEnvelope {
                public_key,
                operation,
            },
            timestamp,
        ) {
            Ok(id) => accepted.push(id),
            Err(_) if skip_invalid => {}
            Err(error) => {
                return Err(Error::msg(format!(
                    "proposal operation {operation_id_value} failed deterministic execution: {error}"
                )));
            }
        }
    }
    let mut state = replay.read_ledger()?;
    for operation_id_value in &accepted {
        let operation = state
            .operations
            .get_mut(operation_id_value)
            .expect("accepted replay operation exists");
        operation.status = OperationStatus::Finalized;
        operation.block_height = Some(height);
    }
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
    let genesis = ledger
        .genesis_authority
        .clone()
        .or_else(|| legacy_genesis_authority(&ledger));
    let eligible_count = governance_eligible_node_ids(&ledger, now).len();
    let active_validator_count = ledger.consensus.active_validators.len();
    let enabled = genesis.is_some()
        && (eligible_count < GOVERNANCE_NODE_THRESHOLD
            || active_validator_count < MIN_ACTIVE_VALIDATORS);
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
        last_block_hash: chain_tip_hash(&ledger).map(str::to_owned),
        last_block_at: chain_tip_timestamp(&ledger),
        pending_operation_count,
        producer_node_id: genesis.map(|authority| authority.node_id),
        node1_production_enabled: enabled,
        governance_eligible_count: eligible_count,
        threshold: GOVERNANCE_NODE_THRESHOLD,
        active_validator_count,
        minimum_active_validators: MIN_ACTIVE_VALIDATORS,
        availability_mode: ledger.availability_mode,
        availability_earning_enabled: ledger.availability_mode == AvailabilityMode::Node1Trusted
            || active_validator_count >= MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        minimum_decentralized_availability_validators: MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        pruned_through_height: ledger.pruned_through_height,
        retained_block_count: ledger.blocks.len(),
        retained_operation_count: ledger.operations.len(),
    })
}

pub fn block_by_height(paths: &DataPaths, height: u64) -> Result<BlockRecord> {
    if height == 0 {
        return Err(Error::msg("block height starts at 1"));
    }
    let ledger = paths.read_ledger()?;
    if height <= ledger.pruned_through_height {
        return Err(Error::msg(format!(
            "block {height} was pruned; retained history starts at {}",
            ledger.pruned_through_height + 1
        )));
    }
    ledger
        .blocks
        .get((height - ledger.pruned_through_height - 1) as usize)
        .cloned()
        .ok_or_else(|| Error::msg(format!("block {height} does not exist")))
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
    paths.with_ledger_mut(|ledger| {
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
        if eligible_count >= GOVERNANCE_NODE_THRESHOLD
            && active_validator_count >= MIN_ACTIVE_VALIDATORS
        {
            return Err(Error::msg(format!(
                "Node 1 block production is disabled at {eligible_count} Governance-Eligible Nodes and {active_validator_count} Active Validators; multi-Validator consensus is required"
            )));
        }
        reset_multi_validator_consensus_if_node1_mode(ledger, now);
        migrate_legacy_pending_operations(ledger);
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
    })
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
    let ledger = paths.read_ledger()?;
    let genesis_exists = ledger.genesis_authority.is_some() || ledger.nodes.contains_key(&1);
    let multi_validator_ready = governance_eligible_node_ids(&ledger, now).len()
        >= GOVERNANCE_NODE_THRESHOLD
        && ledger.consensus.active_validators.len() >= MIN_ACTIVE_VALIDATORS;
    if !genesis_exists || multi_validator_ready {
        return Ok(None);
    }
    let due = chain_tip_timestamp(&ledger).is_none_or(|timestamp| {
        now.saturating_sub(timestamp) >= ledger.settings.block_interval_seconds
    });
    if !due {
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
            if !matches!(operation.status, OperationStatus::Finalized)
                || operation.block_height != Some(block.height)
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

fn migrate_legacy_pending_operations(ledger: &mut LedgerState) {
    if chain_height(ledger) > 0 || !ledger.pending_operation_ids.is_empty() {
        return;
    }
    let mut legacy = ledger
        .operations
        .values()
        .filter(|operation| operation.block_height.is_none())
        .map(|operation| {
            (
                operation.created_at,
                operation.nonce,
                operation.operation_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    legacy.sort();
    ledger.pending_operation_ids = legacy.into_iter().map(|(_, _, id)| id).collect();
}

fn ledger_state_root(ledger: &LedgerState) -> Result<String> {
    let mut committed = ledger.clone();
    committed.blocks.clear();
    committed.pruned_through_height = 0;
    committed.pruned_tip_hash = None;
    committed.pruned_tip_timestamp = None;
    committed.pruned_operation_count = 0;
    committed.operation_history_from_height = 1;
    committed.operations.clear();
    for account in committed.accounts.values_mut() {
        account.operation_ids.clear();
    }
    for node in committed.nodes.values_mut() {
        node.last_heartbeat = None;
    }
    committed.pending_operation_ids.clear();
    let consensus = std::mem::take(&mut committed.consensus);
    committed.consensus.active_validators = consensus.active_validators;
    committed.consensus.last_selection_epoch = consensus.last_selection_epoch;
    committed.consensus.double_sign_evidence = consensus.double_sign_evidence;
    committed.finalized_checkpoint = None;
    Ok(sha256_full_id("state", &serde_json::to_vec(&committed)?))
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
    if mature.len() < GOVERNANCE_NODE_THRESHOLD {
        return Err(Error::msg(format!(
            "TreasurySpend requires at least {GOVERNANCE_NODE_THRESHOLD} Governance-Eligible Nodes with 180 days of service; current count is {}",
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
                && tally.yes_power > 0
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
        GovernanceProposalAction::SetParameter { parameter, value } => {
            let mut settings = ledger.settings.clone();
            set_governance_parameter(&mut settings, parameter, value)?;
            if governance_parameter_is_critical(parameter)
                && *kind != GovernanceProposalKind::Critical
            {
                return Err(Error::msg(format!(
                    "parameter '{parameter}' requires a CRITICAL proposal"
                )));
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
        "SetParameter" | "PauseEmission" | "ResumeEmission" => {
            let genesis = ensure_genesis_authority(ledger)?;
            if genesis.owner_address != operation.unsigned.signer
                || genesis.owner_public_key != public_key
                || governance_eligible_node_ids(ledger, executed_at).len()
                    >= GOVERNANCE_NODE_THRESHOLD
            {
                return Err(Error::msg("direct governance signer or mode is invalid"));
            }
            cancel_distributed_governance_proposals(ledger, executed_at);
            match operation.unsigned.action.as_str() {
                "SetParameter" => {
                    set_governance_parameter(
                        &mut ledger.settings,
                        payload_str(payload, "parameter")?,
                        payload_str(payload, "new_value")?,
                    )?;
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
            | "validator-bond"
            | "max-active-validators"
            | "max-validator-rotations"
            | "consensus-round-timeout-seconds"
            | "availability-slot-seconds"
            | "availability-verifier-count"
            | "availability-quorum"
            | "availability-audit-rate-bps"
            | "availability-auditor-count"
            | "availability-audit-quorum"
    )
}

fn apply_governance_proposal_action(
    ledger: &mut LedgerState,
    action: &GovernanceProposalAction,
    now: i64,
) -> Result<()> {
    match action {
        GovernanceProposalAction::SetParameter { parameter, value } => {
            set_governance_parameter(&mut ledger.settings, parameter, value)?;
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

fn cancel_distributed_governance_proposals(ledger: &mut LedgerState, now: i64) {
    let cancellable = ledger
        .governance
        .proposals
        .iter()
        .filter_map(|(proposal_id, proposal)| {
            matches!(
                proposal.status,
                GovernanceProposalStatus::Voting | GovernanceProposalStatus::Passed
            )
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
    let direct = eligible.len() < GOVERNANCE_NODE_THRESHOLD;
    Ok(GovernanceStatusView {
        mode: if direct {
            "NODE1_DIRECT".to_owned()
        } else {
            "NODE_VOTING".to_owned()
        },
        threshold: GOVERNANCE_NODE_THRESHOLD,
        governance_eligible_count: eligible.len(),
        governance_eligible_node_ids: eligible,
        genesis_node_id: genesis.as_ref().map(|authority| authority.node_id),
        genesis_owner_address: genesis.map(|authority| authority.owner_address),
        node1_direct_actions_enabled: direct,
        emission_paused: ledger.governance.emission_paused,
        pause_reason: ledger.governance.pause_reason.clone(),
        current_epoch_seconds: ledger.epoch_seconds_snapshot,
        current_epoch_mint_amount: ledger.epoch_mint_amount_snapshot,
        current_reward_immediate_bps: ledger.reward_immediate_bps_snapshot,
        current_reward_vesting_seconds: ledger.reward_vesting_seconds_snapshot,
        availability_mode: ledger.availability_mode,
        availability_activated_at: ledger.availability_activated_at,
        availability_activated_epoch: ledger.availability_activated_epoch,
        minimum_decentralized_availability_validators: MIN_DECENTRALIZED_AVAILABILITY_VALIDATORS,
        settings: ledger.settings,
        last_action_at: ledger.governance.last_action_at,
    })
}

pub fn governance_set_parameter(
    paths: &DataPaths,
    name: &str,
    password: &str,
    parameter: &str,
    value: &str,
    now: i64,
) -> Result<GovernanceReceipt> {
    let parameter = parameter.to_owned();
    let value = value.to_owned();
    execute_node1_governance(paths, name, password, "SetParameter", now, move |ledger| {
        let (old_value, new_value) =
            set_governance_parameter(&mut ledger.settings, &parameter, &value)?;
        Ok(json!({
            "parameter": parameter,
            "old_value": old_value,
            "new_value": new_value,
        }))
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
        if eligible_count >= GOVERNANCE_NODE_THRESHOLD {
            return Err(Error::msg(format!(
                "Node 1 direct governance is disabled at {eligible_count} Governance-Eligible Nodes; node voting is required"
            )));
        }
        cancel_distributed_governance_proposals(ledger, now);
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
        .iter()
        .filter_map(|(node_id, node)| {
            let probe_fresh = node.last_probe_success.is_some_and(|timestamp| {
                timestamp <= now
                    && now.saturating_sub(timestamp) <= ledger.settings.probe_validity_seconds
            });
            (matches!(node.status, NodeStatus::Active)
                && node_owns_ip_slot_at(ledger, *node_id, now)
                && node.service_bond >= ledger.settings.required_service_bond
                && node.total_eligible_seconds >= ledger.settings.governance_min_service_seconds
                && probe_fresh)
                .then_some(*node_id)
        })
        .collect()
}

fn reset_active_heartbeats(ledger: &mut LedgerState, now: i64) {
    for node in ledger.nodes.values_mut() {
        if matches!(node.status, NodeStatus::Active) {
            node.last_heartbeat = Some(now);
        }
    }
}

fn set_governance_parameter(
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
        "required-service-bond" => {
            let parsed = parse_mrk(value)?;
            if parsed > MAX_SUPPLY {
                return Err(Error::msg(
                    "required-service-bond must not exceed MAX_SUPPLY",
                ));
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
            if parsed < settings.availability_slot_seconds {
                return Err(Error::msg(
                    "probe-validity-seconds cannot be shorter than availability-slot-seconds",
                ));
            }
            let old = settings.probe_validity_seconds;
            settings.probe_validity_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-slot-seconds" => {
            let parsed = integer(value, parameter, 60, 300)? as i64;
            if parsed > settings.probe_validity_seconds {
                return Err(Error::msg(
                    "availability-slot-seconds cannot exceed probe-validity-seconds",
                ));
            }
            let old = settings.availability_slot_seconds;
            settings.availability_slot_seconds = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-verifier-count" => {
            let parsed = integer(value, parameter, 3, 30)? as u32;
            if parsed < settings.availability_quorum {
                return Err(Error::msg(
                    "availability-verifier-count cannot be lower than availability-quorum",
                ));
            }
            let old = settings.availability_verifier_count;
            settings.availability_verifier_count = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-quorum" => {
            let parsed = integer(value, parameter, 2, 21)? as u32;
            if parsed > settings.availability_verifier_count {
                return Err(Error::msg(
                    "availability-quorum cannot exceed availability-verifier-count",
                ));
            }
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
            if parsed < settings.availability_audit_quorum {
                return Err(Error::msg(
                    "availability-auditor-count cannot be lower than availability-audit-quorum",
                ));
            }
            let old = settings.availability_auditor_count;
            settings.availability_auditor_count = parsed;
            (old.to_string(), parsed.to_string())
        }
        "availability-audit-quorum" => {
            let parsed = integer(value, parameter, 1, 7)? as u32;
            if parsed > settings.availability_auditor_count {
                return Err(Error::msg(
                    "availability-audit-quorum cannot exceed availability-auditor-count",
                ));
            }
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
            if settings.max_validator_rotations > parsed / 3 {
                return Err(Error::msg(
                    "max-active-validators must retain more than two-thirds of the committee across rotation",
                ));
            }
            let old = settings.max_active_validators;
            settings.max_active_validators = parsed;
            (old.to_string(), parsed.to_string())
        }
        "max-validator-rotations" => {
            let parsed = integer(value, parameter, 1, 10)? as u32;
            if parsed > settings.max_active_validators / 3 {
                return Err(Error::msg(
                    "max-validator-rotations cannot replace more than one-third of the committee",
                ));
            }
            let old = settings.max_validator_rotations;
            settings.max_validator_rotations = parsed;
            (old.to_string(), parsed.to_string())
        }
        "consensus-round-timeout-seconds" => {
            let parsed = integer(value, parameter, 5, 30)? as i64;
            let old = settings.consensus_round_timeout_seconds;
            settings.consensus_round_timeout_seconds = parsed;
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

fn sign_operation(
    ledger: &LedgerState,
    signer: (&EncryptedKeyFile, &Ed25519KeyPair),
    module: &str,
    action: &str,
    nonce: u64,
    valid_until: i64,
    payload: Value,
) -> Result<SignedOperation> {
    let (keyfile, key_pair) = signer;
    let unsigned = UnsignedOperation {
        ledger_id: ledger.ledger_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        module: module.to_owned(),
        action: action.to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: nonce,
        valid_until,
        payload,
    };
    let bytes = serde_json::to_vec(&unsigned)?;
    Ok(SignedOperation {
        signature: sign_bytes(key_pair, &bytes),
        unsigned,
    })
}

fn verify_operation(operation: &SignedOperation, public_key: &str) -> Result<()> {
    let bytes = serde_json::to_vec(&operation.unsigned)?;
    verify_bytes(public_key, &bytes, &operation.signature)
}

fn operation_id(operation: &SignedOperation) -> Result<String> {
    Ok(sha256_id("op", &serde_json::to_vec(operation)?))
}

fn finalize_operation(
    ledger: &mut LedgerState,
    operation: &SignedOperation,
    operation_id: &str,
    now: i64,
) -> Result<()> {
    reset_multi_validator_consensus_if_node1_mode(ledger, now);
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
            created_at: now,
            status: OperationStatus::Pending,
            payload: operation.unsigned.payload.clone(),
            signature: operation.signature.clone(),
            block_height: None,
            signed_operation: Some(operation.clone()),
        },
    );
    ledger.pending_operation_ids.push(operation_id.to_owned());
    sort_pending_operation_ids(ledger);
    Ok(())
}

fn sort_pending_operation_ids(ledger: &mut LedgerState) {
    ledger.pending_operation_ids.sort_by(|left, right| {
        let left_record = &ledger.operations[left];
        let right_record = &ledger.operations[right];
        (
            left_record
                .signed_operation
                .as_ref()
                .map(|operation| operation.unsigned.valid_until)
                .unwrap_or(i64::MAX),
            left_record.signer.as_str(),
            left_record.nonce,
            left.as_str(),
        )
            .cmp(&(
                right_record
                    .signed_operation
                    .as_ref()
                    .map(|operation| operation.unsigned.valid_until)
                    .unwrap_or(i64::MAX),
                right_record.signer.as_str(),
                right_record.nonce,
                right.as_str(),
            ))
    });
}

fn add_history(ledger: &mut LedgerState, address: &str, operation_id: &str) {
    let account = ledger.accounts.entry(address.to_owned()).or_default();
    if !account.operation_ids.iter().any(|id| id == operation_id) {
        account.operation_ids.push(operation_id.to_owned());
    }
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
    let url = Url::parse(endpoint)
        .map_err(|error| Error::msg(format!("invalid endpoint URL: {error}")))?;
    if url.scheme() != "wss" {
        return Err(Error::msg("node endpoint must use wss://"));
    }
    if url.host().is_none() {
        return Err(Error::msg("node endpoint is missing its host"));
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

fn apply_reward_ip_update(
    ledger: &mut LedgerState,
    node_id: u64,
    endpoint: &str,
    reward_ip: &str,
    declared_slot: &str,
    updated_at: i64,
) -> Result<()> {
    parse_wss_endpoint(endpoint)?;
    let new_slot = validate_reward_ip_slot(reward_ip, declared_slot)?;
    let warmup_until = updated_at
        .checked_add(ledger.settings.warmup_seconds)
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
    node.endpoint = endpoint.to_owned();
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
        node.reward_vesting_schedules.clear();
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
            let last_probe_success = node.last_probe_success?;
            let slash_at = last_probe_success.checked_add(ledger.settings.offline_slash_seconds)?;
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
        node.reward_vesting_schedules.clear();
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

/// Applies deterministic Epoch transitions while constructing or replaying a block post-state.
/// Callers outside block execution must never advance economic state from their local clock.
fn settle_elapsed_epochs_for_block(ledger: &mut LedgerState, block_timestamp: i64) -> Result<()> {
    loop {
        let epoch_end = ledger
            .epoch_started_at
            .checked_add(ledger.epoch_seconds_snapshot)
            .ok_or_else(|| Error::msg("Epoch boundary overflow"))?;
        if block_timestamp < epoch_end {
            break;
        }
        settle_one_epoch(ledger, epoch_end)?;
        ledger.epoch_started_at = epoch_end;
        ledger.epoch_number += 1;
        ledger.epoch_seconds_snapshot = ledger.settings.epoch_seconds;
        ledger.epoch_mint_amount_snapshot = ledger.settings.epoch_mint_amount;
        ledger.reward_immediate_bps_snapshot = ledger.settings.reward_immediate_bps;
        ledger.reward_vesting_seconds_snapshot = ledger.settings.reward_vesting_seconds;
        let slot_seconds = ledger.settings.availability_slot_seconds;
        ledger.availability_slots.retain(|_, record| {
            record
                .slot
                .checked_mul(slot_seconds)
                .and_then(|start| start.checked_add(slot_seconds))
                .is_some_and(|end| end > epoch_end)
        });
        refresh_validator_committee(ledger, epoch_end)?;
        activate_multi_validator_availability_if_ready(ledger, epoch_end);
    }
    Ok(())
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

fn settle_one_epoch(ledger: &mut LedgerState, epoch_end: i64) -> Result<()> {
    settle_reward_vesting(ledger, epoch_end)?;
    let epoch_seconds = u64::try_from(ledger.epoch_seconds_snapshot)
        .map_err(|_| Error::msg("current Epoch duration must be positive"))?;
    let mut weights = BTreeMap::<u64, u128>::new();
    let mut total_weight = 0_u128;
    for (node_id, node) in &ledger.nodes {
        if node.epoch_eligible_seconds > epoch_seconds {
            return Err(Error::msg(
                "Node eligible seconds exceed the current Epoch duration",
            ));
        }
        let factor = if node.validator
            && node.validator_signature_rate_bps
                >= ledger.settings.validator_signature_threshold_bps
        {
            ledger.settings.validator_weight_bps
        } else {
            10_000
        };
        let weight = u128::from(node.epoch_eligible_seconds) * u128::from(factor);
        if weight > 0 {
            weights.insert(*node_id, weight);
            total_weight = total_weight
                .checked_add(weight)
                .ok_or_else(|| Error::msg("total Node reward weight overflow"))?;
        }
    }
    if total_weight == 0 {
        for node in ledger.nodes.values_mut() {
            node.epoch_eligible_seconds = 0;
        }
        return Ok(());
    }
    let budget = ledger.epoch_mint_amount_snapshot.min(ledger.pool_remaining);
    if budget == 0 {
        for node in ledger.nodes.values_mut() {
            node.epoch_eligible_seconds = 0;
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
    let required_bond = ledger.settings.required_service_bond;
    for (node_id, reward, _) in allocations {
        let node = ledger.nodes.get_mut(&node_id).expect("weighted node");
        let bond_needed = required_bond.saturating_sub(node.service_bond);
        let to_bond = reward.min(bond_needed);
        node.service_bond += to_bond;
        let reward_after_bond = reward - to_bond;
        let immediate = reward_after_bond
            .checked_mul(u128::from(ledger.reward_immediate_bps_snapshot))
            .ok_or_else(|| Error::msg("immediate Node reward calculation overflow"))?
            / BPS_DENOMINATOR;
        let vesting = reward_after_bond - immediate;
        node.claimable_reward = node
            .claimable_reward
            .checked_add(immediate)
            .ok_or_else(|| Error::msg("claimable Node reward overflow"))?;
        if vesting > 0 {
            let ends_at = epoch_end
                .checked_add(ledger.reward_vesting_seconds_snapshot)
                .ok_or_else(|| Error::msg("Node reward vesting boundary overflow"))?;
            node.reward_vesting_schedules.push(RewardVestingSchedule {
                total_amount: vesting,
                released_amount: 0,
                starts_at: epoch_end,
                ends_at,
            });
        }
    }
    for node in ledger.nodes.values_mut() {
        node.epoch_eligible_seconds = 0;
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

fn settle_node_reward_vesting(node: &mut NodeRecord, epoch_end: i64) -> Result<()> {
    for schedule in &mut node.reward_vesting_schedules {
        let vested = if epoch_end <= schedule.starts_at {
            0
        } else if epoch_end >= schedule.ends_at {
            schedule.total_amount
        } else {
            let elapsed = u128::try_from(epoch_end - schedule.starts_at)
                .map_err(|_| Error::msg("Node reward vesting elapsed time is invalid"))?;
            let duration = u128::try_from(schedule.ends_at - schedule.starts_at)
                .map_err(|_| Error::msg("Node reward vesting duration is invalid"))?;
            schedule
                .total_amount
                .checked_mul(elapsed)
                .ok_or_else(|| Error::msg("Node reward vesting calculation overflow"))?
                / duration
        };
        let newly_released = vested
            .checked_sub(schedule.released_amount)
            .ok_or_else(|| Error::msg("Node reward vesting amount regressed"))?;
        node.claimable_reward = node
            .claimable_reward
            .checked_add(newly_released)
            .ok_or_else(|| Error::msg("claimable Node reward overflow"))?;
        schedule.released_amount = vested;
    }
    node.reward_vesting_schedules
        .retain(|schedule| schedule.released_amount < schedule.total_amount);
    Ok(())
}

fn node_vesting_reward(node: &NodeRecord) -> Result<u128> {
    node.reward_vesting_schedules
        .iter()
        .try_fold(0_u128, |total, schedule| {
            let remaining = schedule
                .total_amount
                .checked_sub(schedule.released_amount)
                .ok_or_else(|| Error::msg("Node reward vesting amount is invalid"))?;
            total
                .checked_add(remaining)
                .ok_or_else(|| Error::msg("Node vesting reward overflow"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn validator_state_must_be_cleared_before_node_drain() {
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
    }

    fn availability_test_node(node_id: u64) -> NodeRecord {
        NodeRecord {
            node_id,
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
            epoch_eligible_seconds: 0,
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 0,
            reward_vesting_schedules: Vec::new(),
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
        ledger.settings.required_service_bond = 0;
        for node_id in 1..=7 {
            let mut node = availability_test_node(node_id);
            node.validator_bond = ledger.settings.validator_bond;
            node.validator_candidate_since = Some(0);
            let slot = node.ip_slot.clone();
            ledger.nodes.insert(node_id, node);
            assert!(bind_ip_slot_if_available(&mut ledger, &slot, node_id, 0));
        }
        let trusted = availability_verifier_set(&ledger, 1, 0);
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
        let decentralized = availability_verifier_set(&ledger, 1, 5);
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
        let fallback = availability_verifier_set(&ledger, 1, 10);
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
    fn thirty_one_seat_committee_rotates_at_most_ten_nodes_per_finalized_epoch() {
        let mut ledger = LedgerState::default();
        ledger.settings.required_service_bond = 0;
        ledger.settings.governance_min_service_seconds = 0;
        ledger.settings.max_active_validators = 31;
        ledger.settings.max_validator_rotations = 10;
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
        let second = ledger.consensus.active_validators.clone();
        let first_set = first.into_iter().collect::<BTreeSet<_>>();
        let second_set = second.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(first_set.intersection(&second_set).count(), 21);
        assert_eq!(second_set.difference(&first_set).count(), 10);
        assert_eq!(second, (11..=41).collect::<Vec<_>>());
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
        let set = availability_verifier_set(&ledger, 1, 0);
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
        let primary_at =
            availability_scheduled_at(&primary_ticket, 10, 60, AvailabilityVerifierRole::Primary)
                .unwrap();
        let audit_at =
            availability_scheduled_at(&audit_ticket, 10, 60, AvailabilityVerifierRole::Audit)
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
        target.epoch_eligible_seconds = 0;
        target.total_eligible_seconds = 0;
        ledger.nodes.insert(10, target);
        ledger.consensus.active_validators = (1..=9).collect();
        let set = availability_verifier_set(&ledger, 10, 0);
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
        assert_eq!(ledger.nodes[&10].epoch_eligible_seconds, 0);
        apply(
            &mut ledger,
            set.auditor_ids[0],
            AvailabilityVerifierRole::Audit,
            10,
        );
        assert_eq!(ledger.nodes[&10].epoch_eligible_seconds, 0);
        apply(
            &mut ledger,
            set.auditor_ids[1],
            AvailabilityVerifierRole::Audit,
            11,
        );
        assert_eq!(ledger.nodes[&10].epoch_eligible_seconds, 60);
        assert_eq!(ledger.nodes[&10].total_eligible_seconds, 60);
        let record = &ledger.availability_slots["10:0"];
        assert_eq!(record.primary_operation_ids.len(), 3);
        assert_eq!(record.audit_operation_ids.len(), 2);
        assert_eq!(record.credited_seconds, 60);
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
                    epoch_eligible_seconds: 0,
                    total_eligible_seconds: if mature { 180 * 86_400 } else { 30 * 86_400 },
                    service_bond: if node_id == 1 {
                        10_000_000 * crate::amount::MRK_SCALE
                    } else {
                        100 * crate::amount::MRK_SCALE
                    },
                    service_bond_unlock_at: None,
                    offline_slashed_at: None,
                    offline_slashed_service_bond: 0,
                    offline_slashed_vesting_reward: 0,
                    claimable_reward: 0,
                    reward_vesting_schedules: Vec::new(),
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
        ledger.nodes.insert(
            1,
            NodeRecord {
                node_id: 1,
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
                epoch_eligible_seconds: 60,
                total_eligible_seconds: 60,
                service_bond: 0,
                service_bond_unlock_at: None,
                offline_slashed_at: None,
                offline_slashed_service_bond: 0,
                offline_slashed_vesting_reward: 0,
                claimable_reward: 0,
                reward_vesting_schedules: Vec::new(),
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
        let node = &ledger.nodes[&1];
        let expected = 500 * crate::amount::MRK_SCALE;
        let reward_after_bond = expected - 10;
        let immediate = reward_after_bond * 1_000 / BPS_DENOMINATOR;
        let vesting = reward_after_bond - immediate;
        assert_eq!(node.service_bond, 10);
        assert_eq!(node.claimable_reward, immediate);
        assert_eq!(node_vesting_reward(node).unwrap(), vesting);
        assert_eq!(node.reward_vesting_schedules.len(), 1);
        assert_eq!(
            ledger.lifetime_minted,
            crate::amount::GENESIS_TREASURY_ALLOCATION + expected
        );

        settle_elapsed_epochs_for_block(&mut ledger, now + 90).unwrap();
        assert_eq!(
            ledger.nodes[&1].claimable_reward, immediate,
            "vesting must advance only at Epoch boundaries"
        );

        ledger.settings.required_service_bond = 0;
        ledger.settings.epoch_seconds = 120;
        ledger.settings.epoch_mint_amount = 450 * crate::amount::MRK_SCALE;
        ledger.settings.reward_immediate_bps = 2_000;
        ledger.settings.reward_vesting_seconds = 1_000;
        ledger.nodes.get_mut(&1).unwrap().epoch_eligible_seconds = 60;
        let node_one_before = ledger.nodes[&1].claimable_reward;
        let mut node_two = ledger.nodes[&1].clone();
        node_two.node_id = 2;
        node_two.epoch_eligible_seconds = 30;
        node_two.total_eligible_seconds = 30;
        node_two.service_bond = 0;
        node_two.claimable_reward = 0;
        node_two.reward_vesting_schedules.clear();
        ledger.nodes.insert(2, node_two);
        settle_elapsed_epochs_for_block(&mut ledger, now + 120).unwrap();
        let first_schedule_release = vesting * 60 / (180 * 86_400);
        let second_budget = 500 * crate::amount::MRK_SCALE;
        let node_two_reward = second_budget / 3;
        let node_one_reward = second_budget - node_two_reward;
        assert_eq!(
            ledger.nodes[&1].claimable_reward - node_one_before,
            node_one_reward / 10 + first_schedule_release
        );
        assert_eq!(ledger.nodes[&2].claimable_reward, node_two_reward / 10);
        assert_eq!(
            ledger.epoch_mint_amount_snapshot,
            450 * crate::amount::MRK_SCALE,
            "governance changes must become active in the next Epoch"
        );
        assert_eq!(ledger.epoch_seconds_snapshot, 120);
        assert_eq!(ledger.reward_immediate_bps_snapshot, 2_000);
        assert_eq!(ledger.reward_vesting_seconds_snapshot, 1_000);
        let epoch_number = ledger.epoch_number;
        ledger.nodes.get_mut(&1).unwrap().epoch_eligible_seconds = 60;
        settle_elapsed_epochs_for_block(&mut ledger, now + 180).unwrap();
        assert_eq!(ledger.epoch_number, epoch_number);
        assert_eq!(ledger.nodes[&1].epoch_eligible_seconds, 60);
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
            set_governance_parameter(&mut settings, "reward-immediate-bps", "2500").unwrap(),
            ("1000".to_owned(), "2500".to_owned())
        );
        assert_eq!(settings.reward_immediate_bps, 2_500);
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
    fn overlapping_reward_schedules_release_independently() {
        let mut node = NodeRecord {
            node_id: 1,
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
            epoch_eligible_seconds: 0,
            total_eligible_seconds: 0,
            service_bond: 0,
            service_bond_unlock_at: None,
            offline_slashed_at: None,
            offline_slashed_service_bond: 0,
            offline_slashed_vesting_reward: 0,
            claimable_reward: 10,
            reward_vesting_schedules: vec![
                RewardVestingSchedule {
                    total_amount: 90,
                    released_amount: 0,
                    starts_at: 0,
                    ends_at: 180,
                },
                RewardVestingSchedule {
                    total_amount: 180,
                    released_amount: 0,
                    starts_at: 60,
                    ends_at: 240,
                },
            ],
            validator: false,
            validator_signature_rate_bps: 0,
            validator_bond: 0,
            validator_candidate_since: None,
            validator_last_epoch: None,
            validator_consecutive_epochs: 0,
            validator_exit_requested_at: None,
            validator_bond_unlock_at: None,
        };

        settle_node_reward_vesting(&mut node, 120).unwrap();
        assert_eq!(node.claimable_reward, 130);
        assert_eq!(node_vesting_reward(&node).unwrap(), 150);
        assert_eq!(node.reward_vesting_schedules.len(), 2);

        settle_node_reward_vesting(&mut node, 240).unwrap();
        assert_eq!(node.claimable_reward, 280);
        assert_eq!(node_vesting_reward(&node).unwrap(), 0);
        assert!(node.reward_vesting_schedules.is_empty());
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
        register_node(
            &paths,
            "node1",
            password,
            "wss://1.1.1.1/v1/relay",
            "0.02MRK",
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
            .with_ledger_mut(|ledger| Ok(prune_history_with_limits(ledger, 2, 1, 1)))
            .unwrap();
        assert_eq!(report.pruned_blocks, 2);
        assert_eq!(report.retained_blocks, 2);
        assert_eq!(report.pruned_through_height, 2);
        assert_eq!(
            paths.read_ledger().unwrap().operation_history_from_height,
            4
        );
        assert!(
            block_by_height(&paths, 1)
                .unwrap_err()
                .to_string()
                .contains("pruned")
        );
        assert_eq!(block_by_height(&paths, 3).unwrap().height, 3);
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
