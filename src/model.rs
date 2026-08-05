use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::amount::{GENESIS_TREASURY_ALLOCATION, MRK_SCALE, NODE_EMISSION_ALLOCATION};

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_LEDGER_ID: &str = "mrk-local";
pub const TRANSFER_FEE: u128 = MRK_SCALE / 1_000;
pub const DEFAULT_OPERATION_VALIDITY_SECONDS: i64 = 600;

fn default_epoch_mint_amount() -> u128 {
    100 * MRK_SCALE
}

fn default_epoch_seconds() -> i64 {
    300
}

fn default_reward_immediate_bps() -> u32 {
    1_000
}

fn default_reward_vesting_seconds() -> i64 {
    180 * 86_400
}

fn default_probe_validity_seconds() -> i64 {
    300
}

fn default_availability_slot_seconds() -> i64 {
    60
}

fn default_availability_verifier_count() -> u32 {
    5
}

fn default_availability_quorum() -> u32 {
    3
}

fn default_availability_audit_rate_bps() -> u32 {
    500
}

fn default_availability_auditor_count() -> u32 {
    3
}

fn default_availability_audit_quorum() -> u32 {
    2
}

fn default_governance_min_service_seconds() -> u64 {
    30 * 86_400
}

fn default_block_interval_seconds() -> i64 {
    10
}

fn default_validator_bond() -> u128 {
    50_000 * MRK_SCALE
}

fn default_max_active_validators() -> u32 {
    31
}

fn default_max_validator_rotations() -> u32 {
    10
}

fn default_consensus_round_timeout_seconds() -> i64 {
    10
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerSettings {
    pub epoch_seconds: i64,
    #[serde(default = "default_epoch_mint_amount")]
    pub epoch_mint_amount: u128,
    #[serde(default = "default_reward_immediate_bps")]
    pub reward_immediate_bps: u32,
    #[serde(default = "default_reward_vesting_seconds")]
    pub reward_vesting_seconds: i64,
    pub validator_weight_bps: u32,
    pub validator_signature_threshold_bps: u32,
    pub min_service_bond: u128,
    pub warmup_seconds: i64,
    pub heartbeat_grace_seconds: i64,
    #[serde(default = "default_probe_validity_seconds")]
    pub probe_validity_seconds: i64,
    #[serde(default = "default_availability_slot_seconds")]
    pub availability_slot_seconds: i64,
    #[serde(default = "default_availability_verifier_count")]
    pub availability_verifier_count: u32,
    #[serde(default = "default_availability_quorum")]
    pub availability_quorum: u32,
    #[serde(default = "default_availability_audit_rate_bps")]
    pub availability_audit_rate_bps: u32,
    #[serde(default = "default_availability_auditor_count")]
    pub availability_auditor_count: u32,
    #[serde(default = "default_availability_audit_quorum")]
    pub availability_audit_quorum: u32,
    pub ip_reuse_cooldown_seconds: i64,
    #[serde(default = "default_governance_min_service_seconds")]
    pub governance_min_service_seconds: u64,
    #[serde(default = "default_block_interval_seconds")]
    pub block_interval_seconds: i64,
    #[serde(default = "default_validator_bond")]
    pub validator_bond: u128,
    #[serde(default = "default_max_active_validators")]
    pub max_active_validators: u32,
    #[serde(default = "default_max_validator_rotations")]
    pub max_validator_rotations: u32,
    #[serde(default = "default_consensus_round_timeout_seconds")]
    pub consensus_round_timeout_seconds: i64,
}

impl Default for LedgerSettings {
    fn default() -> Self {
        Self {
            epoch_seconds: default_epoch_seconds(),
            epoch_mint_amount: default_epoch_mint_amount(),
            reward_immediate_bps: default_reward_immediate_bps(),
            reward_vesting_seconds: default_reward_vesting_seconds(),
            validator_weight_bps: 12_500,
            validator_signature_threshold_bps: 9_500,
            min_service_bond: 100 * MRK_SCALE,
            warmup_seconds: 7 * 86_400,
            heartbeat_grace_seconds: 90,
            probe_validity_seconds: default_probe_validity_seconds(),
            availability_slot_seconds: default_availability_slot_seconds(),
            availability_verifier_count: default_availability_verifier_count(),
            availability_quorum: default_availability_quorum(),
            availability_audit_rate_bps: default_availability_audit_rate_bps(),
            availability_auditor_count: default_availability_auditor_count(),
            availability_audit_quorum: default_availability_audit_quorum(),
            ip_reuse_cooldown_seconds: 7 * 86_400,
            governance_min_service_seconds: default_governance_min_service_seconds(),
            block_interval_seconds: default_block_interval_seconds(),
            validator_bond: default_validator_bond(),
            max_active_validators: default_max_active_validators(),
            max_validator_rotations: default_max_validator_rotations(),
            consensus_round_timeout_seconds: default_consensus_round_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockConsensusMode {
    #[default]
    Node1,
    MultiValidator,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AvailabilityMode {
    #[default]
    Node1Trusted,
    MultiValidator,
}

impl std::fmt::Display for AvailabilityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node1Trusted => write!(f, "NODE1_TRUSTED"),
            Self::MultiValidator => write!(f, "MULTI_VALIDATOR"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AvailabilityVerifierRole {
    Primary,
    Audit,
}

impl std::fmt::Display for AvailabilityVerifierRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary => write!(f, "PRIMARY"),
            Self::Audit => write!(f, "AUDIT"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRecord {
    pub version: u32,
    pub ledger_id: String,
    pub height: u64,
    pub previous_block_hash: String,
    pub timestamp: i64,
    pub producer_node_id: u64,
    pub producer_owner_address: String,
    pub operation_ids: Vec<String>,
    pub state_root: String,
    pub block_hash: String,
    pub producer_signature: String,
    #[serde(default)]
    pub consensus_mode: BlockConsensusMode,
    #[serde(default)]
    pub consensus_round: u32,
    #[serde(default)]
    pub validator_set_hash: String,
    #[serde(default)]
    pub commit_signatures: Vec<ConsensusVote>,
    #[serde(default)]
    pub validator_epoch: u64,
    #[serde(default)]
    pub validator_node_ids: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusVoteType {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusVote {
    pub ledger_id: String,
    pub height: u64,
    pub round: u32,
    pub vote_type: ConsensusVoteType,
    pub block_hash: Option<String>,
    pub validator_set_hash: String,
    pub validator_node_id: u64,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub block: BlockRecord,
    pub proposed_at: i64,
    #[serde(default)]
    pub post_state: Option<Box<LedgerState>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator_node_id: u64,
    pub height: u64,
    pub round: u32,
    pub vote_type: ConsensusVoteType,
    pub first_vote: ConsensusVote,
    pub conflicting_vote: ConsensusVote,
    pub recorded_at: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConsensusState {
    #[serde(default)]
    pub active_validators: Vec<u64>,
    #[serde(default)]
    pub last_selection_epoch: Option<u64>,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub round: u32,
    #[serde(default)]
    pub round_started_at: Option<i64>,
    #[serde(default)]
    pub proposal: Option<ConsensusProposal>,
    /// A value that obtained a PREVOTE quorum at this height and must be
    /// reproposed across later rounds until it finalizes or the height changes.
    #[serde(default)]
    pub valid_proposal: Option<ConsensusProposal>,
    #[serde(default)]
    pub valid_round: Option<u32>,
    #[serde(default)]
    pub prevotes: BTreeMap<u64, ConsensusVote>,
    #[serde(default)]
    pub precommits: BTreeMap<u64, ConsensusVote>,
    #[serde(default)]
    pub locks: BTreeMap<u64, String>,
    #[serde(default)]
    pub double_sign_evidence: Vec<DoubleSignEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisAuthority {
    pub node_id: u64,
    pub owner_address: String,
    pub owner_public_key: String,
    pub established_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceActionRecord {
    pub operation_id: String,
    pub action: String,
    pub signer_node_id: u64,
    pub executed_at: i64,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceProposalKind {
    Standard,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceProposalStatus {
    Voting,
    Passed,
    Rejected,
    Executed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceVoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceProposalAction {
    SetParameter {
        parameter: String,
        value: String,
    },
    PauseEmission {
        reason: String,
    },
    ResumeEmission,
    TreasurySpend {
        recipient: String,
        #[serde(with = "u128_string")]
        amount: u128,
        reference_hash: String,
    },
}

mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasurySpendRecord {
    pub proposal_id: u64,
    pub operation_id: String,
    pub recipient: String,
    pub amount: u128,
    pub reference_hash: String,
    pub executed_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceVoteRecord {
    pub node_id: u64,
    pub choice: GovernanceVoteChoice,
    pub power: u128,
    pub operation_id: String,
    pub voted_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceValidatorVoteRecord {
    pub node_id: u64,
    pub choice: GovernanceVoteChoice,
    pub operation_id: String,
    pub voted_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceProposalRecord {
    pub proposal_id: u64,
    pub proposer_node_id: u64,
    pub proposer_reward_address: String,
    pub kind: GovernanceProposalKind,
    pub title: String,
    pub action: GovernanceProposalAction,
    pub created_at: i64,
    pub voting_ends_at: i64,
    pub execute_after: i64,
    pub status: GovernanceProposalStatus,
    pub snapshot_epoch: u64,
    pub power_snapshot: BTreeMap<u64, u128>,
    pub total_power: u128,
    pub votes: BTreeMap<u64, GovernanceVoteRecord>,
    #[serde(default)]
    pub validator_snapshot: Vec<u64>,
    #[serde(default)]
    pub validator_votes: BTreeMap<u64, GovernanceValidatorVoteRecord>,
    #[serde(default)]
    pub timelock_vetoes: BTreeMap<u64, GovernanceVoteRecord>,
    pub proposal_bond: u128,
    pub finalized_at: Option<i64>,
    pub executed_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceState {
    #[serde(default)]
    pub emission_paused: bool,
    #[serde(default)]
    pub pause_reason: Option<String>,
    #[serde(default)]
    pub last_action_at: Option<i64>,
    #[serde(default)]
    pub actions: Vec<GovernanceActionRecord>,
    #[serde(default = "default_next_governance_proposal_id")]
    pub next_proposal_id: u64,
    #[serde(default)]
    pub proposals: BTreeMap<u64, GovernanceProposalRecord>,
}

fn default_next_governance_proposal_id() -> u64 {
    1
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            emission_paused: false,
            pause_reason: None,
            last_action_at: None,
            actions: Vec::new(),
            next_proposal_id: 1,
            proposals: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerState {
    pub version: u32,
    pub ledger_id: String,
    pub created_at: i64,
    pub lifetime_minted: u128,
    pub pool_remaining: u128,
    pub burned: u128,
    pub treasury: u128,
    #[serde(default)]
    pub genesis_treasury_minted: u128,
    #[serde(default)]
    pub treasury_spends: Vec<TreasurySpendRecord>,
    pub epoch_started_at: i64,
    pub epoch_number: u64,
    #[serde(default = "default_epoch_seconds")]
    pub epoch_seconds_snapshot: i64,
    #[serde(default = "default_epoch_mint_amount")]
    pub epoch_mint_amount_snapshot: u128,
    #[serde(default = "default_reward_immediate_bps")]
    pub reward_immediate_bps_snapshot: u32,
    #[serde(default = "default_reward_vesting_seconds")]
    pub reward_vesting_seconds_snapshot: i64,
    pub settings: LedgerSettings,
    pub accounts: BTreeMap<String, AccountState>,
    pub operations: BTreeMap<String, OperationRecord>,
    pub networks: BTreeMap<String, NetworkRecord>,
    pub network_aliases: BTreeMap<String, String>,
    pub nodes: BTreeMap<u64, NodeRecord>,
    pub ip_slots: BTreeMap<String, IpSlotRecord>,
    #[serde(default)]
    pub availability_slots: BTreeMap<String, AvailabilitySlotRecord>,
    pub availability_mode: AvailabilityMode,
    pub availability_activated_at: Option<i64>,
    pub availability_activated_epoch: Option<u64>,
    #[serde(default)]
    pub payment_authorizations: BTreeMap<String, PaymentAuthorizationRecord>,
    pub next_node_id: u64,
    #[serde(default)]
    pub genesis_authority: Option<GenesisAuthority>,
    #[serde(default)]
    pub governance: GovernanceState,
    #[serde(default)]
    pub blocks: Vec<BlockRecord>,
    /// Local history checkpoint used by LITE nodes after pruning a finalized prefix.
    /// These fields are storage metadata and are excluded from the consensus state root.
    #[serde(default)]
    pub pruned_through_height: u64,
    #[serde(default)]
    pub pruned_tip_hash: Option<String>,
    #[serde(default)]
    pub pruned_tip_timestamp: Option<i64>,
    #[serde(default)]
    pub pruned_operation_count: u64,
    #[serde(default = "default_operation_history_from_height")]
    pub operation_history_from_height: u64,
    #[serde(default)]
    pub pending_operation_ids: Vec<String>,
    #[serde(default)]
    pub consensus: ConsensusState,
    /// Compact state captured immediately after the latest finalized block.
    /// The nested checkpoint always has this field set to `None`.
    #[serde(default)]
    pub finalized_checkpoint: Option<Box<LedgerState>>,
}

impl Default for LedgerState {
    fn default() -> Self {
        let now = Utc::now().timestamp();
        Self {
            version: PROTOCOL_VERSION,
            ledger_id: DEFAULT_LEDGER_ID.to_owned(),
            created_at: now,
            lifetime_minted: GENESIS_TREASURY_ALLOCATION,
            pool_remaining: NODE_EMISSION_ALLOCATION,
            burned: 0,
            treasury: GENESIS_TREASURY_ALLOCATION,
            genesis_treasury_minted: GENESIS_TREASURY_ALLOCATION,
            treasury_spends: Vec::new(),
            epoch_started_at: now,
            epoch_number: 0,
            epoch_seconds_snapshot: default_epoch_seconds(),
            epoch_mint_amount_snapshot: default_epoch_mint_amount(),
            reward_immediate_bps_snapshot: default_reward_immediate_bps(),
            reward_vesting_seconds_snapshot: default_reward_vesting_seconds(),
            settings: LedgerSettings::default(),
            accounts: BTreeMap::new(),
            operations: BTreeMap::new(),
            networks: BTreeMap::new(),
            network_aliases: BTreeMap::new(),
            nodes: BTreeMap::new(),
            ip_slots: BTreeMap::new(),
            availability_slots: BTreeMap::new(),
            availability_mode: AvailabilityMode::Node1Trusted,
            availability_activated_at: None,
            availability_activated_epoch: None,
            payment_authorizations: BTreeMap::new(),
            next_node_id: 1,
            genesis_authority: None,
            governance: GovernanceState::default(),
            blocks: Vec::new(),
            pruned_through_height: 0,
            pruned_tip_hash: None,
            pruned_tip_timestamp: None,
            pruned_operation_count: 0,
            operation_history_from_height: 1,
            pending_operation_ids: Vec::new(),
            consensus: ConsensusState::default(),
            finalized_checkpoint: None,
        }
    }
}

fn default_operation_history_from_height() -> u64 {
    1
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub public_key: Option<String>,
    pub liquid: u128,
    pub nonce: u64,
    pub operation_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedOperation {
    pub ledger_id: String,
    pub protocol_version: u32,
    pub module: String,
    pub action: String,
    pub signer: String,
    pub account_nonce: u64,
    pub valid_until: i64,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedOperation {
    #[serde(flatten)]
    pub unsigned: UnsignedOperation,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStatus {
    Pending,
    Finalized,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: String,
    pub kind: String,
    pub signer: String,
    pub nonce: u64,
    pub created_at: i64,
    pub status: OperationStatus,
    pub payload: Value,
    pub signature: String,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub signed_operation: Option<SignedOperation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkRecord {
    pub network_id: String,
    pub commitment: String,
    pub alias: String,
    pub owner_address: String,
    pub owner_public_key: String,
    pub created_at: i64,
    pub escrow_balance: u128,
    pub next_member_serial: u64,
    pub members: BTreeMap<String, MemberRecord>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelayDirection {
    SenderToReceiver,
    ReceiverToSender,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrafficDirectionSettlement {
    pub settled_sequence: u64,
    pub settled_payload_bytes: u64,
    pub settled_amount: u128,
    #[serde(default)]
    pub settled_transcript_hash: Option<String>,
    pub last_receipt_hash: Option<String>,
    pub last_receipt_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentAuthorizationRecord {
    pub authorization_id: String,
    pub network_commitment: String,
    pub network_id: String,
    pub payer_address: String,
    pub node_id: u64,
    pub sender_member_id: String,
    pub receiver_member_id: String,
    pub session_id: String,
    pub price_per_gib: u128,
    pub max_amount: u128,
    pub reserved_remaining: u128,
    pub settled_amount: u128,
    pub created_at: i64,
    pub valid_until: i64,
    pub claim_until: i64,
    pub refunded_at: Option<i64>,
    pub directions: BTreeMap<RelayDirection, TrafficDirectionSettlement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberRecord {
    pub name: String,
    pub member_id: String,
    pub public_key: String,
    pub serial: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub credential_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberCredential {
    pub version: u32,
    pub network_id: String,
    pub member_id: String,
    pub member_public_key: String,
    pub permissions: Vec<String>,
    pub max_connections: u32,
    pub serial: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub owner_signature: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeStatus {
    Initialized,
    WarmingUp,
    Active,
    Draining,
    Exited,
    Suspended,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).unwrap().trim_matches('"')
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardVestingSchedule {
    pub total_amount: u128,
    pub released_amount: u128,
    pub starts_at: i64,
    pub ends_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: u64,
    pub name: String,
    pub owner_address: String,
    pub owner_public_key: String,
    pub relay_public_key: String,
    pub reward_address: String,
    pub endpoint: String,
    pub reward_ip: String,
    pub ip_slot: String,
    pub price_per_gib: u128,
    pub status: NodeStatus,
    pub registered_at: i64,
    pub warmup_until: i64,
    pub active_since: Option<i64>,
    pub last_heartbeat: Option<i64>,
    #[serde(default)]
    pub last_probe_success: Option<i64>,
    #[serde(default)]
    pub probe_success_count: u64,
    #[serde(default)]
    pub last_relay_receipt_at: Option<i64>,
    pub epoch_eligible_seconds: u64,
    pub total_eligible_seconds: u64,
    pub service_bond: u128,
    pub claimable_reward: u128,
    #[serde(default)]
    pub reward_vesting_schedules: Vec<RewardVestingSchedule>,
    pub validator: bool,
    pub validator_signature_rate_bps: u32,
    #[serde(default)]
    pub validator_bond: u128,
    #[serde(default)]
    pub validator_candidate_since: Option<i64>,
    #[serde(default)]
    pub validator_last_epoch: Option<u64>,
    #[serde(default)]
    pub validator_consecutive_epochs: u64,
    #[serde(default)]
    pub validator_exit_requested_at: Option<i64>,
    #[serde(default)]
    pub validator_bond_unlock_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySlotRecord {
    pub target_node_id: u64,
    pub slot: i64,
    pub mode: AvailabilityMode,
    pub selected_primary_ids: Vec<u64>,
    pub primary_operation_ids: BTreeMap<u64, String>,
    pub primary_quorum: u32,
    pub audit_required: bool,
    pub selected_auditor_ids: Vec<u64>,
    pub audit_operation_ids: BTreeMap<u64, String>,
    pub audit_quorum: u32,
    pub credited_seconds: u64,
    pub credited_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpSlotRecord {
    pub node_id: u64,
    pub bound_at: i64,
    pub released_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeStorageMode {
    Lite,
    #[default]
    Full,
}

impl std::fmt::Display for NodeStorageMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lite => write!(f, "LITE"),
            Self::Full => write!(f, "FULL"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalNodeConfig {
    pub version: u32,
    pub name: String,
    pub owner_address: String,
    pub relay_address: String,
    pub reward_address: String,
    pub node_id: Option<u64>,
    #[serde(default)]
    pub storage_mode: NodeStorageMode,
    #[serde(default)]
    pub bootstrap_peer: Option<String>,
    #[serde(default)]
    pub trusted_checkpoint_root: Option<String>,
    #[serde(default)]
    pub bootstrap_allow_insecure_local: bool,
    #[serde(default)]
    pub bootstrap_tls_ca: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{LedgerSettings, LedgerState};

    #[test]
    fn epoch_defaults_to_five_minutes_and_one_hundred_mrk() {
        let settings = LedgerSettings::default();
        let ledger = LedgerState::default();
        assert_eq!(settings.epoch_seconds, 300);
        assert_eq!(ledger.epoch_seconds_snapshot, 300);
        assert_eq!(settings.epoch_mint_amount, 100 * super::MRK_SCALE);
        assert_eq!(ledger.epoch_mint_amount_snapshot, 100 * super::MRK_SCALE);
        assert_eq!(settings.reward_immediate_bps, 1_000);
        assert_eq!(ledger.reward_immediate_bps_snapshot, 1_000);
        assert_eq!(settings.reward_vesting_seconds, 180 * 86_400);
        assert_eq!(ledger.reward_vesting_seconds_snapshot, 180 * 86_400);
        assert_eq!(settings.availability_verifier_count, 5);
        assert_eq!(settings.availability_quorum, 3);
        assert_eq!(settings.availability_audit_rate_bps, 500);
        assert_eq!(
            ledger.availability_mode,
            super::AvailabilityMode::Node1Trusted
        );
        assert_eq!(ledger.version, 1);
    }
}
