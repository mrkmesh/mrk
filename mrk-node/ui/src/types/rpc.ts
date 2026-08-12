export interface SystemPing {
  node_version: string
  protocol: string
  protocol_version: number
  ledger_id: string
  time: number
}

export interface ChainStatus {
  mode: string
  height: number
  burned_base_units: string
  burned_display: string
  total_settled_traffic_bytes: string
  total_settled_traffic_display: string
  last_block_hash: string | null
  last_block_at: number | null
  pending_operation_count: number
  active_validator_count: number
  availability_mode: string
  availability_earning_enabled: boolean
  pruned_through_height: number
  retained_block_count: number
  retained_operation_count: number
}

export interface BootstrapCheckpoint {
  height: number
  finalized_at: number
  state_root: string
}

export interface BlockSummary {
  height: number
  block_hash: string
  timestamp: number
  producer_node_id: number
  operation_count: number
  consensus_mode: string
}

export interface BlockList {
  blocks: BlockSummary[]
  next_cursor: number | null
}

export interface BlockRecord {
  version: number
  ledger_id: string
  height: number
  previous_block_hash: string
  timestamp: number
  producer_node_id: number
  producer_owner_address: string
  operation_ids: string[]
  state_root: string
  block_hash: string
  producer_signature: string
  consensus_mode: string
  consensus_round: number
  validator_set_hash: string
  commit_signatures: unknown[]
  validator_epoch: number
  validator_node_ids: number[]
}

export interface OperationRecord {
  operation_id: string
  kind: string
  signer: string
  nonce: number
  created_at: number
  status: string
  error?: string | null
  payload: unknown
  signature: string
  block_height: number | null
  fee_payer?: string | null
  fee_charged: string
  fee_burned: string
  fee_to_treasury: string
}

export interface BlockOperations {
  operations: OperationRecord[]
  next_cursor: number | null
}

export interface Balance {
  address: string
  balance: string | number
  balance_display: string
  nonce: number
}

export interface AccountRankingEntry {
  rank: number
  address: string
  balance_base_units: string
  balance_display: string
  balance_share_bps: number
}

export interface AccountRankingList {
  accounts: AccountRankingEntry[]
  funded_account_count: number
  total_account_balance_base_units: string
  total_account_balance_display: string
  snapshot_epoch: number
  snapshot_height: number
  next_cursor: string | null
}

export interface NodeRecord {
  node_id: number
  previous_node_id: number | null
  name: string
  owner_address: string
  endpoint: string
  reward_ip: string
  price_per_gib_display: string
  relay_capability_revision: number
  payment_window_bytes: number
  payment_window_seconds: number
  status: string
  registered_at: number
  warmup_until: number
  last_probe_success: number | null
  probe_success_count: number
  availability: string | null
  probe_valid_until: number | null
  offline_exit_at: number | null
  owns_ip_slot: boolean
  ip_slot_reusable_at: number | null
  service_bond_display: string
  governance_bond_display: string
  governance_bonded_at: number | null
  governance_exit_requested_at: number | null
  governance_bond_unlock_at: number | null
  validator: boolean
  validator_candidate: boolean
  [key: string]: unknown
}

export interface NodeList {
  nodes: NodeRecord[]
  next_cursor: number | null
}

export interface GovernanceProposal {
  proposal_id: number
  proposer_node_id: number
  kind: string
  title: string
  created_at: number
  voting_ends_at: number
  execute_after: number
  status: string
  action: unknown
  [key: string]: unknown
}

export interface TreasuryStatus {
  balance_display: string
  genesis_allocation_display: string
  total_spent_display: string
  spending_enabled: boolean
  [key: string]: unknown
}
