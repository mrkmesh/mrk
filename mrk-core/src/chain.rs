use crate::{Result, crypto::sha256_full_id, model::LedgerState};

pub(crate) fn height(ledger: &LedgerState) -> u64 {
    ledger.pruned_through_height + ledger.blocks.len() as u64
}

pub(crate) fn next_height(ledger: &LedgerState) -> u64 {
    height(ledger) + 1
}

pub(crate) fn tip_hash(ledger: &LedgerState) -> Option<&str> {
    ledger
        .blocks
        .last()
        .map(|block| block.block_hash.as_str())
        .or(ledger.pruned_tip_hash.as_deref())
}

pub(crate) fn tip_timestamp(ledger: &LedgerState) -> Option<i64> {
    ledger
        .blocks
        .last()
        .map(|block| block.timestamp)
        .or(ledger.pruned_tip_timestamp)
}

/// Earliest wall-clock timestamp at which the next block may be proposed.
/// Node 1 and multi-Validator production share this chain-level cadence.
pub(crate) fn next_block_at(ledger: &LedgerState) -> Option<i64> {
    tip_timestamp(ledger)
        .map(|timestamp| timestamp.saturating_add(ledger.settings.block_interval_seconds))
}

pub(crate) fn block_is_due(ledger: &LedgerState, now: i64) -> bool {
    next_block_at(ledger).is_none_or(|timestamp| now >= timestamp)
}

/// Consensus timeouts for a new height cannot start before that height is
/// eligible for proposal under the block cadence.
pub(crate) fn consensus_timer_started_at(
    ledger: &LedgerState,
    started_at: Option<i64>,
) -> Option<i64> {
    match (started_at, next_block_at(ledger)) {
        (Some(started), Some(ready)) => Some(started.max(ready)),
        (Some(started), None) => Some(started),
        (None, ready) => ready,
    }
}

/// Computes the consensus root from active state only. Append-only block,
/// operation, and account-history tables are intentionally excluded.
pub(crate) fn state_root(ledger: &LedgerState) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::{block_is_due, consensus_timer_started_at, next_block_at};
    use crate::model::LedgerState;

    #[test]
    fn block_cadence_and_consensus_timer_share_the_chain_tip() {
        let mut ledger = LedgerState::default();
        ledger.settings.block_interval_seconds = 3;
        ledger.pruned_through_height = 7;
        ledger.pruned_tip_timestamp = Some(100);

        assert_eq!(next_block_at(&ledger), Some(103));
        assert!(!block_is_due(&ledger, 102));
        assert!(block_is_due(&ledger, 103));
        assert_eq!(consensus_timer_started_at(&ledger, Some(101)), Some(103));
        assert_eq!(consensus_timer_started_at(&ledger, Some(105)), Some(105));
    }
}
