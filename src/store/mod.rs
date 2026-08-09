use std::collections::BTreeSet;

use redb::WriteTransaction;
use serde::Serialize;

use crate::{
    Error, Result,
    chain::next_height,
    model::{BlockRecord, LedgerState, OperationRecord, OperationStatus},
};

mod block;
pub(crate) mod checkpoint;
mod operation;

pub const LITE_BLOCK_RETENTION_SECONDS: u64 = 7 * 86_400;
pub const LITE_RETAIN_ACCOUNT_OPERATIONS: usize = 1_024;

pub fn lite_retain_blocks(block_interval_seconds: i64) -> usize {
    let interval = u64::try_from(block_interval_seconds.max(1)).expect("positive interval");
    usize::try_from(LITE_BLOCK_RETENTION_SECONDS.div_ceil(interval))
        .expect("seven-day block retention fits usize")
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HistoryPruneReport {
    pub pruned_blocks: usize,
    pub pruned_operations: usize,
    pub pruned_account_history_entries: usize,
    pub pruned_through_height: u64,
    pub retained_blocks: usize,
    pub retained_operations: usize,
}

pub(crate) struct CatchUpHistory {
    pub tip_height: u64,
    pub blocks: Vec<BlockRecord>,
    pub operations: Vec<OperationRecord>,
    pub finalized_checkpoint: Option<Box<LedgerState>>,
}

pub(crate) fn initialize_tables(write: &WriteTransaction) -> Result<()> {
    block::initialize(write)?;
    operation::initialize(write)?;
    checkpoint::initialize(write)
}

pub(crate) fn hydrate_ledger(write: &WriteTransaction, ledger: &mut LedgerState) -> Result<()> {
    ledger.blocks = block::hydrate(write)?;
    operation::hydrate(write, ledger)
}

/// Builds the bounded runtime view used by block production and consensus.
/// Persisted history remains in its own tables; only the chain tip and pending
/// operation bodies enter the hot transaction.
pub(crate) fn hydrate_active_ledger(
    write: &WriteTransaction,
    ledger: &mut LedgerState,
) -> Result<()> {
    if let Some(tip) = block::tip(write)? {
        ledger.pruned_through_height = tip.height;
        ledger.pruned_tip_hash = Some(tip.block_hash);
        ledger.pruned_tip_timestamp = Some(tip.timestamp);
    }
    ledger.blocks.clear();
    ledger.operations = operation::hydrate_pending(write, &ledger.pending_operation_ids)?;
    for account in ledger.accounts.values_mut() {
        account.operation_ids.clear();
    }
    Ok(())
}

pub(crate) fn operation_exists(write: &WriteTransaction, operation_id: &str) -> Result<bool> {
    operation::contains(write, operation_id)
}

pub(crate) fn persist_histories(
    write: &WriteTransaction,
    before: &LedgerState,
    after: &LedgerState,
) -> Result<()> {
    for (index, block) in after.blocks.iter().enumerate() {
        let expected = after.pruned_through_height + index as u64 + 1;
        if block.height != expected {
            return Err(Error::msg(format!(
                "block history is not contiguous: expected height {expected}, got {}",
                block.height
            )));
        }
    }
    block::persist(write, &before.blocks, &after.blocks)?;
    operation::persist(write, before, after)
}

pub(crate) fn persisted_state(ledger: &LedgerState) -> LedgerState {
    let mut state = ledger.clone();
    state.blocks.clear();
    state.operations.clear();
    for account in state.accounts.values_mut() {
        account.operation_ids.clear();
    }
    state
}

pub(crate) fn collect_catch_up_from_tables(
    write: &WriteTransaction,
    ledger: &LedgerState,
    from_height: u64,
    max_blocks: usize,
) -> Result<CatchUpHistory> {
    let tip = block::tip(write)?;
    let tip_height = tip
        .as_ref()
        .map_or(ledger.pruned_through_height, |block| block.height);
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
    let mut blocks = Vec::new();
    for height in (from_height + 1)..=tip_height {
        if blocks.len() >= max_blocks.clamp(1, crate::consensus::MAX_CATCH_UP_BLOCKS) {
            break;
        }
        blocks.push(
            block::get(write, height)?
                .ok_or_else(|| Error::msg(format!("retained block {height} is missing")))?,
        );
    }
    let operation_ids = blocks
        .iter()
        .flat_map(|block| block.operation_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let operations = operation_ids
        .iter()
        .map(|operation_id| {
            operation::get(write, operation_id)?.ok_or_else(|| {
                Error::msg(format!(
                    "catch-up block references pruned operation {operation_id}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let reached_tip = blocks.last().map_or(from_height == tip_height, |block| {
        block.height == tip_height
    });
    let finalized_checkpoint = reached_tip
        .then(|| ledger.finalized_checkpoint.clone())
        .flatten()
        .filter(|checkpoint| checkpoint.pruned_through_height == tip_height);
    Ok(CatchUpHistory {
        tip_height,
        blocks,
        operations,
        finalized_checkpoint,
    })
}

pub(crate) fn block_by_height_from_table(
    write: &WriteTransaction,
    pruned_through_height: u64,
    height: u64,
) -> Result<BlockRecord> {
    if height == 0 {
        return Err(Error::msg("block height starts at 1"));
    }
    if height <= pruned_through_height {
        return Err(Error::msg(format!(
            "block {height} was pruned; retained history starts at {}",
            pruned_through_height + 1
        )));
    }
    block::get(write, height)?.ok_or_else(|| Error::msg(format!("block {height} does not exist")))
}

pub(crate) fn prune_history(
    ledger: &mut LedgerState,
    retained_block_limit: usize,
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

    let mut retained_operation_ids = ledger
        .pending_operation_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for block in &ledger.blocks {
        retained_operation_ids.extend(block.operation_ids.iter().cloned());
    }
    ledger.operation_history_from_height = ledger
        .blocks
        .first()
        .map_or_else(|| next_height(ledger), |block| block.height);
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

#[cfg(test)]
mod tests {
    use super::lite_retain_blocks;

    #[test]
    fn lite_block_retention_tracks_seven_days_of_configured_cadence() {
        assert_eq!(lite_retain_blocks(1), 604_800);
        assert_eq!(lite_retain_blocks(3), 201_600);
        assert_eq!(lite_retain_blocks(10), 60_480);
        assert_eq!(lite_retain_blocks(300), 2_016);
    }
}
