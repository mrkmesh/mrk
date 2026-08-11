use crate::model::LedgerState;

pub const RETENTION: usize = 24;
pub const INTERVAL_SECONDS: i64 = 3_600;

pub(crate) fn should_persist(previous: Option<&LedgerState>, latest: &LedgerState) -> bool {
    !previous
        .and_then(|checkpoint| checkpoint.pruned_tip_timestamp)
        .zip(latest.pruned_tip_timestamp)
        .is_some_and(|(previous, latest)| latest.saturating_sub(previous) < INTERVAL_SECONDS)
}
