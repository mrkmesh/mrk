use crate::model::LedgerState;

pub const RETENTION: usize = 24;
pub const TARGET_BLOCKS: i64 = 3_600;
pub const MAX_INTERVAL_SECONDS: i64 = 6 * 3_600;

pub(crate) fn interval_seconds(latest: &LedgerState) -> i64 {
    latest
        .settings
        .block_interval_seconds
        .max(1)
        .saturating_mul(TARGET_BLOCKS)
        .min(MAX_INTERVAL_SECONDS)
}

pub(crate) fn should_persist(previous: Option<&LedgerState>, latest: &LedgerState) -> bool {
    let interval_seconds = interval_seconds(latest);
    !previous
        .and_then(|checkpoint| checkpoint.pruned_tip_timestamp)
        .zip(latest.pruned_tip_timestamp)
        .is_some_and(|(previous, latest)| latest.saturating_sub(previous) < interval_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_interval_tracks_block_cadence_with_a_six_hour_cap() {
        let mut ledger = LedgerState::default();
        assert_eq!(interval_seconds(&ledger), 6 * 3_600);

        ledger.settings.block_interval_seconds = 1;
        assert_eq!(interval_seconds(&ledger), 3_600);

        ledger.settings.block_interval_seconds = 3;
        assert_eq!(interval_seconds(&ledger), 3 * 3_600);
    }
}
