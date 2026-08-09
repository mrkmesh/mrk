use redb::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};

use crate::{Error, Result, model::LedgerState};

const CHECKPOINTS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("bootstrap_checkpoints/v1");

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(CHECKPOINTS_TABLE).map_err(redb_error)?;
    Ok(())
}

pub(crate) fn store(
    write: &WriteTransaction,
    height: u64,
    checkpoint: &LedgerState,
    retained_limit: usize,
) -> Result<()> {
    let bytes = serde_json::to_vec(checkpoint)?;
    let mut table = write.open_table(CHECKPOINTS_TABLE).map_err(redb_error)?;
    if let Some(existing) = table.get(height).map_err(redb_error)? {
        if existing.value() != bytes.as_slice() {
            return Err(Error::msg(format!(
                "checkpoint at height {height} is immutable"
            )));
        }
    } else {
        table.insert(height, bytes.as_slice()).map_err(redb_error)?;
    }
    let heights = table
        .iter()
        .map_err(redb_error)?
        .map(|entry| entry.map(|(height, _)| height.value()).map_err(redb_error))
        .collect::<Result<Vec<_>>>()?;
    for stale_height in heights
        .iter()
        .take(heights.len().saturating_sub(retained_limit.max(1)))
    {
        table.remove(*stale_height).map_err(redb_error)?;
    }
    Ok(())
}

pub(crate) fn get(read: &ReadTransaction, height: u64) -> Result<Option<LedgerState>> {
    let table = read.open_table(CHECKPOINTS_TABLE).map_err(redb_error)?;
    table
        .get(height)
        .map_err(redb_error)?
        .map(|bytes| serde_json::from_slice(bytes.value()))
        .transpose()
        .map_err(Into::into)
}

pub(crate) fn latest(read: &ReadTransaction) -> Result<Option<(u64, LedgerState)>> {
    let table = read.open_table(CHECKPOINTS_TABLE).map_err(redb_error)?;
    table
        .iter()
        .map_err(redb_error)?
        .next_back()
        .map(|entry| {
            let (height, bytes) = entry.map_err(redb_error)?;
            Ok((height.value(), serde_json::from_slice(bytes.value())?))
        })
        .transpose()
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}
