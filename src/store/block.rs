use std::collections::BTreeMap;

use redb::{ReadableTable, TableDefinition, WriteTransaction};

use crate::{Error, Result, model::BlockRecord};

const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks/v1");

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(BLOCKS_TABLE).map_err(redb_error)?;
    Ok(())
}

pub(super) fn hydrate(write: &WriteTransaction) -> Result<Vec<BlockRecord>> {
    let table = write.open_table(BLOCKS_TABLE).map_err(redb_error)?;
    table
        .iter()
        .map_err(redb_error)?
        .map(|entry| {
            let (_, value) = entry.map_err(redb_error)?;
            serde_json::from_slice(value.value()).map_err(Into::into)
        })
        .collect()
}

pub(super) fn tip(write: &WriteTransaction) -> Result<Option<BlockRecord>> {
    let table = write.open_table(BLOCKS_TABLE).map_err(redb_error)?;
    table
        .iter()
        .map_err(redb_error)?
        .next_back()
        .map(|entry| {
            let (_, value) = entry.map_err(redb_error)?;
            serde_json::from_slice(value.value()).map_err(Into::into)
        })
        .transpose()
}

pub(super) fn get(write: &WriteTransaction, height: u64) -> Result<Option<BlockRecord>> {
    let table = write.open_table(BLOCKS_TABLE).map_err(redb_error)?;
    table
        .get(height)
        .map_err(redb_error)?
        .map(|value| serde_json::from_slice(value.value()))
        .transpose()
        .map_err(Into::into)
}

pub(super) fn persist(
    write: &WriteTransaction,
    before: &[BlockRecord],
    after: &[BlockRecord],
) -> Result<()> {
    let after_len = after.len();
    let before = before
        .iter()
        .map(|block| (block.height, block))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .iter()
        .map(|block| (block.height, block))
        .collect::<BTreeMap<_, _>>();
    if after.len() != after_len {
        return Err(Error::msg("block history contains duplicate heights"));
    }
    let previous_tip = before.keys().next_back().copied();
    if let Some(height) = after.keys().find(|height| {
        !before.contains_key(height) && previous_tip.is_some_and(|tip| **height <= tip)
    }) {
        return Err(Error::msg(format!(
            "block {height} is not an append to the existing chain"
        )));
    }
    let mut table = write.open_table(BLOCKS_TABLE).map_err(redb_error)?;

    // Deletions are only used by explicit history pruning. Ordinary block
    // production never visits or rewrites an existing row.
    for height in before.keys() {
        if !after.contains_key(height) {
            table.remove(height).map_err(redb_error)?;
        }
    }

    for (height, block) in &after {
        let bytes = serde_json::to_vec(block)?;
        if let Some(previous) = before.get(height) {
            if serde_json::to_vec(previous)? != bytes {
                return Err(Error::msg(format!(
                    "append-only block {height} was modified"
                )));
            }
            continue;
        }
        if table.get(height).map_err(redb_error)?.is_some() {
            return Err(Error::msg(format!(
                "append-only block {height} already exists"
            )));
        }
        table.insert(height, bytes.as_slice()).map_err(redb_error)?;
    }
    Ok(())
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}
