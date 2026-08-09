use std::collections::{BTreeMap, BTreeSet};

use redb::{ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    Error, Result,
    model::{LedgerState, OperationRecord},
    operation::{OperationBody, OperationFinality},
};

const OPERATION_BODIES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("operation_bodies/v1");
const OPERATION_FINALITY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("operation_finality/v1");
const ACCOUNT_OPERATION_HISTORY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("account_operation_history/v1");

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(OPERATION_FINALITY_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(ACCOUNT_OPERATION_HISTORY_TABLE)
        .map_err(redb_error)?;
    Ok(())
}

pub(super) fn hydrate(write: &WriteTransaction, ledger: &mut LedgerState) -> Result<()> {
    ledger.operations = hydrate_operations(write)?;
    hydrate_account_histories(write, ledger)
}

pub(super) fn hydrate_pending(
    write: &WriteTransaction,
    operation_ids: &[String],
) -> Result<BTreeMap<String, OperationRecord>> {
    let bodies = write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    let finality = write
        .open_table(OPERATION_FINALITY_TABLE)
        .map_err(redb_error)?;
    operation_ids
        .iter()
        .map(|operation_id| {
            let body = bodies
                .get(operation_id.as_str())
                .map_err(redb_error)?
                .ok_or_else(|| {
                    Error::msg(format!("pending operation {operation_id} has no body"))
                })?;
            let body: OperationBody = serde_json::from_slice(body.value())?;
            let finality = finality
                .get(operation_id.as_str())
                .map_err(redb_error)?
                .ok_or_else(|| {
                    Error::msg(format!("pending operation {operation_id} has no finality"))
                })?;
            let finality: OperationFinality = serde_json::from_slice(finality.value())?;
            Ok((operation_id.clone(), body.with_finality(finality)))
        })
        .collect()
}

pub(super) fn contains(write: &WriteTransaction, operation_id: &str) -> Result<bool> {
    let table = write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    table
        .get(operation_id)
        .map(|value| value.is_some())
        .map_err(redb_error)
}

pub(super) fn get(write: &WriteTransaction, operation_id: &str) -> Result<Option<OperationRecord>> {
    let bodies = write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    let Some(body) = bodies.get(operation_id).map_err(redb_error)? else {
        return Ok(None);
    };
    let body: OperationBody = serde_json::from_slice(body.value())?;
    let finality = write
        .open_table(OPERATION_FINALITY_TABLE)
        .map_err(redb_error)?;
    let finality = finality
        .get(operation_id)
        .map_err(redb_error)?
        .ok_or_else(|| {
            Error::msg(format!(
                "operation {operation_id} has no persisted finality record"
            ))
        })?;
    let finality: OperationFinality = serde_json::from_slice(finality.value())?;
    Ok(Some(body.with_finality(finality)))
}

pub(super) fn persist(
    write: &WriteTransaction,
    before: &LedgerState,
    after: &LedgerState,
) -> Result<()> {
    persist_operations(write, &before.operations, &after.operations)?;
    persist_account_histories(write, before, after)
}

fn hydrate_operations(write: &WriteTransaction) -> Result<BTreeMap<String, OperationRecord>> {
    let bodies = write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    let finality = write
        .open_table(OPERATION_FINALITY_TABLE)
        .map_err(redb_error)?;
    let mut operations = BTreeMap::new();
    for entry in bodies.iter().map_err(redb_error)? {
        let (key, value) = entry.map_err(redb_error)?;
        let operation_id = key.value();
        let body: OperationBody = serde_json::from_slice(value.value())?;
        let status = finality
            .get(operation_id)
            .map_err(redb_error)?
            .ok_or_else(|| {
                Error::msg(format!(
                    "operation {operation_id} has no persisted finality record"
                ))
            })?;
        let status: OperationFinality = serde_json::from_slice(status.value())?;
        operations.insert(operation_id.to_owned(), body.with_finality(status));
    }
    Ok(operations)
}

fn persist_operations(
    write: &WriteTransaction,
    before: &BTreeMap<String, OperationRecord>,
    after: &BTreeMap<String, OperationRecord>,
) -> Result<()> {
    let mut bodies = write
        .open_table(OPERATION_BODIES_TABLE)
        .map_err(redb_error)?;
    let mut finality = write
        .open_table(OPERATION_FINALITY_TABLE)
        .map_err(redb_error)?;
    for operation_id in before.keys() {
        if !after.contains_key(operation_id) {
            bodies.remove(operation_id.as_str()).map_err(redb_error)?;
            finality.remove(operation_id.as_str()).map_err(redb_error)?;
        }
    }

    for (operation_id, record) in after {
        let body = serde_json::to_vec(&OperationBody::from(record))?;
        if let Some(previous) = before.get(operation_id) {
            if serde_json::to_vec(&OperationBody::from(previous))? != body {
                return Err(Error::msg(format!(
                    "immutable operation body {operation_id} was modified"
                )));
            }
        } else {
            if bodies
                .get(operation_id.as_str())
                .map_err(redb_error)?
                .is_some()
            {
                return Err(Error::msg(format!(
                    "immutable operation body {operation_id} already exists"
                )));
            }
            bodies
                .insert(operation_id.as_str(), body.as_slice())
                .map_err(redb_error)?;
        }
        let status = serde_json::to_vec(&OperationFinality::from(record))?;
        let changed = match before.get(operation_id) {
            Some(previous) => serde_json::to_vec(&OperationFinality::from(previous))? != status,
            None => true,
        };
        if changed {
            finality
                .insert(operation_id.as_str(), status.as_slice())
                .map_err(redb_error)?;
        }
    }
    Ok(())
}

fn hydrate_account_histories(write: &WriteTransaction, ledger: &mut LedgerState) -> Result<()> {
    for account in ledger.accounts.values_mut() {
        account.operation_ids.clear();
    }
    let table = write
        .open_table(ACCOUNT_OPERATION_HISTORY_TABLE)
        .map_err(redb_error)?;
    for entry in table.iter().map_err(redb_error)? {
        let (key, _) = entry.map_err(redb_error)?;
        let Some((address, operation_id)) = key.value().split_once('\0') else {
            return Err(Error::msg("account operation history key is malformed"));
        };
        if let Some(account) = ledger.accounts.get_mut(address) {
            account.operation_ids.push(operation_id.to_owned());
        }
    }
    for account in ledger.accounts.values_mut() {
        account.operation_ids.sort_by(|left, right| {
            let left_record = ledger.operations.get(left);
            let right_record = ledger.operations.get(right);
            left_record
                .map(|record| (record.created_at, record.nonce, left.as_str()))
                .cmp(&right_record.map(|record| (record.created_at, record.nonce, right.as_str())))
        });
    }
    Ok(())
}

fn account_history_keys(ledger: &LedgerState) -> BTreeSet<String> {
    ledger
        .accounts
        .iter()
        .flat_map(|(address, account)| {
            account
                .operation_ids
                .iter()
                .map(move |operation_id| format!("{address}\0{operation_id}"))
        })
        .collect()
}

fn persist_account_histories(
    write: &WriteTransaction,
    before: &LedgerState,
    after: &LedgerState,
) -> Result<()> {
    let before = account_history_keys(before);
    let after = account_history_keys(after);
    let mut table = write
        .open_table(ACCOUNT_OPERATION_HISTORY_TABLE)
        .map_err(redb_error)?;
    for key in before.difference(&after) {
        table.remove(key.as_str()).map_err(redb_error)?;
    }
    let empty: &[u8] = &[];
    for key in after.difference(&before) {
        table.insert(key.as_str(), empty).map_err(redb_error)?;
    }
    Ok(())
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}
