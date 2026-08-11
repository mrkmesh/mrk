use redb::{ReadTransaction, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    chain::{height as chain_height, tip_hash as chain_tip_hash},
    model::LedgerState,
};

const ACCOUNT_RANKING_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("account_ranking/v1");
const LATEST_SNAPSHOT_KEY: &str = "latest";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AccountRankingBalance {
    pub address: String,
    pub balance: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AccountRankingSnapshot {
    pub ledger_id: String,
    pub epoch: u64,
    pub height: u64,
    pub block_hash: Option<String>,
    pub total_balance: u128,
    pub accounts: Vec<AccountRankingBalance>,
}

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write
        .open_table(ACCOUNT_RANKING_TABLE)
        .map_err(redb_error)?;
    Ok(())
}

pub(crate) fn snapshot_for_finalized_transition(
    before: &LedgerState,
    after: &LedgerState,
) -> Result<Option<AccountRankingSnapshot>> {
    if after.epoch_number <= before.epoch_number
        || chain_height(after) != chain_height(before).saturating_add(1)
    {
        return Ok(None);
    }
    let total_balance = before
        .accounts
        .values()
        .try_fold(0_u128, |total, account| total.checked_add(account.balance))
        .ok_or_else(|| Error::msg("total account balance overflow"))?;
    let mut accounts = before
        .accounts
        .iter()
        .filter(|(_, account)| account.balance > 0)
        .map(|(address, account)| AccountRankingBalance {
            address: address.clone(),
            balance: account.balance,
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|left, right| {
        right
            .balance
            .cmp(&left.balance)
            .then_with(|| left.address.cmp(&right.address))
    });
    Ok(Some(AccountRankingSnapshot {
        ledger_id: before.ledger_id.clone(),
        epoch: after.epoch_number - 1,
        height: chain_height(before),
        block_hash: chain_tip_hash(before).map(str::to_owned),
        total_balance,
        accounts,
    }))
}

pub(crate) fn store(write: &WriteTransaction, snapshot: &AccountRankingSnapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    let mut table = write
        .open_table(ACCOUNT_RANKING_TABLE)
        .map_err(redb_error)?;
    table
        .insert(LATEST_SNAPSHOT_KEY, bytes.as_slice())
        .map_err(redb_error)?;
    Ok(())
}

pub(crate) fn latest(read: &ReadTransaction) -> Result<Option<AccountRankingSnapshot>> {
    let table = read.open_table(ACCOUNT_RANKING_TABLE).map_err(redb_error)?;
    table
        .get(LATEST_SNAPSHOT_KEY)
        .map_err(redb_error)?
        .map(|bytes| serde_json::from_slice(bytes.value()))
        .transpose()
        .map_err(Into::into)
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}
