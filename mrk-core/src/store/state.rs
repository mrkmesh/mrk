use std::collections::{BTreeMap, BTreeSet};

use redb::{ReadableTable, TableDefinition, WriteTransaction};
use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, Result, model::LedgerState};

const COMMITTED_META_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_meta/v1");
const COMMITTED_META_KEY: &str = "state/v1";

const ACCOUNTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_accounts/v1");
const COMMITTED_ACCOUNTS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_accounts/v1");
const NETWORKS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_networks/v1");
const COMMITTED_NETWORKS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_networks/v1");
const NODES_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("state_nodes/v1");
const COMMITTED_NODES_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_committed_nodes/v1");
const IP_SLOTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_ip_slots/v1");
const COMMITTED_IP_SLOTS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_ip_slots/v1");
const AVAILABILITY_SLOTS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_availability_slots/v1");
const COMMITTED_AVAILABILITY_SLOTS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_availability_slots/v1");
const PAYMENT_AUTHORIZATIONS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_payment_authorizations/v1");
const COMMITTED_PAYMENT_AUTHORIZATIONS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_committed_payment_authorizations/v1");
const TREASURY_SPENDS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_treasury_spends/v1");
const COMMITTED_TREASURY_SPENDS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_committed_treasury_spends/v1");
const GOVERNANCE_ACTIONS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_governance_actions/v1");
const COMMITTED_GOVERNANCE_ACTIONS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_committed_governance_actions/v1");
const GOVERNANCE_PROPOSALS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_governance_proposals/v1");
const COMMITTED_GOVERNANCE_PROPOSALS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_committed_governance_proposals/v1");
const DOUBLE_SIGN_EVIDENCE_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_double_sign_evidence/v1");
const COMMITTED_DOUBLE_SIGN_EVIDENCE_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("state_committed_double_sign_evidence/v1");

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(COMMITTED_META_TABLE).map_err(redb_error)?;
    write.open_table(ACCOUNTS_TABLE).map_err(redb_error)?;
    write
        .open_table(COMMITTED_ACCOUNTS_TABLE)
        .map_err(redb_error)?;
    write.open_table(NETWORKS_TABLE).map_err(redb_error)?;
    write
        .open_table(COMMITTED_NETWORKS_TABLE)
        .map_err(redb_error)?;
    write.open_table(NODES_TABLE).map_err(redb_error)?;
    write
        .open_table(COMMITTED_NODES_TABLE)
        .map_err(redb_error)?;
    write.open_table(IP_SLOTS_TABLE).map_err(redb_error)?;
    write
        .open_table(COMMITTED_IP_SLOTS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(AVAILABILITY_SLOTS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_AVAILABILITY_SLOTS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(PAYMENT_AUTHORIZATIONS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_PAYMENT_AUTHORIZATIONS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(TREASURY_SPENDS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_TREASURY_SPENDS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(GOVERNANCE_ACTIONS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_GOVERNANCE_ACTIONS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(GOVERNANCE_PROPOSALS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_GOVERNANCE_PROPOSALS_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(DOUBLE_SIGN_EVIDENCE_TABLE)
        .map_err(redb_error)?;
    write
        .open_table(COMMITTED_DOUBLE_SIGN_EVIDENCE_TABLE)
        .map_err(redb_error)?;
    Ok(())
}

pub(super) fn hydrate(write: &WriteTransaction, ledger: &mut LedgerState) -> Result<()> {
    ledger.accounts = read_string_map(write, ACCOUNTS_TABLE)?;
    ledger.networks = read_string_map(write, NETWORKS_TABLE)?;
    ledger.network_aliases = network_aliases(&ledger.networks)?;
    ledger.nodes = read_u64_map(write, NODES_TABLE)?;
    ledger.ip_slots = read_string_map(write, IP_SLOTS_TABLE)?;
    ledger.availability_slots = read_string_map(write, AVAILABILITY_SLOTS_TABLE)?;
    ledger.payment_authorizations = read_string_map(write, PAYMENT_AUTHORIZATIONS_TABLE)?;
    ledger.treasury_spends = read_vec(write, TREASURY_SPENDS_TABLE)?;
    ledger.governance.actions = read_vec(write, GOVERNANCE_ACTIONS_TABLE)?;
    ledger.governance.proposals = read_u64_map(write, GOVERNANCE_PROPOSALS_TABLE)?;
    ledger.consensus.double_sign_evidence = read_vec(write, DOUBLE_SIGN_EVIDENCE_TABLE)?;

    let committed_meta = write
        .open_table(COMMITTED_META_TABLE)
        .map_err(redb_error)?
        .get(COMMITTED_META_KEY)
        .map_err(redb_error)?
        .map(|bytes| serde_json::from_slice::<LedgerState>(bytes.value()))
        .transpose()?;
    ledger.finalized_checkpoint = committed_meta
        .map(|mut committed| {
            committed.accounts = ledger.accounts.clone();
            committed.networks = ledger.networks.clone();
            committed.nodes = ledger.nodes.clone();
            committed.ip_slots = ledger.ip_slots.clone();
            committed.availability_slots = ledger.availability_slots.clone();
            committed.payment_authorizations = ledger.payment_authorizations.clone();
            committed.treasury_spends = ledger.treasury_spends.clone();
            committed.governance.actions = ledger.governance.actions.clone();
            committed.governance.proposals = ledger.governance.proposals.clone();
            committed.consensus.double_sign_evidence =
                ledger.consensus.double_sign_evidence.clone();
            Ok::<LedgerState, Error>(committed)
        })
        .transpose()?
        .map(|mut committed| {
            apply_string_overlay(write, COMMITTED_ACCOUNTS_TABLE, &mut committed.accounts)?;
            apply_string_overlay(write, COMMITTED_NETWORKS_TABLE, &mut committed.networks)?;
            apply_u64_overlay(write, COMMITTED_NODES_TABLE, &mut committed.nodes)?;
            apply_string_overlay(write, COMMITTED_IP_SLOTS_TABLE, &mut committed.ip_slots)?;
            apply_string_overlay(
                write,
                COMMITTED_AVAILABILITY_SLOTS_TABLE,
                &mut committed.availability_slots,
            )?;
            apply_string_overlay(
                write,
                COMMITTED_PAYMENT_AUTHORIZATIONS_TABLE,
                &mut committed.payment_authorizations,
            )?;
            apply_vec_overlay(
                write,
                COMMITTED_TREASURY_SPENDS_TABLE,
                &mut committed.treasury_spends,
            )?;
            apply_vec_overlay(
                write,
                COMMITTED_GOVERNANCE_ACTIONS_TABLE,
                &mut committed.governance.actions,
            )?;
            apply_u64_overlay(
                write,
                COMMITTED_GOVERNANCE_PROPOSALS_TABLE,
                &mut committed.governance.proposals,
            )?;
            apply_vec_overlay(
                write,
                COMMITTED_DOUBLE_SIGN_EVIDENCE_TABLE,
                &mut committed.consensus.double_sign_evidence,
            )?;
            committed.network_aliases = network_aliases(&committed.networks)?;
            Ok::<Box<LedgerState>, Error>(Box::new(committed))
        })
        .transpose()?;
    Ok(())
}

pub(super) fn persist(
    write: &WriteTransaction,
    before: &LedgerState,
    after: &LedgerState,
) -> Result<()> {
    persist_string_map(write, ACCOUNTS_TABLE, &before.accounts, &after.accounts)?;
    persist_string_map(write, NETWORKS_TABLE, &before.networks, &after.networks)?;
    persist_u64_map(write, NODES_TABLE, &before.nodes, &after.nodes)?;
    persist_string_map(write, IP_SLOTS_TABLE, &before.ip_slots, &after.ip_slots)?;
    persist_string_map(
        write,
        AVAILABILITY_SLOTS_TABLE,
        &before.availability_slots,
        &after.availability_slots,
    )?;
    persist_string_map(
        write,
        PAYMENT_AUTHORIZATIONS_TABLE,
        &before.payment_authorizations,
        &after.payment_authorizations,
    )?;
    persist_vec(
        write,
        TREASURY_SPENDS_TABLE,
        &before.treasury_spends,
        &after.treasury_spends,
    )?;
    persist_vec(
        write,
        GOVERNANCE_ACTIONS_TABLE,
        &before.governance.actions,
        &after.governance.actions,
    )?;
    persist_u64_map(
        write,
        GOVERNANCE_PROPOSALS_TABLE,
        &before.governance.proposals,
        &after.governance.proposals,
    )?;
    persist_vec(
        write,
        DOUBLE_SIGN_EVIDENCE_TABLE,
        &before.consensus.double_sign_evidence,
        &after.consensus.double_sign_evidence,
    )?;

    let mut committed_meta = write.open_table(COMMITTED_META_TABLE).map_err(redb_error)?;
    if let Some(committed) = after.finalized_checkpoint.as_deref() {
        let bytes = serde_json::to_vec(&super::persisted_state(committed))?;
        committed_meta
            .insert(COMMITTED_META_KEY, bytes.as_slice())
            .map_err(redb_error)?;
        persist_string_overlay(
            write,
            COMMITTED_ACCOUNTS_TABLE,
            &after.accounts,
            &committed.accounts,
        )?;
        persist_string_overlay(
            write,
            COMMITTED_NETWORKS_TABLE,
            &after.networks,
            &committed.networks,
        )?;
        persist_u64_overlay(write, COMMITTED_NODES_TABLE, &after.nodes, &committed.nodes)?;
        persist_string_overlay(
            write,
            COMMITTED_IP_SLOTS_TABLE,
            &after.ip_slots,
            &committed.ip_slots,
        )?;
        persist_string_overlay(
            write,
            COMMITTED_AVAILABILITY_SLOTS_TABLE,
            &after.availability_slots,
            &committed.availability_slots,
        )?;
        persist_string_overlay(
            write,
            COMMITTED_PAYMENT_AUTHORIZATIONS_TABLE,
            &after.payment_authorizations,
            &committed.payment_authorizations,
        )?;
        persist_vec_overlay(
            write,
            COMMITTED_TREASURY_SPENDS_TABLE,
            &after.treasury_spends,
            &committed.treasury_spends,
        )?;
        persist_vec_overlay(
            write,
            COMMITTED_GOVERNANCE_ACTIONS_TABLE,
            &after.governance.actions,
            &committed.governance.actions,
        )?;
        persist_u64_overlay(
            write,
            COMMITTED_GOVERNANCE_PROPOSALS_TABLE,
            &after.governance.proposals,
            &committed.governance.proposals,
        )?;
        persist_vec_overlay(
            write,
            COMMITTED_DOUBLE_SIGN_EVIDENCE_TABLE,
            &after.consensus.double_sign_evidence,
            &committed.consensus.double_sign_evidence,
        )?;
    } else {
        committed_meta
            .remove(COMMITTED_META_KEY)
            .map_err(redb_error)?;
        clear_string_table(write, COMMITTED_ACCOUNTS_TABLE)?;
        clear_string_table(write, COMMITTED_NETWORKS_TABLE)?;
        clear_u64_table(write, COMMITTED_NODES_TABLE)?;
        clear_string_table(write, COMMITTED_IP_SLOTS_TABLE)?;
        clear_string_table(write, COMMITTED_AVAILABILITY_SLOTS_TABLE)?;
        clear_string_table(write, COMMITTED_PAYMENT_AUTHORIZATIONS_TABLE)?;
        clear_u64_table(write, COMMITTED_TREASURY_SPENDS_TABLE)?;
        clear_u64_table(write, COMMITTED_GOVERNANCE_ACTIONS_TABLE)?;
        clear_u64_table(write, COMMITTED_GOVERNANCE_PROPOSALS_TABLE)?;
        clear_u64_table(write, COMMITTED_DOUBLE_SIGN_EVIDENCE_TABLE)?;
    }
    Ok(())
}

fn read_string_map<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
) -> Result<BTreeMap<String, T>> {
    let table = write.open_table(definition).map_err(redb_error)?;
    table
        .iter()
        .map_err(redb_error)?
        .map(|entry| {
            let (key, value) = entry.map_err(redb_error)?;
            Ok((
                key.value().to_owned(),
                serde_json::from_slice(value.value())?,
            ))
        })
        .collect()
}

fn read_u64_map<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
) -> Result<BTreeMap<u64, T>> {
    let table = write.open_table(definition).map_err(redb_error)?;
    table
        .iter()
        .map_err(redb_error)?
        .map(|entry| {
            let (key, value) = entry.map_err(redb_error)?;
            Ok((key.value(), serde_json::from_slice(value.value())?))
        })
        .collect()
}

fn read_vec<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
) -> Result<Vec<T>> {
    let rows = read_u64_map::<T>(write, definition)?;
    ensure_contiguous(&rows)?;
    Ok(rows.into_values().collect())
}

fn persist_string_map<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    before: &BTreeMap<String, T>,
    after: &BTreeMap<String, T>,
) -> Result<()> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for key in before.keys().filter(|key| !after.contains_key(*key)) {
        table.remove(key.as_str()).map_err(redb_error)?;
    }
    for (key, value) in after {
        let bytes = serde_json::to_vec(value)?;
        let unchanged = before
            .get(key)
            .map(serde_json::to_vec)
            .transpose()?
            .is_some_and(|previous| previous == bytes);
        if !unchanged {
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(redb_error)?;
        }
    }
    Ok(())
}

fn persist_u64_map<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    before: &BTreeMap<u64, T>,
    after: &BTreeMap<u64, T>,
) -> Result<()> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for key in before.keys().filter(|key| !after.contains_key(*key)) {
        table.remove(*key).map_err(redb_error)?;
    }
    for (key, value) in after {
        let bytes = serde_json::to_vec(value)?;
        let unchanged = before
            .get(key)
            .map(serde_json::to_vec)
            .transpose()?
            .is_some_and(|previous| previous == bytes);
        if !unchanged {
            table.insert(*key, bytes.as_slice()).map_err(redb_error)?;
        }
    }
    Ok(())
}

fn persist_vec<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    before: &[T],
    after: &[T],
) -> Result<()> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for index in after.len()..before.len() {
        table.remove(index as u64).map_err(redb_error)?;
    }
    for (index, value) in after.iter().enumerate() {
        let bytes = serde_json::to_vec(value)?;
        let unchanged = before
            .get(index)
            .map(serde_json::to_vec)
            .transpose()?
            .is_some_and(|previous| previous == bytes);
        if !unchanged {
            table
                .insert(index as u64, bytes.as_slice())
                .map_err(redb_error)?;
        }
    }
    Ok(())
}

fn persist_string_overlay<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    current: &BTreeMap<String, T>,
    committed: &BTreeMap<String, T>,
) -> Result<()> {
    clear_string_table(write, definition)?;
    let keys = current
        .keys()
        .chain(committed.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for key in keys {
        let current_bytes = current.get(&key).map(serde_json::to_vec).transpose()?;
        let committed_bytes = committed.get(&key).map(serde_json::to_vec).transpose()?;
        if current_bytes != committed_bytes {
            let bytes = serde_json::to_vec(&committed.get(&key))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(redb_error)?;
        }
    }
    Ok(())
}

fn persist_u64_overlay<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    current: &BTreeMap<u64, T>,
    committed: &BTreeMap<u64, T>,
) -> Result<()> {
    clear_u64_table(write, definition)?;
    let keys = current
        .keys()
        .chain(committed.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for key in keys {
        let current_bytes = current.get(&key).map(serde_json::to_vec).transpose()?;
        let committed_bytes = committed.get(&key).map(serde_json::to_vec).transpose()?;
        if current_bytes != committed_bytes {
            let bytes = serde_json::to_vec(&committed.get(&key))?;
            table.insert(key, bytes.as_slice()).map_err(redb_error)?;
        }
    }
    Ok(())
}

fn persist_vec_overlay<T: Serialize>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    current: &[T],
    committed: &[T],
) -> Result<()> {
    clear_u64_table(write, definition)?;
    let mut table = write.open_table(definition).map_err(redb_error)?;
    for index in 0..current.len().max(committed.len()) {
        let current_bytes = current.get(index).map(serde_json::to_vec).transpose()?;
        let committed_bytes = committed.get(index).map(serde_json::to_vec).transpose()?;
        if current_bytes != committed_bytes {
            let bytes = serde_json::to_vec(&committed.get(index))?;
            table
                .insert(index as u64, bytes.as_slice())
                .map_err(redb_error)?;
        }
    }
    Ok(())
}

fn apply_string_overlay<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
    target: &mut BTreeMap<String, T>,
) -> Result<()> {
    let table = write.open_table(definition).map_err(redb_error)?;
    for entry in table.iter().map_err(redb_error)? {
        let (key, value) = entry.map_err(redb_error)?;
        match serde_json::from_slice::<Option<T>>(value.value())? {
            Some(record) => {
                target.insert(key.value().to_owned(), record);
            }
            None => {
                target.remove(key.value());
            }
        }
    }
    Ok(())
}

fn apply_u64_overlay<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    target: &mut BTreeMap<u64, T>,
) -> Result<()> {
    let table = write.open_table(definition).map_err(redb_error)?;
    for entry in table.iter().map_err(redb_error)? {
        let (key, value) = entry.map_err(redb_error)?;
        match serde_json::from_slice::<Option<T>>(value.value())? {
            Some(record) => {
                target.insert(key.value(), record);
            }
            None => {
                target.remove(&key.value());
            }
        }
    }
    Ok(())
}

fn apply_vec_overlay<T: DeserializeOwned>(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
    target: &mut Vec<T>,
) -> Result<()> {
    let mut rows = std::mem::take(target)
        .into_iter()
        .enumerate()
        .map(|(index, value)| (index as u64, value))
        .collect::<BTreeMap<_, _>>();
    apply_u64_overlay(write, definition, &mut rows)?;
    ensure_contiguous(&rows)?;
    *target = rows.into_values().collect();
    Ok(())
}

fn ensure_contiguous<T>(rows: &BTreeMap<u64, T>) -> Result<()> {
    if rows
        .keys()
        .copied()
        .ne(0..u64::try_from(rows.len()).expect("table length fits u64"))
    {
        return Err(Error::msg("indexed state table is not contiguous"));
    }
    Ok(())
}

fn network_aliases(
    networks: &BTreeMap<String, crate::model::NetworkRecord>,
) -> Result<BTreeMap<String, String>> {
    let mut aliases = BTreeMap::new();
    for (commitment, network) in networks {
        if network.commitment != *commitment {
            return Err(Error::msg(format!(
                "network table key {commitment} does not match its record commitment {}",
                network.commitment
            )));
        }
        if aliases
            .insert(network.alias.clone(), commitment.clone())
            .is_some()
        {
            return Err(Error::msg(format!(
                "network alias '{}' is duplicated in persisted state",
                network.alias
            )));
        }
    }
    Ok(aliases)
}

fn clear_string_table(
    write: &WriteTransaction,
    definition: TableDefinition<&str, &[u8]>,
) -> Result<()> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    let keys = table
        .iter()
        .map_err(redb_error)?
        .map(|entry| {
            entry
                .map(|(key, _)| key.value().to_owned())
                .map_err(redb_error)
        })
        .collect::<Result<Vec<_>>>()?;
    for key in keys {
        table.remove(key.as_str()).map_err(redb_error)?;
    }
    Ok(())
}

fn clear_u64_table(
    write: &WriteTransaction,
    definition: TableDefinition<u64, &[u8]>,
) -> Result<()> {
    let mut table = write.open_table(definition).map_err(redb_error)?;
    let keys = table
        .iter()
        .map_err(redb_error)?
        .map(|entry| entry.map(|(key, _)| key.value()).map_err(redb_error))
        .collect::<Result<Vec<_>>>()?;
    for key in keys {
        table.remove(key).map_err(redb_error)?;
    }
    Ok(())
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}
