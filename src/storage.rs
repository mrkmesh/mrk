use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, backends::InMemoryBackend};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    Error, Result,
    crypto::EncryptedKeyFile,
    model::{LedgerState, LocalNodeConfig, MemberCredential, SignedOperation},
    relay::{ReceiverReceipt, SenderCheckpoint},
    store,
};

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct PendingTrafficSettlement {
    pub sender_checkpoint: SenderCheckpoint,
    pub receiver_receipt: ReceiverReceipt,
    #[serde(default)]
    pub submission_operation_id: Option<String>,
}

/// Local Relay recovery state. This is deliberately not consensus state: the
/// authorization is settled or refunded through the ordinary chain actions.
#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct UnsettledRelaySession {
    pub authorization_id: String,
    pub network_id: String,
    pub network_commitment: String,
    pub node_id: u64,
    pub sender_member_id: String,
    pub receiver_member_id: String,
    pub disconnected_at: i64,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ActiveRelaySession {
    pub authorization_id: String,
    pub network_id: String,
    pub network_commitment: String,
    pub node_id: u64,
    pub sender_member_id: String,
    pub receiver_member_id: String,
    pub opened_at: i64,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RelayAutoAbandonUsage {
    pub network_commitment: String,
    pub member_id: String,
    pub window_started_at: i64,
    pub abandoned_bytes: u64,
    pub last_authorization_id: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct PendingMemberIssue {
    pub operation_id: String,
    pub network: String,
    pub member: String,
    pub owner_public_key: String,
    pub operation: SignedOperation,
    pub keyfile: EncryptedKeyFile,
    pub credential: MemberCredential,
    pub created_at: i64,
}

pub struct MemberIssueLock {
    _file: File,
}

#[derive(Clone)]
pub struct DataPaths {
    pub root: PathBuf,
    chain_db: Arc<OnceLock<std::result::Result<Mutex<Database>, String>>>,
}

impl DataPaths {
    pub(crate) fn in_memory_with_ledger(state: LedgerState) -> Result<Self> {
        let database = Database::builder()
            .create_with_backend(InMemoryBackend::new())
            .map_err(redb_error)?;
        let chain_db = Arc::new(OnceLock::new());
        chain_db
            .set(Ok(Mutex::new(database)))
            .map_err(|_| Error::msg("in-memory ledger database was already initialized"))?;
        let paths = Self {
            root: PathBuf::new(),
            chain_db,
        };
        paths.with_ledger_mut(|ledger| {
            *ledger = state;
            Ok(())
        })?;
        Ok(paths)
    }

    pub fn new(root: Option<PathBuf>) -> Result<Self> {
        let root = match root {
            Some(root) => root,
            None => default_data_root()?,
        };
        let paths = Self {
            root,
            chain_db: Arc::new(OnceLock::new()),
        };
        paths.ensure()?;
        Ok(paths)
    }

    pub fn ensure(&self) -> Result<()> {
        ensure_private_dir(&self.root)?;
        ensure_private_dir(&self.root.join("accounts"))?;
        ensure_private_dir(&self.root.join("nodes"))?;
        ensure_private_dir(&self.root.join("networks"))?;
        Ok(())
    }

    pub fn chain_db_path(&self) -> PathBuf {
        self.root.join("chain.redb")
    }

    pub fn account_key_path(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.root.join("accounts").join(format!("{name}.json")))
    }

    pub fn node_dir(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.root.join("nodes").join(name))
    }

    pub fn node_config_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.node_dir(name)?.join("config.json"))
    }

    pub fn node_owner_key_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.node_dir(name)?.join("owner.key.json"))
    }

    pub fn node_relay_key_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.node_dir(name)?.join("relay.key.json"))
    }

    pub fn node_reward_key_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.node_dir(name)?.join("reward.key.json"))
    }

    pub fn daemon_socket_path(&self) -> PathBuf {
        self.root.join("mrk.sock")
    }

    pub fn member_key_path(&self, network: &str, member: &str) -> Result<PathBuf> {
        validate_name(network)?;
        validate_name(member)?;
        Ok(self
            .root
            .join("networks")
            .join(network)
            .join(format!("{member}.key.json")))
    }

    pub fn member_credential_path(&self, network: &str, member: &str) -> Result<PathBuf> {
        validate_name(network)?;
        validate_name(member)?;
        Ok(self
            .root
            .join("networks")
            .join(network)
            .join(format!("{member}.credential.json")))
    }

    pub fn pending_member_issue_path(&self, network: &str, member: &str) -> Result<PathBuf> {
        validate_name(network)?;
        validate_name(member)?;
        Ok(self
            .root
            .join("networks")
            .join(network)
            .join(format!(".{member}.issue.pending.json")))
    }

    pub fn acquire_member_issue_lock(
        &self,
        network: &str,
        member: &str,
    ) -> Result<MemberIssueLock> {
        validate_name(network)?;
        validate_name(member)?;
        let directory = self.root.join("networks").join(network);
        ensure_private_dir(&directory)?;
        let path = directory.join(format!(".{member}.issue.lock"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        #[cfg(unix)]
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::msg(format!(
                "member '{member}' is already being issued by another local process"
            )));
        }
        file.set_len(0)?;
        file.write_all(std::process::id().to_string().as_bytes())?;
        file.sync_all()?;
        set_private_file(&path)?;
        Ok(MemberIssueLock { _file: file })
    }

    pub fn pending_member_issue(
        &self,
        network: &str,
        member: &str,
    ) -> Result<Option<PendingMemberIssue>> {
        let path = self.pending_member_issue_path(network, member)?;
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::Io(error)),
        }
    }

    pub fn store_pending_member_issue(&self, pending: &PendingMemberIssue) -> Result<PathBuf> {
        let path = self.pending_member_issue_path(&pending.network, &pending.member)?;
        atomic_write_json(&path, pending)?;
        set_private_file(&path)?;
        Ok(path)
    }

    pub fn remove_pending_member_issue(&self, network: &str, member: &str) -> Result<()> {
        let path = self.pending_member_issue_path(network, member)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    }

    pub fn load_or_init_ledger(&self) -> Result<LedgerState> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let mut state = {
            let mut table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
            let existing = table
                .get(LEDGER_STATE_KEY)
                .map_err(redb_error)?
                .map(|bytes| bytes.value().to_vec());
            match existing {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => {
                    let state = LedgerState::default();
                    let bytes = serde_json::to_vec(&store::persisted_state(&state))?;
                    table
                        .insert(LEDGER_STATE_KEY, bytes.as_slice())
                        .map_err(redb_error)?;
                    state
                }
            }
        };
        write
            .open_table(PENDING_TRAFFIC_TABLE)
            .map_err(redb_error)?;
        write
            .open_table(UNSETTLED_RELAY_TABLE)
            .map_err(redb_error)?;
        write
            .open_table(ACTIVE_RELAY_SESSION_TABLE)
            .map_err(redb_error)?;
        write
            .open_table(RELAY_AUTO_ABANDON_USAGE_TABLE)
            .map_err(redb_error)?;
        store::hydrate_ledger(&write, &mut state)?;
        write.commit().map_err(redb_error)?;
        Ok(state)
    }

    pub fn with_ledger_mut<T>(
        &self,
        operation: impl FnOnce(&mut LedgerState) -> Result<T>,
    ) -> Result<T> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let mut ledger = load_persisted_ledger(&write)?;
        store::hydrate_ledger(&write, &mut ledger)?;
        let before = ledger.clone();
        let result = operation(&mut ledger)?;
        store::persist_histories(&write, &before, &ledger)?;
        store_persisted_ledger(&write, &ledger)?;
        write.commit().map_err(redb_error)?;
        Ok(result)
    }

    /// Mutates consensus state without materializing finalized history. The
    /// returned runtime ledger represents the persisted chain prefix through
    /// `pruned_*` and contains only pending operations plus blocks appended by
    /// this transaction.
    pub(crate) fn with_active_ledger_mut<T>(
        &self,
        operation: impl FnOnce(&mut LedgerState) -> Result<T>,
    ) -> Result<T> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let mut ledger = load_persisted_ledger(&write)?;
        let retained_prefix = (
            ledger.pruned_through_height,
            ledger.pruned_tip_hash.clone(),
            ledger.pruned_tip_timestamp,
        );
        store::hydrate_active_ledger(&write, &mut ledger)?;
        let before = ledger.clone();
        let result = operation(&mut ledger)?;
        store::persist_histories(&write, &before, &ledger)?;
        {
            let mut state = store::persisted_state(&ledger);
            state.pruned_through_height = retained_prefix.0;
            state.pruned_tip_hash = retained_prefix.1;
            state.pruned_tip_timestamp = retained_prefix.2;
            store_persisted_state(&write, &state)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(result)
    }

    pub(crate) fn read_active_ledger(&self) -> Result<LedgerState> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let mut ledger = load_persisted_ledger(&write)?;
        store::hydrate_active_ledger(&write, &mut ledger)?;
        write.commit().map_err(redb_error)?;
        Ok(ledger)
    }

    pub(crate) fn operation_exists(&self, operation_id: &str) -> Result<bool> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let exists = store::operation_exists(&write, operation_id)?;
        write.commit().map_err(redb_error)?;
        Ok(exists)
    }

    pub(crate) fn consensus_catch_up_history(
        &self,
        from_height: u64,
        max_blocks: usize,
    ) -> Result<store::CatchUpHistory> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let ledger = load_persisted_ledger(&write)?;
        let history =
            store::collect_catch_up_from_tables(&write, &ledger, from_height, max_blocks)?;
        write.commit().map_err(redb_error)?;
        Ok(history)
    }

    pub(crate) fn stored_block(&self, height: u64) -> Result<crate::model::BlockRecord> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::initialize_tables(&write)?;
        let pruned_through_height = load_persisted_ledger(&write)?.pruned_through_height;
        let block = store::block_by_height_from_table(&write, pruned_through_height, height)?;
        write.commit().map_err(redb_error)?;
        Ok(block)
    }

    pub fn read_ledger(&self) -> Result<LedgerState> {
        self.load_or_init_ledger()
    }

    pub fn store_bootstrap_checkpoint(
        &self,
        height: u64,
        checkpoint: &LedgerState,
        retained_limit: usize,
    ) -> Result<()> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        store::checkpoint::store(&write, height, checkpoint, retained_limit)?;
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn bootstrap_checkpoint(&self, height: u64) -> Result<Option<LedgerState>> {
        let db = self.open_chain_db()?;
        let read = db.begin_read().map_err(redb_error)?;
        store::checkpoint::get(&read, height)
    }

    pub fn latest_bootstrap_checkpoint(&self) -> Result<Option<(u64, LedgerState)>> {
        let db = self.open_chain_db()?;
        let read = db.begin_read().map_err(redb_error)?;
        store::checkpoint::latest(&read)
    }

    pub fn store_pending_traffic_settlement(
        &self,
        settlement: &PendingTrafficSettlement,
    ) -> Result<()> {
        let key = pending_traffic_key(
            &settlement.sender_checkpoint.authorization_id,
            settlement.sender_checkpoint.direction,
        )?;
        let bytes = serde_json::to_vec(settlement)?;
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(PENDING_TRAFFIC_TABLE)
                .map_err(redb_error)?;
            let replace = match table.get(key.as_str()).map_err(redb_error)? {
                Some(existing) => {
                    let existing: PendingTrafficSettlement =
                        serde_json::from_slice(existing.value())?;
                    (!existing.sender_checkpoint.final_checkpoint
                        || settlement.sender_checkpoint.final_checkpoint)
                        && settlement.sender_checkpoint.sequence
                            >= existing.sender_checkpoint.sequence
                        && settlement.sender_checkpoint.cumulative_sent_bytes
                            >= existing.sender_checkpoint.cumulative_sent_bytes
                }
                None => true,
            };
            if replace {
                table
                    .insert(key.as_str(), bytes.as_slice())
                    .map_err(redb_error)?;
            }
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn pending_traffic_settlements(&self) -> Result<Vec<PendingTrafficSettlement>> {
        let db = self.open_chain_db()?;
        let read = db.begin_read().map_err(redb_error)?;
        let table = read.open_table(PENDING_TRAFFIC_TABLE).map_err(redb_error)?;
        let mut settlements = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (_, value) = entry.map_err(redb_error)?;
            settlements.push(serde_json::from_slice(value.value())?);
        }
        Ok(settlements)
    }

    pub fn remove_pending_traffic_settlement_if_not_newer(
        &self,
        authorization_id: &str,
        direction: crate::model::RelayDirection,
        maximum_sequence: u64,
        submitted_final_checkpoint: bool,
    ) -> Result<()> {
        let key = pending_traffic_key(authorization_id, direction)?;
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(PENDING_TRAFFIC_TABLE)
                .map_err(redb_error)?;
            let remove = match table.get(key.as_str()).map_err(redb_error)? {
                Some(existing) => {
                    let existing: PendingTrafficSettlement =
                        serde_json::from_slice(existing.value())?;
                    existing.sender_checkpoint.sequence < maximum_sequence
                        || (existing.sender_checkpoint.sequence == maximum_sequence
                            && (submitted_final_checkpoint
                                || !existing.sender_checkpoint.final_checkpoint))
                }
                None => false,
            };
            if remove {
                table.remove(key.as_str()).map_err(redb_error)?;
            }
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn store_unsettled_relay_session(&self, session: &UnsettledRelaySession) -> Result<()> {
        let bytes = serde_json::to_vec(session)?;
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(UNSETTLED_RELAY_TABLE)
                .map_err(redb_error)?;
            table
                .insert(session.authorization_id.as_str(), bytes.as_slice())
                .map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn unsettled_relay_sessions(&self) -> Result<Vec<UnsettledRelaySession>> {
        let db = self.open_chain_db()?;
        let read = db.begin_read().map_err(redb_error)?;
        let table = read.open_table(UNSETTLED_RELAY_TABLE).map_err(redb_error)?;
        let mut sessions: Vec<UnsettledRelaySession> = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (_, value) = entry.map_err(redb_error)?;
            sessions.push(serde_json::from_slice(value.value())?);
        }
        sessions.sort_by_key(|session| std::cmp::Reverse(session.disconnected_at));
        Ok(sessions)
    }

    pub fn remove_unsettled_relay_session(&self, authorization_id: &str) -> Result<()> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(UNSETTLED_RELAY_TABLE)
                .map_err(redb_error)?;
            table.remove(authorization_id).map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn store_active_relay_session(&self, session: &ActiveRelaySession) -> Result<()> {
        let bytes = serde_json::to_vec(session)?;
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(ACTIVE_RELAY_SESSION_TABLE)
                .map_err(redb_error)?;
            table
                .insert(session.authorization_id.as_str(), bytes.as_slice())
                .map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn remove_active_relay_session(&self, authorization_id: &str) -> Result<()> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        {
            let mut table = write
                .open_table(ACTIVE_RELAY_SESSION_TABLE)
                .map_err(redb_error)?;
            table.remove(authorization_id).map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(())
    }

    pub fn promote_active_relay_sessions(&self, disconnected_at: i64) -> Result<usize> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        let active_sessions = {
            let table = write
                .open_table(ACTIVE_RELAY_SESSION_TABLE)
                .map_err(redb_error)?;
            table
                .iter()
                .map_err(redb_error)?
                .map(|entry| {
                    let (_, value) = entry.map_err(redb_error)?;
                    serde_json::from_slice::<ActiveRelaySession>(value.value()).map_err(Into::into)
                })
                .collect::<Result<Vec<_>>>()?
        };
        {
            let mut unsettled = write
                .open_table(UNSETTLED_RELAY_TABLE)
                .map_err(redb_error)?;
            let mut active = write
                .open_table(ACTIVE_RELAY_SESSION_TABLE)
                .map_err(redb_error)?;
            for session in &active_sessions {
                let unsettled_session = UnsettledRelaySession {
                    authorization_id: session.authorization_id.clone(),
                    network_id: session.network_id.clone(),
                    network_commitment: session.network_commitment.clone(),
                    node_id: session.node_id,
                    sender_member_id: session.sender_member_id.clone(),
                    receiver_member_id: session.receiver_member_id.clone(),
                    disconnected_at,
                };
                let bytes = serde_json::to_vec(&unsettled_session)?;
                unsettled
                    .insert(session.authorization_id.as_str(), bytes.as_slice())
                    .map_err(redb_error)?;
                active
                    .remove(session.authorization_id.as_str())
                    .map_err(redb_error)?;
            }
        }
        write.commit().map_err(redb_error)?;
        Ok(active_sessions.len())
    }

    pub fn try_record_relay_auto_abandon(
        &self,
        network_commitment: &str,
        member_ids: &[&str],
        abandoned_bytes: u64,
        maximum_bytes_per_day: u64,
        authorization_id: &str,
        now: i64,
    ) -> Result<bool> {
        if maximum_bytes_per_day == 0 || abandoned_bytes > maximum_bytes_per_day {
            return Ok(false);
        }
        let mut unique_members = member_ids.to_vec();
        unique_members.sort_unstable();
        unique_members.dedup();
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        let mut updates = Vec::new();
        {
            let table = write
                .open_table(RELAY_AUTO_ABANDON_USAGE_TABLE)
                .map_err(redb_error)?;
            for member_id in unique_members {
                let key = format!("{network_commitment}:{member_id}");
                let existing = table
                    .get(key.as_str())
                    .map_err(redb_error)?
                    .map(|value| serde_json::from_slice::<RelayAutoAbandonUsage>(value.value()))
                    .transpose()?;
                let existing =
                    existing.filter(|usage| now.saturating_sub(usage.window_started_at) < 86_400);
                let repeated_authorization = existing
                    .as_ref()
                    .is_some_and(|usage| usage.last_authorization_id == authorization_id);
                let (window_started_at, already_abandoned) = existing.map_or((now, 0), |usage| {
                    (usage.window_started_at, usage.abandoned_bytes)
                });
                let total = already_abandoned
                    .checked_add(if repeated_authorization {
                        0
                    } else {
                        abandoned_bytes
                    })
                    .ok_or_else(|| Error::msg("Relay auto-abandon usage overflow"))?;
                if total > maximum_bytes_per_day {
                    return Ok(false);
                }
                updates.push((
                    key,
                    RelayAutoAbandonUsage {
                        network_commitment: network_commitment.to_owned(),
                        member_id: member_id.to_owned(),
                        window_started_at,
                        abandoned_bytes: total,
                        last_authorization_id: authorization_id.to_owned(),
                        updated_at: now,
                    },
                ));
            }
        }
        {
            let mut table = write
                .open_table(RELAY_AUTO_ABANDON_USAGE_TABLE)
                .map_err(redb_error)?;
            for (key, usage) in updates {
                let bytes = serde_json::to_vec(&usage)?;
                table
                    .insert(key.as_str(), bytes.as_slice())
                    .map_err(redb_error)?;
            }
        }
        write.commit().map_err(redb_error)?;
        Ok(true)
    }

    fn open_chain_db(&self) -> Result<MutexGuard<'_, Database>> {
        match self.chain_db.get_or_init(|| {
            Database::create(self.chain_db_path())
                .map(Mutex::new)
                .map_err(|error| error.to_string())
        }) {
            Ok(db) => db
                .lock()
                .map_err(|_| Error::msg("redb database lock is poisoned")),
            Err(error) => Err(Error::msg(format!("redb: {error}"))),
        }
    }

    pub fn compact_chain_db(&self) -> Result<bool> {
        let mut db = self.open_chain_db()?;
        db.compact().map_err(redb_error)
    }

    pub fn write_keyfile(&self, path: &Path, keyfile: &EncryptedKeyFile) -> Result<()> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        atomic_write_json(path, keyfile)?;
        set_private_file(path)?;
        Ok(())
    }

    pub fn read_keyfile(&self, path: &Path) -> Result<EncryptedKeyFile> {
        read_json(path)
    }

    pub fn write_node_config(&self, config: &LocalNodeConfig) -> Result<()> {
        let path = self.node_config_path(&config.name)?;
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        atomic_write_json(&path, config)
    }

    pub fn read_node_config(&self, name: &str) -> Result<LocalNodeConfig> {
        read_json(&self.node_config_path(name)?)
    }
}

const LEDGER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ledger");
const LEDGER_STATE_KEY: &str = "state/v1";
const PENDING_TRAFFIC_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("pending_traffic_settlements/v1");
const UNSETTLED_RELAY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("unsettled_relay_sessions/v1");
const ACTIVE_RELAY_SESSION_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("active_relay_sessions/v1");
const RELAY_AUTO_ABANDON_USAGE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("relay_auto_abandon_usage/v1");

fn load_persisted_ledger(write: &redb::WriteTransaction) -> Result<LedgerState> {
    let table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
    match table.get(LEDGER_STATE_KEY).map_err(redb_error)? {
        Some(bytes) => Ok(serde_json::from_slice(bytes.value())?),
        None => Ok(LedgerState::default()),
    }
}

fn store_persisted_ledger(write: &redb::WriteTransaction, ledger: &LedgerState) -> Result<()> {
    store_persisted_state(write, &store::persisted_state(ledger))
}

fn store_persisted_state(write: &redb::WriteTransaction, state: &LedgerState) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    let mut table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
    table
        .insert(LEDGER_STATE_KEY, bytes.as_slice())
        .map_err(redb_error)?;
    Ok(())
}

fn pending_traffic_key(
    authorization_id: &str,
    direction: crate::model::RelayDirection,
) -> Result<String> {
    Ok(format!(
        "{authorization_id}:{}",
        serde_json::to_string(&direction)?
    ))
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}

fn default_data_root() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::msg("could not determine the user home directory"))?;
    Ok(default_data_root_for_home(&home))
}

fn default_data_root_for_home(home: &Path) -> PathBuf {
    home.join(".mrk")
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::msg(format!("file does not exist: {}", path.display()))
        } else {
            Error::Io(error)
        }
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let random = crate::crypto::random_bytes::<8>()?;
    let temp = path.with_extension(format!("tmp-{}", crate::crypto::hex_lower(&random)));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    set_private_file(&temp)?;
    fs::rename(&temp, path)?;
    Ok(())
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Error::msg(
            "name must contain only ASCII letters, digits, '-' or '_' and be at most 64 characters",
        ));
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_data_root_is_hidden_mrk_directory_under_home() {
        assert_eq!(
            default_data_root_for_home(Path::new("/home/alice")),
            PathBuf::from("/home/alice/.mrk")
        );
    }

    #[test]
    fn daemon_socket_is_single_root_level_path() {
        let root = std::env::temp_dir().join(format!(
            "mrk-node-socket-path-{}",
            crate::crypto::hex_lower(&crate::crypto::random_bytes::<8>().unwrap())
        ));
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        assert_eq!(paths.daemon_socket_path(), root.join("mrk.sock"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ledger_is_persisted_in_redb() {
        let root = std::env::temp_dir().join(format!(
            "mrk-redb-{}",
            crate::crypto::hex_lower(&crate::crypto::random_bytes::<8>().unwrap())
        ));
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        paths.read_ledger().unwrap();
        assert!(root.join("chain.redb").is_file());
        assert!(!root.join("ledger.json").exists());
    }

    #[test]
    fn pending_traffic_receipts_never_regress_during_flush_races() {
        let paths = DataPaths::in_memory_with_ledger(LedgerState::default()).unwrap();
        let settlement = |sequence, bytes, submission_operation_id| PendingTrafficSettlement {
            sender_checkpoint: SenderCheckpoint {
                ledger_id: "ledger".to_owned(),
                protocol_version: crate::model::PROTOCOL_VERSION,
                node_id: 1,
                authorization_id: "authorization".to_owned(),
                session_id: "session".to_owned(),
                direction: crate::model::RelayDirection::SenderToReceiver,
                sequence,
                cumulative_sent_bytes: bytes,
                transcript_hash: format!("hash-{sequence}"),
                checkpoint_at: sequence as i64,
                sender_member_id: "sender".to_owned(),
                final_checkpoint: false,
                sender_signature: "signature".to_owned(),
            },
            receiver_receipt: ReceiverReceipt {
                ledger_id: "ledger".to_owned(),
                protocol_version: crate::model::PROTOCOL_VERSION,
                node_id: 1,
                authorization_id: "authorization".to_owned(),
                session_id: "session".to_owned(),
                direction: crate::model::RelayDirection::SenderToReceiver,
                sequence,
                cumulative_received_bytes: bytes,
                transcript_hash: format!("hash-{sequence}"),
                sender_checkpoint_hash: format!("checkpoint-{sequence}"),
                received_at: sequence as i64,
                receiver_member_id: "receiver".to_owned(),
                receiver_signature: "signature".to_owned(),
            },
            submission_operation_id,
        };
        paths
            .store_pending_traffic_settlement(&settlement(2, 20, None))
            .unwrap();
        paths
            .store_pending_traffic_settlement(&settlement(1, 10, Some("old-operation".to_owned())))
            .unwrap();
        paths
            .remove_pending_traffic_settlement_if_not_newer(
                "authorization",
                crate::model::RelayDirection::SenderToReceiver,
                1,
                false,
            )
            .unwrap();
        let pending = paths.pending_traffic_settlements().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sender_checkpoint.sequence, 2);

        let mut final_settlement = settlement(2, 20, None);
        final_settlement.sender_checkpoint.final_checkpoint = true;
        paths
            .store_pending_traffic_settlement(&final_settlement)
            .unwrap();
        paths
            .store_pending_traffic_settlement(&settlement(2, 20, None))
            .unwrap();
        assert!(
            paths.pending_traffic_settlements().unwrap()[0]
                .sender_checkpoint
                .final_checkpoint
        );
        paths
            .remove_pending_traffic_settlement_if_not_newer(
                "authorization",
                crate::model::RelayDirection::SenderToReceiver,
                2,
                false,
            )
            .unwrap();
        assert_eq!(paths.pending_traffic_settlements().unwrap().len(), 1);
        paths
            .remove_pending_traffic_settlement_if_not_newer(
                "authorization",
                crate::model::RelayDirection::SenderToReceiver,
                2,
                true,
            )
            .unwrap();
        assert!(paths.pending_traffic_settlements().unwrap().is_empty());
    }

    #[test]
    fn unsettled_relay_sessions_are_persistent_and_replace_by_authorization() {
        let paths = DataPaths::in_memory_with_ledger(LedgerState::default()).unwrap();
        let mut session = UnsettledRelaySession {
            authorization_id: "authorization".to_owned(),
            network_id: "network-id".to_owned(),
            network_commitment: "network-commitment".to_owned(),
            node_id: 1,
            sender_member_id: "sender".to_owned(),
            receiver_member_id: "receiver".to_owned(),
            disconnected_at: 10,
        };
        paths.store_unsettled_relay_session(&session).unwrap();
        session.disconnected_at = 20;
        paths.store_unsettled_relay_session(&session).unwrap();
        assert_eq!(
            paths.unsettled_relay_sessions().unwrap(),
            vec![session.clone()]
        );
        paths
            .remove_unsettled_relay_session("authorization")
            .unwrap();
        assert!(paths.unsettled_relay_sessions().unwrap().is_empty());

        let active = ActiveRelaySession {
            authorization_id: session.authorization_id.clone(),
            network_id: session.network_id.clone(),
            network_commitment: session.network_commitment.clone(),
            node_id: session.node_id,
            sender_member_id: session.sender_member_id.clone(),
            receiver_member_id: session.receiver_member_id.clone(),
            opened_at: 25,
        };
        paths.store_active_relay_session(&active).unwrap();
        assert_eq!(paths.promote_active_relay_sessions(30).unwrap(), 1);
        let promoted = paths.unsettled_relay_sessions().unwrap();
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].disconnected_at, 30);
        assert_eq!(promoted[0].authorization_id, active.authorization_id);

        assert!(
            paths
                .try_record_relay_auto_abandon(
                    "network-commitment",
                    &["sender", "receiver"],
                    40,
                    100,
                    "authorization-1",
                    40,
                )
                .unwrap()
        );
        assert!(
            paths
                .try_record_relay_auto_abandon(
                    "network-commitment",
                    &["sender", "receiver"],
                    40,
                    100,
                    "authorization-1",
                    41,
                )
                .unwrap()
        );
        assert!(
            !paths
                .try_record_relay_auto_abandon(
                    "network-commitment",
                    &["sender", "receiver"],
                    70,
                    100,
                    "authorization-2",
                    42,
                )
                .unwrap()
        );
        assert!(
            paths
                .try_record_relay_auto_abandon(
                    "network-commitment",
                    &["sender", "receiver"],
                    70,
                    100,
                    "authorization-2",
                    86_500,
                )
                .unwrap()
        );
    }
}
