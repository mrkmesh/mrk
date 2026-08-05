use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, backends::InMemoryBackend};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    Error, Result,
    crypto::EncryptedKeyFile,
    model::{LedgerState, LocalNodeConfig},
    relay::{ReceiverReceipt, SenderCheckpoint},
};

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct PendingTrafficSettlement {
    pub sender_checkpoint: SenderCheckpoint,
    pub receiver_receipt: ReceiverReceipt,
    #[serde(default)]
    pub submission_operation_id: Option<String>,
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

    pub fn load_or_init_ledger(&self) -> Result<LedgerState> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        let state = {
            let mut table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
            let existing = table
                .get(LEDGER_STATE_KEY)
                .map_err(redb_error)?
                .map(|bytes| bytes.value().to_vec());
            match existing {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => {
                    let state = LedgerState::default();
                    let bytes = serde_json::to_vec(&state)?;
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
        write.commit().map_err(redb_error)?;
        Ok(state)
    }

    pub fn with_ledger_mut<T>(
        &self,
        operation: impl FnOnce(&mut LedgerState) -> Result<T>,
    ) -> Result<T> {
        let db = self.open_chain_db()?;
        let write = db.begin_write().map_err(redb_error)?;
        let mut ledger = {
            let table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
            match table.get(LEDGER_STATE_KEY).map_err(redb_error)? {
                Some(bytes) => serde_json::from_slice(bytes.value())?,
                None => LedgerState::default(),
            }
        };
        let result = operation(&mut ledger)?;
        {
            let mut table = write.open_table(LEDGER_TABLE).map_err(redb_error)?;
            let bytes = serde_json::to_vec(&ledger)?;
            table
                .insert(LEDGER_STATE_KEY, bytes.as_slice())
                .map_err(redb_error)?;
        }
        write.commit().map_err(redb_error)?;
        Ok(result)
    }

    pub fn read_ledger(&self) -> Result<LedgerState> {
        self.load_or_init_ledger()
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
                    settlement.sender_checkpoint.sequence >= existing.sender_checkpoint.sequence
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
                    existing.sender_checkpoint.sequence <= maximum_sequence
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
                protocol_version: 1,
                node_id: 1,
                authorization_id: "authorization".to_owned(),
                session_id: "session".to_owned(),
                direction: crate::model::RelayDirection::SenderToReceiver,
                sequence,
                cumulative_sent_bytes: bytes,
                transcript_hash: format!("hash-{sequence}"),
                checkpoint_at: sequence as i64,
                sender_member_id: "sender".to_owned(),
                sender_signature: "signature".to_owned(),
            },
            receiver_receipt: ReceiverReceipt {
                ledger_id: "ledger".to_owned(),
                protocol_version: 1,
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
            )
            .unwrap();
        let pending = paths.pending_traffic_settlements().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sender_checkpoint.sequence, 2);
    }
}
