use std::collections::BTreeMap;

use redb::{ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    model::{BlockConsensusMode, BlockRecord, ConsensusVote, ConsensusVoteType},
};

const BLOCKS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks/v1");

/// Disk-only block representation. A committed vote signs fields already fixed
/// by its block, so only the validator, timestamp, and signature are stored.
#[derive(Serialize, Deserialize)]
struct StoredBlock {
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "l")]
    ledger_id: String,
    #[serde(rename = "h")]
    height: u64,
    #[serde(rename = "p")]
    previous_block_hash: String,
    #[serde(rename = "t")]
    timestamp: i64,
    #[serde(rename = "n")]
    producer_node_id: u64,
    #[serde(rename = "o")]
    producer_owner_address: String,
    #[serde(rename = "x")]
    operation_ids: Vec<String>,
    #[serde(rename = "r")]
    state_root: String,
    #[serde(rename = "b")]
    block_hash: String,
    #[serde(rename = "s")]
    producer_signature: String,
    #[serde(rename = "m")]
    consensus_mode: BlockConsensusMode,
    #[serde(rename = "q")]
    consensus_round: u32,
    #[serde(rename = "z")]
    validator_set_hash: String,
    #[serde(rename = "c")]
    commit_signatures: Vec<StoredCommitSignature>,
    #[serde(rename = "e")]
    validator_epoch: u64,
    #[serde(rename = "i")]
    validator_node_ids: Vec<u64>,
}

/// Tuple encoding deliberately avoids repeating JSON field names per vote.
#[derive(Serialize, Deserialize)]
struct StoredCommitSignature(u64, i64, String);

impl TryFrom<&BlockRecord> for StoredBlock {
    type Error = Error;

    fn try_from(block: &BlockRecord) -> Result<Self> {
        let expected_hash = Some(block.block_hash.as_str());
        let commit_signatures = block
            .commit_signatures
            .iter()
            .map(|vote| {
                if vote.ledger_id != block.ledger_id
                    || vote.height != block.height
                    || vote.round != block.consensus_round
                    || vote.vote_type != ConsensusVoteType::Precommit
                    || vote.block_hash.as_deref() != expected_hash
                    || vote.validator_set_hash != block.validator_set_hash
                {
                    return Err(Error::msg(format!(
                        "block {} contains a commit vote for different consensus fields",
                        block.height
                    )));
                }
                Ok(StoredCommitSignature(
                    vote.validator_node_id,
                    vote.timestamp,
                    vote.signature.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            version: block.version,
            ledger_id: block.ledger_id.clone(),
            height: block.height,
            previous_block_hash: block.previous_block_hash.clone(),
            timestamp: block.timestamp,
            producer_node_id: block.producer_node_id,
            producer_owner_address: block.producer_owner_address.clone(),
            operation_ids: block.operation_ids.clone(),
            state_root: block.state_root.clone(),
            block_hash: block.block_hash.clone(),
            producer_signature: block.producer_signature.clone(),
            consensus_mode: block.consensus_mode.clone(),
            consensus_round: block.consensus_round,
            validator_set_hash: block.validator_set_hash.clone(),
            commit_signatures,
            validator_epoch: block.validator_epoch,
            validator_node_ids: block.validator_node_ids.clone(),
        })
    }
}

impl From<StoredBlock> for BlockRecord {
    fn from(block: StoredBlock) -> Self {
        let commit_signatures = block
            .commit_signatures
            .into_iter()
            .map(
                |StoredCommitSignature(validator_node_id, timestamp, signature)| ConsensusVote {
                    ledger_id: block.ledger_id.clone(),
                    height: block.height,
                    round: block.consensus_round,
                    vote_type: ConsensusVoteType::Precommit,
                    block_hash: Some(block.block_hash.clone()),
                    validator_set_hash: block.validator_set_hash.clone(),
                    validator_node_id,
                    timestamp,
                    signature,
                },
            )
            .collect();
        Self {
            version: block.version,
            ledger_id: block.ledger_id,
            height: block.height,
            previous_block_hash: block.previous_block_hash,
            timestamp: block.timestamp,
            producer_node_id: block.producer_node_id,
            producer_owner_address: block.producer_owner_address,
            operation_ids: block.operation_ids,
            state_root: block.state_root,
            block_hash: block.block_hash,
            producer_signature: block.producer_signature,
            consensus_mode: block.consensus_mode,
            consensus_round: block.consensus_round,
            validator_set_hash: block.validator_set_hash,
            commit_signatures,
            validator_epoch: block.validator_epoch,
            validator_node_ids: block.validator_node_ids,
        }
    }
}

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
            decode(value.value())
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
            decode(value.value())
        })
        .transpose()
}

pub(super) fn get(write: &WriteTransaction, height: u64) -> Result<Option<BlockRecord>> {
    let table = write.open_table(BLOCKS_TABLE).map_err(redb_error)?;
    table
        .get(height)
        .map_err(redb_error)?
        .map(|value| decode(value.value()))
        .transpose()
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

    for height in before.keys() {
        if !after.contains_key(height) {
            table.remove(height).map_err(redb_error)?;
        }
    }

    for (height, block) in &after {
        let bytes = encode(block)?;
        if let Some(previous) = before.get(height) {
            if encode(previous)? != bytes {
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

fn encode(block: &BlockRecord) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&StoredBlock::try_from(block)?)?)
}

fn decode(bytes: &[u8]) -> Result<BlockRecord> {
    Ok(serde_json::from_slice::<StoredBlock>(bytes)?.into())
}

fn redb_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("redb: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_commit_omits_fields_repeated_by_its_block() {
        let block = BlockRecord {
            version: 1,
            ledger_id: "ledger".to_owned(),
            height: 42,
            previous_block_hash: "previous".to_owned(),
            timestamp: 100,
            producer_node_id: 1,
            producer_owner_address: "owner".to_owned(),
            operation_ids: vec!["operation".to_owned()],
            state_root: "state".to_owned(),
            block_hash: "block".to_owned(),
            producer_signature: "producer-signature".to_owned(),
            consensus_mode: BlockConsensusMode::MultiValidator,
            consensus_round: 3,
            validator_set_hash: "validators".to_owned(),
            commit_signatures: vec![ConsensusVote {
                ledger_id: "ledger".to_owned(),
                height: 42,
                round: 3,
                vote_type: ConsensusVoteType::Precommit,
                block_hash: Some("block".to_owned()),
                validator_set_hash: "validators".to_owned(),
                validator_node_id: 2,
                timestamp: 101,
                signature: "validator-signature".to_owned(),
            }],
            validator_epoch: 7,
            validator_node_ids: vec![1, 2, 3, 4],
        };

        let compact = encode(&block).unwrap();
        let expanded = serde_json::to_vec(&block).unwrap();
        assert!(compact.len() < expanded.len());
        assert_eq!(
            serde_json::to_value(decode(&compact).unwrap()).unwrap(),
            serde_json::to_value(block).unwrap()
        );
    }
}
