use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{BlockRecord, ConsensusVote, OperationRecord, SignedOperation};

pub const CONSENSUS_PROTOCOL: &str = "mrk.consensus.v1";
pub const MAX_CONSENSUS_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_CATCH_UP_BLOCKS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusChallenge {
    pub protocol: String,
    pub challenge: String,
    pub server_node_id: u64,
    pub server_owner_public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

pub fn challenge_signing_bytes(challenge: &ConsensusChallenge) -> Vec<u8> {
    format!(
        "mrk-consensus-challenge-v1:{}:{}:{}:{}:{}",
        challenge.protocol,
        challenge.server_node_id,
        challenge.server_owner_public_key,
        challenge.challenge,
        challenge.timestamp
    )
    .into_bytes()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusHello {
    pub protocol: String,
    pub validator_node_id: u64,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOperationEnvelope {
    pub public_key: String,
    pub operation: SignedOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusWireMessage {
    Challenge {
        challenge: ConsensusChallenge,
    },
    Hello {
        hello: ConsensusHello,
    },
    Welcome {
        server_node_id: u64,
        authenticated_validator_node_id: u64,
    },
    SyncRequest {
        height: u64,
        round: u32,
    },
    SyncState {
        height: u64,
        round: u32,
        proposal: Option<BlockRecord>,
        prevotes: Vec<ConsensusVote>,
        precommits: Vec<ConsensusVote>,
        pending_operations: Vec<PendingOperationEnvelope>,
    },
    Operation {
        envelope: PendingOperationEnvelope,
    },
    CatchUpRequest {
        from_height: u64,
    },
    CatchUpChunk {
        tip_height: u64,
        blocks: Vec<BlockRecord>,
        operations: Vec<OperationRecord>,
        finalized_checkpoint_json: Option<String>,
    },
    Proposal {
        block: BlockRecord,
    },
    Vote {
        vote: ConsensusVote,
    },
    StatusRequest,
    Status {
        status: Value,
    },
    Ack {
        kind: String,
        finalized_height: Option<u64>,
    },
    Error {
        code: String,
        message: String,
    },
    Ping {
        timestamp: i64,
    },
    Pong {
        timestamp: i64,
    },
}

pub fn hello_signing_bytes(
    challenge: &ConsensusChallenge,
    validator_node_id: u64,
    timestamp: i64,
) -> Vec<u8> {
    format!(
        "mrk-consensus-hello-v1:{}:{}:{}:{}",
        challenge.server_node_id, challenge.challenge, validator_node_id, timestamp
    )
    .into_bytes()
}
