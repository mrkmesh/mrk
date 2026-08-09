use serde::{Deserialize, Serialize};

use ring::signature::Ed25519KeyPair;

use crate::{
    Result,
    crypto::{EncryptedKeyFile, sha256_id, sign_bytes, verify_bytes},
    model::{
        LedgerState, OperationRecord, OperationStatus, PROTOCOL_VERSION, SignedOperation,
        UnsignedOperation,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OperationBody {
    pub operation_id: String,
    pub kind: String,
    pub signer: String,
    pub nonce: u64,
    pub created_at: i64,
    pub payload: serde_json::Value,
    pub signature: String,
    pub signed_operation: Option<SignedOperation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OperationFinality {
    pub status: OperationStatus,
    pub block_height: Option<u64>,
}

impl From<&OperationRecord> for OperationBody {
    fn from(record: &OperationRecord) -> Self {
        Self {
            operation_id: record.operation_id.clone(),
            kind: record.kind.clone(),
            signer: record.signer.clone(),
            nonce: record.nonce,
            created_at: record.created_at,
            payload: record.payload.clone(),
            signature: record.signature.clone(),
            signed_operation: record.signed_operation.clone(),
        }
    }
}

impl From<&OperationRecord> for OperationFinality {
    fn from(record: &OperationRecord) -> Self {
        Self {
            status: record.status.clone(),
            block_height: record.block_height,
        }
    }
}

impl OperationBody {
    pub(crate) fn with_finality(self, finality: OperationFinality) -> OperationRecord {
        OperationRecord {
            operation_id: self.operation_id,
            kind: self.kind,
            signer: self.signer,
            nonce: self.nonce,
            created_at: self.created_at,
            status: finality.status,
            payload: self.payload,
            signature: self.signature,
            block_height: finality.block_height,
            signed_operation: self.signed_operation,
        }
    }
}

pub(crate) fn sign(
    ledger: &LedgerState,
    signer: (&EncryptedKeyFile, &Ed25519KeyPair),
    module: &str,
    action: &str,
    nonce: u64,
    valid_until: i64,
    payload: serde_json::Value,
) -> Result<SignedOperation> {
    let (keyfile, key_pair) = signer;
    let unsigned = UnsignedOperation {
        ledger_id: ledger.ledger_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        module: module.to_owned(),
        action: action.to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: nonce,
        valid_until,
        payload,
    };
    let bytes = serde_json::to_vec(&unsigned)?;
    Ok(SignedOperation {
        signature: sign_bytes(key_pair, &bytes),
        unsigned,
    })
}

pub(crate) fn verify(operation: &SignedOperation, public_key: &str) -> Result<()> {
    let bytes = serde_json::to_vec(&operation.unsigned)?;
    verify_bytes(public_key, &bytes, &operation.signature)
}

pub(crate) fn id(operation: &SignedOperation) -> Result<String> {
    Ok(sha256_id("op", &serde_json::to_vec(operation)?))
}

pub(crate) fn sort_pending(ledger: &mut LedgerState) {
    ledger.pending_operation_ids.sort_by(|left, right| {
        let left_record = &ledger.operations[left];
        let right_record = &ledger.operations[right];
        (
            left_record
                .signed_operation
                .as_ref()
                .map(|operation| operation.unsigned.valid_until)
                .unwrap_or(i64::MAX),
            left_record.signer.as_str(),
            left_record.nonce,
            left.as_str(),
        )
            .cmp(&(
                right_record
                    .signed_operation
                    .as_ref()
                    .map(|operation| operation.unsigned.valid_until)
                    .unwrap_or(i64::MAX),
                right_record.signer.as_str(),
                right_record.nonce,
                right.as_str(),
            ))
    });
}

pub(crate) fn add_history(ledger: &mut LedgerState, address: &str, operation_id: &str) {
    let account = ledger.accounts.entry(address.to_owned()).or_default();
    if !account.operation_ids.iter().any(|id| id == operation_id) {
        account.operation_ids.push(operation_id.to_owned());
    }
}
