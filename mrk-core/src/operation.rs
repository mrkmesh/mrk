use serde::{Deserialize, Serialize};

use ring::signature::Ed25519KeyPair;

use crate::{
    Error, Result,
    crypto::{EncryptedKeyFile, sha256_id, sign_bytes, verify_bytes},
    fee,
    model::{
        LedgerState, OperationRecord, OperationStatus, PROTOCOL_VERSION, SignedOperation,
        UnsignedOperation,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OperationBody {
    pub created_at: i64,
    pub signed_operation: SignedOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OperationFinality {
    pub status: OperationStatus,
    pub block_height: Option<u64>,
    pub error: Option<String>,
    pub fee_payer: Option<String>,
    pub fee_charged: u128,
    pub fee_burned: u128,
    pub fee_to_treasury: u128,
}

impl TryFrom<&OperationRecord> for OperationBody {
    type Error = Error;

    fn try_from(record: &OperationRecord) -> Result<Self> {
        let signed_operation = record.signed_operation.clone().ok_or_else(|| {
            Error::msg(format!(
                "operation {} has no signed operation body",
                record.operation_id
            ))
        })?;
        let unsigned = &signed_operation.unsigned;
        let expected_id = id(&signed_operation)?;
        if record.operation_id != expected_id
            || record.kind != format!("{}.{}", unsigned.module, unsigned.action)
            || record.signer != unsigned.signer
            || record.nonce != unsigned.account_nonce
            || record.payload != unsigned.payload
            || record.signature != signed_operation.signature
        {
            return Err(Error::msg(format!(
                "operation {} does not match its signed operation body",
                record.operation_id
            )));
        }
        Ok(Self {
            created_at: record.created_at,
            signed_operation,
        })
    }
}

impl From<&OperationRecord> for OperationFinality {
    fn from(record: &OperationRecord) -> Self {
        Self {
            status: record.status.clone(),
            block_height: record.block_height,
            error: record.error.clone(),
            fee_payer: record.fee_payer.clone(),
            fee_charged: record.fee_charged,
            fee_burned: record.fee_burned,
            fee_to_treasury: record.fee_to_treasury,
        }
    }
}

impl OperationBody {
    pub(crate) fn with_finality(
        self,
        operation_id: String,
        finality: OperationFinality,
    ) -> Result<OperationRecord> {
        let actual_id = id(&self.signed_operation)?;
        if actual_id != operation_id {
            return Err(Error::msg(format!(
                "operation body key {operation_id} does not match signed operation id {actual_id}"
            )));
        }
        let unsigned = &self.signed_operation.unsigned;
        Ok(OperationRecord {
            operation_id,
            kind: format!("{}.{}", unsigned.module, unsigned.action),
            signer: unsigned.signer.clone(),
            nonce: unsigned.account_nonce,
            created_at: self.created_at,
            status: finality.status,
            error: finality.error,
            payload: unsigned.payload.clone(),
            signature: self.signed_operation.signature.clone(),
            block_height: finality.block_height,
            signed_operation: Some(self.signed_operation),
            fee_payer: finality.fee_payer,
            fee_charged: finality.fee_charged,
            fee_burned: finality.fee_burned,
            fee_to_treasury: finality.fee_to_treasury,
        })
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
    let fee_quote = fee::quote(ledger, module, action, &payload)?;
    let unsigned = UnsignedOperation {
        ledger_id: ledger.ledger_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        module: module.to_owned(),
        action: action.to_owned(),
        signer: keyfile.address.clone(),
        account_nonce: nonce,
        valid_until,
        max_fee_base_units: fee_quote.recommended_max_fee,
        fee_policy_version: fee_quote.policy_version,
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

#[cfg(test)]
mod storage_tests {
    use super::*;
    use crate::model::{OperationStatus, UnsignedOperation};

    #[test]
    fn compact_body_round_trips_without_expanded_record_fields() {
        let signed_operation = SignedOperation {
            unsigned: UnsignedOperation {
                ledger_id: "ledger".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                module: "payment".to_owned(),
                action: "transfer".to_owned(),
                signer: "alice".to_owned(),
                account_nonce: 9,
                valid_until: 1_000,
                max_fee_base_units: 10,
                fee_policy_version: 1,
                payload: serde_json::json!({
                    "recipient": "bob",
                    "memo": "a deliberately repeated payload used to measure storage"
                }),
            },
            signature: "signature".to_owned(),
        };
        let operation_id = id(&signed_operation).unwrap();
        let record = OperationRecord {
            operation_id: operation_id.clone(),
            kind: "payment.transfer".to_owned(),
            signer: "alice".to_owned(),
            nonce: 9,
            created_at: 900,
            status: OperationStatus::Finalized,
            error: None,
            payload: signed_operation.unsigned.payload.clone(),
            signature: signed_operation.signature.clone(),
            block_height: Some(2),
            signed_operation: Some(signed_operation),
            fee_payer: Some("alice".to_owned()),
            fee_charged: 10,
            fee_burned: 5,
            fee_to_treasury: 5,
        };
        let body = OperationBody::try_from(&record).unwrap();
        assert!(
            serde_json::to_vec(&body).unwrap().len() < serde_json::to_vec(&record).unwrap().len()
        );
        let restored = body
            .with_finality(operation_id, OperationFinality::from(&record))
            .unwrap();
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(record).unwrap()
        );
    }
}
