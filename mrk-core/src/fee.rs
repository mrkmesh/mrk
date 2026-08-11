use serde_json::Value;

use crate::{
    Error, Result,
    amount::MRK_SCALE,
    model::{FEE_MULTIPLIER_BPS, LedgerState, UnsignedOperation},
};

pub const FEE_CHANGE_BUFFER_BPS: u128 = 12_500;
pub const MIN_BASE_FEE_PER_UNIT: u128 = MRK_SCALE / 10_000;
pub const MAX_BASE_FEE_PER_UNIT: u128 = MRK_SCALE / 10;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeQuote {
    pub policy_version: u64,
    pub units: u64,
    pub fee: u128,
    pub recommended_max_fee: u128,
}

pub fn operation_fee_units(module: &str, action: &str, payload: &Value) -> u64 {
    match (module, action) {
        ("Asset", "Transfer") => 1,
        ("NetworkRegistry", "CreateNetwork") => 100,
        ("NetworkRegistry", "IssueMember") => 10,
        ("NetworkRegistry", "RevokeMember") => 1,
        ("NetworkEscrow", "FundNetwork" | "SetSpendingPolicy") => 1,
        ("TrafficPayment", "ReserveSession") => 1,
        ("TrafficPayment", "Refund" | "Settle") => 0,
        ("NodeRegistry", "RegisterNode") => {
            u64::from(
                payload
                    .get("previous_node_id")
                    .is_some_and(|value| !value.is_null()),
            ) * 1_000
        }
        ("NodeRegistry", "UpdateRewardIp") => 100,
        ("NodeRegistry", "UpdatePrice") => 10,
        ("NodeRegistry", "DrainNode") => 0,
        ("NodeRegistry", "WithdrawServiceBond") => 1,
        ("NodeEmissionController", "ClaimNodeReward") => 1,
        ("StakeVault", "BondGovernance" | "BondValidator") => 1,
        ("StakeVault", "ExitGovernance" | "ExitValidator") => 0,
        ("StakeVault", "WithdrawGovernanceBond" | "WithdrawValidatorBond") => 1,
        ("Governance", "CreateProposal") => 10,
        (
            "Governance",
            "VoteProposal"
            | "ValidatorVoteProposal"
            | "VetoTreasuryProposal"
            | "FinalizeProposal"
            | "ExecuteProposal"
            | "SetParameters"
            | "PauseEmission"
            | "ResumeEmission",
        ) => 0,
        ("Availability", "AttestProbe") => 0,
        _ => 1,
    }
}

pub fn quote(
    ledger: &LedgerState,
    module: &str,
    action: &str,
    payload: &Value,
) -> Result<FeeQuote> {
    let units = operation_fee_units(module, action, payload);
    let policy = &ledger.settings.fee_policy;
    let fee = if units == 0 {
        0
    } else {
        policy
            .base_fee_per_unit
            .checked_mul(u128::from(units))
            .and_then(|fee| fee.checked_mul(u128::from(ledger.fee_multiplier_bps)))
            .and_then(|fee| fee.checked_add(u128::from(FEE_MULTIPLIER_BPS) - 1))
            .map(|fee| fee / u128::from(FEE_MULTIPLIER_BPS))
            .ok_or_else(|| Error::msg("operation fee overflow"))?
    };
    let recommended_max_fee = fee
        .checked_mul(FEE_CHANGE_BUFFER_BPS)
        .and_then(|fee| fee.checked_add(9_999))
        .map(|fee| fee / 10_000)
        .ok_or_else(|| Error::msg("operation maximum fee overflow"))?;
    Ok(FeeQuote {
        policy_version: policy.version,
        units,
        fee,
        recommended_max_fee,
    })
}

pub fn validate_envelope(ledger: &LedgerState, operation: &UnsignedOperation) -> Result<FeeQuote> {
    let quote = quote(
        ledger,
        &operation.module,
        &operation.action,
        &operation.payload,
    )?;
    if quote.fee == 0 {
        return Ok(quote);
    }
    if operation.fee_policy_version == 0
        || operation.fee_policy_version > ledger.settings.fee_policy.version
    {
        return Err(Error::msg("operation fee policy version is invalid"));
    }
    if operation.max_fee_base_units < quote.fee {
        return Err(Error::msg(format!(
            "operation maximum fee is below the required fee: maximum {}, required {}",
            operation.max_fee_base_units, quote.fee
        )));
    }
    Ok(quote)
}

pub fn next_epoch_multiplier(ledger: &LedgerState) -> Result<u32> {
    let policy = &ledger.settings.fee_policy;
    if policy.target_units_per_epoch == 0 {
        return Ok(ledger.fee_multiplier_bps);
    }
    let current = u128::from(ledger.fee_multiplier_bps);
    let target = u128::from(policy.target_units_per_epoch);
    let used = u128::from(ledger.fee_units_used_in_epoch);
    let denominator = u128::from(policy.adjustment_denominator);
    let next = if used > target {
        let pressure = (used - target).min(target);
        let change = current
            .checked_mul(pressure)
            .and_then(|value| value.checked_div(target))
            .and_then(|value| value.checked_div(denominator))
            .unwrap_or_default()
            .max(1);
        current.saturating_add(change)
    } else if used < target {
        let pressure = (target - used).min(target);
        let change = current
            .checked_mul(pressure)
            .and_then(|value| value.checked_div(target))
            .and_then(|value| value.checked_div(denominator))
            .unwrap_or_default();
        current.saturating_sub(change)
    } else {
        current
    };
    u32::try_from(next.clamp(
        u128::from(policy.min_multiplier_bps),
        u128::from(policy.max_multiplier_bps),
    ))
    .map_err(|_| Error::msg("fee multiplier overflow"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn operation_weights_quote_exact_fees_and_a_buffered_cap() {
        let ledger = LedgerState::default();
        let transfer = quote(&ledger, "Asset", "Transfer", &json!({})).unwrap();
        let network = quote(&ledger, "NetworkRegistry", "CreateNetwork", &json!({})).unwrap();
        let first_registration = quote(
            &ledger,
            "NodeRegistry",
            "RegisterNode",
            &json!({"previous_node_id": null}),
        )
        .unwrap();
        let replacement_registration = quote(
            &ledger,
            "NodeRegistry",
            "RegisterNode",
            &json!({"previous_node_id": 7}),
        )
        .unwrap();

        assert_eq!(transfer.units, 1);
        assert_eq!(transfer.fee, MRK_SCALE / 1_000);
        assert_eq!(transfer.recommended_max_fee, transfer.fee * 5 / 4);
        assert_eq!(network.units, 100);
        assert_eq!(network.fee, transfer.fee * 100);
        assert_eq!(first_registration.fee, 0);
        assert_eq!(replacement_registration.units, 1_000);
    }

    #[test]
    fn congestion_multiplier_moves_gradually_and_stays_bounded() {
        let mut ledger = LedgerState::default();
        ledger.fee_units_used_in_epoch = ledger.settings.fee_policy.target_units_per_epoch * 2;
        assert_eq!(next_epoch_multiplier(&ledger).unwrap(), 11_250);

        ledger.fee_units_used_in_epoch = 0;
        assert_eq!(next_epoch_multiplier(&ledger).unwrap(), 8_750);

        ledger.fee_multiplier_bps = ledger.settings.fee_policy.min_multiplier_bps;
        assert_eq!(
            next_epoch_multiplier(&ledger).unwrap(),
            ledger.settings.fee_policy.min_multiplier_bps
        );
    }

    #[test]
    fn signed_maximum_fee_rejects_price_slippage() {
        let ledger = LedgerState::default();
        let required = quote(&ledger, "Asset", "Transfer", &json!({})).unwrap();
        let operation = UnsignedOperation {
            ledger_id: ledger.ledger_id.clone(),
            protocol_version: crate::model::PROTOCOL_VERSION,
            module: "Asset".to_owned(),
            action: "Transfer".to_owned(),
            signer: "mrk1payer".to_owned(),
            account_nonce: 1,
            valid_until: i64::MAX,
            max_fee_base_units: required.fee - 1,
            fee_policy_version: required.policy_version,
            payload: json!({}),
        };
        assert!(validate_envelope(&ledger, &operation).is_err());
    }
}
