use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    model::{NodeStatus, SignedOperation},
    service,
    storage::DataPaths,
};

pub const RPC_PROTOCOL: &str = "mrk.rpc.v1";

#[derive(Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

impl Request {
    pub fn is_mutation(&self) -> bool {
        self.method == "operation.submit"
    }
}

#[derive(Serialize)]
pub struct Response {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

impl Response {
    pub fn success(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: u64, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(ResponseError {
                code,
                message: message.into(),
            }),
        }
    }
}

#[derive(Serialize)]
pub struct ResponseError {
    pub code: &'static str,
    pub message: String,
}

pub fn execute(paths: &DataPaths, request: Request) -> Result<serde_json::Value> {
    let now = Utc::now().timestamp();
    let result = match request.method.as_str() {
        "system.ping" => {
            let ledger = paths.read_ledger()?;
            serde_json::json!({
                "protocol": RPC_PROTOCOL,
                "protocol_version": crate::model::PROTOCOL_VERSION,
                "ledger_id": ledger.ledger_id,
                "time": now,
            })
        }
        "chain.status" => serde_json::to_value(service::block_status(paths, now)?)?,
        "fee.quote" => serde_json::to_value(service::fee_quote(
            paths,
            required_str(&request.params, "module")?,
            required_str(&request.params, "action")?,
            request
                .params
                .get("payload")
                .unwrap_or(&serde_json::Value::Null),
        )?)?,
        "chain.checkpoints" => serde_json::to_value(service::bootstrap_checkpoints(paths)?)?,
        "chain.bootstrap" => {
            let snapshot = match request.params.get("height") {
                Some(height) => service::bootstrap_snapshot_at(
                    paths,
                    height
                        .as_u64()
                        .ok_or_else(|| Error::msg("RPC parameter 'height' must be a u64"))?,
                )?,
                None => service::bootstrap_snapshot(paths)?,
            };
            serde_json::to_value(snapshot)?
        }
        "chain.catch_up" => serde_json::to_value(service::consensus_catch_up_chunk(
            paths,
            required_u64(&request.params, "from_height")?,
            crate::consensus::MAX_CATCH_UP_BLOCKS,
        )?)?,
        "block.list" => serde_json::to_value(service::blocks(
            paths,
            optional_u64(&request.params, "cursor")?,
            page_limit(&request.params, 100)?,
        )?)?,
        "block.get" => serde_json::to_value(service::block_by_height(
            paths,
            required_u64(&request.params, "height")?,
        )?)?,
        "block.operations" => serde_json::to_value(service::block_operations(
            paths,
            required_u64(&request.params, "height")?,
            optional_u64(&request.params, "cursor")?.unwrap_or(0) as usize,
            page_limit(&request.params, 100)?,
        )?)?,
        "account.balance" => serde_json::to_value(service::balance(
            paths,
            required_str(&request.params, "address")?,
        )?)?,
        "account.list" => serde_json::to_value(service::account_rankings(
            paths,
            optional_str(&request.params, "cursor")?,
            page_limit(&request.params, 1_000)?,
        )?)?,
        "account.history" => serde_json::to_value(service::account_history(
            paths,
            required_str(&request.params, "address")?,
            page_limit(&request.params, 1_000)?,
        )?)?,
        "operation.get" => serde_json::to_value(service::operation(
            paths,
            required_str(&request.params, "operation_id")?,
        )?)?,
        "operation.submit" => {
            let public_key = required_str(&request.params, "public_key")?.to_owned();
            let operation: SignedOperation = serde_json::from_value(
                request
                    .params
                    .get("operation")
                    .cloned()
                    .ok_or_else(|| Error::msg("missing 'operation' parameter"))?,
            )?;
            let operation_id = service::submit_consensus_operation(
                paths,
                crate::consensus::PendingOperationEnvelope {
                    public_key,
                    operation,
                },
                now,
            )?;
            serde_json::json!({ "operation_id": operation_id, "status": "PENDING" })
        }
        "network.get" => serde_json::to_value(service::network_by_alias(
            paths,
            required_str(&request.params, "alias")?,
        )?)?,
        "node.list" => serde_json::to_value(service::registry_nodes(
            paths,
            optional_node_status(&request.params, "status")?,
            optional_node_availability(&request.params, "availability")?,
            optional_bool(&request.params, "validator")?.unwrap_or(false),
            optional_u64(&request.params, "cursor")?,
            page_limit(&request.params, 1_000)?,
            now,
        )?)?,
        "node.get" => serde_json::to_value(service::registry_node_by_id(
            paths,
            required_u64(&request.params, "node_id")?,
            now,
        )?)?,
        "node.discover" => serde_json::to_value(service::discover_relays(
            paths,
            optional_u64(&request.params, "cursor")?,
            page_limit(&request.params, 1_000)?,
            now,
        )?)?,
        "payment.get" => serde_json::to_value(service::relay_authorization_view(
            paths,
            required_str(&request.params, "authorization_id")?,
        )?)?,
        "payment.status" => serde_json::to_value(service::payment_authorization_status(
            paths,
            required_str(&request.params, "identifier")?,
        )?)?,
        "payment.history" => serde_json::to_value(service::payment_history(
            paths,
            required_str(&request.params, "network")?,
            request
                .params
                .get("member")
                .and_then(serde_json::Value::as_str),
            page_limit(&request.params, 1_000)?,
        )?)?,
        "payment.unsettled" => serde_json::to_value(service::unsettled_payments(
            paths,
            request
                .params
                .get("network")
                .and_then(serde_json::Value::as_str),
            request
                .params
                .get("member")
                .and_then(serde_json::Value::as_str),
            None,
        )?)?,
        "governance.status" => serde_json::to_value(service::governance_status(paths, now)?)?,
        "governance.list" => serde_json::to_value(service::governance_proposals(paths)?)?,
        "governance.get" => {
            let (proposal, tally) =
                service::governance_proposal(paths, required_u64(&request.params, "proposal_id")?)?;
            serde_json::json!({
                "proposal": proposal,
                "tally": {
                    "proposal_id": tally.proposal_id,
                    "status": tally.status,
                    "total_power": tally.total_power.to_string(),
                    "yes_power": tally.yes_power.to_string(),
                    "no_power": tally.no_power.to_string(),
                    "abstain_power": tally.abstain_power.to_string(),
                    "participation_power": tally.participation_power.to_string(),
                    "validator_total": tally.validator_total,
                    "validator_yes": tally.validator_yes,
                    "validator_no": tally.validator_no,
                    "validator_abstain": tally.validator_abstain,
                    "validator_quorum": tally.validator_quorum,
                    "timelock_veto_power": tally.timelock_veto_power.to_string(),
                    "voting_ends_at": tally.voting_ends_at,
                    "execute_after": tally.execute_after,
                }
            })
        }
        "treasury.status" => serde_json::to_value(service::treasury_status(paths, now)?)?,
        "treasury.history" => serde_json::Value::Array(
            service::treasury_history(paths, page_limit(&request.params, 1_000)?)?
                .into_iter()
                .map(|spend| {
                    serde_json::json!({
                        "proposal_id": spend.proposal_id,
                        "operation_id": spend.operation_id,
                        "recipient": spend.recipient,
                        "amount": spend.amount,
                        "amount_display": crate::amount::format_mrk(spend.amount),
                        "reference_hash": spend.reference_hash,
                        "executed_at": spend.executed_at,
                    })
                })
                .collect(),
        ),
        _ => {
            return Err(Error::msg(format!(
                "unknown RPC method: {}",
                request.method
            )));
        }
    };
    Ok(result)
}

fn required_str<'a>(params: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    params
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::msg(format!("missing or invalid '{name}' parameter")))
}

fn required_u64(params: &serde_json::Value, name: &str) -> Result<u64> {
    params
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::msg(format!("missing or invalid '{name}' parameter")))
}

fn optional_u64(params: &serde_json::Value, name: &str) -> Result<Option<u64>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))
}

fn optional_str<'a>(params: &'a serde_json::Value, name: &str) -> Result<Option<&'a str>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))
}

fn optional_bool(params: &serde_json::Value, name: &str) -> Result<Option<bool>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))
}

fn page_limit(params: &serde_json::Value, maximum: u64) -> Result<usize> {
    let limit = params.get("limit").map_or(Ok(20), |value| {
        value
            .as_u64()
            .ok_or_else(|| Error::msg("invalid 'limit' parameter"))
    })?;
    if !(1..=maximum).contains(&limit) {
        return Err(Error::msg(format!(
            "page limit must be between 1 and {maximum}"
        )));
    }
    Ok(limit as usize)
}

fn optional_node_status(params: &serde_json::Value, name: &str) -> Result<Option<NodeStatus>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let normalized = value
        .as_str()
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))?
        .replace('-', "_")
        .to_ascii_uppercase();
    let status = match normalized.as_str() {
        "INITIALIZED" => NodeStatus::Initialized,
        "WARMING_UP" => NodeStatus::WarmingUp,
        "ACTIVE" => NodeStatus::Active,
        "DRAINING" => NodeStatus::Draining,
        "EXITED" => NodeStatus::Exited,
        "SUSPENDED" => NodeStatus::Suspended,
        _ => return Err(Error::msg(format!("invalid '{name}' parameter"))),
    };
    Ok(Some(status))
}

fn optional_node_availability(
    params: &serde_json::Value,
    name: &str,
) -> Result<Option<service::RegistryNodeAvailability>> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let normalized = value
        .as_str()
        .ok_or_else(|| Error::msg(format!("invalid '{name}' parameter")))?
        .replace('-', "_")
        .to_ascii_uppercase();
    let availability = match normalized.as_str() {
        "ONLINE" => service::RegistryNodeAvailability::Online,
        "PROBE_STALE" => service::RegistryNodeAvailability::ProbeStale,
        "UNVERIFIED" => service::RegistryNodeAvailability::Unverified,
        "IP_SLOT_UNAVAILABLE" => service::RegistryNodeAvailability::IpSlotUnavailable,
        "EXIT_PENDING" => service::RegistryNodeAvailability::ExitPending,
        _ => return Err(Error::msg(format!("invalid '{name}' parameter"))),
    };
    Ok(Some(availability))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explorer_queries_are_read_only() {
        for method in [
            "chain.status",
            "fee.quote",
            "chain.checkpoints",
            "block.list",
            "block.get",
            "block.operations",
            "account.balance",
            "account.list",
            "operation.get",
            "node.list",
            "governance.list",
            "treasury.status",
        ] {
            let request = Request {
                id: 1,
                method: method.to_owned(),
                params: serde_json::Value::Null,
            };
            assert!(!request.is_mutation(), "{method}");
        }
    }
}
