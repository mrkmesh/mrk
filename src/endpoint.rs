use url::Url;

use crate::{Error, Result};

pub const CONSENSUS_PATH: &str = "/v1/consensus";
pub const RELAY_PATH: &str = "/v1/relay";
pub const RPC_PATH: &str = "/v1/rpc";

pub fn normalize_websocket_url(endpoint: &str, default_path: &str) -> Result<Url> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(Error::msg("WebSocket endpoint must not be empty"));
    }
    let candidate = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("wss://{endpoint}")
    };
    let mut url = Url::parse(&candidate)
        .map_err(|error| Error::msg(format!("invalid WebSocket endpoint: {error}")))?;
    if !matches!(url.scheme(), "wss" | "ws") {
        return Err(Error::msg("WebSocket endpoint must use wss:// or ws://"));
    }
    if url.host().is_none() {
        return Err(Error::msg("WebSocket endpoint is missing its host"));
    }
    if matches!(url.path(), "" | "/") {
        url.set_path(default_path);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_missing_websocket_scheme_and_path() {
        assert_eq!(
            normalize_websocket_url("relay.example.com", RELAY_PATH)
                .unwrap()
                .as_str(),
            "wss://relay.example.com/v1/relay"
        );
        assert_eq!(
            normalize_websocket_url("relay.example.com:9443", RPC_PATH)
                .unwrap()
                .as_str(),
            "wss://relay.example.com:9443/v1/rpc"
        );
        assert_eq!(
            normalize_websocket_url("wss://relay.example.com/", CONSENSUS_PATH)
                .unwrap()
                .as_str(),
            "wss://relay.example.com/v1/consensus"
        );
    }

    #[test]
    fn preserves_explicit_websocket_scheme_and_path() {
        assert_eq!(
            normalize_websocket_url("ws://127.0.0.1:8787/v1/rpc", RPC_PATH)
                .unwrap()
                .as_str(),
            "ws://127.0.0.1:8787/v1/rpc"
        );
        assert_eq!(
            normalize_websocket_url("relay.example.com/custom", RELAY_PATH)
                .unwrap()
                .as_str(),
            "wss://relay.example.com/custom"
        );
    }
}
