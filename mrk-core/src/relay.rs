use std::io::{Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    Error, Result,
    crypto::{random_bytes, sha256_id},
    model::{MemberCredential, RelayDirection},
};

pub const RELAY_PROTOCOL: &str = "mrk.relay.v1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_LEN: usize = 20;
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;
pub const RELAY_PAYMENT_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
pub const RELAY_PAYMENT_WINDOW_SECONDS: i64 = 15;
pub const RELAY_PAYMENT_CLAIM_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const RELAY_CHECKPOINT_FINAL_FLAG: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointRequest {
    pub authorization_id: String,
    pub session_id: String,
    pub direction: RelayDirection,
    pub sequence: u64,
    pub cumulative_sent_bytes: u64,
    pub transcript_hash: String,
    pub requested_at: i64,
    pub final_checkpoint: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseIntent {
    pub authorization_id: String,
    pub session_id: String,
    pub direction: RelayDirection,
    pub sequence: u64,
    pub cumulative_sent_bytes: u64,
    pub transcript_hash: String,
    pub requested_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderCheckpoint {
    pub ledger_id: String,
    pub protocol_version: u32,
    pub node_id: u64,
    pub authorization_id: String,
    pub session_id: String,
    pub direction: RelayDirection,
    pub sequence: u64,
    pub cumulative_sent_bytes: u64,
    pub transcript_hash: String,
    pub checkpoint_at: i64,
    pub sender_member_id: String,
    pub final_checkpoint: bool,
    pub sender_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiverReceipt {
    pub ledger_id: String,
    pub protocol_version: u32,
    pub node_id: u64,
    pub authorization_id: String,
    pub session_id: String,
    pub direction: RelayDirection,
    pub sequence: u64,
    pub cumulative_received_bytes: u64,
    pub transcript_hash: String,
    pub sender_checkpoint_hash: String,
    pub received_at: i64,
    pub receiver_member_id: String,
    pub receiver_signature: String,
}

pub fn sender_checkpoint_signing_bytes(checkpoint: &SenderCheckpoint) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "ledger_id": checkpoint.ledger_id,
        "protocol_version": checkpoint.protocol_version,
        "node_id": checkpoint.node_id,
        "authorization_id": checkpoint.authorization_id,
        "session_id": checkpoint.session_id,
        "direction": checkpoint.direction,
        "sequence": checkpoint.sequence,
        "cumulative_sent_bytes": checkpoint.cumulative_sent_bytes,
        "transcript_hash": checkpoint.transcript_hash,
        "checkpoint_at": checkpoint.checkpoint_at,
        "sender_member_id": checkpoint.sender_member_id,
        "final_checkpoint": checkpoint.final_checkpoint,
    }))?)
}

pub fn sender_checkpoint_hash(checkpoint: &SenderCheckpoint) -> Result<String> {
    Ok(crate::crypto::sha256_full_id(
        "sender-checkpoint",
        &serde_json::to_vec(checkpoint)?,
    ))
}

pub fn receiver_receipt_signing_bytes(receipt: &ReceiverReceipt) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "ledger_id": receipt.ledger_id,
        "protocol_version": receipt.protocol_version,
        "node_id": receipt.node_id,
        "authorization_id": receipt.authorization_id,
        "session_id": receipt.session_id,
        "direction": receipt.direction,
        "sequence": receipt.sequence,
        "cumulative_received_bytes": receipt.cumulative_received_bytes,
        "transcript_hash": receipt.transcript_hash,
        "sender_checkpoint_hash": receipt.sender_checkpoint_hash,
        "received_at": receipt.received_at,
        "receiver_member_id": receipt.receiver_member_id,
    }))?)
}

pub fn relay_transcript_initial_hash(
    ledger_id: &str,
    node_id: u64,
    authorization_id: &str,
    session_id: &str,
    direction: RelayDirection,
) -> String {
    sha256_id(
        "relay-transcript",
        format!(
            "{ledger_id}:{node_id}:{authorization_id}:{session_id}:{}",
            serde_json::to_string(&direction).expect("serializable direction")
        )
        .as_bytes(),
    )
}

pub fn relay_transcript_next_hash(previous_hash: &str, sequence: u64, payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(previous_hash.len() + 16 + payload.len());
    bytes.extend_from_slice(previous_hash.as_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    sha256_id("relay-transcript-step", &bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengePayload {
    pub challenge: String,
    pub relay_public_key: String,
    pub node_id: u64,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloPayload {
    pub credential: MemberCredential,
    pub timestamp: i64,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WelcomePayload {
    pub connection_id: u64,
    pub max_channels: u32,
    pub max_message_size: u32,
    pub heartbeat_seconds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPayload {
    pub peer_id: String,
    pub authorization_id: String,
    #[serde(default)]
    pub metadata: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncomingPayload {
    pub peer_id: String,
    pub authorization_id: String,
    pub session_id: String,
    #[serde(default)]
    pub metadata: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbePayload {
    pub protocol: String,
    pub node_id: u64,
    pub relay_public_key: String,
    pub timestamp: i64,
    pub challenge: String,
    pub signature: String,
}

pub fn credential_signing_bytes(credential: &MemberCredential) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "version": credential.version,
        "network_id": credential.network_id,
        "member_id": credential.member_id,
        "member_public_key": credential.member_public_key,
        "permissions": credential.permissions,
        "max_connections": credential.max_connections,
        "serial": credential.serial,
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
    }))?)
}

pub fn hello_signing_bytes(
    challenge: &ChallengePayload,
    credential: &MemberCredential,
    timestamp: i64,
) -> Result<Vec<u8>> {
    let credential_bytes = serde_json::to_vec(credential)?;
    let credential_hash = sha256_id("credential", &credential_bytes);
    Ok(format!(
        "mrk-relay-hello-v1:{}:{}:{}:{timestamp}",
        challenge.challenge, challenge.relay_public_key, credential_hash
    )
    .into_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    Challenge = 1,
    Hello = 2,
    Welcome = 3,
    Open = 4,
    Incoming = 5,
    Accept = 6,
    Reject = 7,
    Data = 8,
    Close = 9,
    Ping = 10,
    Pong = 11,
    Error = 12,
    SenderCheckpoint = 13,
    ReceiverReceipt = 14,
    CheckpointRequest = 15,
    CloseIntent = 16,
    Drain = 17,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Challenge),
            2 => Ok(Self::Hello),
            3 => Ok(Self::Welcome),
            4 => Ok(Self::Open),
            5 => Ok(Self::Incoming),
            6 => Ok(Self::Accept),
            7 => Ok(Self::Reject),
            8 => Ok(Self::Data),
            9 => Ok(Self::Close),
            10 => Ok(Self::Ping),
            11 => Ok(Self::Pong),
            12 => Ok(Self::Error),
            13 => Ok(Self::SenderCheckpoint),
            14 => Ok(Self::ReceiverReceipt),
            15 => Ok(Self::CheckpointRequest),
            16 => Ok(Self::CloseIntent),
            17 => Ok(Self::Drain),
            _ => Err(Error::msg(format!("unknown relay frame type {value}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayFrame {
    pub frame_type: FrameType,
    pub flags: u16,
    pub channel_id: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl RelayFrame {
    pub fn control(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            flags: 0,
            channel_id: 0,
            sequence: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(Error::msg("relay frame payload exceeds 1 MiB"));
        }
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| Error::msg("relay frame payload length overflow"))?;
        let mut output = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        output.push(FRAME_VERSION);
        output.push(self.frame_type as u8);
        output.extend_from_slice(&self.flags.to_be_bytes());
        output.extend_from_slice(&self.channel_id.to_be_bytes());
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(Error::msg("relay frame is shorter than its header"));
        }
        if bytes[0] != FRAME_VERSION {
            return Err(Error::msg(format!(
                "unsupported relay frame version {}",
                bytes[0]
            )));
        }
        let payload_len = u32::from_be_bytes(bytes[16..20].try_into().expect("frame header"));
        let payload_len = payload_len as usize;
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(Error::msg("relay frame payload exceeds 1 MiB"));
        }
        if bytes.len() != FRAME_HEADER_LEN + payload_len {
            return Err(Error::msg(
                "relay frame payload length does not match header",
            ));
        }
        Ok(Self {
            frame_type: FrameType::try_from(bytes[1])?,
            flags: u16::from_be_bytes(bytes[2..4].try_into().expect("frame header")),
            channel_id: u32::from_be_bytes(bytes[4..8].try_into().expect("frame header")),
            sequence: u64::from_be_bytes(bytes[8..16].try_into().expect("frame header")),
            payload: bytes[FRAME_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WsMessage {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Vec<u8>),
}

pub fn websocket_accept_key(client_key: &str) -> Result<String> {
    let decoded = STANDARD
        .decode(client_key.trim())
        .map_err(|_| Error::msg("invalid Sec-WebSocket-Key"))?;
    if decoded.len() != 16 {
        return Err(Error::msg("Sec-WebSocket-Key must decode to 16 bytes"));
    }
    let input = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key.trim());
    Ok(STANDARD.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes()).as_ref()))
}

pub fn websocket_server_response(request: &str) -> Result<String> {
    websocket_server_response_for_protocol(request, "/v1/relay", RELAY_PROTOCOL)
}

pub fn websocket_server_response_for_protocol(
    request: &str,
    endpoint: &str,
    subprotocol: &str,
) -> Result<String> {
    let mut lines = request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Error::msg("missing WebSocket request line"))?;
    let mut request_parts = request_line.split_whitespace();
    if request_parts.next() != Some("GET") || request_parts.next() != Some(endpoint) {
        return Err(Error::msg(format!(
            "WebSocket endpoint must be GET {endpoint}"
        )));
    }
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut version_13 = false;
    let mut protocol = false;
    let mut key = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgrade = value.trim().eq_ignore_ascii_case("websocket"),
            "connection" => {
                connection_upgrade = value
                    .split(',')
                    .any(|item| item.trim().eq_ignore_ascii_case("upgrade"));
            }
            "sec-websocket-version" => version_13 = value.trim() == "13",
            "sec-websocket-protocol" => {
                protocol = value.split(',').any(|item| item.trim() == subprotocol);
            }
            "sec-websocket-key" => key = Some(value.trim()),
            _ => {}
        }
    }
    if !upgrade || !connection_upgrade || !version_13 || !protocol {
        return Err(Error::msg(
            "invalid WebSocket upgrade or missing required subprotocol",
        ));
    }
    let accept =
        websocket_accept_key(key.ok_or_else(|| Error::msg("missing Sec-WebSocket-Key header"))?)?;
    Ok(format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {subprotocol}\r\n\r\n"
    ))
}

pub fn read_ws_message(reader: &mut impl Read, require_mask: bool) -> Result<WsMessage> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    if header[0] & 0x70 != 0 || header[0] & 0x80 == 0 {
        return Err(Error::msg(
            "fragmented WebSocket messages and RSV extensions are unsupported",
        ));
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if require_mask && !masked {
        return Err(Error::msg("client WebSocket messages must be masked"));
    }
    let mut payload_len = u64::from(header[1] & 0x7f);
    if payload_len == 126 {
        let mut extended = [0_u8; 2];
        reader.read_exact(&mut extended)?;
        payload_len = u64::from(u16::from_be_bytes(extended));
    } else if payload_len == 127 {
        let mut extended = [0_u8; 8];
        reader.read_exact(&mut extended)?;
        payload_len = u64::from_be_bytes(extended);
    }
    let max_message = (FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD) as u64;
    if payload_len > max_message {
        return Err(Error::msg("WebSocket message exceeds relay limit"));
    }
    if opcode >= 8 && payload_len > 125 {
        return Err(Error::msg("WebSocket control frame exceeds 125 bytes"));
    }
    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask)?;
    }
    let mut payload = vec![0_u8; payload_len as usize];
    reader.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    match opcode {
        2 => Ok(WsMessage::Binary(payload)),
        8 => Ok(WsMessage::Close(payload)),
        9 => Ok(WsMessage::Ping(payload)),
        10 => Ok(WsMessage::Pong(payload)),
        1 => Err(Error::msg("text WebSocket messages are not supported")),
        _ => Err(Error::msg(format!("unsupported WebSocket opcode {opcode}"))),
    }
}

pub fn write_ws_message(
    writer: &mut impl Write,
    message: &WsMessage,
    mask_payload: bool,
) -> Result<()> {
    let (opcode, payload) = match message {
        WsMessage::Binary(payload) => (2_u8, payload),
        WsMessage::Close(payload) => (8, payload),
        WsMessage::Ping(payload) => (9, payload),
        WsMessage::Pong(payload) => (10, payload),
    };
    if payload.len() > FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD {
        return Err(Error::msg("WebSocket message exceeds relay limit"));
    }
    if opcode >= 8 && payload.len() > 125 {
        return Err(Error::msg("WebSocket control frame exceeds 125 bytes"));
    }
    let mut header = Vec::with_capacity(14);
    header.push(0x80 | opcode);
    let mask_bit = if mask_payload { 0x80 } else { 0 };
    match payload.len() {
        0..=125 => header.push(mask_bit | payload.len() as u8),
        126..=65_535 => {
            header.push(mask_bit | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(mask_bit | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    writer.write_all(&header)?;
    if mask_payload {
        let mask = random_bytes::<4>()?;
        writer.write_all(&mask)?;
        let mut masked = payload.clone();
        for (index, byte) in masked.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        writer.write_all(&masked)?;
    } else {
        writer.write_all(payload)?;
    }
    writer.flush()?;
    Ok(())
}

pub async fn read_ws_message_async(
    reader: &mut (impl AsyncRead + Unpin),
    require_mask: bool,
) -> Result<WsMessage> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] & 0x70 != 0 || header[0] & 0x80 == 0 {
        return Err(Error::msg(
            "fragmented WebSocket messages and RSV extensions are unsupported",
        ));
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    if require_mask && !masked {
        return Err(Error::msg("client WebSocket messages must be masked"));
    }
    let mut payload_len = u64::from(header[1] & 0x7f);
    if payload_len == 126 {
        let mut extended = [0_u8; 2];
        reader.read_exact(&mut extended).await?;
        payload_len = u64::from(u16::from_be_bytes(extended));
    } else if payload_len == 127 {
        let mut extended = [0_u8; 8];
        reader.read_exact(&mut extended).await?;
        payload_len = u64::from_be_bytes(extended);
    }
    let max_message = (FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD) as u64;
    if payload_len > max_message {
        return Err(Error::msg("WebSocket message exceeds relay limit"));
    }
    if opcode >= 8 && payload_len > 125 {
        return Err(Error::msg("WebSocket control frame exceeds 125 bytes"));
    }
    let mut mask = [0_u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; payload_len as usize];
    reader.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    match opcode {
        2 => Ok(WsMessage::Binary(payload)),
        8 => Ok(WsMessage::Close(payload)),
        9 => Ok(WsMessage::Ping(payload)),
        10 => Ok(WsMessage::Pong(payload)),
        1 => Err(Error::msg("text WebSocket messages are not supported")),
        _ => Err(Error::msg(format!("unsupported WebSocket opcode {opcode}"))),
    }
}

pub async fn write_ws_message_async(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &WsMessage,
    mask_payload: bool,
) -> Result<()> {
    let (opcode, payload) = match message {
        WsMessage::Binary(payload) => (2_u8, payload),
        WsMessage::Close(payload) => (8, payload),
        WsMessage::Ping(payload) => (9, payload),
        WsMessage::Pong(payload) => (10, payload),
    };
    if payload.len() > FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD {
        return Err(Error::msg("WebSocket message exceeds relay limit"));
    }
    if opcode >= 8 && payload.len() > 125 {
        return Err(Error::msg("WebSocket control frame exceeds 125 bytes"));
    }
    let mut header = Vec::with_capacity(14);
    header.push(0x80 | opcode);
    let mask_bit = if mask_payload { 0x80 } else { 0 };
    match payload.len() {
        0..=125 => header.push(mask_bit | payload.len() as u8),
        126..=65_535 => {
            header.push(mask_bit | 126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(mask_bit | 127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    writer.write_all(&header).await?;
    if mask_payload {
        let mask = random_bytes::<4>()?;
        writer.write_all(&mask).await?;
        let mut masked = payload.clone();
        for (index, byte) in masked.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        writer.write_all(&masked).await?;
    } else {
        writer.write_all(payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn relay_frame_round_trip() {
        let frame = RelayFrame {
            frame_type: FrameType::Data,
            flags: 3,
            channel_id: 42,
            sequence: 9,
            payload: b"opaque bytes".to_vec(),
        };
        assert_eq!(RelayFrame::decode(&frame.encode().unwrap()).unwrap(), frame);
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn masked_websocket_binary_round_trip() {
        let message = WsMessage::Binary(b"hello".to_vec());
        let mut bytes = Vec::new();
        write_ws_message(&mut bytes, &message, true).unwrap();
        assert_eq!(
            read_ws_message(&mut Cursor::new(bytes), true).unwrap(),
            message
        );
    }

    #[test]
    fn rejects_oversized_frames_and_unmasked_clients() {
        let oversized = RelayFrame::control(
            FrameType::Data,
            vec![0_u8; MAX_FRAME_PAYLOAD.saturating_add(1)],
        );
        assert!(oversized.encode().is_err());

        let mut bytes = Vec::new();
        write_ws_message(&mut bytes, &WsMessage::Binary(b"unmasked".to_vec()), false).unwrap();
        assert!(read_ws_message(&mut Cursor::new(bytes), true).is_err());
    }
}
