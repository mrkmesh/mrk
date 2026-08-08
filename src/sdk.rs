//! Async client SDK for authenticated, paid, end-to-end encrypted Relay streams.

use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    hkdf::{self, HKDF_SHA256},
    rand::SystemRandom,
    signature::Ed25519KeyPair,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
        WriteHalf, split,
    },
    sync::{Mutex, mpsc, oneshot, watch},
};

use crate::{
    Error,
    crypto::{
        EncryptedKeyFile, address_from_public_key, decrypt_key, hex_lower, random_bytes,
        sha256_full_id, verify_bytes,
    },
    model::{
        DEFAULT_OPERATION_VALIDITY_SECONDS, MemberCredential, NetworkRecord, OperationStatus,
        PROTOCOL_VERSION, RelayDirection, SignedOperation, UnsignedOperation,
    },
    relay::{
        ChallengePayload, FrameType, HelloPayload, IncomingPayload, OpenPayload,
        RELAY_CHECKPOINT_FINAL_FLAG, RELAY_PAYMENT_WINDOW_BYTES, RELAY_PAYMENT_WINDOW_SECONDS,
        ReceiverReceipt, RelayFrame, SenderCheckpoint, WelcomePayload, WsMessage,
        credential_signing_bytes, hello_signing_bytes, read_ws_message_async,
        receiver_receipt_signing_bytes, relay_transcript_initial_hash, relay_transcript_next_hash,
        sender_checkpoint_hash, sender_checkpoint_signing_bytes, write_ws_message_async,
    },
    relay_client::{BoxedIo, connect_websocket, rpc_call},
    service::{self, RelayAuthorizationView},
    storage::DataPaths,
};

const PIPE_E2E_PROTOCOL: &str = "mrk.pipe.e2e.v1";
const KEY_OFFER: u8 = 1;
const KEY_RESPONSE: u8 = 2;
const ENCRYPTED_RECORD: u8 = 3;
const RECORD_DATA: u8 = 1;
const RECORD_FIN: u8 = 2;
const RECORD_CONFIRM: u8 = 3;
const RECORD_READY: u8 = 4;
const SESSION_KEY_BYTES: usize = 64;
const AEAD_OVERHEAD: usize = 1 + 1 + 16;
const DEFAULT_STREAM_BUFFER: usize = 256 * 1024;
const DEFAULT_CHANNEL_QUEUE: usize = 32;
const DEFAULT_INCOMING_QUEUE: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum RelayError {
    InvalidConfig(String),
    Transport(String),
    Authentication(String),
    Authorization(String),
    PeerOffline,
    PeerRejected,
    HandshakeTimeout,
    Protocol(String),
    Crypto(String),
    ConnectionClosed,
}

impl Display for RelayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid SDK configuration: {message}")
            }
            Self::Transport(message) => write!(formatter, "Relay transport failed: {message}"),
            Self::Authentication(message) => {
                write!(formatter, "Relay authentication failed: {message}")
            }
            Self::Authorization(message) => {
                write!(formatter, "Relay authorization failed: {message}")
            }
            Self::PeerOffline => formatter.write_str("target member is not online"),
            Self::PeerRejected => formatter.write_str("peer rejected Relay stream"),
            Self::HandshakeTimeout => formatter.write_str("encrypted stream handshake timed out"),
            Self::Protocol(message) => write!(formatter, "Relay protocol failed: {message}"),
            Self::Crypto(message) => write!(formatter, "stream cryptography failed: {message}"),
            Self::ConnectionClosed => formatter.write_str("Relay connection is closed"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<Error> for RelayError {
    fn from(error: Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

pub trait MemberSigner: Send + Sync {
    fn public_key(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<String, RelayError>;
}

pub struct KeystoreSigner {
    public_key: String,
    key_pair: Ed25519KeyPair,
}

impl KeystoreSigner {
    pub fn unlock(keyfile: &EncryptedKeyFile, password: &str) -> Result<Self, RelayError> {
        Ok(Self {
            public_key: keyfile.public_key.clone(),
            key_pair: decrypt_key(keyfile, password)
                .map_err(|error| RelayError::Authentication(error.to_string()))?,
        })
    }
}

impl MemberSigner for KeystoreSigner {
    fn public_key(&self) -> &str {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<String, RelayError> {
        Ok(STANDARD.encode(self.key_pair.sign(message).as_ref()))
    }
}

#[derive(Clone)]
pub struct MemberIdentity {
    credential: MemberCredential,
    network_owner_public_key: String,
    signer: Arc<dyn MemberSigner>,
    network: Option<NetworkRecord>,
}

impl MemberIdentity {
    pub fn new(
        credential: MemberCredential,
        network_owner_public_key: String,
        signer: Arc<dyn MemberSigner>,
    ) -> Result<Self, RelayError> {
        if credential.member_public_key != signer.public_key() {
            return Err(RelayError::InvalidConfig(
                "member signer does not match the credential".to_owned(),
            ));
        }
        verify_bytes(
            &network_owner_public_key,
            &credential_signing_bytes(&credential)?,
            &credential.owner_signature,
        )
        .map_err(|error| RelayError::Authentication(error.to_string()))?;
        Ok(Self {
            credential,
            network_owner_public_key,
            signer,
            network: None,
        })
    }

    pub fn from_data_paths(
        paths: &DataPaths,
        network: &str,
        member: &str,
        password: &str,
    ) -> Result<Self, RelayError> {
        let network_record = service::network_by_alias(paths, network)
            .map_err(|error| RelayError::InvalidConfig(error.to_string()))?;
        Self::from_data_paths_with_network_record(paths, network, member, password, &network_record)
    }

    pub async fn from_relay(
        paths: &DataPaths,
        network: &str,
        member: &str,
        password: &str,
        endpoint: &str,
        allow_insecure_local: bool,
        tls_ca: Option<&Path>,
    ) -> Result<Self, RelayError> {
        let mut rpc_endpoint =
            crate::endpoint::normalize_websocket_url(endpoint, crate::endpoint::RELAY_PATH)
                .map_err(|error| RelayError::InvalidConfig(error.to_string()))?;
        rpc_endpoint.set_path(crate::endpoint::RPC_PATH);
        rpc_endpoint.set_query(None);
        rpc_endpoint.set_fragment(None);
        let value = rpc_call(
            rpc_endpoint.as_str(),
            "network.get",
            serde_json::json!({ "alias": network }),
            allow_insecure_local,
            tls_ca,
        )
        .await
        .map_err(|error| {
            RelayError::InvalidConfig(format!(
                "could not load Network '{network}' from Relay RPC: {error}"
            ))
        })?;
        let network_record: NetworkRecord = serde_json::from_value(value).map_err(|error| {
            RelayError::InvalidConfig(format!(
                "Relay RPC returned an invalid Network '{network}': {error}"
            ))
        })?;
        Self::from_data_paths_with_network_record(paths, network, member, password, &network_record)
    }

    pub fn from_data_paths_with_network_record(
        paths: &DataPaths,
        network: &str,
        member: &str,
        password: &str,
        network_record: &NetworkRecord,
    ) -> Result<Self, RelayError> {
        let credential = service::member_credential(paths, network, member)
            .map_err(|error| RelayError::InvalidConfig(error.to_string()))?;
        if network_record.alias != network || network_record.network_id != credential.network_id {
            return Err(RelayError::InvalidConfig(format!(
                "Network '{network}' does not match the local member credential"
            )));
        }
        let keyfile = paths
            .read_keyfile(
                &paths
                    .member_key_path(network, member)
                    .map_err(|error| RelayError::InvalidConfig(error.to_string()))?,
            )
            .map_err(|error| RelayError::InvalidConfig(error.to_string()))?;
        let signer = Arc::new(KeystoreSigner::unlock(&keyfile, password)?);
        let mut identity = Self::new(credential, network_record.owner_public_key.clone(), signer)?;
        identity.network = Some(network_record.clone());
        Ok(identity)
    }

    pub fn credential(&self) -> &MemberCredential {
        &self.credential
    }

    pub fn network_owner_public_key(&self) -> &str {
        &self.network_owner_public_key
    }

    fn sign(&self, message: &[u8]) -> Result<String, RelayError> {
        self.signer.sign(message)
    }

    fn signer_address(&self) -> Result<String, RelayError> {
        let public_key = STANDARD.decode(self.signer.public_key()).map_err(|_| {
            RelayError::InvalidConfig("member public key is not valid base64".to_owned())
        })?;
        Ok(address_from_public_key(&public_key))
    }
}

#[derive(Clone)]
pub struct ClientOptions {
    pub endpoint: String,
    pub identity: MemberIdentity,
    pub allow_insecure_local: bool,
    pub tls_ca: Option<PathBuf>,
    pub stream_buffer_bytes: usize,
}

impl ClientOptions {
    pub fn new(endpoint: impl Into<String>, identity: MemberIdentity) -> Self {
        Self {
            endpoint: endpoint.into(),
            identity,
            allow_insecure_local: false,
            tls_ca: None,
            stream_buffer_bytes: DEFAULT_STREAM_BUFFER,
        }
    }

    pub fn allow_insecure_local(mut self, allow: bool) -> Self {
        self.allow_insecure_local = allow;
        self
    }

    pub fn tls_ca(mut self, path: impl Into<PathBuf>) -> Self {
        self.tls_ca = Some(path.into());
        self
    }

    pub fn stream_buffer_bytes(mut self, bytes: usize) -> Self {
        self.stream_buffer_bytes = bytes;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connected,
    Closed,
}

pub struct RelayClient;

impl RelayClient {
    pub async fn connect(options: ClientOptions) -> Result<RelayConnection, RelayError> {
        if options.stream_buffer_bytes == 0 {
            return Err(RelayError::InvalidConfig(
                "stream buffer must be greater than zero".to_owned(),
            ));
        }
        validate_local_identity(&options.identity)?;
        let mut socket = connect_websocket(
            &options.endpoint,
            options.allow_insecure_local,
            options.tls_ca.as_deref(),
        )
        .await
        .map_err(|error| RelayError::Transport(error.to_string()))?;
        let challenge_frame = read_socket_frame(&mut socket).await?;
        if challenge_frame.frame_type != FrameType::Challenge {
            return Err(RelayError::Protocol(
                "Relay did not send CHALLENGE first".to_owned(),
            ));
        }
        let challenge: ChallengePayload = serde_json::from_slice(&challenge_frame.payload)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        if (Utc::now().timestamp() - challenge.timestamp).abs() > 30 {
            return Err(RelayError::Authentication(
                "Relay challenge timestamp is outside the 30 second window".to_owned(),
            ));
        }
        let timestamp = Utc::now().timestamp();
        let hello = HelloPayload {
            credential: options.identity.credential.clone(),
            timestamp,
            proof: options.identity.sign(&hello_signing_bytes(
                &challenge,
                &options.identity.credential,
                timestamp,
            )?)?,
        };
        write_socket_frame(
            &mut socket,
            RelayFrame::control(
                FrameType::Hello,
                serde_json::to_vec(&hello)
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
            ),
        )
        .await?;
        let welcome_frame = read_socket_frame(&mut socket).await?;
        if welcome_frame.frame_type == FrameType::Error {
            return Err(frame_error(&welcome_frame.payload));
        }
        if welcome_frame.frame_type != FrameType::Welcome {
            return Err(RelayError::Protocol(
                "Relay did not send WELCOME after HELLO".to_owned(),
            ));
        }
        let welcome: WelcomePayload = serde_json::from_slice(&welcome_frame.payload)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        if welcome.max_message_size as usize <= AEAD_OVERHEAD {
            return Err(RelayError::Protocol(
                "Relay frame limit is too small for encrypted streams".to_owned(),
            ));
        }
        let (reader, writer) = split(socket);
        let (commands, command_receiver) = mpsc::channel(128);
        let (incoming_sender, incoming) = mpsc::channel(DEFAULT_INCOMING_QUEUE);
        let (state_sender, state) = watch::channel(ConnectionState::Connected);
        let inner = Arc::new(ConnectionInner {
            options: options.clone(),
            commands,
            incoming: Mutex::new(incoming),
            open_lock: Mutex::new(()),
            node_id: challenge.node_id,
            max_payload: welcome.max_message_size as usize,
            state,
        });
        tokio::spawn(async move {
            run_connection_driver(
                reader,
                writer,
                command_receiver,
                incoming_sender,
                welcome.heartbeat_seconds,
            )
            .await;
            let _ = state_sender.send(ConnectionState::Closed);
        });
        Ok(RelayConnection { inner })
    }
}

#[derive(Clone)]
pub struct RelayConnection {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    options: ClientOptions,
    commands: mpsc::Sender<DriverCommand>,
    incoming: Mutex<mpsc::Receiver<IncomingEvent>>,
    open_lock: Mutex<()>,
    node_id: u64,
    max_payload: usize,
    state: watch::Receiver<ConnectionState>,
}

impl RelayConnection {
    /// Atomically reserves Network Fund under the current Owner policy, waits for
    /// finality, and opens an encrypted Relay stream to `peer_id`.
    pub async fn open_auto(
        &self,
        peer_id: impl Into<String>,
    ) -> Result<EncryptedStream, RelayError> {
        let peer_id = peer_id.into();
        let _guard = self.inner.open_lock.lock().await;
        let authorization_id = self.reserve_member_session(&peer_id).await?;
        let view = self
            .resolve_authorization(&authorization_id, true, &peer_id)
            .await?;
        let (response, receiver) = oneshot::channel();
        self.inner
            .commands
            .send(DriverCommand::Open {
                peer_id,
                authorization_id,
                commands: self.inner.commands.clone(),
                response,
            })
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;
        let transport = receiver.await.map_err(|_| RelayError::ConnectionClosed)??;
        build_encrypted_stream(self.inner.clone(), transport, view, true).await
    }

    pub async fn accept(&self) -> Result<IncomingStream, RelayError> {
        let event = self
            .inner
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or(RelayError::ConnectionClosed)?;
        Ok(IncomingStream {
            connection: self.clone(),
            event: Some(event),
        })
    }

    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.inner.state.clone()
    }

    pub async fn close(&self) -> Result<(), RelayError> {
        self.inner
            .commands
            .send(DriverCommand::Shutdown)
            .await
            .map_err(|_| RelayError::ConnectionClosed)
    }

    async fn resolve_authorization(
        &self,
        authorization_id: &str,
        initiator: bool,
        peer_id: &str,
    ) -> Result<RelayAuthorizationView, RelayError> {
        let endpoint = self.rpc_endpoint()?;
        let value = rpc_call(
            endpoint.as_str(),
            "payment.get",
            serde_json::json!({"authorization_id": authorization_id}),
            self.inner.options.allow_insecure_local,
            self.inner.options.tls_ca.as_deref(),
        )
        .await
        .map_err(|error| RelayError::Authorization(error.to_string()))?;
        let view: RelayAuthorizationView = serde_json::from_value(value)
            .map_err(|error| RelayError::Authorization(error.to_string()))?;
        validate_authorization(
            &view,
            &self.inner.options.identity,
            self.inner.node_id,
            authorization_id,
            peer_id,
            initiator,
        )?;
        Ok(view)
    }

    fn rpc_endpoint(&self) -> Result<url::Url, RelayError> {
        let mut endpoint = crate::endpoint::normalize_websocket_url(
            &self.inner.options.endpoint,
            crate::endpoint::RELAY_PATH,
        )
        .map_err(|error| RelayError::InvalidConfig(error.to_string()))?;
        endpoint.set_path(crate::endpoint::RPC_PATH);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }

    async fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RelayError> {
        let endpoint = self.rpc_endpoint()?;
        rpc_call(
            endpoint.as_str(),
            method,
            params,
            self.inner.options.allow_insecure_local,
            self.inner.options.tls_ca.as_deref(),
        )
        .await
        .map_err(|error| RelayError::Authorization(error.to_string()))
    }

    async fn reserve_member_session(&self, peer_id: &str) -> Result<String, RelayError> {
        let configured_network = self
            .inner
            .options
            .identity
            .network
            .as_ref()
            .ok_or_else(|| {
                RelayError::InvalidConfig(
                    "automatic payment requires a MemberIdentity loaded with its Network record"
                        .to_owned(),
                )
            })?;
        let network: NetworkRecord = serde_json::from_value(
            self.rpc(
                "network.get",
                serde_json::json!({"alias": configured_network.alias}),
            )
            .await?,
        )
        .map_err(|error| RelayError::Authorization(error.to_string()))?;
        if network.network_id != self.inner.options.identity.credential.network_id {
            return Err(RelayError::Authorization(
                "Network record does not match the member credential".to_owned(),
            ));
        }
        if !network.spending_policy.enabled {
            return Err(RelayError::Authorization(
                "member spending is disabled for this Network".to_owned(),
            ));
        }
        let peer = network
            .members
            .values()
            .find(|member| member.member_id == peer_id)
            .ok_or_else(|| {
                RelayError::Authorization("target member is not in this Network".to_owned())
            })?;
        let now = Utc::now().timestamp();
        let valid_until = now
            .saturating_add(i64::from(network.spending_policy.max_session_minutes) * 60)
            .min(self.inner.options.identity.credential.expires_at)
            .min(peer.expires_at);
        if valid_until <= now {
            return Err(RelayError::Authorization(
                "a Relay member credential has expired".to_owned(),
            ));
        }
        let signer_address = self.inner.options.identity.signer_address()?;
        let balance = self
            .rpc(
                "account.balance",
                serde_json::json!({"address": signer_address}),
            )
            .await?;
        let nonce = balance
            .get("nonce")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| RelayError::Authorization("invalid account nonce".to_owned()))?
            .saturating_add(1);
        let chain = self.rpc("system.ping", serde_json::json!({})).await?;
        let ledger_id = chain
            .get("ledger_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RelayError::Authorization("invalid ledger identity".to_owned()))?;
        let session_id = hex_lower(
            &random_bytes::<32>().map_err(|error| RelayError::Crypto(error.to_string()))?,
        );
        let unsigned = UnsignedOperation {
            ledger_id: ledger_id.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            module: "TrafficPayment".to_owned(),
            action: "ReserveSession".to_owned(),
            signer: signer_address,
            account_nonce: nonce,
            valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({
                "network": network.alias,
                "node_id": self.inner.node_id,
                "sender_member_id": self.inner.options.identity.credential.member_id,
                "receiver_member_id": peer_id,
                "session_id": session_id,
                "max_amount_base_units": network.spending_policy.max_session_amount.to_string(),
                "authorization_valid_until": valid_until,
                "spending_policy_revision": network.spending_policy.revision,
            }),
        };
        let operation = SignedOperation {
            signature: self.inner.options.identity.sign(
                &serde_json::to_vec(&unsigned)
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
            )?,
            unsigned,
        };
        let submission = self
            .rpc(
                "operation.submit",
                serde_json::json!({
                    "public_key": self.inner.options.identity.signer.public_key(),
                    "operation": operation,
                }),
            )
            .await?;
        let authorization_id = submission
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RelayError::Authorization("payment reservation ID is missing".to_owned())
            })?
            .to_owned();
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let status: service::PaymentAuthorizationStatusView = serde_json::from_value(
                self.rpc(
                    "payment.status",
                    serde_json::json!({"identifier": authorization_id}),
                )
                .await?,
            )
            .map_err(|error| RelayError::Authorization(error.to_string()))?;
            match status.status {
                OperationStatus::Finalized if status.authorization.is_some() => {
                    return Ok(authorization_id);
                }
                OperationStatus::Rejected | OperationStatus::Expired => {
                    return Err(RelayError::Authorization(
                        "automatic payment reservation was not finalized".to_owned(),
                    ));
                }
                OperationStatus::Pending | OperationStatus::Finalized => {}
            }
            if Instant::now() >= deadline {
                return Err(RelayError::Authorization(
                    "timed out waiting for automatic payment finality".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

pub struct IncomingStream {
    connection: RelayConnection,
    event: Option<IncomingEvent>,
}

impl IncomingStream {
    pub fn peer_id(&self) -> &str {
        &self
            .event
            .as_ref()
            .expect("pending incoming stream")
            .peer_id
    }

    pub fn authorization_id(&self) -> &str {
        &self
            .event
            .as_ref()
            .expect("pending incoming stream")
            .authorization_id
    }

    pub async fn accept(mut self) -> Result<EncryptedStream, RelayError> {
        let event = self.event.as_ref().expect("pending incoming stream");
        let view = self
            .connection
            .resolve_authorization(&event.authorization_id, false, &event.peer_id)
            .await?;
        let event = self.event.take().expect("pending incoming stream");
        let (response, receiver) = oneshot::channel();
        self.connection
            .inner
            .commands
            .send(DriverCommand::Accept {
                channel_id: event.channel_id,
                commands: self.connection.inner.commands.clone(),
                response,
            })
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;
        let transport = receiver.await.map_err(|_| RelayError::ConnectionClosed)??;
        build_encrypted_stream(self.connection.inner.clone(), transport, view, false).await
    }

    pub async fn reject(mut self) -> Result<(), RelayError> {
        let event = self.event.take().expect("pending incoming stream");
        self.connection
            .inner
            .commands
            .send(DriverCommand::Reject {
                channel_id: event.channel_id,
            })
            .await
            .map_err(|_| RelayError::ConnectionClosed)
    }
}

impl Drop for IncomingStream {
    fn drop(&mut self) {
        if let Some(event) = self.event.take() {
            let _ = self
                .connection
                .inner
                .commands
                .try_send(DriverCommand::Reject {
                    channel_id: event.channel_id,
                });
        }
    }
}

struct IncomingEvent {
    channel_id: u32,
    peer_id: String,
    authorization_id: String,
}

enum DriverCommand {
    Open {
        peer_id: String,
        authorization_id: String,
        commands: mpsc::Sender<DriverCommand>,
        response: oneshot::Sender<Result<ChannelTransport, RelayError>>,
    },
    Accept {
        channel_id: u32,
        commands: mpsc::Sender<DriverCommand>,
        response: oneshot::Sender<Result<ChannelTransport, RelayError>>,
    },
    Reject {
        channel_id: u32,
    },
    Write {
        frame: RelayFrame,
        response: oneshot::Sender<Result<(), RelayError>>,
    },
    Remove {
        channel_id: u32,
    },
    Shutdown,
}

struct ChannelTransport {
    channel_id: u32,
    commands: mpsc::Sender<DriverCommand>,
    incoming: mpsc::Receiver<RelayFrame>,
}

impl ChannelTransport {
    async fn send(&self, frame: RelayFrame) -> Result<(), RelayError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(DriverCommand::Write { frame, response })
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;
        receiver.await.map_err(|_| RelayError::ConnectionClosed)?
    }

    async fn receive(&mut self) -> Result<RelayFrame, RelayError> {
        self.incoming
            .recv()
            .await
            .ok_or(RelayError::ConnectionClosed)
    }
}

impl Drop for ChannelTransport {
    fn drop(&mut self) {
        let _ = self.commands.try_send(DriverCommand::Remove {
            channel_id: self.channel_id,
        });
    }
}

async fn run_connection_driver(
    mut reader: ReadHalf<BoxedIo>,
    mut writer: WriteHalf<BoxedIo>,
    mut commands: mpsc::Receiver<DriverCommand>,
    incoming_sender: mpsc::Sender<IncomingEvent>,
    heartbeat_seconds: u32,
) {
    let mut routes = HashMap::<u32, mpsc::Sender<RelayFrame>>::new();
    let mut pending_incoming = HashMap::<u32, IncomingPayload>::new();
    let mut pending_open = None;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(u64::from(heartbeat_seconds)));
    heartbeat.tick().await;
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    DriverCommand::Open { peer_id, authorization_id, commands, response } => {
                        if pending_open.is_some() {
                            let _ = response.send(Err(RelayError::Protocol(
                                "another Relay OPEN is already pending".to_owned(),
                            )));
                            continue;
                        }
                        let frame = RelayFrame::control(
                            FrameType::Open,
                            match serde_json::to_vec(&OpenPayload {
                                peer_id,
                                authorization_id,
                                metadata: String::new(),
                            }) {
                                Ok(payload) => payload,
                                Err(error) => {
                                    let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                                    continue;
                                }
                            },
                        );
                        if let Err(error) = write_driver_frame(&mut writer, frame).await {
                            let _ = response.send(Err(error));
                            break;
                        }
                        pending_open = Some((commands, response));
                    }
                    DriverCommand::Accept { channel_id, commands, response } => {
                        if pending_incoming.remove(&channel_id).is_none() {
                            let _ = response.send(Err(RelayError::Protocol(
                                "incoming Relay stream is no longer pending".to_owned(),
                            )));
                            continue;
                        }
                        let (sender, incoming) = mpsc::channel(DEFAULT_CHANNEL_QUEUE);
                        routes.insert(channel_id, sender);
                        let frame = RelayFrame {
                            frame_type: FrameType::Accept,
                            flags: 0,
                            channel_id,
                            sequence: 0,
                            payload: Vec::new(),
                        };
                        if let Err(error) = write_driver_frame(&mut writer, frame).await {
                            routes.remove(&channel_id);
                            let _ = response.send(Err(error));
                            break;
                        }
                        let _ = response.send(Ok(ChannelTransport {
                            channel_id,
                            commands,
                            incoming,
                        }));
                    }
                    DriverCommand::Reject { channel_id } => {
                        if pending_incoming.remove(&channel_id).is_some() {
                            let _ = write_driver_frame(&mut writer, RelayFrame {
                                frame_type: FrameType::Reject,
                                flags: 0,
                                channel_id,
                                sequence: 0,
                                payload: Vec::new(),
                            }).await;
                        }
                    }
                    DriverCommand::Write { frame, response } => {
                        let result = write_driver_frame(&mut writer, frame).await;
                        let failed = result.is_err();
                        let _ = response.send(result);
                        if failed { break; }
                    }
                    DriverCommand::Remove { channel_id } => {
                        routes.remove(&channel_id);
                    }
                    DriverCommand::Shutdown => {
                        let _ = write_ws_message_async(&mut writer, &WsMessage::Close(Vec::new()), true).await;
                        break;
                    }
                }
            }
            message = read_ws_message_async(&mut reader, false) => {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => {
                        sdk_debug(&format!("connection driver read failed: {error}"));
                        break;
                    }
                };
                match message {
                    WsMessage::Binary(bytes) => {
                        let frame = match RelayFrame::decode(&bytes) {
                            Ok(frame) => frame,
                            Err(error) => {
                                sdk_debug(&format!("connection driver frame decode failed: {error}"));
                                break;
                            }
                        };
                        match frame.frame_type {
                            FrameType::Accept => {
                                let Some((commands, response)) = pending_open.take() else { break };
                                let (sender, incoming) = mpsc::channel(DEFAULT_CHANNEL_QUEUE);
                                routes.insert(frame.channel_id, sender);
                                let _ = response.send(Ok(ChannelTransport {
                                    channel_id: frame.channel_id,
                                    commands,
                                    incoming,
                                }));
                            }
                            FrameType::Reject => {
                                if let Some((_, response)) = pending_open.take() {
                                    let _ = response.send(Err(RelayError::PeerRejected));
                                } else {
                                    break;
                                }
                            }
                            FrameType::Incoming => {
                                let payload: IncomingPayload = match serde_json::from_slice(&frame.payload) {
                                    Ok(payload) => payload,
                                    Err(_) => break,
                                };
                                pending_incoming.insert(frame.channel_id, payload.clone());
                                if incoming_sender.send(IncomingEvent {
                                    channel_id: frame.channel_id,
                                    peer_id: payload.peer_id,
                                    authorization_id: payload.authorization_id,
                                }).await.is_err() {
                                    break;
                                }
                            }
                            FrameType::Data
                            | FrameType::SenderCheckpoint
                            | FrameType::ReceiverReceipt
                            | FrameType::Close => {
                                let channel_id = frame.channel_id;
                                let Some(sender) = routes.get(&channel_id).cloned() else {
                                    sdk_debug("connection driver received a frame for an unknown channel");
                                    break;
                                };
                                let closed = matches!(frame.frame_type, FrameType::Close);
                                if sender.send(frame).await.is_err() || closed {
                                    routes.remove(&channel_id);
                                }
                            }
                            FrameType::Ping => {
                                if write_driver_frame(&mut writer, RelayFrame {
                                    frame_type: FrameType::Pong,
                                    ..frame
                                }).await.is_err() {
                                    break;
                                }
                            }
                            FrameType::Pong => {}
                            FrameType::Error => {
                                for sender in routes.values() {
                                    let _ = sender.send(frame.clone()).await;
                                }
                                if let Some((_, response)) = pending_open.take() {
                                    let _ = response.send(Err(frame_error(&frame.payload)));
                                }
                                break;
                            }
                            _ => {
                                sdk_debug("connection driver received an unexpected authenticated frame");
                                break;
                            },
                        }
                    }
                    WsMessage::Ping(payload) => {
                        if write_ws_message_async(&mut writer, &WsMessage::Pong(payload), true).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Pong(_) => {}
                    WsMessage::Close(_) => {
                        sdk_debug("Relay closed the WebSocket connection");
                        break;
                    },
                }
            }
            _ = heartbeat.tick() => {
                if write_driver_frame(
                    &mut writer,
                    RelayFrame::control(FrameType::Ping, Vec::new()),
                ).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn write_driver_frame(
    writer: &mut WriteHalf<BoxedIo>,
    frame: RelayFrame,
) -> Result<(), RelayError> {
    write_ws_message_async(writer, &WsMessage::Binary(frame.encode()?), true)
        .await
        .map_err(|error| RelayError::Transport(error.to_string()))
}

async fn read_socket_frame(socket: &mut BoxedIo) -> Result<RelayFrame, RelayError> {
    loop {
        match read_ws_message_async(socket, false)
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?
        {
            WsMessage::Binary(bytes) => return Ok(RelayFrame::decode(&bytes)?),
            WsMessage::Ping(payload) => {
                write_ws_message_async(socket, &WsMessage::Pong(payload), true)
                    .await
                    .map_err(|error| RelayError::Transport(error.to_string()))?;
            }
            WsMessage::Pong(_) => {}
            WsMessage::Close(_) => return Err(RelayError::ConnectionClosed),
        }
    }
}

async fn write_socket_frame(socket: &mut BoxedIo, frame: RelayFrame) -> Result<(), RelayError> {
    write_ws_message_async(socket, &WsMessage::Binary(frame.encode()?), true)
        .await
        .map_err(|error| RelayError::Transport(error.to_string()))
}

fn frame_error(payload: &[u8]) -> RelayError {
    let message = serde_json::from_slice::<crate::relay::ErrorPayload>(payload)
        .map(|error| error.message)
        .unwrap_or_else(|_| "Relay returned an invalid protocol error".to_owned());
    if message == "target member is not online" {
        RelayError::PeerOffline
    } else {
        RelayError::Protocol(message)
    }
}

fn validate_local_identity(identity: &MemberIdentity) -> Result<(), RelayError> {
    let now = Utc::now().timestamp();
    if identity.credential.version != PROTOCOL_VERSION
        || now < identity.credential.issued_at
        || now >= identity.credential.expires_at
    {
        return Err(RelayError::Authentication(
            "member credential is not currently valid".to_owned(),
        ));
    }
    for permission in ["connect", "send", "receive"] {
        if !identity
            .credential
            .permissions
            .iter()
            .any(|item| item == permission)
        {
            return Err(RelayError::Authentication(format!(
                "member credential is missing '{permission}' permission"
            )));
        }
    }
    Ok(())
}

fn validate_authorization(
    view: &RelayAuthorizationView,
    identity: &MemberIdentity,
    node_id: u64,
    authorization_id: &str,
    peer_id: &str,
    initiator: bool,
) -> Result<(), RelayError> {
    let authorization = &view.authorization;
    let (expected_local, expected_peer, expected_local_key) = if initiator {
        (
            authorization.sender_member_id.as_str(),
            authorization.receiver_member_id.as_str(),
            view.sender_public_key.as_str(),
        )
    } else {
        (
            authorization.receiver_member_id.as_str(),
            authorization.sender_member_id.as_str(),
            view.receiver_public_key.as_str(),
        )
    };
    if !view.finalized
        || authorization.authorization_id != authorization_id
        || authorization.node_id != node_id
        || authorization.network_id != identity.credential.network_id
        || identity.credential.member_id != expected_local
        || identity.credential.member_public_key != expected_local_key
        || peer_id != expected_peer
        || authorization.refunded_at.is_some()
        || authorization.reserved_remaining == 0
        || Utc::now().timestamp() >= authorization.valid_until
    {
        return Err(RelayError::Authorization(
            "payment authorization does not match this stream".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyOffer {
    protocol: String,
    channel_id: u32,
    authorization_id: String,
    session_id: String,
    sender_credential: MemberCredential,
    sender_ephemeral_key: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyResponse {
    protocol: String,
    channel_id: u32,
    authorization_id: String,
    session_id: String,
    sender_member_id: String,
    sender_ephemeral_key: String,
    offer_hash: String,
    receiver_credential: MemberCredential,
    receiver_ephemeral_key: String,
    signature: String,
}

struct SessionKeyMaterial;

impl hkdf::KeyType for SessionKeyMaterial {
    fn len(&self) -> usize {
        SESSION_KEY_BYTES
    }
}

struct StreamCipher {
    outgoing: LessSafeKey,
    incoming: LessSafeKey,
    context: Vec<u8>,
}

impl StreamCipher {
    fn derive(shared_secret: &[u8], context: Vec<u8>, initiator: bool) -> Result<Self, RelayError> {
        let salt = hkdf::Salt::new(HKDF_SHA256, &context);
        let prk = salt.extract(shared_secret);
        let info = [PIPE_E2E_PROTOCOL.as_bytes(), context.as_slice()];
        let okm = prk
            .expand(&info, SessionKeyMaterial)
            .map_err(|_| RelayError::Crypto("could not derive stream session keys".to_owned()))?;
        let mut keys = [0_u8; SESSION_KEY_BYTES];
        okm.fill(&mut keys)
            .map_err(|_| RelayError::Crypto("could not derive stream session keys".to_owned()))?;
        let sender_key = stream_aead_key(&keys[..32])?;
        let receiver_key = stream_aead_key(&keys[32..])?;
        let (outgoing, incoming) = if initiator {
            (sender_key, receiver_key)
        } else {
            (receiver_key, sender_key)
        };
        Ok(Self {
            outgoing,
            incoming,
            context,
        })
    }

    fn encrypt(
        &self,
        direction: RelayDirection,
        sequence: u64,
        record_type: u8,
        bytes: &[u8],
    ) -> Result<Vec<u8>, RelayError> {
        let mut plaintext = Vec::with_capacity(1 + bytes.len());
        plaintext.push(record_type);
        plaintext.extend_from_slice(bytes);
        self.outgoing
            .seal_in_place_append_tag(
                stream_nonce(sequence),
                Aad::from(stream_aad(&self.context, direction, sequence)?),
                &mut plaintext,
            )
            .map_err(|_| RelayError::Crypto("could not encrypt stream DATA".to_owned()))?;
        let mut payload = Vec::with_capacity(1 + plaintext.len());
        payload.push(ENCRYPTED_RECORD);
        payload.extend_from_slice(&plaintext);
        Ok(payload)
    }

    fn decrypt(
        &self,
        direction: RelayDirection,
        sequence: u64,
        payload: &[u8],
    ) -> Result<(u8, Vec<u8>), RelayError> {
        if payload.first() != Some(&ENCRYPTED_RECORD) {
            return Err(RelayError::Protocol(
                "peer sent an unencrypted stream record".to_owned(),
            ));
        }
        let mut ciphertext = payload[1..].to_vec();
        let plaintext = self
            .incoming
            .open_in_place(
                stream_nonce(sequence),
                Aad::from(stream_aad(&self.context, direction, sequence)?),
                &mut ciphertext,
            )
            .map_err(|_| RelayError::Crypto("stream DATA authentication failed".to_owned()))?;
        let (&record_type, bytes) = plaintext
            .split_first()
            .ok_or_else(|| RelayError::Protocol("encrypted stream record is empty".to_owned()))?;
        Ok((record_type, bytes.to_vec()))
    }
}

fn stream_aead_key(bytes: &[u8]) -> Result<LessSafeKey, RelayError> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, bytes)
            .map_err(|_| RelayError::Crypto("could not initialize AES-256-GCM".to_owned()))?,
    ))
}

fn stream_nonce(sequence: u64) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    Nonce::assume_unique_for_key(nonce)
}

fn stream_aad(
    context: &[u8],
    direction: RelayDirection,
    sequence: u64,
) -> Result<Vec<u8>, RelayError> {
    let mut aad = Vec::with_capacity(context.len() + 32);
    aad.extend_from_slice(context);
    aad.extend_from_slice(
        &serde_json::to_vec(&direction).map_err(|error| RelayError::Protocol(error.to_string()))?,
    );
    aad.extend_from_slice(&sequence.to_be_bytes());
    Ok(aad)
}

struct DirectionState {
    sequence: u64,
    cumulative_bytes: u64,
    transcript_hash: String,
    window_started_at: Option<Instant>,
    window_started_bytes: u64,
    awaiting_receipt: bool,
    pending_checkpoint: Option<SenderCheckpoint>,
}

struct EstablishedChannel {
    transport: ChannelTransport,
    cipher: StreamCipher,
    outgoing: DirectionState,
    incoming: DirectionState,
    outgoing_direction: RelayDirection,
    incoming_direction: RelayDirection,
    initiator: bool,
}

struct EstablishedChannelParts {
    cipher: StreamCipher,
    outgoing: DirectionState,
    incoming: DirectionState,
    outgoing_direction: RelayDirection,
    incoming_direction: RelayDirection,
    initiator: bool,
}

async fn establish_channel(
    mut transport: ChannelTransport,
    identity: &MemberIdentity,
    view: &RelayAuthorizationView,
    initiator: bool,
) -> Result<EstablishedChannel, RelayError> {
    match establish_channel_parts(&mut transport, identity, view, initiator).await {
        Ok(parts) => Ok(EstablishedChannel {
            transport,
            cipher: parts.cipher,
            outgoing: parts.outgoing,
            incoming: parts.incoming,
            outgoing_direction: parts.outgoing_direction,
            incoming_direction: parts.incoming_direction,
            initiator: parts.initiator,
        }),
        Err(error) => {
            let _ = transport
                .send(RelayFrame {
                    frame_type: FrameType::Close,
                    flags: 0,
                    channel_id: transport.channel_id,
                    sequence: 0,
                    payload: Vec::new(),
                })
                .await;
            Err(error)
        }
    }
}

async fn establish_channel_parts(
    transport: &mut ChannelTransport,
    identity: &MemberIdentity,
    view: &RelayAuthorizationView,
    initiator: bool,
) -> Result<EstablishedChannelParts, RelayError> {
    let outgoing_direction = if initiator {
        RelayDirection::SenderToReceiver
    } else {
        RelayDirection::ReceiverToSender
    };
    let incoming_direction = if initiator {
        RelayDirection::ReceiverToSender
    } else {
        RelayDirection::SenderToReceiver
    };
    let mut outgoing = initial_direction(view, outgoing_direction);
    let mut incoming = initial_direction(view, incoming_direction);
    let private_key = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
        .map_err(|_| RelayError::Crypto("could not generate ephemeral X25519 key".to_owned()))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| RelayError::Crypto("could not compute ephemeral X25519 key".to_owned()))?;
    let local_ephemeral_key = STANDARD.encode(public_key.as_ref());

    let (peer_ephemeral_key, offer_bytes, response_bytes) = if initiator {
        let mut offer = KeyOffer {
            protocol: PIPE_E2E_PROTOCOL.to_owned(),
            channel_id: transport.channel_id,
            authorization_id: view.authorization.authorization_id.clone(),
            session_id: view.authorization.session_id.clone(),
            sender_credential: identity.credential.clone(),
            sender_ephemeral_key: local_ephemeral_key.clone(),
            signature: String::new(),
        };
        offer.signature = identity.sign(&key_offer_signing_bytes(&offer)?)?;
        let offer_bytes =
            serde_json::to_vec(&offer).map_err(|error| RelayError::Protocol(error.to_string()))?;
        let mut payload = vec![KEY_OFFER];
        payload.extend_from_slice(&offer_bytes);
        send_handshake_payload(transport, &mut outgoing, payload).await?;

        let payload = receive_handshake_payload(transport, &mut incoming).await?;
        if payload.first() != Some(&KEY_RESPONSE) {
            return Err(RelayError::Protocol(
                "peer did not return a key response".to_owned(),
            ));
        }
        let response_bytes = payload[1..].to_vec();
        let response: KeyResponse = serde_json::from_slice(&response_bytes)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        validate_key_response(
            &response,
            &offer,
            &offer_bytes,
            identity,
            view,
            transport.channel_id,
        )?;
        (
            decode_ephemeral_key(&response.receiver_ephemeral_key)?,
            offer_bytes,
            response_bytes,
        )
    } else {
        let payload = receive_handshake_payload(transport, &mut incoming).await?;
        if payload.first() != Some(&KEY_OFFER) {
            return Err(RelayError::Protocol(
                "peer did not send a key offer".to_owned(),
            ));
        }
        let offer_bytes = payload[1..].to_vec();
        let offer: KeyOffer = serde_json::from_slice(&offer_bytes)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        validate_key_offer(&offer, identity, view, transport.channel_id)?;
        let peer_key = decode_ephemeral_key(&offer.sender_ephemeral_key)?;
        let mut response = KeyResponse {
            protocol: PIPE_E2E_PROTOCOL.to_owned(),
            channel_id: transport.channel_id,
            authorization_id: view.authorization.authorization_id.clone(),
            session_id: view.authorization.session_id.clone(),
            sender_member_id: offer.sender_credential.member_id.clone(),
            sender_ephemeral_key: offer.sender_ephemeral_key.clone(),
            offer_hash: sha256_full_id("pipe-offer", &offer_bytes),
            receiver_credential: identity.credential.clone(),
            receiver_ephemeral_key: local_ephemeral_key,
            signature: String::new(),
        };
        response.signature = identity.sign(&key_response_signing_bytes(&response)?)?;
        let response_bytes = serde_json::to_vec(&response)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        let mut payload = vec![KEY_RESPONSE];
        payload.extend_from_slice(&response_bytes);
        send_handshake_payload(transport, &mut outgoing, payload).await?;
        (peer_key, offer_bytes, response_bytes)
    };

    let peer_public_key = UnparsedPublicKey::new(&X25519, peer_ephemeral_key);
    let shared_secret =
        agreement::agree_ephemeral(private_key, &peer_public_key, |secret| secret.to_vec())
            .map_err(|_| RelayError::Crypto("X25519 key agreement failed".to_owned()))?;
    let context = encryption_context(view, transport.channel_id, &offer_bytes, &response_bytes)?;
    let cipher = StreamCipher::derive(&shared_secret, context, initiator)?;

    if initiator {
        send_encrypted_record(
            transport,
            &cipher,
            outgoing_direction,
            &mut outgoing,
            RECORD_CONFIRM,
            b"mrk-pipe-confirm-v1",
        )
        .await?;
        let (record_type, bytes) =
            receive_encrypted_record(transport, &cipher, incoming_direction, &mut incoming).await?;
        if record_type != RECORD_READY || bytes != b"mrk-pipe-ready-v1" {
            return Err(RelayError::Protocol(
                "peer did not confirm the encrypted stream".to_owned(),
            ));
        }
    } else {
        let (record_type, bytes) =
            receive_encrypted_record(transport, &cipher, incoming_direction, &mut incoming).await?;
        if record_type != RECORD_CONFIRM || bytes != b"mrk-pipe-confirm-v1" {
            return Err(RelayError::Protocol(
                "peer did not confirm the encrypted stream".to_owned(),
            ));
        }
        send_encrypted_record(
            transport,
            &cipher,
            outgoing_direction,
            &mut outgoing,
            RECORD_READY,
            b"mrk-pipe-ready-v1",
        )
        .await?;
    }
    Ok(EstablishedChannelParts {
        cipher,
        outgoing,
        incoming,
        outgoing_direction,
        incoming_direction,
        initiator,
    })
}

fn initial_direction(view: &RelayAuthorizationView, direction: RelayDirection) -> DirectionState {
    let settled = view
        .authorization
        .directions
        .get(&direction)
        .cloned()
        .unwrap_or_default();
    let transcript_hash = settled.settled_transcript_hash.clone().unwrap_or_else(|| {
        relay_transcript_initial_hash(
            &view.ledger_id,
            view.authorization.node_id,
            &view.authorization.authorization_id,
            &view.authorization.session_id,
            direction,
        )
    });
    DirectionState {
        sequence: settled.settled_sequence,
        cumulative_bytes: settled.settled_payload_bytes,
        transcript_hash,
        window_started_at: None,
        window_started_bytes: settled.settled_payload_bytes,
        awaiting_receipt: false,
        pending_checkpoint: None,
    }
}

fn key_offer_signing_bytes(offer: &KeyOffer) -> Result<Vec<u8>, RelayError> {
    serde_json::to_vec(&serde_json::json!({
        "protocol": offer.protocol,
        "channel_id": offer.channel_id,
        "authorization_id": offer.authorization_id,
        "session_id": offer.session_id,
        "sender_credential": offer.sender_credential,
        "sender_ephemeral_key": offer.sender_ephemeral_key,
    }))
    .map_err(|error| RelayError::Protocol(error.to_string()))
}

fn key_response_signing_bytes(response: &KeyResponse) -> Result<Vec<u8>, RelayError> {
    serde_json::to_vec(&serde_json::json!({
        "protocol": response.protocol,
        "channel_id": response.channel_id,
        "authorization_id": response.authorization_id,
        "session_id": response.session_id,
        "sender_member_id": response.sender_member_id,
        "sender_ephemeral_key": response.sender_ephemeral_key,
        "offer_hash": response.offer_hash,
        "receiver_credential": response.receiver_credential,
        "receiver_ephemeral_key": response.receiver_ephemeral_key,
    }))
    .map_err(|error| RelayError::Protocol(error.to_string()))
}

fn validate_key_offer(
    offer: &KeyOffer,
    identity: &MemberIdentity,
    view: &RelayAuthorizationView,
    channel_id: u32,
) -> Result<(), RelayError> {
    if offer.protocol != PIPE_E2E_PROTOCOL
        || offer.channel_id != channel_id
        || offer.authorization_id != view.authorization.authorization_id
        || offer.session_id != view.authorization.session_id
        || offer.sender_credential.member_id != view.authorization.sender_member_id
        || offer.sender_credential.member_public_key != view.sender_public_key
    {
        return Err(RelayError::Authentication(
            "key offer does not match the authorized sender".to_owned(),
        ));
    }
    validate_peer_credential(&offer.sender_credential, identity)?;
    verify_bytes(
        &offer.sender_credential.member_public_key,
        &key_offer_signing_bytes(offer)?,
        &offer.signature,
    )
    .map_err(|error| RelayError::Authentication(error.to_string()))
}

fn validate_key_response(
    response: &KeyResponse,
    offer: &KeyOffer,
    offer_bytes: &[u8],
    identity: &MemberIdentity,
    view: &RelayAuthorizationView,
    channel_id: u32,
) -> Result<(), RelayError> {
    if response.protocol != PIPE_E2E_PROTOCOL
        || response.channel_id != channel_id
        || response.authorization_id != view.authorization.authorization_id
        || response.session_id != view.authorization.session_id
        || response.sender_member_id != offer.sender_credential.member_id
        || response.sender_ephemeral_key != offer.sender_ephemeral_key
        || response.offer_hash != sha256_full_id("pipe-offer", offer_bytes)
        || response.receiver_credential.member_id != view.authorization.receiver_member_id
        || response.receiver_credential.member_public_key != view.receiver_public_key
    {
        return Err(RelayError::Authentication(
            "key response does not match the authorized receiver".to_owned(),
        ));
    }
    validate_peer_credential(&response.receiver_credential, identity)?;
    verify_bytes(
        &response.receiver_credential.member_public_key,
        &key_response_signing_bytes(response)?,
        &response.signature,
    )
    .map_err(|error| RelayError::Authentication(error.to_string()))
}

fn validate_peer_credential(
    credential: &MemberCredential,
    identity: &MemberIdentity,
) -> Result<(), RelayError> {
    let now = Utc::now().timestamp();
    if credential.version != PROTOCOL_VERSION
        || credential.network_id != identity.credential.network_id
        || now < credential.issued_at
        || now >= credential.expires_at
        || !credential.permissions.iter().any(|item| item == "connect")
        || !credential.permissions.iter().any(|item| item == "send")
        || !credential.permissions.iter().any(|item| item == "receive")
    {
        return Err(RelayError::Authentication(
            "peer member credential is invalid".to_owned(),
        ));
    }
    verify_bytes(
        &identity.network_owner_public_key,
        &credential_signing_bytes(credential)?,
        &credential.owner_signature,
    )
    .map_err(|error| RelayError::Authentication(error.to_string()))
}

fn decode_ephemeral_key(encoded: &str) -> Result<[u8; 32], RelayError> {
    STANDARD
        .decode(encoded)
        .map_err(|_| RelayError::Authentication("ephemeral key is not valid base64".to_owned()))?
        .try_into()
        .map_err(|_| RelayError::Authentication("ephemeral key has the wrong length".to_owned()))
}

fn encryption_context(
    view: &RelayAuthorizationView,
    channel_id: u32,
    offer_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<Vec<u8>, RelayError> {
    let mut transcript = Vec::with_capacity(offer_bytes.len() + response_bytes.len());
    transcript.extend_from_slice(offer_bytes);
    transcript.extend_from_slice(response_bytes);
    serde_json::to_vec(&serde_json::json!({
        "protocol": PIPE_E2E_PROTOCOL,
        "ledger_id": view.ledger_id,
        "node_id": view.authorization.node_id,
        "channel_id": channel_id,
        "authorization_id": view.authorization.authorization_id,
        "session_id": view.authorization.session_id,
        "sender_member_id": view.authorization.sender_member_id,
        "receiver_member_id": view.authorization.receiver_member_id,
        "handshake_transcript_hash": sha256_full_id("pipe-handshake", &transcript),
    }))
    .map_err(|error| RelayError::Protocol(error.to_string()))
}

async fn send_handshake_payload(
    transport: &ChannelTransport,
    state: &mut DirectionState,
    payload: Vec<u8>,
) -> Result<(), RelayError> {
    advance_outgoing_state(state, &payload)?;
    transport
        .send(RelayFrame {
            frame_type: FrameType::Data,
            flags: 0,
            channel_id: transport.channel_id,
            sequence: state.sequence,
            payload,
        })
        .await
}

async fn receive_handshake_payload(
    transport: &mut ChannelTransport,
    state: &mut DirectionState,
) -> Result<Vec<u8>, RelayError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let frame = transport.receive().await?;
        match frame.frame_type {
            FrameType::Data => {
                advance_incoming_state(state, &frame)?;
                Ok(frame.payload)
            }
            FrameType::Error => Err(frame_error(&frame.payload)),
            FrameType::Close => Err(RelayError::Protocol(
                "peer closed during encrypted stream handshake".to_owned(),
            )),
            _ => Err(RelayError::Protocol(
                "unexpected frame during encrypted stream handshake".to_owned(),
            )),
        }
    })
    .await
    .map_err(|_| RelayError::HandshakeTimeout)?
}

async fn send_encrypted_record(
    transport: &ChannelTransport,
    cipher: &StreamCipher,
    direction: RelayDirection,
    state: &mut DirectionState,
    record_type: u8,
    bytes: &[u8],
) -> Result<(), RelayError> {
    let sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| RelayError::Protocol("Relay DATA sequence overflow".to_owned()))?;
    let payload = cipher.encrypt(direction, sequence, record_type, bytes)?;
    advance_outgoing_state(state, &payload)?;
    transport
        .send(RelayFrame {
            frame_type: FrameType::Data,
            flags: 0,
            channel_id: transport.channel_id,
            sequence: state.sequence,
            payload,
        })
        .await
}

async fn receive_encrypted_record(
    transport: &mut ChannelTransport,
    cipher: &StreamCipher,
    direction: RelayDirection,
    state: &mut DirectionState,
) -> Result<(u8, Vec<u8>), RelayError> {
    let payload = receive_handshake_payload(transport, state).await?;
    cipher.decrypt(direction, state.sequence, &payload)
}

fn advance_outgoing_state(state: &mut DirectionState, payload: &[u8]) -> Result<(), RelayError> {
    state.sequence = state
        .sequence
        .checked_add(1)
        .ok_or_else(|| RelayError::Protocol("Relay DATA sequence overflow".to_owned()))?;
    state.window_started_at.get_or_insert_with(Instant::now);
    state.cumulative_bytes = state
        .cumulative_bytes
        .checked_add(payload.len() as u64)
        .ok_or_else(|| RelayError::Protocol("Relay byte counter overflow".to_owned()))?;
    state.transcript_hash =
        relay_transcript_next_hash(&state.transcript_hash, state.sequence, payload);
    Ok(())
}

fn advance_incoming_state(
    state: &mut DirectionState,
    frame: &RelayFrame,
) -> Result<(), RelayError> {
    if frame.sequence != state.sequence.saturating_add(1) {
        return Err(RelayError::Protocol(
            "received Relay DATA sequence gap".to_owned(),
        ));
    }
    state.sequence = frame.sequence;
    state.window_started_at.get_or_insert_with(Instant::now);
    state.cumulative_bytes = state
        .cumulative_bytes
        .checked_add(frame.payload.len() as u64)
        .ok_or_else(|| RelayError::Protocol("Relay byte counter overflow".to_owned()))?;
    state.transcript_hash =
        relay_transcript_next_hash(&state.transcript_hash, frame.sequence, &frame.payload);
    Ok(())
}

#[derive(Clone, Debug)]
enum StreamStatus {
    Running,
    RemoteFin,
    CleanEof,
    Failed(String),
}

pub struct EncryptedStream {
    io: DuplexStream,
    status: watch::Receiver<StreamStatus>,
    peer_id: String,
    authorization_id: String,
    local_fin_receipted: Arc<CompletionSignal>,
}

struct CompletionSignal {
    done: AtomicBool,
    waker: StdMutex<Option<Waker>>,
}

impl CompletionSignal {
    fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            waker: StdMutex::new(None),
        }
    }

    fn complete(&self) {
        self.done.store(true, Ordering::Release);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }

    fn poll(&self, context: &Context<'_>) -> Poll<()> {
        if self.done.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let mut waker = self
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.done.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            *waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl EncryptedStream {
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let filled_before = buffer.filled().len();
        match Pin::new(&mut self.io).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == filled_before => {
                match self.status.borrow().clone() {
                    StreamStatus::Failed(message) => {
                        Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, message)))
                    }
                    StreamStatus::Running => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                    StreamStatus::RemoteFin | StreamStatus::CleanEof => Poll::Ready(Ok(())),
                }
            }
            result => result,
        }
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.io).poll_shutdown(context) {
            Poll::Ready(Ok(())) => {
                if let StreamStatus::Failed(message) = self.status.borrow().clone() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)))
                } else if self.local_fin_receipted.poll(context).is_ready() {
                    Poll::Ready(Ok(()))
                } else if let StreamStatus::Failed(message) = self.status.borrow().clone() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, message)))
                } else {
                    Poll::Pending
                }
            }
            result => result,
        }
    }
}

async fn build_encrypted_stream(
    connection: Arc<ConnectionInner>,
    transport: ChannelTransport,
    view: RelayAuthorizationView,
    initiator: bool,
) -> Result<EncryptedStream, RelayError> {
    let peer_id = if initiator {
        view.authorization.receiver_member_id.clone()
    } else {
        view.authorization.sender_member_id.clone()
    };
    let authorization_id = view.authorization.authorization_id.clone();
    let established =
        establish_channel(transport, &connection.options.identity, &view, initiator).await?;
    let (application_io, actor_io) = tokio::io::duplex(connection.options.stream_buffer_bytes);
    let (status_sender, status) = watch::channel(StreamStatus::Running);
    let local_fin_receipted = Arc::new(CompletionSignal::new());
    let identity = connection.options.identity.clone();
    let max_payload = connection.max_payload;
    let actor_status = status_sender.clone();
    let actor_local_fin_receipted = local_fin_receipted.clone();
    tokio::spawn(async move {
        let result = run_stream_actor(
            established,
            actor_io,
            view,
            identity,
            max_payload,
            actor_status,
            actor_local_fin_receipted.clone(),
        )
        .await;
        let terminal = match result {
            Ok(()) => StreamStatus::CleanEof,
            Err(error) => StreamStatus::Failed(error.to_string()),
        };
        status_sender.send_replace(terminal);
        actor_local_fin_receipted.wake();
    });
    Ok(EncryptedStream {
        io: application_io,
        status,
        peer_id,
        authorization_id,
        local_fin_receipted,
    })
}

async fn run_stream_actor(
    mut channel: EstablishedChannel,
    actor_io: DuplexStream,
    view: RelayAuthorizationView,
    identity: MemberIdentity,
    max_payload: usize,
    status: watch::Sender<StreamStatus>,
    local_fin_receipted: Arc<CompletionSignal>,
) -> Result<(), RelayError> {
    let result = run_stream_loop(
        &mut channel,
        actor_io,
        &view,
        &identity,
        max_payload,
        &status,
        &local_fin_receipted,
    )
    .await;
    if result.is_err() {
        if let Err(error) = &result {
            sdk_debug(&format!(
                "member {} stream actor failed: {error}",
                identity.credential.member_id
            ));
        }
        let _ = channel
            .transport
            .send(RelayFrame {
                frame_type: FrameType::Close,
                flags: 0,
                channel_id: channel.transport.channel_id,
                sequence: channel.outgoing.sequence,
                payload: Vec::new(),
            })
            .await;
    }
    result
}

async fn run_stream_loop(
    channel: &mut EstablishedChannel,
    actor_io: DuplexStream,
    view: &RelayAuthorizationView,
    identity: &MemberIdentity,
    max_payload: usize,
    status: &watch::Sender<StreamStatus>,
    local_fin_receipted_signal: &CompletionSignal,
) -> Result<(), RelayError> {
    let (mut application_input, application_output) = split(actor_io);
    let mut application_output = Some(application_output);
    let chunk_size = (max_payload - AEAD_OVERHEAD).min(64 * 1024);
    let mut input = vec![0_u8; chunk_size];
    let mut payment_timer = tokio::time::interval(Duration::from_secs(1));
    payment_timer.tick().await;
    let mut local_fin = false;
    let mut remote_fin = false;
    let mut local_fin_receipted = false;
    let mut remote_fin_receipted = false;
    loop {
        if channel.initiator
            && local_fin
            && remote_fin
            && local_fin_receipted
            && remote_fin_receipted
        {
            sdk_debug(&format!(
                "member {} completed both authenticated FIN directions; closing Relay route",
                identity.credential.member_id
            ));
            channel
                .transport
                .send(RelayFrame {
                    frame_type: FrameType::Close,
                    flags: 0,
                    channel_id: channel.transport.channel_id,
                    sequence: channel.outgoing.sequence,
                    payload: Vec::new(),
                })
                .await?;
            return Ok(());
        }
        tokio::select! {
            input_result = application_input.read(&mut input), if !local_fin && !channel.outgoing.awaiting_receipt => {
                let size = input_result.map_err(|error| RelayError::Transport(error.to_string()))?;
                if size == 0 {
                    sdk_debug("local application write half closed; sending authenticated FIN");
                    send_encrypted_record(
                        &channel.transport,
                        &channel.cipher,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        RECORD_FIN,
                        &[],
                    ).await?;
                    local_fin = true;
                    send_checkpoint(
                        &channel.transport,
                        identity,
                        view,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        true,
                    ).await?;
                    continue;
                }
                send_encrypted_record(
                    &channel.transport,
                    &channel.cipher,
                    channel.outgoing_direction,
                    &mut channel.outgoing,
                    RECORD_DATA,
                    &input[..size],
                ).await?;
                if channel.outgoing.cumulative_bytes.saturating_sub(channel.outgoing.window_started_bytes)
                    >= RELAY_PAYMENT_WINDOW_BYTES
                {
                    send_checkpoint(
                        &channel.transport,
                        identity,
                        view,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        false,
                    ).await?;
                }
            }
            frame_result = channel.transport.receive() => {
                let frame = frame_result?;
                match frame.frame_type {
                    FrameType::Data => {
                        advance_incoming_state(&mut channel.incoming, &frame)?;
                        let (record_type, bytes) = channel.cipher.decrypt(
                            channel.incoming_direction,
                            frame.sequence,
                            &frame.payload,
                        )?;
                        match record_type {
                            RECORD_DATA if !remote_fin => {
                                let output = application_output.as_mut().ok_or_else(|| {
                                    RelayError::Protocol("stream output is already closed".to_owned())
                                })?;
                                output.write_all(&bytes).await
                                    .map_err(|error| RelayError::Transport(error.to_string()))?;
                                output.flush().await
                                    .map_err(|error| RelayError::Transport(error.to_string()))?;
                            }
                            RECORD_FIN if bytes.is_empty() && !remote_fin => {
                                sdk_debug("received authenticated FIN");
                                remote_fin = true;
                                status.send_replace(StreamStatus::RemoteFin);
                                if let Some(mut output) = application_output.take() {
                                    output.shutdown().await.map_err(|error| {
                                        RelayError::Transport(error.to_string())
                                    })?;
                                }
                            }
                            RECORD_DATA => {
                                return Err(RelayError::Protocol(
                                    "peer sent DATA after authenticated FIN".to_owned(),
                                ));
                            }
                            _ => {
                                return Err(RelayError::Protocol(
                                    "unexpected encrypted stream record".to_owned(),
                                ));
                            }
                        }
                    }
                    FrameType::SenderCheckpoint => {
                        sdk_debug("received SenderCheckpoint");
                        let checkpoint: SenderCheckpoint = serde_json::from_slice(&frame.payload)
                            .map_err(|error| RelayError::Protocol(error.to_string()))?;
                        validate_incoming_checkpoint(
                            &checkpoint,
                            &frame,
                            view,
                            channel.incoming_direction,
                            &channel.incoming,
                        )?;
                        let receipt = sign_receipt(identity, &checkpoint)?;
                        channel.transport.send(RelayFrame {
                            frame_type: FrameType::ReceiverReceipt,
                            flags: 0,
                            channel_id: channel.transport.channel_id,
                            sequence: checkpoint.sequence,
                            payload: serde_json::to_vec(&receipt)
                                .map_err(|error| RelayError::Protocol(error.to_string()))?,
                        }).await?;
                        channel.incoming.window_started_at = None;
                        channel.incoming.window_started_bytes = channel.incoming.cumulative_bytes;
                        if remote_fin && frame.flags & RELAY_CHECKPOINT_FINAL_FLAG != 0 {
                            remote_fin_receipted = true;
                        }
                    }
                    FrameType::ReceiverReceipt => {
                        sdk_debug("received ReceiverReceipt");
                        let receipt: ReceiverReceipt = serde_json::from_slice(&frame.payload)
                            .map_err(|error| RelayError::Protocol(error.to_string()))?;
                        validate_outgoing_receipt(
                            &receipt,
                            view,
                            channel.outgoing_direction,
                            &channel.outgoing,
                        )?;
                        channel.outgoing.window_started_at = None;
                        channel.outgoing.window_started_bytes = channel.outgoing.cumulative_bytes;
                        channel.outgoing.awaiting_receipt = false;
                        channel.outgoing.pending_checkpoint = None;
                        if local_fin {
                            local_fin_receipted = true;
                            local_fin_receipted_signal.complete();
                        }
                    }
                    FrameType::Close => {
                        if !channel.initiator
                            && local_fin
                            && remote_fin
                            && remote_fin_receipted
                        {
                            // The initiator only closes after receiving our final receipt and
                            // writing its final receipt before CLOSE on the same ordered WebSocket.
                            // Relay validates and persists that receipt before removing the route,
                            // even if the forwarded receipt and CLOSE arrive back-to-back here.
                            local_fin_receipted_signal.complete();
                            return Ok(());
                        }
                        return Err(RelayError::Protocol(format!(
                            "Relay stream closed before completion (local_fin={local_fin}, remote_fin={remote_fin}, local_receipt={local_fin_receipted}, remote_receipt={remote_fin_receipted})"
                        )));
                    }
                    FrameType::Error => return Err(frame_error(&frame.payload)),
                    _ => {
                        return Err(RelayError::Protocol(
                            "unexpected frame on encrypted stream".to_owned(),
                        ));
                    }
                }
            }
            _ = payment_timer.tick(), if !local_fin && !channel.outgoing.awaiting_receipt && channel.outgoing.window_started_at.is_some() => {
                let authorization_expiring = Utc::now().timestamp()
                    >= view.authorization.valid_until.saturating_sub(5);
                let window_elapsed = channel.outgoing.window_started_at.is_some_and(|started| {
                    started.elapsed() >= Duration::from_secs((RELAY_PAYMENT_WINDOW_SECONDS + 1) as u64)
                });
                if authorization_expiring {
                    send_encrypted_record(
                        &channel.transport,
                        &channel.cipher,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        RECORD_FIN,
                        &[],
                    ).await?;
                    local_fin = true;
                    send_checkpoint(
                        &channel.transport,
                        identity,
                        view,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        true,
                    ).await?;
                } else if window_elapsed
                    && channel.outgoing.cumulative_bytes > channel.outgoing.window_started_bytes
                {
                    send_checkpoint(
                        &channel.transport,
                        identity,
                        view,
                        channel.outgoing_direction,
                        &mut channel.outgoing,
                        false,
                    ).await?;
                }
            }
        }
    }
}

async fn send_checkpoint(
    transport: &ChannelTransport,
    identity: &MemberIdentity,
    view: &RelayAuthorizationView,
    direction: RelayDirection,
    state: &mut DirectionState,
    final_checkpoint: bool,
) -> Result<(), RelayError> {
    let mut checkpoint = SenderCheckpoint {
        ledger_id: view.ledger_id.clone(),
        protocol_version: PROTOCOL_VERSION,
        node_id: view.authorization.node_id,
        authorization_id: view.authorization.authorization_id.clone(),
        session_id: view.authorization.session_id.clone(),
        direction,
        sequence: state.sequence,
        cumulative_sent_bytes: state.cumulative_bytes,
        transcript_hash: state.transcript_hash.clone(),
        checkpoint_at: Utc::now().timestamp(),
        sender_member_id: identity.credential.member_id.clone(),
        final_checkpoint,
        sender_signature: String::new(),
    };
    checkpoint.sender_signature = identity.sign(&sender_checkpoint_signing_bytes(&checkpoint)?)?;
    transport
        .send(RelayFrame {
            frame_type: FrameType::SenderCheckpoint,
            flags: if final_checkpoint {
                RELAY_CHECKPOINT_FINAL_FLAG
            } else {
                0
            },
            channel_id: transport.channel_id,
            sequence: checkpoint.sequence,
            payload: serde_json::to_vec(&checkpoint)
                .map_err(|error| RelayError::Protocol(error.to_string()))?,
        })
        .await?;
    state.awaiting_receipt = true;
    state.pending_checkpoint = Some(checkpoint);
    Ok(())
}

fn sdk_debug(message: &str) {
    if std::env::var_os("MRK_RELAY_DEBUG").is_some() {
        eprintln!("Relay SDK: {message}");
    }
}

fn sign_receipt(
    identity: &MemberIdentity,
    checkpoint: &SenderCheckpoint,
) -> Result<ReceiverReceipt, RelayError> {
    let mut receipt = ReceiverReceipt {
        ledger_id: checkpoint.ledger_id.clone(),
        protocol_version: checkpoint.protocol_version,
        node_id: checkpoint.node_id,
        authorization_id: checkpoint.authorization_id.clone(),
        session_id: checkpoint.session_id.clone(),
        direction: checkpoint.direction,
        sequence: checkpoint.sequence,
        cumulative_received_bytes: checkpoint.cumulative_sent_bytes,
        transcript_hash: checkpoint.transcript_hash.clone(),
        sender_checkpoint_hash: sender_checkpoint_hash(checkpoint)?,
        received_at: Utc::now().timestamp(),
        receiver_member_id: identity.credential.member_id.clone(),
        receiver_signature: String::new(),
    };
    receipt.receiver_signature = identity.sign(&receiver_receipt_signing_bytes(&receipt)?)?;
    Ok(receipt)
}

fn validate_incoming_checkpoint(
    checkpoint: &SenderCheckpoint,
    frame: &RelayFrame,
    view: &RelayAuthorizationView,
    direction: RelayDirection,
    state: &DirectionState,
) -> Result<(), RelayError> {
    let (expected_member, public_key) = match direction {
        RelayDirection::SenderToReceiver => (
            view.authorization.sender_member_id.as_str(),
            view.sender_public_key.as_str(),
        ),
        RelayDirection::ReceiverToSender => (
            view.authorization.receiver_member_id.as_str(),
            view.receiver_public_key.as_str(),
        ),
    };
    if checkpoint.direction != direction
        || checkpoint.ledger_id != view.ledger_id
        || checkpoint.protocol_version != PROTOCOL_VERSION
        || checkpoint.node_id != view.authorization.node_id
        || checkpoint.authorization_id != view.authorization.authorization_id
        || checkpoint.session_id != view.authorization.session_id
        || checkpoint.sequence != state.sequence
        || checkpoint.sequence != frame.sequence
        || checkpoint.cumulative_sent_bytes != state.cumulative_bytes
        || checkpoint.transcript_hash != state.transcript_hash
        || checkpoint.sender_member_id != expected_member
        || checkpoint.checkpoint_at > Utc::now().timestamp().saturating_add(30)
    {
        return Err(RelayError::Protocol(
            "SenderCheckpoint does not match received encrypted DATA".to_owned(),
        ));
    }
    verify_bytes(
        public_key,
        &sender_checkpoint_signing_bytes(checkpoint)?,
        &checkpoint.sender_signature,
    )
    .map_err(|error| RelayError::Authentication(error.to_string()))
}

fn validate_outgoing_receipt(
    receipt: &ReceiverReceipt,
    view: &RelayAuthorizationView,
    direction: RelayDirection,
    state: &DirectionState,
) -> Result<(), RelayError> {
    let checkpoint = state.pending_checkpoint.as_ref().ok_or_else(|| {
        RelayError::Protocol("unexpected ReceiverReceipt without a checkpoint".to_owned())
    })?;
    let (expected_member, public_key) = match direction {
        RelayDirection::SenderToReceiver => (
            view.authorization.receiver_member_id.as_str(),
            view.receiver_public_key.as_str(),
        ),
        RelayDirection::ReceiverToSender => (
            view.authorization.sender_member_id.as_str(),
            view.sender_public_key.as_str(),
        ),
    };
    if receipt.direction != direction
        || receipt.ledger_id != view.ledger_id
        || receipt.protocol_version != PROTOCOL_VERSION
        || receipt.node_id != view.authorization.node_id
        || receipt.authorization_id != checkpoint.authorization_id
        || receipt.session_id != checkpoint.session_id
        || receipt.sequence != checkpoint.sequence
        || receipt.cumulative_received_bytes != checkpoint.cumulative_sent_bytes
        || receipt.transcript_hash != checkpoint.transcript_hash
        || receipt.sender_checkpoint_hash != sender_checkpoint_hash(checkpoint)?
        || receipt.receiver_member_id != expected_member
        || receipt.received_at < checkpoint.checkpoint_at
        || receipt.received_at.saturating_sub(checkpoint.checkpoint_at) > 30
    {
        return Err(RelayError::Protocol(
            "invalid ReceiverReceipt for encrypted DATA".to_owned(),
        ));
    }
    verify_bytes(
        public_key,
        &receiver_receipt_signing_bytes(receipt)?,
        &receipt.receiver_signature,
    )
    .map_err(|error| RelayError::Authentication(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED_SECRET: [u8; 32] = [0x5a; 32];

    #[test]
    fn member_identity_accepts_a_remote_network_record_without_local_network_state() {
        let random = crate::crypto::random_bytes::<8>().unwrap();
        let root = std::env::temp_dir().join(format!(
            "mrk-sdk-remote-network-{}",
            crate::crypto::hex_lower(&random)
        ));
        let paths = DataPaths::new(Some(root.clone())).unwrap();
        let password = "sdk-remote-network-password";
        service::create_account(&paths, "owner", password).unwrap();
        let network_record =
            service::create_network(&paths, "owner", password, "team", Utc::now().timestamp())
                .unwrap();
        let (credential, _) = service::issue_member(
            &paths,
            "owner",
            password,
            "team",
            "alice",
            7,
            Utc::now().timestamp(),
        )
        .unwrap();
        paths
            .with_ledger_mut(|ledger| {
                ledger.networks.clear();
                ledger.network_aliases.clear();
                Ok(())
            })
            .unwrap();

        assert!(MemberIdentity::from_data_paths(&paths, "team", "alice", password).is_err());
        let identity = MemberIdentity::from_data_paths_with_network_record(
            &paths,
            "team",
            "alice",
            password,
            &network_record,
        )
        .unwrap();
        assert_eq!(identity.credential().member_id, credential.member_id);

        let mut wrong_network = network_record;
        wrong_network.network_id = "different-network".to_owned();
        assert!(
            MemberIdentity::from_data_paths_with_network_record(
                &paths,
                "team",
                "alice",
                password,
                &wrong_network,
            )
            .is_err()
        );

        drop(paths);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stream_cipher_round_trips_both_directions_without_plaintext() {
        let context = b"bound relay stream context".to_vec();
        let initiator = StreamCipher::derive(&SHARED_SECRET, context.clone(), true).unwrap();
        let receiver = StreamCipher::derive(&SHARED_SECRET, context, false).unwrap();
        let forward_plaintext = b"sender to receiver";
        let forward = initiator
            .encrypt(
                RelayDirection::SenderToReceiver,
                7,
                RECORD_DATA,
                forward_plaintext,
            )
            .unwrap();
        assert!(
            !forward
                .windows(forward_plaintext.len())
                .any(|window| window == forward_plaintext)
        );
        assert_eq!(
            receiver
                .decrypt(RelayDirection::SenderToReceiver, 7, &forward)
                .unwrap(),
            (RECORD_DATA, forward_plaintext.to_vec())
        );

        let reverse_plaintext = b"receiver to sender";
        let reverse = receiver
            .encrypt(
                RelayDirection::ReceiverToSender,
                11,
                RECORD_FIN,
                reverse_plaintext,
            )
            .unwrap();
        assert_eq!(
            initiator
                .decrypt(RelayDirection::ReceiverToSender, 11, &reverse)
                .unwrap(),
            (RECORD_FIN, reverse_plaintext.to_vec())
        );
    }

    #[test]
    fn stream_cipher_rejects_relay_modification_and_context_substitution() {
        let context = b"original stream context".to_vec();
        let initiator = StreamCipher::derive(&SHARED_SECRET, context.clone(), true).unwrap();
        let payload = initiator
            .encrypt(
                RelayDirection::SenderToReceiver,
                3,
                RECORD_DATA,
                b"authenticated bytes",
            )
            .unwrap();

        let mut tampered = payload.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            StreamCipher::derive(&SHARED_SECRET, context.clone(), false)
                .unwrap()
                .decrypt(RelayDirection::SenderToReceiver, 3, &tampered)
                .is_err()
        );
        assert!(
            StreamCipher::derive(&SHARED_SECRET, context.clone(), false)
                .unwrap()
                .decrypt(RelayDirection::SenderToReceiver, 4, &payload)
                .is_err()
        );
        assert!(
            StreamCipher::derive(&SHARED_SECRET, context, false)
                .unwrap()
                .decrypt(RelayDirection::ReceiverToSender, 3, &payload)
                .is_err()
        );
        assert!(
            StreamCipher::derive(&SHARED_SECRET, b"different stream context".to_vec(), false)
                .unwrap()
                .decrypt(RelayDirection::SenderToReceiver, 3, &payload)
                .is_err()
        );
    }

    #[test]
    fn stream_cipher_rejects_unencrypted_records() {
        let receiver =
            StreamCipher::derive(&SHARED_SECRET, b"stream context".to_vec(), false).unwrap();
        assert!(matches!(
            receiver.decrypt(
                RelayDirection::SenderToReceiver,
                1,
                b"plaintext Relay payload"
            ),
            Err(RelayError::Protocol(_))
        ));
    }
}
