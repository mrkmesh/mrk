use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

const RPC_PROTOCOL: &str = "mrk.rpc.v1";

use crate::{
    Error, Result,
    consensus::{CONSENSUS_PROTOCOL, ConsensusWireMessage, MAX_CONSENSUS_MESSAGE_SIZE},
    crypto::random_bytes,
    endpoint::{CONSENSUS_PATH, RELAY_PATH, RPC_PATH, normalize_websocket_url},
    relay::{
        ChallengePayload, ErrorPayload, FrameType, IncomingPayload, OpenPayload, ProbePayload,
        RelayFrame, WelcomePayload, WsMessage, read_ws_message_async, websocket_accept_key,
        write_ws_message_async,
    },
    service,
    storage::DataPaths,
};

#[doc(hidden)]
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
#[doc(hidden)]
pub type BoxedIo = Box<dyn AsyncIo>;

pub struct RelayConnection {
    reader: ReadHalf<BoxedIo>,
    writer: WriteHalf<BoxedIo>,
    pub welcome: WelcomePayload,
    pub node_id: u64,
}

#[derive(serde::Deserialize)]
struct RpcResponse {
    id: u64,
    result: Option<serde_json::Value>,
    error: Option<RpcResponseError>,
}

#[derive(serde::Deserialize)]
struct RpcResponseError {
    code: String,
    message: String,
}

pub fn run_rpc_call(
    endpoint: &str,
    method: &str,
    params: serde_json::Value,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<serde_json::Value> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(rpc_call(
        endpoint,
        method,
        params,
        allow_insecure_local,
        tls_ca,
    ))
}

pub fn run_public_chain_sync(paths: DataPaths, node_name: String) -> Result<u64> {
    let config = paths.read_node_config(&node_name)?;
    let peer = config
        .bootstrap_peer
        .clone()
        .ok_or_else(|| Error::msg("Node has no bootstrap peer configured"))?;
    let tls_ca = config.bootstrap_tls_ca.map(PathBuf::from);
    let allow_insecure_local = config.bootstrap_allow_insecure_local;
    let pending = service::consensus_pending_operations(&paths).unwrap_or_default();
    let mut from_height = service::block_status(&paths, Utc::now().timestamp())?.height;
    let runtime = tokio::runtime::Runtime::new()?;
    let (blocks, operations, checkpoint) = runtime.block_on(async {
        for envelope in pending {
            let _ = rpc_call(
                &peer,
                "operation.submit",
                serde_json::json!({
                    "public_key": envelope.public_key,
                    "operation": envelope.operation,
                }),
                allow_insecure_local,
                tls_ca.as_deref(),
            )
            .await;
        }
        let mut blocks = Vec::new();
        let mut operations = Vec::new();
        let checkpoint = loop {
            let value = rpc_call(
                &peer,
                "chain.catch_up",
                serde_json::json!({ "from_height": from_height }),
                allow_insecure_local,
                tls_ca.as_deref(),
            )
            .await?;
            let chunk: service::ConsensusCatchUpChunk = serde_json::from_value(value)?;
            if chunk.blocks.is_empty() {
                break None;
            }
            from_height = chunk.blocks.last().expect("non-empty chunk").height;
            blocks.extend(chunk.blocks);
            operations.extend(chunk.operations);
            if blocks.len() > 4_096 {
                return Err(Error::msg(
                    "public catch-up exceeds 4,096 blocks; install a newer explicitly trusted checkpoint",
                ));
            }
            if let Some(checkpoint) = chunk.finalized_checkpoint {
                break Some(checkpoint);
            }
        };
        Ok::<_, Error>((blocks, operations, checkpoint))
    })?;
    if blocks.is_empty() {
        service::reconcile_local_node_registration(&paths, &node_name)?;
        return Ok(service::block_status(&paths, Utc::now().timestamp())?.height);
    }
    let checkpoint = checkpoint
        .ok_or_else(|| Error::msg("public catch-up reached no verifiable finalized checkpoint"))?;
    let height = service::apply_consensus_catch_up(&paths, blocks, operations, *checkpoint)?;
    service::reconcile_local_node_registration(&paths, &node_name)?;
    Ok(height)
}

#[doc(hidden)]
pub async fn rpc_call(
    endpoint: &str,
    method: &str,
    params: serde_json::Value,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<serde_json::Value> {
    let mut stream = connect_websocket_protocol(
        endpoint,
        RPC_PATH,
        RPC_PROTOCOL,
        allow_insecure_local,
        tls_ca,
    )
    .await?;
    let request_id = u64::from_be_bytes(random_bytes::<8>()?);
    write_ws_message_async(
        &mut stream,
        &WsMessage::Binary(serde_json::to_vec(&serde_json::json!({
            "id": request_id,
            "method": method,
            "params": params,
        }))?),
        true,
    )
    .await?;
    let WsMessage::Binary(bytes) = read_ws_message_async(&mut stream, false).await? else {
        return Err(Error::msg("RPC server returned a non-binary response"));
    };
    let response: RpcResponse = serde_json::from_slice(&bytes)?;
    if response.id != request_id {
        return Err(Error::msg("RPC response ID does not match request"));
    }
    if let Some(error) = response.error {
        return Err(Error::msg(format!("RPC {}: {}", error.code, error.message)));
    }
    response
        .result
        .ok_or_else(|| Error::msg("RPC response is missing both result and error"))
}

impl RelayConnection {
    pub async fn connect(
        paths: &DataPaths,
        network: &str,
        member: &str,
        password: &str,
        endpoint: &str,
        allow_insecure_local: bool,
    ) -> Result<Self> {
        Self::connect_with_ca(
            paths,
            network,
            member,
            password,
            endpoint,
            allow_insecure_local,
            None,
        )
        .await
    }

    pub async fn connect_with_ca(
        paths: &DataPaths,
        network: &str,
        member: &str,
        password: &str,
        endpoint: &str,
        allow_insecure_local: bool,
        tls_ca: Option<&Path>,
    ) -> Result<Self> {
        let mut stream = connect_websocket(endpoint, allow_insecure_local, tls_ca).await?;
        let challenge_frame = read_relay_frame(&mut stream).await?;
        if challenge_frame.frame_type != FrameType::Challenge {
            return Err(Error::msg("Relay did not send CHALLENGE first"));
        }
        let challenge: ChallengePayload = serde_json::from_slice(&challenge_frame.payload)?;
        if (Utc::now().timestamp() - challenge.timestamp).abs() > 30 {
            return Err(Error::msg(
                "Relay CHALLENGE timestamp is outside the 30 second window",
            ));
        }
        let hello = service::create_member_hello(
            paths,
            network,
            member,
            password,
            &challenge,
            Utc::now().timestamp(),
        )?;
        write_relay_frame(
            &mut stream,
            RelayFrame::control(FrameType::Hello, serde_json::to_vec(&hello)?),
        )
        .await?;
        let welcome_frame = read_relay_frame(&mut stream).await?;
        if welcome_frame.frame_type == FrameType::Error {
            return Err(protocol_error(&welcome_frame.payload));
        }
        if welcome_frame.frame_type != FrameType::Welcome {
            return Err(Error::msg("Relay did not send WELCOME after HELLO"));
        }
        let welcome = serde_json::from_slice(&welcome_frame.payload)?;
        let (reader, writer) = split(stream);
        Ok(Self {
            reader,
            writer,
            welcome,
            node_id: challenge.node_id,
        })
    }

    pub async fn open(
        &mut self,
        peer_id: &str,
        authorization_id: &str,
        metadata: &str,
    ) -> Result<u32> {
        self.write_frame(RelayFrame::control(
            FrameType::Open,
            serde_json::to_vec(&OpenPayload {
                peer_id: peer_id.to_owned(),
                authorization_id: authorization_id.to_owned(),
                metadata: metadata.to_owned(),
            })?,
        ))
        .await?;
        loop {
            let frame = self.read_frame().await?;
            match frame.frame_type {
                FrameType::Accept => return Ok(frame.channel_id),
                FrameType::Reject => return Err(Error::msg("peer rejected relay channel")),
                FrameType::Error => return Err(protocol_error(&frame.payload)),
                FrameType::Ping => {
                    self.write_frame(RelayFrame {
                        frame_type: FrameType::Pong,
                        ..frame
                    })
                    .await?;
                }
                _ => return Err(Error::msg("unexpected frame while opening relay channel")),
            }
        }
    }

    pub async fn accept(&mut self) -> Result<(u32, IncomingPayload)> {
        loop {
            let frame = self.read_frame().await?;
            match frame.frame_type {
                FrameType::Incoming => {
                    let incoming = serde_json::from_slice(&frame.payload)?;
                    self.write_frame(RelayFrame {
                        frame_type: FrameType::Accept,
                        flags: 0,
                        channel_id: frame.channel_id,
                        sequence: 0,
                        payload: Vec::new(),
                    })
                    .await?;
                    return Ok((frame.channel_id, incoming));
                }
                FrameType::Error => return Err(protocol_error(&frame.payload)),
                FrameType::Ping => {
                    self.write_frame(RelayFrame {
                        frame_type: FrameType::Pong,
                        ..frame
                    })
                    .await?;
                }
                _ => return Err(Error::msg("unexpected frame while awaiting relay channel")),
            }
        }
    }

    pub async fn send_data(
        &mut self,
        channel_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        self.write_frame(RelayFrame {
            frame_type: FrameType::Data,
            flags: 0,
            channel_id,
            sequence,
            payload,
        })
        .await
    }

    pub async fn receive_data(
        &mut self,
        channel_id: u32,
        expected_sequence: u64,
    ) -> Result<Vec<u8>> {
        loop {
            let frame = self.read_frame().await?;
            match frame.frame_type {
                FrameType::Data if frame.channel_id == channel_id => {
                    if frame.sequence != expected_sequence {
                        return Err(Error::msg("received relay DATA sequence gap"));
                    }
                    return Ok(frame.payload);
                }
                FrameType::Close if frame.channel_id == channel_id => {
                    return Err(Error::msg("peer closed relay channel"));
                }
                FrameType::Error => return Err(protocol_error(&frame.payload)),
                FrameType::Ping => {
                    self.write_frame(RelayFrame {
                        frame_type: FrameType::Pong,
                        ..frame
                    })
                    .await?;
                }
                FrameType::Pong => {}
                _ => return Err(Error::msg("unexpected relay frame on active channel")),
            }
        }
    }

    async fn read_frame(&mut self) -> Result<RelayFrame> {
        loop {
            match read_ws_message_async(&mut self.reader, false).await? {
                WsMessage::Binary(bytes) => return RelayFrame::decode(&bytes),
                WsMessage::Ping(payload) => {
                    write_ws_message_async(&mut self.writer, &WsMessage::Pong(payload), true)
                        .await?;
                }
                WsMessage::Pong(_) => {}
                WsMessage::Close(_) => return Err(Error::msg("Relay closed the connection")),
            }
        }
    }

    async fn write_frame(&mut self, frame: RelayFrame) -> Result<()> {
        write_ws_message_async(&mut self.writer, &WsMessage::Binary(frame.encode()?), true).await
    }
}

pub fn run_node_probe(
    paths: DataPaths,
    verifier_name: String,
    password: String,
    node_id: u64,
    allow_insecure_local: bool,
) -> Result<service::AvailabilitySubmissionView> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?
        .block_on(async move {
            let now = Utc::now().timestamp();
            let request = service::availability_probe_request(
                &paths,
                &verifier_name,
                &password,
                node_id,
                now,
            )?;
            let wait_seconds = request.scheduled_at.saturating_sub(Utc::now().timestamp());
            if wait_seconds > 0 {
                tokio::time::sleep(Duration::from_secs(wait_seconds as u64)).await;
            }
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                fetch_probe(
                    &request.target.endpoint,
                    &request.target.reward_ip,
                    &request.challenge,
                    allow_insecure_local,
                ),
            )
            .await
            .map_err(|_| Error::msg("node Probe timed out after 10 seconds"))??;
            if response.node_id != node_id || response.challenge != request.challenge {
                return Err(Error::msg("node Probe response does not match request"));
            }
            service::submit_node_probe_attestation(
                &paths,
                &verifier_name,
                &password,
                service::AvailabilityAttestationRequest {
                    epoch: request.epoch,
                    slot: request.slot,
                    role: request.role,
                    ticket_signature: request.ticket_signature,
                    response,
                    now: Utc::now().timestamp(),
                },
            )
        })
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AvailabilityBatchReport {
    pub selected: usize,
    pub submitted: usize,
    pub failed: usize,
}

pub fn run_availability_probe_batch(
    paths: DataPaths,
    verifier_name: String,
    password: String,
    ticket_signer: &service::AvailabilityTicketSigner,
    allow_insecure_local: bool,
    limit: usize,
    concurrency: usize,
) -> Result<AvailabilityBatchReport> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(concurrency.clamp(1, 64))
        .enable_all()
        .build()
        .map_err(Error::Io)?
        .block_on(async move {
            let requests = service::availability_probe_requests(
                &paths,
                &verifier_name,
                ticket_signer,
                Utc::now().timestamp(),
                limit,
            )?;
            let selected = requests.len();
            let concurrency = concurrency.clamp(1, 64);
            let mut requests = requests.into_iter();
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let Some(request) = requests.next() else {
                    break;
                };
                tasks.spawn(async move {
                    let response = tokio::time::timeout(
                        Duration::from_secs(10),
                        fetch_probe(
                            &request.target.endpoint,
                            &request.target.reward_ip,
                            &request.challenge,
                            allow_insecure_local,
                        ),
                    )
                    .await
                    .map_err(|_| Error::msg("node Probe timed out after 10 seconds"))??;
                    if response.node_id != request.target.node_id
                        || response.challenge != request.challenge
                    {
                        return Err(Error::msg("node Probe response does not match request"));
                    }
                    Ok::<_, Error>((request, response))
                });
            }
            let mut submitted = 0_usize;
            let mut failed = 0_usize;
            while let Some(outcome) = tasks.join_next().await {
                match outcome {
                    Ok(Ok((request, response))) => {
                        match service::submit_node_probe_attestation(
                            &paths,
                            &verifier_name,
                            &password,
                            service::AvailabilityAttestationRequest {
                                epoch: request.epoch,
                                slot: request.slot,
                                role: request.role,
                                ticket_signature: request.ticket_signature,
                                response,
                                now: Utc::now().timestamp(),
                            },
                        ) {
                            Ok(_) => submitted += 1,
                            Err(_) => failed += 1,
                        }
                    }
                    Ok(Err(_)) | Err(_) => failed += 1,
                }
                if let Some(request) = requests.next() {
                    tasks.spawn(async move {
                        let response = tokio::time::timeout(
                            Duration::from_secs(10),
                            fetch_probe(
                                &request.target.endpoint,
                                &request.target.reward_ip,
                                &request.challenge,
                                allow_insecure_local,
                            ),
                        )
                        .await
                        .map_err(|_| Error::msg("node Probe timed out after 10 seconds"))??;
                        if response.node_id != request.target.node_id
                            || response.challenge != request.challenge
                        {
                            return Err(Error::msg("node Probe response does not match request"));
                        }
                        Ok::<_, Error>((request, response))
                    });
                }
            }
            Ok(AvailabilityBatchReport {
                selected,
                submitted,
                failed,
            })
        })
}

pub fn sync_consensus_peer(
    paths: DataPaths,
    name: String,
    password: String,
    target_node_id: u64,
    allow_insecure_local: bool,
    tls_ca: Option<PathBuf>,
) -> Result<Vec<ConsensusWireMessage>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?
        .block_on(async move {
            tokio::time::timeout(Duration::from_secs(60), async move {
                let local = paths.read_node_config(&name)?;
                if local.node_id == Some(target_node_id) {
                    return Err(Error::msg(
                        "refusing to open a consensus connection to self",
                    ));
                }
                let target = service::node_record_by_id(&paths, target_node_id)?;
                let mut url = normalize_websocket_url(&target.endpoint, RELAY_PATH)?;
                url.set_path(CONSENSUS_PATH);
                url.set_query(None);
                url.set_fragment(None);
                let mut stream = connect_websocket_protocol(
                    url.as_str(),
                    CONSENSUS_PATH,
                    CONSENSUS_PROTOCOL,
                    allow_insecure_local,
                    tls_ca.as_deref(),
                )
                .await?;
                let challenge_message = read_consensus_message(&mut stream).await?;
                let ConsensusWireMessage::Challenge { challenge } = challenge_message else {
                    return Err(Error::msg("consensus peer did not send CHALLENGE first"));
                };
                if challenge.server_node_id != target_node_id {
                    return Err(Error::msg("consensus challenge came from the wrong Node"));
                }
                let hello = service::create_consensus_hello(
                    &paths,
                    &name,
                    &password,
                    &challenge,
                    Utc::now().timestamp(),
                )?;
                write_consensus_message_async(&mut stream, &ConsensusWireMessage::Hello { hello })
                    .await?;
                let ConsensusWireMessage::Welcome {
                    server_node_id,
                    authenticated_validator_node_id,
                } = read_consensus_message(&mut stream).await?
                else {
                    return Err(Error::msg("consensus peer rejected HELLO"));
                };
                if server_node_id != target_node_id
                    || Some(authenticated_validator_node_id) != local.node_id
                {
                    return Err(Error::msg("consensus WELCOME identifies the wrong peer"));
                }
                let mut catch_up_from =
                    service::block_status(&paths, Utc::now().timestamp())?.height;
                let mut catch_up_blocks = Vec::new();
                let mut catch_up_operations = Vec::new();
                loop {
                    write_consensus_message_async(
                        &mut stream,
                        &ConsensusWireMessage::CatchUpRequest {
                            from_height: catch_up_from,
                        },
                    )
                    .await?;
                    let response = read_consensus_message(&mut stream).await?;
                    let ConsensusWireMessage::CatchUpChunk {
                        tip_height,
                        blocks,
                        operations,
                        finalized_checkpoint_json,
                    } = response
                    else {
                        if let ConsensusWireMessage::Error { code, message } = response {
                            return Err(Error::msg(format!(
                                "consensus peer returned {code}: {message}"
                            )));
                        }
                        return Err(Error::msg(
                            "consensus peer returned an invalid catch-up chunk",
                        ));
                    };
                    if tip_height < catch_up_from {
                        return Err(Error::msg(
                            "consensus peer tip moved behind catch-up position",
                        ));
                    }
                    if blocks.is_empty() {
                        if tip_height != catch_up_from {
                            return Err(Error::msg(
                                "consensus peer returned an empty catch-up gap",
                            ));
                        }
                        break;
                    }
                    catch_up_from = blocks.last().expect("non-empty").height;
                    catch_up_blocks.extend(blocks);
                    catch_up_operations.extend(operations);
                    if let Some(checkpoint_json) = finalized_checkpoint_json {
                        if catch_up_from != tip_height {
                            return Err(Error::msg(
                                "consensus peer sent a checkpoint before its advertised tip",
                            ));
                        }
                        let checkpoint = serde_json::from_str(&checkpoint_json)?;
                        service::apply_consensus_catch_up(
                            &paths,
                            std::mem::take(&mut catch_up_blocks),
                            std::mem::take(&mut catch_up_operations),
                            checkpoint,
                        )
                        .map_err(|error| {
                            Error::msg(format!("failed to apply consensus catch-up: {error}"))
                        })?;
                        break;
                    }
                    if catch_up_from == tip_height {
                        return Err(Error::msg(
                            "consensus peer reached its tip without a finalized checkpoint",
                        ));
                    }
                }
                let status = service::consensus_status(&paths, Utc::now().timestamp())?;
                let ledger = paths.read_ledger()?;
                let mut outbound = Vec::new();
                outbound.extend(
                    service::consensus_pending_operations(&paths)?
                        .into_iter()
                        .map(|envelope| ConsensusWireMessage::Operation { envelope }),
                );
                if let Some(proposal) = ledger.consensus.proposal {
                    outbound.push(ConsensusWireMessage::Proposal {
                        block: proposal.block,
                    });
                }
                outbound.extend(
                    ledger
                        .consensus
                        .prevotes
                        .into_values()
                        .map(|vote| ConsensusWireMessage::Vote { vote }),
                );
                outbound.extend(
                    ledger
                        .consensus
                        .precommits
                        .into_values()
                        .map(|vote| ConsensusWireMessage::Vote { vote }),
                );
                write_consensus_message_async(
                    &mut stream,
                    &ConsensusWireMessage::SyncRequest {
                        height: status.height,
                        round: status.round,
                    },
                )
                .await?;
                let sync = read_consensus_message(&mut stream).await?;
                let ConsensusWireMessage::SyncState {
                    height,
                    round,
                    proposal,
                    prevotes,
                    precommits,
                    pending_operations,
                } = &sync
                else {
                    if let ConsensusWireMessage::Error { code, message } = sync {
                        return Err(Error::msg(format!(
                            "consensus peer returned {code}: {message}"
                        )));
                    }
                    return Err(Error::msg("consensus peer returned an invalid SYNC_STATE"));
                };
                if *height != status.height {
                    return Err(Error::msg("consensus SYNC_STATE changed height"));
                }
                if *round != status.round {
                    if *round > status.round {
                        // A single peer cannot force a round jump. Advance at most
                        // one round and only after our own authenticated state
                        // machine says its local timeout has elapsed.
                        let _ = service::advance_consensus_round(&paths, Utc::now().timestamp());
                    }
                    return Ok(vec![sync]);
                }
                for envelope in pending_operations.iter().cloned() {
                    service::submit_consensus_operation(&paths, envelope, Utc::now().timestamp())?;
                }
                if let Some(block) = proposal.clone() {
                    service::submit_consensus_proposal(&paths, block, Utc::now().timestamp())?;
                }
                for vote in prevotes.iter().chain(precommits.iter()).cloned() {
                    let submission =
                        service::submit_consensus_vote(&paths, vote, Utc::now().timestamp())?;
                    if submission.finalized_block.is_some() {
                        break;
                    }
                }

                let mut responses = Vec::with_capacity(outbound.len() + 2);
                responses.push(sync);
                for message in outbound {
                    write_consensus_message_async(&mut stream, &message).await?;
                    let response = read_consensus_message(&mut stream).await?;
                    if let ConsensusWireMessage::Error { code, message } = &response {
                        return Err(Error::msg(format!(
                            "consensus peer returned {code}: {message}"
                        )));
                    }
                    let finalized = matches!(
                        response,
                        ConsensusWireMessage::Ack {
                            finalized_height: Some(_),
                            ..
                        }
                    );
                    responses.push(response);
                    if finalized {
                        break;
                    }
                }
                write_consensus_message_async(&mut stream, &ConsensusWireMessage::StatusRequest)
                    .await?;
                responses.push(read_consensus_message(&mut stream).await?);
                Ok(responses)
            })
            .await
            .map_err(|_| Error::msg("consensus peer synchronization timed out"))?
        })
}

async fn read_consensus_message(stream: &mut BoxedIo) -> Result<ConsensusWireMessage> {
    loop {
        match read_ws_message_async(stream, false).await? {
            WsMessage::Binary(bytes) => {
                if bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
                    return Err(Error::msg("consensus message exceeds 16 MiB"));
                }
                return Ok(serde_json::from_slice(&bytes)?);
            }
            WsMessage::Ping(payload) => {
                write_ws_message_async(stream, &WsMessage::Pong(payload), true).await?;
            }
            WsMessage::Pong(_) => {}
            WsMessage::Close(_) => return Err(Error::msg("consensus peer closed connection")),
        }
    }
}

async fn write_consensus_message_async(
    stream: &mut BoxedIo,
    message: &ConsensusWireMessage,
) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_CONSENSUS_MESSAGE_SIZE {
        return Err(Error::msg("consensus message exceeds 16 MiB"));
    }
    write_ws_message_async(stream, &WsMessage::Binary(bytes), true).await
}

#[doc(hidden)]
pub async fn connect_websocket(
    endpoint: &str,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<BoxedIo> {
    connect_websocket_protocol(
        endpoint,
        RELAY_PATH,
        crate::relay::RELAY_PROTOCOL,
        allow_insecure_local,
        tls_ca,
    )
    .await
}

async fn connect_websocket_protocol(
    endpoint: &str,
    expected_path: &str,
    subprotocol: &str,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<BoxedIo> {
    let url = normalize_websocket_url(endpoint, expected_path)?;
    if url.path() != expected_path {
        return Err(Error::msg(format!(
            "WebSocket URL path must be {expected_path}"
        )));
    }
    let mut stream = connect_transport(&url, allow_insecure_local, tls_ca).await?;
    websocket_client_upgrade(&mut stream, &url, subprotocol).await?;
    Ok(stream)
}

async fn connect_transport(
    url: &Url,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<BoxedIo> {
    connect_transport_at(url, None, allow_insecure_local, tls_ca).await
}

async fn connect_transport_at(
    url: &Url,
    connect_ip: Option<IpAddr>,
    allow_insecure_local: bool,
    tls_ca: Option<&Path>,
) -> Result<BoxedIo> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::msg("Relay URL is missing its host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::msg("Relay URL is missing its port"))?;
    let tcp = if let Some(ip) = connect_ip {
        TcpStream::connect(std::net::SocketAddr::new(ip, port)).await?
    } else {
        TcpStream::connect((host, port)).await?
    };
    tcp.set_nodelay(true)?;
    let stream: BoxedIo = match url.scheme() {
        "wss" => {
            let mut roots =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = tls_ca {
                roots
                    .add(CertificateDer::from(load_pem_block(path, "CERTIFICATE")?))
                    .map_err(|error| Error::msg(format!("invalid TLS CA certificate: {error}")))?;
            }
            let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = ServerName::try_from(host.to_owned())
                .map_err(|_| Error::msg("Relay host is not a valid TLS server name"))?;
            let tls = TlsConnector::from(Arc::new(config))
                .connect(server_name, tcp)
                .await
                .map_err(|error| Error::msg(format!("Relay TLS handshake failed: {error}")))?;
            Box::new(tls)
        }
        "ws" if allow_insecure_local && is_local_host(host) => Box::new(tcp),
        "ws" => {
            return Err(Error::msg(
                "plaintext ws:// is allowed only for loopback with --allow-insecure-local",
            ));
        }
        _ => return Err(Error::msg("Relay URL must use wss://")),
    };
    Ok(stream)
}

async fn fetch_probe(
    endpoint: &str,
    reward_ip: &str,
    challenge: &str,
    allow_insecure_local: bool,
) -> Result<ProbePayload> {
    let url = normalize_websocket_url(endpoint, RELAY_PATH)?;
    let reward_ip = reward_ip
        .parse::<IpAddr>()
        .map_err(|_| Error::msg("registered Probe reward IP is invalid"))?;
    let mut stream =
        connect_transport_at(&url, Some(reward_ip), allow_insecure_local, None).await?;
    let host = url.host_str().expect("validated endpoint");
    let request = format!(
        "GET /v1/probe?challenge={challenge} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        authority(&url)
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::with_capacity(2_048);
    let mut chunk = [0_u8; 2_048];
    loop {
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..size]);
        if response.len() > 64 * 1024 {
            return Err(Error::msg("node Probe HTTP response exceeds 64 KiB"));
        }
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| Error::msg("node Probe returned an invalid HTTP response"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| Error::msg("node Probe HTTP headers are not valid UTF-8"))?;
    if !headers.starts_with("HTTP/1.1 200 ") {
        return Err(Error::msg(format!(
            "node Probe endpoint rejected request for {host}"
        )));
    }
    Ok(serde_json::from_slice(&response[header_end..])?)
}

async fn websocket_client_upgrade(
    stream: &mut BoxedIo,
    url: &Url,
    subprotocol: &str,
) -> Result<()> {
    let key = STANDARD.encode(random_bytes::<16>()?);
    let authority = authority(url);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {subprotocol}\r\n\r\n",
        url.path()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::with_capacity(1_024);
    let mut byte = [0_u8; 1];
    while response.len() < 8_192 {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(Error::msg("Relay WebSocket response headers exceed 8 KiB"));
    }
    let response = std::str::from_utf8(&response)
        .map_err(|_| Error::msg("Relay WebSocket response is not valid HTTP"))?;
    if !response.starts_with("HTTP/1.1 101 ") {
        return Err(Error::msg("Relay rejected the WebSocket upgrade"));
    }
    let expected_accept = websocket_accept_key(&key)?;
    let mut accept_matches = false;
    let mut protocol_matches = false;
    for line in response.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-accept" => accept_matches = value.trim() == expected_accept,
            "sec-websocket-protocol" => protocol_matches = value.trim() == subprotocol,
            _ => {}
        }
    }
    if !accept_matches || !protocol_matches {
        return Err(Error::msg(
            "Relay WebSocket response has an invalid accept key or subprotocol",
        ));
    }
    Ok(())
}

fn authority(url: &Url) -> String {
    let host = url.host_str().expect("validated URL");
    if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        format!("[{host}]:{}", url.port_or_known_default().unwrap())
    } else {
        format!("{host}:{}", url.port_or_known_default().unwrap())
    }
}

async fn read_relay_frame(stream: &mut BoxedIo) -> Result<RelayFrame> {
    loop {
        match read_ws_message_async(stream, false).await? {
            WsMessage::Binary(bytes) => return RelayFrame::decode(&bytes),
            WsMessage::Ping(payload) => {
                write_ws_message_async(stream, &WsMessage::Pong(payload), true).await?;
            }
            WsMessage::Pong(_) => {}
            WsMessage::Close(_) => return Err(Error::msg("Relay closed the connection")),
        }
    }
}

async fn write_relay_frame(stream: &mut BoxedIo, frame: RelayFrame) -> Result<()> {
    write_ws_message_async(stream, &WsMessage::Binary(frame.encode()?), true).await
}

fn protocol_error(payload: &[u8]) -> Error {
    serde_json::from_slice::<ErrorPayload>(payload).map_or_else(
        |_| Error::msg("Relay returned an invalid protocol error"),
        |error| Error::msg(format!("Relay {}: {}", error.code, error.message)),
    )
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn load_pem_block(path: &Path, label: &str) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end).map(|(body, _)| body))
        .ok_or_else(|| Error::msg(format!("{} does not contain a PEM {label}", path.display())))?;
    let encoded = body.lines().map(str::trim).collect::<String>();
    STANDARD
        .decode(encoded)
        .map_err(|_| Error::msg(format!("{} contains invalid PEM base64", path.display())))
}
