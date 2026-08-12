use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use mrk_core::{
    Error, Result,
    endpoint::{RELAY_PATH, RPC_PATH, normalize_websocket_url},
    model::NetworkRecord,
    relay_client::rpc_call,
    service,
    storage::DataPaths,
};
use tokio::io::{AsyncWriteExt, split};

use mrk_sdk::{ClientOptions, MemberIdentity, RelayClient, RelayError};

const PIPE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
static PIPE_INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn peer_member_id(network: &NetworkRecord, peer: &str) -> Result<String> {
    if let Some(member) = network.members.get(peer) {
        return Ok(member.member_id.clone());
    }
    if network
        .members
        .values()
        .any(|member| member.member_id == peer)
    {
        return Ok(peer.to_owned());
    }
    Err(Error::msg(format!(
        "peer Member '{peer}' was not found by name or member_id in Network '{}'",
        network.alias
    )))
}

async fn load_network_record(
    endpoint: &str,
    network: &str,
    allow_insecure_local: bool,
    tls_ca: Option<&std::path::Path>,
) -> Result<NetworkRecord> {
    let mut rpc_endpoint = normalize_websocket_url(endpoint, RELAY_PATH)?;
    rpc_endpoint.set_path(RPC_PATH);
    rpc_endpoint.set_query(None);
    rpc_endpoint.set_fragment(None);
    let value = rpc_call(
        rpc_endpoint.as_str(),
        "network.get",
        serde_json::json!({"alias": network}),
        allow_insecure_local,
        tls_ca,
    )
    .await?;
    serde_json::from_value(value).map_err(Into::into)
}

extern "C" fn record_pipe_interrupt(_: libc::c_int) {
    PIPE_INTERRUPTED.store(true, Ordering::Release);
}

struct PipeInterruptGuard {
    previous: libc::sighandler_t,
}

impl PipeInterruptGuard {
    fn install() -> Result<Self> {
        PIPE_INTERRUPTED.store(false, Ordering::Release);
        // SAFETY: SIGINT is process-global and the handler only performs an atomic store.
        let previous = unsafe {
            libc::signal(
                libc::SIGINT,
                record_pipe_interrupt as *const () as libc::sighandler_t,
            )
        };
        if previous == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { previous })
    }
}

impl Drop for PipeInterruptGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` came from the successful signal installation above.
        unsafe {
            libc::signal(libc::SIGINT, self.previous);
        }
    }
}

async fn wait_for_pipe_interrupt() {
    loop {
        if PIPE_INTERRUPTED.swap(false, Ordering::AcqRel) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub struct StdioPipeOptions {
    pub paths: DataPaths,
    pub network: String,
    pub member: String,
    pub password: String,
    pub endpoint: String,
    pub peer: Option<String>,
    pub allow_insecure_local: bool,
    pub tls_ca: Option<PathBuf>,
    pub max_auto_recovery_bytes: u64,
    pub yes: bool,
}

pub struct RecoverySettlementOptions {
    pub paths: DataPaths,
    pub network: String,
    pub member: String,
    pub password: String,
    pub endpoint: String,
    pub authorization_id: String,
    pub allow_insecure_local: bool,
    pub tls_ca: Option<PathBuf>,
    pub max_auto_recovery_bytes: u64,
}

fn confirm_pipe_service_fee(fee: u128, recommended_max_fee: u128, yes: bool) -> Result<()> {
    if fee == 0 {
        return Ok(());
    }
    eprintln!("Service fee: {}", super::format_mrk(fee));
    eprintln!(
        "Maximum service fee: {}",
        super::format_mrk(recommended_max_fee)
    );
    if yes {
        return Ok(());
    }

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            Error::msg(
                "mrk pipe needs --yes to confirm a service fee when no controlling terminal is available",
            )
        })?;
    let mut reader = std::io::BufReader::new(tty.try_clone()?);
    let mut writer = tty;
    std::io::Write::write_all(&mut writer, b"Type \"yes\" to confirm and submit: ")?;
    std::io::Write::flush(&mut writer)?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut reader, &mut answer)?;
    if answer.trim() != "yes" {
        return Err(Error::msg("operation cancelled"));
    }
    Ok(())
}

pub fn run_stdio_pipe(options: StdioPipeOptions) -> Result<()> {
    let _interrupt_guard = PipeInterruptGuard::install()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?;
    let result = runtime.block_on(async move {
            let StdioPipeOptions {
                paths,
                network,
                member,
                password,
                endpoint,
                peer,
                allow_insecure_local,
                tls_ca,
                max_auto_recovery_bytes,
                yes,
            } = options;
            if let Some(peer) = &peer {
                eprintln!("pipe: resolving peer {peer} on Network {network}");
            } else {
                eprintln!("pipe: loading Network {network}");
            }
            let network_record = load_network_record(
                &endpoint,
                &network,
                allow_insecure_local,
                tls_ca.as_deref(),
            )
            .await?;
            let peer = peer
                .map(|peer| peer_member_id(&network_record, &peer))
                .transpose()?;
            eprintln!("pipe: loading Member {member} identity");
            let identity = MemberIdentity::from_data_paths_with_network_record(
                &paths,
                &network,
                &member,
                &password,
                &network_record,
            )
            .map_err(|error| Error::msg(error.to_string()))?;
            let unsettled = if peer.is_some() && max_auto_recovery_bytes > 0 {
                eprintln!("pipe: checking interrupted Relay sessions");
                let mut rpc_endpoint = normalize_websocket_url(&endpoint, RELAY_PATH)?;
                rpc_endpoint.set_path(RPC_PATH);
                rpc_endpoint.set_query(None);
                rpc_endpoint.set_fragment(None);
                let value = rpc_call(
                    rpc_endpoint.as_str(),
                    "payment.unsettled",
                    serde_json::json!({"network": network, "member": member}),
                    allow_insecure_local,
                    tls_ca.as_deref(),
                )
                .await?;
                serde_json::from_value::<Vec<service::UnsettledPaymentView>>(value)?
            } else {
                Vec::new()
            };
            drop(paths);
            let mut client_options = ClientOptions::new(&endpoint, identity)
                .allow_insecure_local(allow_insecure_local);
            if let Some(path) = &tls_ca {
                client_options = client_options.tls_ca(path);
            }
            eprintln!("pipe: connecting to Relay {endpoint}");
            let connection = RelayClient::connect(client_options)
                .await
                .map_err(|error| Error::msg(error.to_string()))?;
            eprintln!("pipe: Relay connection authenticated");
            let stream = if let Some(peer_id) = peer {
                for item in unsettled.into_iter().filter(|item| {
                    let authorization = &item.authorization;
                    authorization.sender_member_id == peer_id
                        || authorization.receiver_member_id == peer_id
                }) {
                    eprintln!(
                        "Recovering interrupted Relay authorization {} before opening a new session",
                        item.session.authorization_id
                    );
                    connection
                        .recover_existing(
                            &peer_id,
                            &item.session.authorization_id,
                            max_auto_recovery_bytes,
                        )
                        .await
                        .map_err(|error| Error::msg(error.to_string()))?;
                }
                eprintln!("pipe: authorizing encrypted stream to member {peer_id}");
                connection
                    .open_auto_with_fee_confirmation(peer_id, move |quote| {
                        confirm_pipe_service_fee(quote.fee, quote.recommended_max_fee, yes)
                            .map_err(|error| RelayError::Authorization(error.to_string()))
                    })
                    .await
                    .map_err(|error| Error::msg(error.to_string()))?
            } else {
                eprintln!("pipe: waiting for an incoming encrypted stream");
                loop {
                    let incoming = connection
                        .accept()
                        .await
                        .map_err(|error| Error::msg(error.to_string()))?;
                    if incoming.is_recovery() {
                        let authorization_id = incoming.authorization_id().to_owned();
                        incoming
                            .recover(max_auto_recovery_bytes)
                            .await
                            .map_err(|error| Error::msg(error.to_string()))?;
                        eprintln!(
                            "Recovered interrupted Relay authorization {authorization_id}; waiting for a new session"
                        );
                        continue;
                    }
                    break incoming
                        .accept()
                        .await
                        .map_err(|error| Error::msg(error.to_string()))?;
                }
            };
            eprintln!(
                "pipe: ready; encrypted Relay stream connected to member {}; piping stdin/stdout",
                stream.peer_id(),
            );
            let (mut stream_reader, mut stream_writer) = split(stream);
            let mut stdin = tokio::io::stdin();
            let mut stdout = tokio::io::stdout();
            let (stop_upload, mut stop_upload_receiver) = tokio::sync::watch::channel(false);
            let upload = async {
                let copy_result = tokio::select! {
                    result = tokio::io::copy(&mut stdin, &mut stream_writer) => {
                        result.map(|_| ())
                    }
                    _ = async {
                        while !*stop_upload_receiver.borrow() {
                            if stop_upload_receiver.changed().await.is_err() {
                                break;
                            }
                        }
                    } => Ok(()),
                };
                if std::env::var_os("MRK_RELAY_DEBUG").is_some() {
                    eprintln!("pipe member {member}: closing local stream input");
                }
                let shutdown_result = stream_writer.shutdown().await;
                copy_result?;
                shutdown_result
            };
            let download = async {
                let copy_result = tokio::io::copy(&mut stream_reader, &mut stdout).await;
                let _ = stop_upload.send(true);
                if std::env::var_os("MRK_RELAY_DEBUG").is_some() {
                    eprintln!("pipe member {member}: authenticated remote EOF");
                }
                copy_result?;
                stdout.flush().await
            };
            let transfer = async { tokio::try_join!(upload, download).map(|_| ()) };
            tokio::pin!(transfer);
            let result = tokio::select! {
                result = &mut transfer => result,
                _ = wait_for_pipe_interrupt() => {
                    eprintln!(
                        "Ctrl+C received; closing Relay stream and settling Network Fund reservation"
                    );
                    let _ = stop_upload.send(true);
                    tokio::select! {
                        result = &mut transfer => result,
                        _ = wait_for_pipe_interrupt() => Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "second Ctrl+C forced shutdown before final receipts completed",
                        )),
                        _ = tokio::time::sleep(PIPE_SHUTDOWN_TIMEOUT) => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Relay final receipt exchange did not complete within 30 seconds",
                        )),
                    }
                }
            };
            result.map_err(|error| Error::msg(format!("pipe member {member}: {error}")))?;
            eprintln!("Relay stream closed; final receipts persisted by Node");
            Ok(())
        });
    // `tokio::io::stdin` uses a blocking reader thread. If the remote side closes while
    // stdin remains open (notably during Node drain), waiting for the Runtime destructor
    // would keep the CLI alive until another byte or EOF arrived on stdin.
    runtime.shutdown_background();
    result
}

pub fn run_recovery_settlement(options: RecoverySettlementOptions) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::Io)?
        .block_on(async move {
            let RecoverySettlementOptions {
                paths,
                network,
                member,
                password,
                endpoint,
                authorization_id,
                allow_insecure_local,
                tls_ca,
                max_auto_recovery_bytes,
            } = options;
            let identity = MemberIdentity::from_relay(
                &paths,
                &network,
                &member,
                &password,
                &endpoint,
                allow_insecure_local,
                tls_ca.as_deref(),
            )
            .await
            .map_err(|error| Error::msg(error.to_string()))?;
            let local_member_id = identity.credential().member_id.clone();
            let mut rpc_endpoint = normalize_websocket_url(&endpoint, RELAY_PATH)?;
            rpc_endpoint.set_path(RPC_PATH);
            rpc_endpoint.set_query(None);
            rpc_endpoint.set_fragment(None);
            let value = rpc_call(
                rpc_endpoint.as_str(),
                "payment.get",
                serde_json::json!({"authorization_id": authorization_id}),
                allow_insecure_local,
                tls_ca.as_deref(),
            )
            .await?;
            let authorization: service::RelayAuthorizationView = serde_json::from_value(value)?;
            if authorization.authorization.network_id != identity.credential().network_id {
                return Err(Error::msg(
                    "payment authorization belongs to a different Network",
                ));
            }
            let initiator = if local_member_id == authorization.authorization.sender_member_id {
                true
            } else if local_member_id == authorization.authorization.receiver_member_id {
                false
            } else {
                return Err(Error::msg(
                    "local Member is not a participant in this payment authorization",
                ));
            };
            let peer_id = if initiator {
                authorization.authorization.receiver_member_id.clone()
            } else {
                authorization.authorization.sender_member_id.clone()
            };
            drop(paths);
            let mut client_options =
                ClientOptions::new(&endpoint, identity).allow_insecure_local(allow_insecure_local);
            if let Some(path) = &tls_ca {
                client_options = client_options.tls_ca(path);
            }
            let connection = RelayClient::connect(client_options)
                .await
                .map_err(|error| Error::msg(error.to_string()))?;
            if initiator {
                connection
                    .recover_existing(&peer_id, &authorization_id, max_auto_recovery_bytes)
                    .await
                    .map_err(|error| Error::msg(error.to_string()))?;
            } else {
                loop {
                    let incoming = connection
                        .accept()
                        .await
                        .map_err(|error| Error::msg(error.to_string()))?;
                    if incoming.authorization_id() == authorization_id
                        && incoming.peer_id() == peer_id
                    {
                        incoming
                            .recover(max_auto_recovery_bytes)
                            .await
                            .map_err(|error| Error::msg(error.to_string()))?;
                        break;
                    }
                    incoming
                        .reject()
                        .await
                        .map_err(|error| Error::msg(error.to_string()))?;
                }
            }
            connection
                .close()
                .await
                .map_err(|error| Error::msg(error.to_string()))?;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mrk_core::model::{MemberRecord, NetworkSpendingPolicy};

    use super::*;

    fn network() -> NetworkRecord {
        let mut members = BTreeMap::new();
        members.insert(
            "client-b".to_owned(),
            MemberRecord {
                name: "client-b".to_owned(),
                member_id: "0123456789abcdef0123456789abcdef".to_owned(),
                public_key: "member-key".to_owned(),
                serial: 2,
                issued_at: 1,
                expires_at: i64::MAX,
                revoked_at: None,
                credential_signature: "signature".to_owned(),
            },
        );
        NetworkRecord {
            network_id: "network-id".to_owned(),
            commitment: "network-commitment".to_owned(),
            alias: "team".to_owned(),
            owner_address: "owner".to_owned(),
            owner_public_key: "owner-key".to_owned(),
            created_at: 1,
            escrow_balance: 0,
            next_member_serial: 3,
            members,
            spending_policy: NetworkSpendingPolicy::default(),
        }
    }

    #[test]
    fn peer_accepts_member_name_or_id() {
        let network = network();
        let member_id = "0123456789abcdef0123456789abcdef";
        assert_eq!(peer_member_id(&network, "client-b").unwrap(), member_id);
        assert_eq!(peer_member_id(&network, member_id).unwrap(), member_id);
        assert!(
            peer_member_id(&network, "missing")
                .unwrap_err()
                .to_string()
                .contains("not found by name or member_id")
        );
    }
}
