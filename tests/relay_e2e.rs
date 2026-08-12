use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use mrk_core::{
    amount::MRK_SCALE,
    consensus::ConsensusWireMessage,
    model::{IpSlotRecord, NodeStatus},
    relay_client::{self, RelayConnection},
    service,
    storage::DataPaths,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_root() -> std::path::PathBuf {
    let random = mrk_core::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-relay-e2e-{}",
        mrk_core::crypto::hex_lower(&random)
    ))
}

fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target_path = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target_path);
        } else {
            std::fs::copy(entry.path(), target_path).unwrap();
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_health(port: u16) {
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.contains("200 OK") {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("relay node did not become healthy");
}

fn pem_block(path: &std::path::Path, label: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text
        .split_once(&begin)
        .unwrap()
        .1
        .split_once(&end)
        .unwrap()
        .0;
    STANDARD
        .decode(body.lines().map(str::trim).collect::<String>())
        .unwrap()
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn two_members_exchange_bidirectional_bytes_through_real_relay() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "relay-e2e-password";
    let now = Utc::now().timestamp();
    service::create_account(&paths, "owner", password).unwrap();
    let owner = service::account_keyfile(&paths, "owner").unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.accounts.get_mut(&owner.address).unwrap().balance = 10 * MRK_SCALE;
            Ok(())
        })
        .unwrap();
    service::create_network(&paths, "owner", password, "team", now).unwrap();
    let (alice_credential, _) =
        service::issue_member(&paths, "owner", password, "team", "alice", 7, now + 1).unwrap();
    let (bob_credential, _) =
        service::issue_member(&paths, "owner", password, "team", "bob", 7, now + 2).unwrap();
    service::init_node(&paths, "node1", password).unwrap();
    let node = service::join_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        Some("0.02MRK"),
        now + 3,
    )
    .unwrap();
    service::fund_network(&paths, "owner", password, "team", "3MRK", now + 4).unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    let alice_key = paths
        .read_keyfile(&paths.member_key_path("team", "alice").unwrap())
        .unwrap();
    let session_id = mrk_core::crypto::hex_lower(&mrk_core::crypto::random_bytes::<32>().unwrap());
    let authorization_operation = service::sign_public_operation(
        &alice_key,
        password,
        service::PublicOperationSigningRequest {
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            module: "TrafficPayment",
            action: "ReserveSession",
            nonce: 1,
            valid_until: now + 5 + mrk_core::model::DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({
                "network_commitment": network.commitment,
                "node_id": node.node_id,
                "sender_member_id": alice_credential.member_id,
                "receiver_member_id": bob_credential.member_id,
                "session_id": session_id,
                "max_amount_base_units": MRK_SCALE.to_string(),
                "authorization_valid_until": now + 3605,
                "spending_policy_revision": network.spending_policy.revision,
                "expected_price_per_gib_base_units": node.price_per_gib.to_string(),
            }),
        },
    )
    .unwrap();
    let authorization_id =
        mrk_core::crypto::sha256_id("op", &serde_json::to_vec(&authorization_operation).unwrap());
    service::submit_signed_network_operation(
        &paths,
        &alice_key.public_key,
        authorization_operation,
        now + 5,
    )
    .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 6).unwrap();
    let port = free_port();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.warmup_seconds = 0;
            ledger.settings.probe_validity_seconds = 300;
            ledger.nodes.get_mut(&node.node_id).unwrap().endpoint =
                format!("ws://127.0.0.1:{port}/v1/relay");
            Ok(())
        })
        .unwrap();
    let client_root = temp_root();
    copy_tree(&root, &client_root);
    let alice_cli_root = temp_root();
    let bob_cli_root = temp_root();
    copy_tree(&root, &alice_cli_root);
    copy_tree(&root, &bob_cli_root);
    drop(paths);
    let client_paths = DataPaths::new(Some(client_root.clone())).unwrap();
    client_paths
        .with_ledger_mut(|ledger| {
            ledger.networks.clear();
            ledger.network_aliases.clear();
            Ok(())
        })
        .unwrap();
    for cli_root in [&alice_cli_root, &bob_cli_root] {
        let cli_paths = DataPaths::new(Some(cli_root.clone())).unwrap();
        cli_paths
            .with_ledger_mut(|ledger| {
                ledger.networks.clear();
                ledger.network_aliases.clear();
                Ok(())
            })
            .unwrap();
    }
    let child = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("node")
        .arg("--node")
        .arg("node1")
        .arg("run")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--allow-insecure-local")
        .env("MRK_KEYSTORE_PASSWORD", password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child_guard = ChildGuard(child);
    wait_for_health(port);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests")
            .join("fixtures");
        let cert_path = fixture_dir.join("localhost-cert.pem");
        let ca_path = fixture_dir.join("test-ca.pem");
        let cert = CertificateDer::from(pem_block(&cert_path, "CERTIFICATE"));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_block(
            &fixture_dir.join("localhost-key.pem"),
            "PRIVATE KEY",
        )));
        let tls_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let tls_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let tls_port = tls_listener.local_addr().unwrap().port();
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let proxy = tokio::spawn(async move {
            loop {
                let (socket, _) = tls_listener.accept().await.unwrap();
                let acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let mut frontend = acceptor.accept(socket).await.unwrap();
                    let mut backend = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut frontend, &mut backend).await;
                });
            }
        });
        let endpoint = format!("wss://localhost:{tls_port}/v1/relay");
        let mut bob = RelayConnection::connect_with_ca(
            &client_paths,
            "team",
            "bob",
            password,
            &endpoint,
            false,
            Some(&ca_path),
        )
        .await
        .unwrap();
        assert!(
            RelayConnection::connect_with_ca(
                &client_paths,
                "team",
                "bob",
                password,
                &endpoint,
                false,
                Some(&ca_path),
            )
            .await
            .is_err()
        );
        let mut alice = RelayConnection::connect_with_ca(
            &client_paths,
            "team",
            "alice",
            password,
            &endpoint,
            false,
            Some(&ca_path),
        )
        .await
        .unwrap();

        let mut rpc_endpoint = url::Url::parse(&endpoint).unwrap();
        rpc_endpoint.set_path("/v1/rpc");
        let list_output = tokio::task::block_in_place(|| {
            Command::new(env!("CARGO_BIN_EXE_mrk"))
                .arg("--data-dir")
                .arg(&client_root)
                .arg("--rpc-endpoint")
                .arg(rpc_endpoint.as_str())
                .arg("--rpc-tls-ca")
                .arg(&ca_path)
                .arg("--output")
                .arg("json")
                .arg("member")
                .arg("list")
                .arg("--network")
                .arg("team")
                .output()
        })
        .unwrap();
        assert!(
            list_output.status.success(),
            "{}",
            String::from_utf8_lossy(&list_output.stderr)
        );
        let online_presence: service::MemberPresenceListView =
            serde_json::from_slice(&list_output.stdout).unwrap();
        assert_eq!(online_presence.relay_node_id, node.node_id);
        assert_eq!(online_presence.members.len(), 2);
        assert!(
            online_presence
                .members
                .iter()
                .all(|member| member.online && member.connection_count == 1)
        );

        let (opened, accepted) = tokio::join!(
            alice.open(&bob_credential.member_id, &authorization_id, "e2e"),
            bob.accept()
        );
        let alice_channel = opened.unwrap();
        let (bob_channel, incoming) = accepted.unwrap();
        assert_eq!(alice_channel, bob_channel);
        assert_eq!(incoming.peer_id, alice_credential.member_id);

        alice
            .send_data(alice_channel, 1, b"alice-to-bob".to_vec())
            .await
            .unwrap();
        assert_eq!(
            bob.receive_data(bob_channel, 1).await.unwrap(),
            b"alice-to-bob"
        );
        bob.send_data(bob_channel, 1, b"bob-to-alice".to_vec())
            .await
            .unwrap();
        assert_eq!(
            alice.receive_data(alice_channel, 1).await.unwrap(),
            b"bob-to-alice"
        );

        drop(alice);
        drop(bob);
        tokio::time::sleep(Duration::from_millis(500)).await;

        let offline_presence: service::MemberPresenceListView = serde_json::from_value(
            tokio::task::block_in_place(|| {
                relay_client::run_rpc_call(
                    rpc_endpoint.as_str(),
                    "member.list",
                    serde_json::json!({"network": "team"}),
                    false,
                    Some(&ca_path),
                )
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            offline_presence
                .members
                .iter()
                .all(|member| !member.online && member.connection_count == 0)
        );
        let unsettled: Vec<service::UnsettledPaymentView> = serde_json::from_value(
            tokio::task::block_in_place(|| {
                relay_client::run_rpc_call(
                    rpc_endpoint.as_str(),
                    "payment.unsettled",
                    serde_json::json!({"network": "team", "member": "alice"}),
                    false,
                    Some(&ca_path),
                )
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(unsettled.len(), 1);
        assert_eq!(unsettled[0].session.authorization_id, authorization_id);
        let mut bob_cli = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&bob_cli_root)
            .arg("pipe")
            .arg("--network")
            .arg("team")
            .arg("--member")
            .arg("bob")
            .arg("--endpoint")
            .arg(&endpoint)
            .arg("--tls-ca")
            .arg(&ca_path)
            .arg("--max-auto-recovery-bytes")
            .arg("1048576")
            .env("MRK_KEYSTORE_PASSWORD", password)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let mut alice_cli = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&alice_cli_root)
            .arg("--yes")
            .arg("pipe")
            .arg("--network")
            .arg("team")
            .arg("--member")
            .arg("alice")
            .arg("--endpoint")
            .arg(&endpoint)
            .arg("--peer")
            .arg("bob")
            .arg("--tls-ca")
            .arg(&ca_path)
            .arg("--max-auto-recovery-bytes")
            .arg("1048576")
            .env("MRK_KEYSTORE_PASSWORD", password)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2_500)).await;

        let mut alice_stdin = alice_cli.stdin.take().unwrap();
        let mut alice_stdout = alice_cli.stdout.take().unwrap();
        let mut bob_stdin = bob_cli.stdin.take().unwrap();
        let mut bob_stdout = bob_cli.stdout.take().unwrap();
        let large_payload = (0..256 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let (alice_tx, alice_rx) = std::sync::mpsc::channel();
        let (alice_eof_tx, alice_eof_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut bytes = vec![0_u8; 16 + 256 * 1024];
            let result = bob_stdout.read_exact(&mut bytes).map(|_| bytes);
            let succeeded = result.is_ok();
            let _ = alice_tx.send(result);
            if succeeded {
                let mut trailing = Vec::new();
                let _ = alice_eof_tx.send(bob_stdout.read_to_end(&mut trailing).map(|_| trailing));
            }
        });
        let (bob_tx, bob_rx) = std::sync::mpsc::channel();
        let (bob_eof_tx, bob_eof_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut bytes = [0_u8; 16];
            let result = alice_stdout.read_exact(&mut bytes).map(|_| bytes);
            let succeeded = result.is_ok();
            let _ = bob_tx.send(result);
            if succeeded {
                let mut trailing = Vec::new();
                let _ = bob_eof_tx.send(alice_stdout.read_to_end(&mut trailing).map(|_| trailing));
            }
        });
        alice_stdin.write_all(b"cli-alice-to-bob").unwrap();
        alice_stdin.write_all(&large_payload).unwrap();
        alice_stdin.flush().unwrap();
        let from_alice = alice_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(&from_alice[..16], b"cli-alice-to-bob");
        assert_eq!(&from_alice[16..], large_payload);
        bob_stdin.write_all(b"cli-bob-to-alice").unwrap();
        bob_stdin.flush().unwrap();
        let from_bob = bob_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(&from_bob, b"cli-bob-to-alice");
        for _ in 0..80 {
            alice_stdin.write_all(b"a").unwrap();
            alice_stdin.flush().unwrap();
            bob_stdin.write_all(b"b").unwrap();
            bob_stdin.flush().unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let unsettled: Vec<service::UnsettledPaymentView> = serde_json::from_value(
            tokio::task::block_in_place(|| {
                relay_client::run_rpc_call(
                    rpc_endpoint.as_str(),
                    "payment.unsettled",
                    serde_json::json!({"network": "team", "member": "alice"}),
                    false,
                    Some(&ca_path),
                )
            })
            .unwrap(),
        )
        .unwrap();
        assert!(unsettled.is_empty());
        // SAFETY: The Node daemon is the live child process spawned above.
        assert_eq!(
            unsafe { libc::kill(child_guard.0.id() as i32, libc::SIGTERM) },
            0
        );
        let trailing = bob_eof_rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(trailing, vec![b'b'; 80]);
        let trailing = alice_eof_rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(trailing, vec![b'a'; 80]);

        assert!(alice_cli.wait().unwrap().success());
        assert!(bob_cli.wait().unwrap().success());
        drop(alice_stdin);
        drop(bob_stdin);
        assert!(child_guard.0.wait().unwrap().success());
        DataPaths::new(Some(root.clone()))
            .unwrap()
            .with_ledger_mut(|ledger| {
                ledger.nodes.get_mut(&node.node_id).unwrap().endpoint =
                    format!("ws://127.0.0.1:{port}/v1/relay");
                Ok(())
            })
            .unwrap();
        let restarted = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&root)
            .arg("node")
            .arg("--node")
            .arg("node1")
            .arg("run")
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--allow-insecure-local")
            .env("MRK_KEYSTORE_PASSWORD", password)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let restarted_guard = ChildGuard(restarted);
        wait_for_health(port);
        let mut finalized_after_cli_exit = false;
        for _ in 0..30 {
            let history = tokio::task::block_in_place(|| {
                relay_client::run_rpc_call(
                    rpc_endpoint.as_str(),
                    "payment.history",
                    serde_json::json!({"network": "team", "limit": 20}),
                    false,
                    Some(&ca_path),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<service::PaymentHistoryView>(value).map_err(Into::into)
            });
            if history.is_ok_and(|history| {
                history.authorizations.iter().any(|authorization| {
                    authorization.authorization_id != authorization_id
                        && authorization.initiator_member_id == alice_credential.member_id
                        && authorization.reserved_remaining == 0
                        && authorization.closed_at.is_some()
                })
            }) {
                finalized_after_cli_exit = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(
            finalized_after_cli_exit,
            "Node should finalize persisted receipts after both pipe CLIs exit"
        );
        drop(restarted_guard);
        proxy.abort();
    });

    drop(child_guard);
    let ledger = DataPaths::new(Some(root.clone()))
        .unwrap()
        .read_ledger()
        .unwrap();
    let automatic = ledger
        .payment_authorizations
        .values()
        .find(|authorization| {
            authorization.authorization_id != authorization_id
                && authorization.initiator_member_id == alice_credential.member_id
        })
        .expect("CLI pipe should create an automatic payment authorization");
    assert_eq!(automatic.reserved_remaining, 0);
    assert!(automatic.closed_at.is_some());
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_root).unwrap();
    std::fs::remove_dir_all(alice_cli_root).unwrap();
    std::fs::remove_dir_all(bob_cli_root).unwrap();
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn validator_authenticates_and_reads_status_over_consensus_websocket() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "consensus-wss-e2e-password";
    let now = Utc::now().timestamp();
    service::init_node(&paths, "node1", password).unwrap();
    let node1 = service::join_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        Some("0.02MRK"),
        now,
    )
    .unwrap();
    service::init_node(&paths, "node2", password).unwrap();
    service::join_node(
        &paths,
        "node2",
        password,
        "wss://8.8.8.8/v1/relay",
        Some("0.02MRK"),
        now,
    )
    .unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.required_governance_bond = 0;
            ledger.settings.validator_bond = 10;
            ledger.settings.warmup_seconds = 0;
            for node in ledger.nodes.values_mut() {
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                ledger
                    .accounts
                    .get_mut(&node.reward_address)
                    .unwrap()
                    .balance = 10;
            }
            Ok(())
        })
        .unwrap();
    service::join_validator_pool(&paths, "node1", password, now).unwrap();
    service::join_validator_pool(&paths, "node2", password, now).unwrap();
    paths
        .with_ledger_mut(|ledger| {
            for node_id in 3..=20 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.5.{node_id}");
                node.ip_slot = format!("v4:9.9.5.{node_id}");
                node.status = NodeStatus::Active;
                node.validator = false;
                node.validator_bond = 0;
                node.validator_candidate_since = None;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                let ip_slot = node.ip_slot.clone();
                ledger.nodes.insert(node_id, node);
                ledger.ip_slots.insert(
                    ip_slot,
                    IpSlotRecord {
                        node_id,
                        bound_at: now,
                        released_at: None,
                    },
                );
            }
            ledger.next_node_id = 21;
            Ok(())
        })
        .unwrap();
    let committee = service::validator_committee(&paths, now).unwrap();
    assert_eq!(committee.active_validator_ids, vec![1, 2]);
    service::produce_node1_block(&paths, "node1", password, false, now).unwrap();

    let port = free_port();
    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&1).unwrap().endpoint = format!("ws://127.0.0.1:{port}/v1/relay");
            Ok(())
        })
        .unwrap();
    drop(paths);
    let client_root = temp_root();
    copy_tree(&root, &client_root);
    let server_paths = DataPaths::new(Some(root.clone())).unwrap();
    service::produce_node1_block(&server_paths, "node1", password, true, now).unwrap();
    let catch_up = service::consensus_catch_up_chunk(&server_paths, 1, 256).unwrap();
    serde_json::to_vec(&ConsensusWireMessage::CatchUpChunk {
        tip_height: catch_up.tip_height,
        blocks: catch_up.blocks,
        operations: catch_up.operations,
        finalized_checkpoint_json: catch_up
            .finalized_checkpoint
            .map(|checkpoint| serde_json::to_string(&checkpoint).unwrap()),
    })
    .unwrap();
    drop(server_paths);
    let child = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("node")
        .arg("--node")
        .arg("node1")
        .arg("run")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--allow-insecure-local")
        .env("MRK_KEYSTORE_PASSWORD", password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child_guard = ChildGuard(child);
    wait_for_health(port);
    let client_paths = DataPaths::new(Some(client_root.clone())).unwrap();

    let responses = relay_client::sync_consensus_peer(
        client_paths.clone(),
        "node2".to_owned(),
        password.to_owned(),
        1,
        true,
        None,
    )
    .unwrap();
    assert!(matches!(
        responses.last(),
        Some(ConsensusWireMessage::Status { .. })
    ));
    let caught_up = service::verify_blockchain(&client_paths).unwrap();
    assert!(caught_up.ok, "{}", caught_up.detail);
    assert!(caught_up.height >= 2);

    drop(child_guard);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_root).unwrap();
}

#[test]
#[ignore = "requires four loopback mrk node processes"]
fn four_independent_validators_gossip_operation_and_finalize() {
    let master_root = temp_root();
    let paths = DataPaths::new(Some(master_root.clone())).unwrap();
    let password = "four-validator-wss-password";
    let now = Utc::now().timestamp();
    let endpoints = [
        "wss://1.1.1.1/v1/relay",
        "wss://8.8.8.8/v1/relay",
        "wss://9.9.9.9/v1/relay",
        "wss://208.67.222.222/v1/relay",
    ];
    let mut registered = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let name = format!("node{}", index + 1);
        service::init_node(&paths, &name, password).unwrap();
        registered.push(
            service::join_node(&paths, &name, password, endpoint, Some("0.02MRK"), now).unwrap(),
        );
    }
    let recipient = service::create_local_account(&paths, "recipient", password).unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.required_governance_bond = 0;
            ledger.settings.validator_bond = 10;
            ledger.settings.warmup_seconds = 0;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.probe_validity_seconds = 300;
            for node in ledger.nodes.values_mut() {
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                ledger
                    .accounts
                    .get_mut(&node.reward_address)
                    .unwrap()
                    .balance = 2 * MRK_SCALE;
            }
            Ok(())
        })
        .unwrap();
    for node_id in 1..=4 {
        service::join_validator_pool(&paths, &format!("node{node_id}"), password, now).unwrap();
    }
    let template = registered[0].clone();
    let ports = (0..4).map(|_| free_port()).collect::<Vec<_>>();
    paths
        .with_ledger_mut(|ledger| {
            for node_id in 5..=20 {
                let mut node = template.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.7.{node_id}");
                node.ip_slot = format!("v4:9.9.7.{node_id}");
                node.status = NodeStatus::Active;
                node.active_since = Some(now);
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                node.validator = false;
                node.validator_bond = 0;
                node.validator_candidate_since = None;
                let ip_slot = node.ip_slot.clone();
                ledger.nodes.insert(node_id, node);
                ledger.ip_slots.insert(
                    ip_slot,
                    IpSlotRecord {
                        node_id,
                        bound_at: now,
                        released_at: None,
                    },
                );
            }
            ledger.next_node_id = 21;
            for (index, port) in ports.iter().enumerate() {
                ledger
                    .nodes
                    .get_mut(&((index + 1) as u64))
                    .unwrap()
                    .endpoint = format!("ws://127.0.0.1:{port}/v1/relay");
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        service::validator_committee(&paths, now)
            .unwrap()
            .active_validator_ids,
        vec![1, 2, 3, 4]
    );
    service::transfer(
        &paths,
        "node:node1",
        password,
        &recipient.address,
        "1MRK",
        now + 1,
    )
    .unwrap();
    drop(paths);

    let mut roots = vec![master_root.clone()];
    for _ in 1..4 {
        let root = temp_root();
        copy_tree(&master_root, &root);
        roots.push(root);
    }
    let mut children = Vec::new();
    // A four-member committee must finalize with one Validator unavailable.
    for index in 0..3 {
        let child = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&roots[index])
            .arg("node")
            .arg("--node")
            .arg(format!("node{}", index + 1))
            .arg("run")
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", ports[index]))
            .arg("--allow-insecure-local")
            .env("MRK_KEYSTORE_PASSWORD", password)
            .stdout(if std::env::var_os("MRK_CONSENSUS_DEBUG").is_some() {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if std::env::var_os("MRK_CONSENSUS_DEBUG").is_some() {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        children.push(ChildGuard(child));
    }
    for port in &ports[..3] {
        wait_for_health(*port);
    }
    thread::sleep(Duration::from_secs(15));

    // The unavailable Validator must catch up after it rejoins.
    let index = 3;
    let child = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&roots[index])
        .arg("node")
        .arg("--node")
        .arg(format!("node{}", index + 1))
        .arg("run")
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", ports[index]))
        .arg("--allow-insecure-local")
        .env("MRK_KEYSTORE_PASSWORD", password)
        .stdout(if std::env::var_os("MRK_CONSENSUS_DEBUG").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(if std::env::var_os("MRK_CONSENSUS_DEBUG").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
        .unwrap();
    children.push(ChildGuard(child));
    wait_for_health(ports[index]);
    thread::sleep(Duration::from_secs(10));
    drop(children);

    let mut hashes = Vec::new();
    for root in &roots {
        let node_paths = DataPaths::new(Some(root.clone())).unwrap();
        let report = service::verify_blockchain(&node_paths).unwrap();
        assert!(report.ok, "{}", report.detail);
        assert!(report.height >= 1);
        assert_eq!(
            service::balance(&node_paths, &recipient.address)
                .unwrap()
                .balance,
            MRK_SCALE
        );
        hashes.push(service::block_by_height(&node_paths, 1).unwrap().block_hash);
    }
    assert!(hashes.iter().all(|hash| hash == &hashes[0]));

    for root in roots {
        std::fs::remove_dir_all(root).unwrap();
    }
}
