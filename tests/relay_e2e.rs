use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use mrk::{
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
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-relay-e2e-{}", mrk::crypto::hex_lower(&random)))
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
    service::create_network(&paths, "owner", password, "team", now).unwrap();
    let (alice_credential, _) =
        service::issue_member(&paths, "owner", password, "team", "alice", 7, now + 1).unwrap();
    let (bob_credential, _) =
        service::issue_member(&paths, "owner", password, "team", "bob", 7, now + 2).unwrap();
    service::init_node(&paths, "node1", password).unwrap();
    let node = service::register_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now + 3,
    )
    .unwrap();
    let owner = service::account_keyfile(&paths, "owner").unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.accounts.get_mut(&owner.address).unwrap().balance = 10 * MRK_SCALE;
            Ok(())
        })
        .unwrap();
    service::fund_network(&paths, "owner", password, "team", "2MRK", now + 4).unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let (_, authorization_operation) = service::prepare_payment_authorization(
        &owner,
        password,
        service::PaymentAuthorizationSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            network: &network,
            node_id: node.node_id,
            sender_member_name: "alice",
            receiver_member_name: "bob",
            max_amount_text: "1MRK",
            valid_minutes: 60,
            nonce,
            now: now + 5,
        },
    )
    .unwrap();
    let authorization_id =
        mrk::crypto::sha256_id("op", &serde_json::to_vec(&authorization_operation).unwrap());
    service::submit_signed_network_operation(
        &paths,
        &owner.public_key,
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
    drop(paths);
    let client_paths = DataPaths::new(Some(client_root.clone())).unwrap();
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
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

        let mut bob_cli = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&client_root)
            .arg("pipe")
            .arg("--network")
            .arg("team")
            .arg("--member")
            .arg("bob")
            .arg("--endpoint")
            .arg(&endpoint)
            .arg("--tls-ca")
            .arg(&ca_path)
            .env("MRK_KEYSTORE_PASSWORD", password)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let mut alice_cli = Command::new(env!("CARGO_BIN_EXE_mrk"))
            .arg("--data-dir")
            .arg(&client_root)
            .arg("pipe")
            .arg("--network")
            .arg("team")
            .arg("--member")
            .arg("alice")
            .arg("--endpoint")
            .arg(&endpoint)
            .arg("--peer")
            .arg(&bob_credential.member_id)
            .arg("--authorization")
            .arg(&authorization_id)
            .arg("--tls-ca")
            .arg(&ca_path)
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
        alice_stdin.write_all(b"cli-alice-to-bob").unwrap();
        alice_stdin.write_all(&large_payload).unwrap();
        alice_stdin.flush().unwrap();
        drop(alice_stdin);
        let from_alice = alice_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(&from_alice[..16], b"cli-alice-to-bob");
        assert_eq!(&from_alice[16..], large_payload);

        let (bob_tx, bob_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut bytes = [0_u8; 16];
            let result = alice_stdout.read_exact(&mut bytes).and_then(|_| {
                let mut trailing = Vec::new();
                alice_stdout
                    .read_to_end(&mut trailing)
                    .map(|_| (bytes, trailing))
            });
            let _ = bob_tx.send(result);
        });
        bob_stdin.write_all(b"cli-bob-to-alice").unwrap();
        bob_stdin.flush().unwrap();
        drop(bob_stdin);
        let (from_bob, trailing) = bob_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(&from_bob, b"cli-bob-to-alice");
        assert!(trailing.is_empty());
        let trailing = alice_eof_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(trailing.is_empty());

        assert!(alice_cli.wait().unwrap().success());
        assert!(bob_cli.wait().unwrap().success());
        proxy.abort();
    });

    drop(child_guard);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(client_root).unwrap();
}

#[test]
#[ignore = "requires loopback TCP sockets"]
fn validator_authenticates_and_reads_status_over_consensus_websocket() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "consensus-wss-e2e-password";
    let now = Utc::now().timestamp();
    service::init_node(&paths, "node1", password).unwrap();
    let node1 = service::register_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now,
    )
    .unwrap();
    service::init_node(&paths, "node2", password).unwrap();
    service::register_node(
        &paths,
        "node2",
        password,
        "wss://8.8.8.8/v1/relay",
        "0.02MRK",
        now,
    )
    .unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
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
            service::register_node(&paths, &name, password, endpoint, "0.02MRK", now).unwrap(),
        );
    }
    let recipient = service::create_local_account(&paths, "recipient", password).unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
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
