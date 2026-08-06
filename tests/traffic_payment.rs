use chrono::Utc;
use mrk::{
    amount::{MRK_SCALE, parse_mrk},
    model::{DEFAULT_OPERATION_VALIDITY_SECONDS, RelayDirection},
    relay::{relay_transcript_initial_hash, relay_transcript_next_hash},
    service,
    storage::DataPaths,
};

fn temp_root() -> std::path::PathBuf {
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-traffic-payment-{}",
        mrk::crypto::hex_lower(&random)
    ))
}

#[test]
fn dual_signed_cumulative_receipt_releases_only_authorized_escrow() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "traffic-payment-test-password";
    let now = Utc::now().timestamp();
    let config = service::init_node(&paths, "node1", password).unwrap();
    let node = service::register_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now,
    )
    .unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .get_mut(&config.reward_address)
                .unwrap()
                .balance = 10 * MRK_SCALE;
            Ok(())
        })
        .unwrap();
    service::create_network(&paths, "node:node1", password, "team", now + 1).unwrap();
    service::fund_network(&paths, "node:node1", password, "team", "2MRK", now + 2).unwrap();
    let (alice, _) =
        service::issue_member(&paths, "node:node1", password, "team", "alice", 7, now + 3).unwrap();
    let (bob, _) =
        service::issue_member(&paths, "node:node1", password, "team", "bob", 7, now + 4).unwrap();
    let owner = service::account_keyfile(&paths, "node:node1").unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let mut unfunded_network = network.clone();
    unfunded_network.escrow_balance = 0;
    let unfunded_error = service::prepare_payment_authorization(
        &owner,
        password,
        service::PaymentAuthorizationSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            network: &unfunded_network,
            node_id: node.node_id,
            sender_member_name: "alice",
            receiver_member_name: "bob",
            max_amount_text: "1MRK",
            valid_minutes: 60,
            nonce,
            now: now + 5,
        },
    )
    .unwrap_err();
    assert!(
        unfunded_error
            .to_string()
            .contains("insufficient Network Escrow")
    );
    let (session_id, authorization_operation) = service::prepare_payment_authorization(
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
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .networks
                .get_mut(&network.commitment)
                .unwrap()
                .escrow_balance = 0;
            Ok(())
        })
        .unwrap();
    let unfunded_submission = service::submit_consensus_operation(
        &paths,
        mrk::consensus::PendingOperationEnvelope {
            public_key: owner.public_key.clone(),
            operation: authorization_operation.clone(),
        },
        now + 5,
    )
    .unwrap_err();
    assert!(
        unfunded_submission
            .to_string()
            .contains("insufficient Network Escrow")
    );
    assert!(
        !paths
            .read_ledger()
            .unwrap()
            .operations
            .contains_key(&authorization_id)
    );
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .networks
                .get_mut(&network.commitment)
                .unwrap()
                .escrow_balance = network.escrow_balance;
            Ok(())
        })
        .unwrap();
    service::submit_signed_network_operation(
        &paths,
        &owner.public_key,
        authorization_operation,
        now + 5,
    )
    .unwrap();
    let pending_authorization = paths
        .with_ledger_mut(|ledger| {
            Ok(ledger
                .payment_authorizations
                .remove(&authorization_id)
                .unwrap())
        })
        .unwrap();
    for identifier in [&authorization_id, &session_id] {
        let status = service::payment_authorization_status(&paths, identifier).unwrap();
        assert_eq!(status.authorization_id, authorization_id);
        assert_eq!(status.session_id, session_id);
        assert!(matches!(
            status.status,
            mrk::model::OperationStatus::Pending
        ));
        assert!(status.authorization.is_none());
    }
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .payment_authorizations
                .insert(authorization_id.clone(), pending_authorization);
            Ok(())
        })
        .unwrap();
    let pending_view = service::relay_authorization_view(&paths, &session_id).unwrap();
    assert_eq!(
        pending_view.authorization.authorization_id,
        authorization_id
    );
    assert!(!pending_view.finalized);
    assert!(
        service::validate_relay_open(
            &paths,
            &authorization_id,
            node.node_id,
            &network.network_id,
            &alice.member_id,
            &bob.member_id,
            now + 5,
        )
        .is_err(),
        "Relay must not serve a merely pending authorization"
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 6).unwrap();
    let finalized_status = service::payment_authorization_status(&paths, &session_id).unwrap();
    assert!(matches!(
        finalized_status.status,
        mrk::model::OperationStatus::Finalized
    ));
    assert!(finalized_status.authorization.is_some());
    assert!(
        service::relay_authorization_view(&paths, &session_id)
            .unwrap()
            .finalized
    );
    service::validate_relay_open(
        &paths,
        &authorization_id,
        node.node_id,
        &network.network_id,
        &alice.member_id,
        &bob.member_id,
        now + 6,
    )
    .unwrap();
    let authorization = service::payment_authorization(&paths, &authorization_id).unwrap();
    assert_eq!(authorization.reserved_remaining, MRK_SCALE);
    assert_eq!(authorization.session_id, session_id);

    let mut transcript = relay_transcript_initial_hash(
        &paths.read_ledger().unwrap().ledger_id,
        node.node_id,
        &authorization_id,
        &session_id,
        RelayDirection::SenderToReceiver,
    );
    let payload = vec![7_u8; 32 * 1024 * 1024];
    transcript = relay_transcript_next_hash(&transcript, 1, &payload);
    let checkpoint = service::sign_sender_checkpoint(
        &paths,
        "team",
        "alice",
        password,
        service::SenderCheckpointSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            node_id: node.node_id,
            authorization_id: &authorization_id,
            session_id: &session_id,
            direction: RelayDirection::SenderToReceiver,
            sequence: 1,
            cumulative_sent_bytes: payload.len() as u64,
            transcript_hash: &transcript,
            checkpoint_at: now + 6,
        },
    )
    .unwrap();
    let receipt =
        service::sign_receiver_receipt(&paths, "team", "bob", password, &checkpoint, now + 7)
            .unwrap();
    let mut forged_receipt = receipt.clone();
    forged_receipt.receiver_signature.replace_range(0..2, "00");
    assert!(
        service::submit_traffic_settlement(
            &paths,
            "node1",
            password,
            checkpoint.clone(),
            forged_receipt,
            now + 8,
        )
        .is_err()
    );
    let before = service::balance(&paths, &config.reward_address)
        .unwrap()
        .balance;
    service::submit_traffic_settlement(
        &paths,
        "node1",
        password,
        checkpoint.clone(),
        receipt.clone(),
        now + 8,
    )
    .unwrap();
    let expected = parse_mrk("0.000625MRK").unwrap();
    let after = service::balance(&paths, &config.reward_address)
        .unwrap()
        .balance;
    assert_eq!(after - before, expected);
    let authorization = service::payment_authorization(&paths, &authorization_id).unwrap();
    assert_eq!(authorization.settled_amount, expected);
    assert_eq!(authorization.reserved_remaining, MRK_SCALE - expected);
    assert_eq!(
        authorization.directions[&RelayDirection::SenderToReceiver]
            .settled_transcript_hash
            .as_deref(),
        Some(transcript.as_str())
    );
    assert_eq!(
        paths.read_ledger().unwrap().nodes[&node.node_id].last_relay_receipt_at,
        Some(now + 7)
    );

    assert!(
        service::submit_traffic_settlement(
            &paths,
            "node1",
            password,
            checkpoint,
            receipt,
            now + 9,
        )
        .is_err()
    );

    let second_payload = [9_u8];
    transcript = relay_transcript_next_hash(&transcript, 2, &second_payload);
    let second_checkpoint = service::sign_sender_checkpoint(
        &paths,
        "team",
        "alice",
        password,
        service::SenderCheckpointSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            node_id: node.node_id,
            authorization_id: &authorization_id,
            session_id: &session_id,
            direction: RelayDirection::SenderToReceiver,
            sequence: 2,
            cumulative_sent_bytes: payload.len() as u64 + 1,
            transcript_hash: &transcript,
            checkpoint_at: now + 10,
        },
    )
    .unwrap();
    let second_receipt = service::sign_receiver_receipt(
        &paths,
        "team",
        "bob",
        password,
        &second_checkpoint,
        now + 11,
    )
    .unwrap();
    service::submit_traffic_settlement(
        &paths,
        "node1",
        password,
        second_checkpoint,
        second_receipt,
        now + 12,
    )
    .unwrap();
    let total_bytes = payload.len() as u128 + 1;
    let price = parse_mrk("0.02MRK").unwrap();
    let gib = 1024_u128 * 1024 * 1024;
    let exact_total = (total_bytes * price).div_ceil(gib);
    assert_eq!(
        service::payment_authorization(&paths, &authorization_id)
            .unwrap()
            .settled_amount,
        exact_total,
        "cumulative settlement must not accumulate per-window rounding"
    );

    let oversized_checkpoint = service::sign_sender_checkpoint(
        &paths,
        "team",
        "alice",
        password,
        service::SenderCheckpointSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            node_id: node.node_id,
            authorization_id: &authorization_id,
            session_id: &session_id,
            direction: RelayDirection::SenderToReceiver,
            sequence: 3,
            cumulative_sent_bytes: 100 * 1024 * 1024 * 1024,
            transcript_hash: "deliberately-large-mutually-attested-prefix",
            checkpoint_at: now + 13,
        },
    )
    .unwrap();
    let oversized_receipt = service::sign_receiver_receipt(
        &paths,
        "team",
        "bob",
        password,
        &oversized_checkpoint,
        now + 14,
    )
    .unwrap();
    assert!(
        service::submit_traffic_settlement(
            &paths,
            "node1",
            password,
            oversized_checkpoint,
            oversized_receipt,
            now + 15,
        )
        .is_err()
    );

    let before_refund = service::network_by_alias(&paths, "team")
        .unwrap()
        .escrow_balance;
    let authorization = service::payment_authorization(&paths, &authorization_id).unwrap();
    let refund_at = authorization.claim_until + 1;
    let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let refund_operation = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            module: "TrafficPayment",
            action: "Refund",
            nonce,
            valid_until: refund_at + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({"authorization_id": authorization_id}),
        },
    )
    .unwrap();
    service::submit_signed_network_operation(
        &paths,
        &owner.public_key,
        refund_operation,
        refund_at,
    )
    .unwrap();
    let refunded = service::payment_authorization(&paths, &authorization_id).unwrap();
    assert_eq!(refunded.reserved_remaining, 0);
    assert_eq!(
        service::network_by_alias(&paths, "team")
            .unwrap()
            .escrow_balance
            - before_refund,
        MRK_SCALE - exact_total
    );
    assert_eq!(alice.member_id, network.members["alice"].member_id);
    assert_eq!(bob.member_id, network.members["bob"].member_id);

    std::fs::remove_dir_all(root).unwrap();
}
