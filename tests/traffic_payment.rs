use chrono::Utc;
use mrk_core::{
    amount::{MRK_SCALE, parse_mrk},
    model::{DEFAULT_OPERATION_VALIDITY_SECONDS, RelayDirection},
    relay::{relay_transcript_initial_hash, relay_transcript_next_hash},
    service,
    storage::{DataPaths, UnsettledRelaySession},
};

#[test]
fn owner_policy_allows_a_member_to_reserve_shared_fund_with_auditable_caps() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "member-reservation-test-password";
    let now = Utc::now().timestamp();
    let config = service::init_node(&paths, "node1", password).unwrap();
    let node = service::join_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        Some("0.02MRK"),
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
        service::issue_member(&paths, "node:node1", password, "team", "alice", 30, now + 3)
            .unwrap();
    let (bob, _) =
        service::issue_member(&paths, "node:node1", password, "team", "bob", 30, now + 4).unwrap();
    let owner = service::account_keyfile(&paths, "node:node1").unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    let owner_nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let policy_operation = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            module: "NetworkEscrow",
            action: "SetSpendingPolicy",
            nonce: owner_nonce,
            valid_until: now + 5 + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({
                "network_commitment": network.commitment,
                "revision": network.spending_policy.revision + 1,
                "enabled": true,
                "max_session_amount_base_units": parse_mrk("0.5MRK").unwrap().to_string(),
                "max_member_reserved_base_units": parse_mrk("0.75MRK").unwrap().to_string(),
                "max_node_price_per_gib_base_units": parse_mrk("1MRK").unwrap().to_string(),
                "max_session_minutes": 60,
            }),
        },
    )
    .unwrap();
    service::submit_signed_network_operation(&paths, &owner.public_key, policy_operation, now + 5)
        .unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    assert_eq!(network.spending_policy.revision, 2);

    let alice_key = paths
        .read_keyfile(&paths.member_key_path("team", "alice").unwrap())
        .unwrap();
    let reserve = |nonce: u64, session_byte: u8, submitted_at: i64| {
        service::sign_public_operation(
            &alice_key,
            password,
            service::PublicOperationSigningRequest {
                max_fee_base_units: u128::MAX,
                fee_policy_version: 1,
                ledger_id: &paths.read_ledger().unwrap().ledger_id,
                module: "TrafficPayment",
                action: "ReserveSession",
                nonce,
                valid_until: submitted_at + DEFAULT_OPERATION_VALIDITY_SECONDS,
                payload: serde_json::json!({
                    "network_commitment": network.commitment,
                    "node_id": node.node_id,
                    "sender_member_id": alice.member_id,
                    "receiver_member_id": bob.member_id,
                    "session_id": format!("{session_byte:02x}").repeat(32),
                    "max_amount_base_units": parse_mrk("1MRK").unwrap().to_string(),
                    "authorization_valid_until": submitted_at + 3600,
                    "spending_policy_revision": network.spending_policy.revision,
                    "expected_price_per_gib_base_units": paths.read_ledger().unwrap().nodes[&node.node_id].price_per_gib.to_string(),
                }),
            },
        )
        .unwrap()
    };
    let first = reserve(1, 0x11, now + 6);
    let first_id = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: first,
        },
        now + 6,
    )
    .unwrap();
    let first = service::payment_authorization(&paths, &first_id).unwrap();
    assert_eq!(first.max_amount, parse_mrk("0.5MRK").unwrap());
    assert_eq!(first.payer_address, owner.address);
    assert_eq!(first.initiator_member_id, alice.member_id);
    assert_eq!(first.spending_policy_revision, 2);
    assert_eq!(first.price_per_gib, parse_mrk("0.02MRK").unwrap());

    let second = reserve(2, 0x22, now + 7);
    let second_id = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: second,
        },
        now + 7,
    )
    .unwrap();
    let second = service::payment_authorization(&paths, &second_id).unwrap();
    assert_eq!(second.max_amount, parse_mrk("0.25MRK").unwrap());

    let exhausted = reserve(3, 0x33, now + 8);
    let exhausted_id = mrk_core::crypto::sha256_id("op", &serde_json::to_vec(&exhausted).unwrap());
    let error = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: exhausted,
        },
        now + 8,
    )
    .unwrap_err();
    assert!(error.to_string().contains("capacity is exhausted"));
    assert!(
        !paths
            .read_ledger()
            .unwrap()
            .operations
            .contains_key(&exhausted_id)
    );

    let stale_quote = reserve(3, 0x44, now + 9);
    service::update_node_price(&paths, "node1", password, "0.03MRK", now + 8).unwrap();
    let stale_quote_error = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: stale_quote,
        },
        now + 9,
    )
    .unwrap_err();
    assert!(stale_quote_error.to_string().contains("price changed"));
    assert_eq!(
        service::payment_authorization(&paths, &first_id)
            .unwrap()
            .price_per_gib,
        parse_mrk("0.02MRK").unwrap()
    );

    let history = service::payment_history(&paths, "team", Some("alice"), 20).unwrap();
    assert_eq!(history.authorizations.len(), 2);
    assert_eq!(history.total_reserved, parse_mrk("0.75MRK").unwrap());
    assert_eq!(history.total_settled, 0);
    assert_eq!(history.fund_balance, parse_mrk("1.248MRK").unwrap());

    service::produce_node1_block(&paths, "node1", password, false, now + 9).unwrap();
    for (direction, sender, receiver, timestamp) in [
        (RelayDirection::SenderToReceiver, "alice", "bob", now + 10),
        (RelayDirection::ReceiverToSender, "bob", "alice", now + 11),
    ] {
        let transcript = relay_transcript_initial_hash(
            &paths.read_ledger().unwrap().ledger_id,
            node.node_id,
            &first_id,
            &first.session_id,
            direction,
        );
        let checkpoint = service::sign_final_sender_checkpoint(
            &paths,
            "team",
            sender,
            password,
            service::SenderCheckpointSigningRequest {
                ledger_id: &paths.read_ledger().unwrap().ledger_id,
                node_id: node.node_id,
                authorization_id: &first_id,
                session_id: &first.session_id,
                direction,
                sequence: 0,
                cumulative_sent_bytes: 0,
                transcript_hash: &transcript,
                checkpoint_at: timestamp,
            },
        )
        .unwrap();
        let receipt = service::sign_receiver_receipt(
            &paths,
            "team",
            receiver,
            password,
            &checkpoint,
            timestamp,
        )
        .unwrap();
        service::submit_traffic_settlement(
            &paths, "node1", password, checkpoint, receipt, timestamp,
        )
        .unwrap();
    }
    let closed = service::payment_authorization(&paths, &first_id).unwrap();
    assert_eq!(closed.reserved_remaining, 0);
    assert_eq!(closed.closed_at, Some(now + 11));
    assert!(
        closed
            .directions
            .values()
            .all(|direction| direction.finalized)
    );
    assert_eq!(
        service::network_by_alias(&paths, "team")
            .unwrap()
            .escrow_balance,
        parse_mrk("1.748MRK").unwrap()
    );

    let reclaim_at = second.claim_until + 1;
    let replacement = reserve(3, 0x44, reclaim_at);
    let replacement_id = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: replacement,
        },
        reclaim_at,
    )
    .unwrap();
    assert_eq!(
        service::payment_authorization(&paths, &replacement_id)
            .unwrap()
            .max_amount,
        parse_mrk("0.5MRK").unwrap()
    );
    let reclaimed = service::payment_authorization(&paths, &second_id).unwrap();
    assert_eq!(reclaimed.reserved_remaining, 0);
    assert_eq!(reclaimed.refunded_at, Some(reclaim_at));
    assert_eq!(
        service::network_by_alias(&paths, "team")
            .unwrap()
            .escrow_balance,
        parse_mrk("1.497MRK").unwrap()
    );

    paths
        .store_unsettled_relay_session(&UnsettledRelaySession {
            authorization_id: replacement_id.clone(),
            network_id: network.network_id.clone(),
            network_commitment: network.commitment.clone(),
            node_id: node.node_id,
            sender_member_id: alice.member_id.clone(),
            receiver_member_id: bob.member_id.clone(),
            disconnected_at: reclaim_at + 1,
        })
        .unwrap();
    assert_eq!(
        service::unsettled_payments(&paths, Some("team"), Some("alice"), None)
            .unwrap()
            .len(),
        1
    );
    service::abandon_traffic_authorization(
        &paths,
        "node1",
        password,
        &replacement_id,
        reclaim_at + 2,
    )
    .unwrap();
    let abandoned = service::payment_authorization(&paths, &replacement_id).unwrap();
    assert_eq!(abandoned.reserved_remaining, 0);
    assert_eq!(abandoned.refunded_at, Some(reclaim_at + 2));
    assert!(paths.unsettled_relay_sessions().unwrap().is_empty());
    assert_eq!(
        service::network_by_alias(&paths, "team")
            .unwrap()
            .escrow_balance,
        parse_mrk("1.997MRK").unwrap()
    );

    std::fs::remove_dir_all(root).unwrap();
}

fn temp_root() -> std::path::PathBuf {
    let random = mrk_core::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-traffic-payment-{}",
        mrk_core::crypto::hex_lower(&random)
    ))
}

#[test]
fn dual_signed_cumulative_receipt_releases_only_authorized_escrow() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "traffic-payment-test-password";
    let now = Utc::now().timestamp();
    let config = service::init_node(&paths, "node1", password).unwrap();
    let node = service::join_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        Some("0.02MRK"),
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
            valid_until: now + 5 + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({
                "network_commitment": network.commitment,
                "node_id": node.node_id,
                "sender_member_id": alice.member_id,
                "receiver_member_id": bob.member_id,
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
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: alice_key.public_key.clone(),
            operation: authorization_operation.clone(),
        },
        now + 5,
    )
    .unwrap_err();
    assert!(
        unfunded_submission
            .to_string()
            .contains("capacity is exhausted")
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
        &alice_key.public_key,
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
            mrk_core::model::OperationStatus::Pending
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
        mrk_core::model::OperationStatus::Finalized
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
    assert!(
        service::validate_relay_open(
            &paths,
            &authorization_id,
            node.node_id,
            &network.network_id,
            &alice.member_id,
            &bob.member_id,
            now + 3605,
        )
        .is_err()
    );
    service::validate_relay_recovery_open(
        &paths,
        &authorization_id,
        node.node_id,
        &network.network_id,
        &alice.member_id,
        &bob.member_id,
        now + 3605,
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
    let ledger_before = paths.read_ledger().unwrap();
    let settlement_id = service::submit_traffic_settlement(
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
    let protocol_fee = expected / 100;
    let treasury_fee = protocol_fee / 2;
    let burned_fee = protocol_fee - treasury_fee;
    assert_eq!(after - before, expected - protocol_fee);
    let ledger_after = paths.read_ledger().unwrap();
    assert_eq!(ledger_after.treasury - ledger_before.treasury, treasury_fee);
    assert_eq!(ledger_after.burned - ledger_before.burned, burned_fee);
    assert_eq!(
        ledger_after.total_settled_traffic_bytes - ledger_before.total_settled_traffic_bytes,
        payload.len() as u128
    );
    let settlement = &ledger_after.operations[&settlement_id];
    assert_eq!(settlement.fee_charged, protocol_fee);
    assert_eq!(settlement.fee_to_treasury, treasury_fee);
    assert_eq!(settlement.fee_burned, burned_fee);
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
    let early_refund_at = authorization.claim_until;
    let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let early_refund = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
            ledger_id: &paths.read_ledger().unwrap().ledger_id,
            module: "TrafficPayment",
            action: "Refund",
            nonce,
            valid_until: early_refund_at + DEFAULT_OPERATION_VALIDITY_SECONDS,
            payload: serde_json::json!({"authorization_id": authorization_id}),
        },
    )
    .unwrap();
    let early_refund_id =
        mrk_core::crypto::sha256_id("op", &serde_json::to_vec(&early_refund).unwrap());
    let error = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: owner.public_key.clone(),
            operation: early_refund,
        },
        early_refund_at,
    )
    .unwrap_err();
    assert!(error.to_string().contains("claim window is still open"));
    let ledger = paths.read_ledger().unwrap();
    assert!(!ledger.operations.contains_key(&early_refund_id));
    assert!(!ledger.pending_operation_ids.contains(&early_refund_id));

    let refund_at = authorization.claim_until + 1;
    let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
    let refund_operation = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
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
