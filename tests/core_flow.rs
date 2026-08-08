use chrono::Utc;
use mrk::{
    amount::MRK_SCALE, model::NodeStorageMode, relay::ChallengePayload, service, storage::DataPaths,
};

fn temp_root(label: &str) -> std::path::PathBuf {
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-{label}-{}", mrk::crypto::hex_lower(&random)))
}

#[test]
fn node_reward_transfer_and_private_network_flow() {
    let root = temp_root("core-flow");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "integration-test-password";
    let bob = service::create_account(&paths, "bob", password).unwrap();
    let node_config = service::init_node(&paths, "node1", password).unwrap();
    assert_eq!(node_config.storage_mode, NodeStorageMode::Full);
    let now = Utc::now().timestamp();

    let slot_seconds = 60;
    let epoch_start = now.div_euclid(slot_seconds) * slot_seconds;
    paths
        .with_ledger_mut(|ledger| {
            ledger.epoch_started_at = epoch_start;
            ledger.settings.epoch_seconds = 60;
            ledger.epoch_seconds_snapshot = 60;
            ledger.settings.availability_slot_seconds = slot_seconds;
            ledger.settings.warmup_seconds = 0;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.required_service_bond = 0;
            Ok(())
        })
        .unwrap();

    let node = service::register_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now,
    )
    .unwrap();
    assert_eq!(node.node_id, 1);
    let request = service::availability_probe_request(&paths, "node1", password, 1, now).unwrap();
    let probe =
        service::node_probe_response(&paths, "node1", password, &request.challenge).unwrap();
    let attestation = service::submit_node_probe_attestation(
        &paths,
        "node1",
        password,
        service::AvailabilityAttestationRequest {
            epoch: request.epoch,
            slot: request.slot,
            role: request.role,
            ticket_signature: request.ticket_signature,
            response: probe,
            now,
        },
    )
    .unwrap();
    let credited_seconds = (epoch_start + slot_seconds - now) as u64;
    assert_eq!(attestation.credited_seconds, credited_seconds);

    let epoch_before_query = paths.read_ledger().unwrap().epoch_number;
    let before_finality = service::node_rewards(&paths, "node1").unwrap();
    assert_eq!(before_finality.claimable_reward, 0);
    assert_eq!(before_finality.vesting_reward, 0);
    assert_eq!(
        paths.read_ledger().unwrap().epoch_number,
        epoch_before_query
    );
    assert!(
        service::claim_node_rewards(&paths, "node1", password, epoch_start + 61).is_err(),
        "claim must not advance an Epoch before a block is finalized"
    );

    service::produce_node1_block(&paths, "node1", password, false, epoch_start + 61).unwrap();
    let finalized_rewards = service::node_rewards(&paths, "node1").unwrap();
    let epoch_after_block = paths.read_ledger().unwrap().epoch_number;
    let repeated_query = service::node_rewards(&paths, "node1").unwrap();
    assert_eq!(
        repeated_query.claimable_reward,
        finalized_rewards.claimable_reward
    );
    assert_eq!(
        repeated_query.vesting_reward,
        finalized_rewards.vesting_reward
    );
    assert_eq!(paths.read_ledger().unwrap().epoch_number, epoch_after_block);

    let (_, claimed) =
        service::claim_node_rewards(&paths, "node1", password, epoch_start + 61).unwrap();
    let expected_epoch_reward = 500 * MRK_SCALE;
    assert_eq!(claimed, expected_epoch_reward / 10);
    let rewards = service::node_rewards(&paths, "node1").unwrap();
    assert_eq!(rewards.vesting_reward, expected_epoch_reward * 9 / 10);
    assert_eq!(rewards.vesting_schedule_count, 1);
    let reward_balance = service::balance(&paths, &node_config.reward_address).unwrap();
    assert_eq!(reward_balance.balance, claimed);
    service::produce_node1_block(&paths, "node1", password, false, epoch_start + 62).unwrap();

    let transfer = service::transfer(
        &paths,
        "node:node1",
        password,
        &bob.address,
        "0.05MRK",
        now + 62,
    )
    .unwrap();
    assert_eq!(transfer.amount, MRK_SCALE / 20);
    assert_eq!(
        service::balance(&paths, &bob.address).unwrap().balance,
        MRK_SCALE / 20
    );

    let network =
        service::create_network(&paths, "node:node1", password, "team", now + 63).unwrap();
    assert_eq!(network.alias, "team");
    service::fund_network(&paths, "node:node1", password, "team", "0.05MRK", now + 64).unwrap();
    let (credential, credential_path) = service::issue_member(
        &paths,
        "node:node1",
        password,
        "team",
        "client-a",
        7,
        now + 65,
    )
    .unwrap();
    assert!(credential_path.exists());
    let relay_key = paths
        .read_keyfile(&paths.node_relay_key_path("node1").unwrap())
        .unwrap();
    let challenge = ChallengePayload {
        challenge: "integration-challenge-1234567890".into(),
        relay_public_key: relay_key.public_key,
        node_id: node.node_id,
        timestamp: now + 65,
    };
    let hello =
        service::create_member_hello(&paths, "team", "client-a", password, &challenge, now + 65)
            .unwrap();
    let authenticated = service::authenticate_member(&paths, &challenge, &hello, now + 65).unwrap();
    assert_eq!(authenticated.member_id, credential.member_id);
    service::revoke_member(
        &paths,
        "node:node1",
        password,
        "team",
        credential.serial,
        now + 66,
    )
    .unwrap();
    assert!(service::authenticate_member(&paths, &challenge, &hello, now + 66).is_err());

    service::init_node(&paths, "node2", password).unwrap();
    let duplicate = service::register_node(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now + 100,
    )
    .unwrap();
    assert_eq!(duplicate.node_id, 2);
    assert_eq!(
        paths
            .read_ledger()
            .unwrap()
            .ip_slots
            .get("v4:1.1.1.1")
            .unwrap()
            .node_id,
        1
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 101).unwrap();

    let stale = service::node_tick(&paths, "node1", now + 400).unwrap();
    assert!(matches!(stale.status, mrk::model::NodeStatus::Active));
    assert_eq!(stale.total_eligible_seconds, credited_seconds);
    service::drain_node(&paths, "node1", password, now + 401).unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 402).unwrap();
    assert!(matches!(
        service::node_record(&paths, "node1").unwrap().status,
        mrk::model::NodeStatus::Exited
    ));
    assert_eq!(
        paths
            .read_ledger()
            .unwrap()
            .ip_slots
            .get("v4:1.1.1.1")
            .unwrap()
            .released_at,
        Some(now + 402)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn externally_signed_transfer_is_verified_and_committed_by_database_owner() {
    let root = temp_root("signed-transfer");
    let paths = DataPaths::new(Some(root)).unwrap();
    let password = "integration-test-password";
    let alice = service::create_local_account(&paths, "alice", password).unwrap();
    let bob = service::create_local_account(&paths, "bob", password).unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .entry(alice.address.clone())
                .or_default()
                .balance = 10 * MRK_SCALE;
            Ok(())
        })
        .unwrap();
    let ledger_id = paths.read_ledger().unwrap().ledger_id;
    let (public_key, operation) = service::sign_transfer_for_submission(
        &alice,
        password,
        service::TransferSigningRequest {
            ledger_id: &ledger_id,
            to: &bob.address,
            amount_text: "2MRK",
            nonce: 1,
            valid_until: Utc::now().timestamp() + 600,
        },
    )
    .unwrap();
    let receipt =
        service::submit_signed_transfer(&paths, &public_key, operation, Utc::now().timestamp())
            .unwrap();
    assert_eq!(receipt.amount, 2 * MRK_SCALE);
    assert_eq!(
        service::balance(&paths, &bob.address).unwrap().balance,
        2 * MRK_SCALE
    );
}

#[test]
fn consensus_replays_signed_operation_identically_across_databases() {
    let first_root = temp_root("consensus-operation-first");
    let second_root = temp_root("consensus-operation-second");
    let first = DataPaths::new(Some(first_root.clone())).unwrap();
    let second = DataPaths::new(Some(second_root.clone())).unwrap();
    let password = "consensus-operation-password";
    let alice = service::create_local_account(&first, "alice", password).unwrap();
    let bob = service::create_local_account(&first, "bob", password).unwrap();
    for paths in [&first, &second] {
        paths
            .with_ledger_mut(|ledger| {
                let account = ledger.accounts.entry(alice.address.clone()).or_default();
                account.public_key = Some(alice.public_key.clone());
                account.balance = 10 * MRK_SCALE;
                Ok(())
            })
            .unwrap();
    }
    let now = Utc::now().timestamp();
    let (public_key, operation) = service::sign_transfer_for_submission(
        &alice,
        password,
        service::TransferSigningRequest {
            ledger_id: &first.read_ledger().unwrap().ledger_id,
            to: &bob.address,
            amount_text: "2MRK",
            nonce: 1,
            valid_until: now + 600,
        },
    )
    .unwrap();
    let envelope = mrk::consensus::PendingOperationEnvelope {
        public_key,
        operation,
    };
    let first_id = service::submit_consensus_operation(&first, envelope.clone(), now).unwrap();
    let second_id = service::submit_consensus_operation(&second, envelope, now).unwrap();
    assert_eq!(first_id, second_id);
    let first_ledger = first.read_ledger().unwrap();
    let second_ledger = second.read_ledger().unwrap();
    assert_eq!(
        first_ledger.pending_operation_ids,
        second_ledger.pending_operation_ids
    );
    assert_eq!(
        first_ledger.accounts[&alice.address].balance,
        second_ledger.accounts[&alice.address].balance
    );
    assert_eq!(
        first_ledger.accounts[&bob.address].balance,
        second_ledger.accounts[&bob.address].balance
    );

    std::fs::remove_dir_all(first_root).unwrap();
    std::fs::remove_dir_all(second_root).unwrap();
}

#[test]
fn externally_signed_network_operations_are_committed_by_database_owner() {
    let paths = DataPaths::new(Some(temp_root("signed-network"))).unwrap();
    let password = "integration-test-password";
    let owner = service::create_local_account(&paths, "owner", password).unwrap();
    let ledger_id = paths.read_ledger().unwrap().ledger_id;
    let now = Utc::now().timestamp();
    let (network_id, commitment) = service::new_network_identity().unwrap();
    let create = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &ledger_id,
            module: "NetworkRegistry",
            action: "CreateNetwork",
            nonce: 1,
            valid_until: now + 600,
            payload: serde_json::json!({
                "alias": "team",
                "network_id": network_id,
                "network_commitment": commitment,
            }),
        },
    )
    .unwrap();
    service::submit_signed_network_operation(&paths, &owner.public_key, create, now).unwrap();
    let network = service::network_by_alias(&paths, "team").unwrap();
    let (_, credential, issue) = service::prepare_member_issue(
        &owner,
        password,
        service::MemberIssueSigningRequest {
            ledger_id: &ledger_id,
            network: &network,
            member_name: "client-a",
            valid_days: 7,
            nonce: 2,
            now,
        },
    )
    .unwrap();
    let (_, _, conflicting_issue) = service::prepare_member_issue(
        &owner,
        password,
        service::MemberIssueSigningRequest {
            ledger_id: &ledger_id,
            network: &network,
            member_name: "client-a",
            valid_days: 7,
            nonce: 2,
            now,
        },
    )
    .unwrap();
    service::submit_signed_network_operation(&paths, &owner.public_key, issue, now).unwrap();
    let conflicting_id =
        mrk::crypto::sha256_id("op", &serde_json::to_vec(&conflicting_issue).unwrap());
    let conflict = service::submit_consensus_operation(
        &paths,
        mrk::consensus::PendingOperationEnvelope {
            public_key: owner.public_key.clone(),
            operation: conflicting_issue,
        },
        now,
    )
    .unwrap_err();
    assert!(
        conflict.to_string().contains("nonce") || conflict.to_string().contains("credential state")
    );
    assert!(
        !paths
            .read_ledger()
            .unwrap()
            .operations
            .contains_key(&conflicting_id)
    );
    let revoke = service::sign_public_operation(
        &owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &ledger_id,
            module: "NetworkRegistry",
            action: "RevokeMember",
            nonce: 3,
            valid_until: now + 600,
            payload: serde_json::json!({ "network": "team", "serial": credential.serial }),
        },
    )
    .unwrap();
    service::submit_signed_network_operation(&paths, &owner.public_key, revoke, now).unwrap();
    assert!(
        service::network_by_alias(&paths, "team").unwrap().members["client-a"]
            .revoked_at
            .is_some()
    );
}
