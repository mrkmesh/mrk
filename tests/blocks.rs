use chrono::Utc;
use mrk::{
    model::{IpSlotRecord, NodeStatus, OperationStatus, RewardVestingSchedule},
    service,
    storage::DataPaths,
};

fn temp_root(label: &str) -> std::path::PathBuf {
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-{label}-{}", mrk::crypto::hex_lower(&random)))
}

fn register(
    paths: &DataPaths,
    name: &str,
    password: &str,
    endpoint: &str,
    now: i64,
) -> mrk::model::NodeRecord {
    service::init_node(paths, name, password).unwrap();
    service::register_node(paths, name, password, endpoint, "0.02MRK", now).unwrap()
}

#[test]
fn ip_slot_conflicts_updates_and_exit_are_finalized_deterministically() {
    let root = temp_root("ip-slot-lifecycle");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "ip-slot-integration-password";
    let now = Utc::now().timestamp();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.warmup_seconds = 0;
            ledger.settings.ip_reuse_cooldown_seconds = 10;
            ledger.settings.service_bond_unlock_seconds = 20;
            Ok(())
        })
        .unwrap();

    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let (treasury_before_exit, pool_before_exit, lifetime_minted_before_exit) = paths
        .with_ledger_mut(|ledger| {
            let node = ledger.nodes.get_mut(&1).unwrap();
            node.service_bond = 100;
            node.claimable_reward = 10;
            node.reward_vesting_schedules = vec![RewardVestingSchedule {
                total_amount: 90,
                released_amount: 30,
                starts_at: now,
                ends_at: now + 1_000,
            }];
            Ok((
                ledger.treasury,
                ledger.pool_remaining,
                ledger.lifetime_minted,
            ))
        })
        .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    let conflicting = register(&paths, "node2", password, "wss://1.1.1.1/v1/relay", now + 2);
    assert_eq!(conflicting.node_id, 2);
    service::produce_node1_block(&paths, "node1", password, false, now + 3).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert!(ledger.nodes.contains_key(&2));
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 1);

    let request = service::availability_probe_request(&paths, "node1", password, 2, now).unwrap();
    let response =
        service::node_probe_response(&paths, "node2", password, &request.challenge).unwrap();
    let attestation = service::submit_node_probe_attestation(
        &paths,
        "node1",
        password,
        service::AvailabilityAttestationRequest {
            epoch: request.epoch,
            slot: request.slot,
            role: request.role,
            ticket_signature: request.ticket_signature,
            response,
            now,
        },
    )
    .unwrap();
    assert_eq!(attestation.credited_seconds, 0);
    assert_eq!(
        service::node_record(&paths, "node2").unwrap().status,
        NodeStatus::WarmingUp
    );

    service::drain_node(&paths, "node1", password, now + 5).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().status,
        NodeStatus::Draining
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 6).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].status, NodeStatus::Exited);
    assert_eq!(ledger.nodes[&1].claimable_reward, 10);
    assert_eq!(ledger.nodes[&1].service_bond, 100);
    assert_eq!(ledger.nodes[&1].service_bond_unlock_at, Some(now + 26));
    assert!(ledger.nodes[&1].reward_vesting_schedules.is_empty());
    assert_eq!(ledger.treasury, treasury_before_exit + 60);
    assert_eq!(ledger.pool_remaining, pool_before_exit);
    assert_eq!(ledger.lifetime_minted, lifetime_minted_before_exit);
    assert_eq!(
        ledger.finalized_checkpoint.as_ref().unwrap().nodes[&1].status,
        NodeStatus::Exited
    );
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, Some(now + 6));

    service::update_reward_ip(&paths, "node2", password, "1.1.1.1", now + 10).unwrap();
    assert_eq!(
        service::node_record(&paths, "node2").unwrap().endpoint,
        "wss://1.1.1.1/v1/relay"
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 11).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 1);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, Some(now + 6));

    service::update_reward_ip(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1/v1/relay",
        now + 15,
    )
    .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 16).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 2);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].bound_at, now + 16);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, None);
    assert_eq!(ledger.nodes[&2].status, NodeStatus::WarmingUp);
    assert!(service::withdraw_service_bond(&paths, "node1", password, now + 25).is_err());
    let reward_address = ledger.nodes[&1].reward_address.clone();
    let reward_balance_before = ledger.accounts[&reward_address].balance;
    drop(ledger);

    let (_, withdrawn) =
        service::withdraw_service_bond(&paths, "node1", password, now + 27).unwrap();
    assert_eq!(withdrawn, 100);
    service::produce_node1_block(&paths, "node1", password, false, now + 28).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].service_bond, 0);
    assert_eq!(ledger.nodes[&1].service_bond_unlock_at, None);
    assert_eq!(
        ledger.accounts[&reward_address].balance,
        reward_balance_before + 100
    );
    assert!(service::verify_blockchain(&paths).unwrap().ok);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn finalized_offline_timeout_slashes_bond_and_vesting_to_treasury() {
    let root = temp_root("offline-slash");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "offline-slash-integration-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let (treasury_before, pool_before, lifetime_minted_before, reward_address) = paths
        .with_ledger_mut(|ledger| {
            ledger.settings.offline_slash_seconds = 10;
            let node = ledger.nodes.get_mut(&1).unwrap();
            node.last_probe_success = Some(now);
            node.service_bond = 100;
            node.claimable_reward = 10;
            node.reward_vesting_schedules = vec![RewardVestingSchedule {
                total_amount: 90,
                released_amount: 30,
                starts_at: now,
                ends_at: now + 1_000,
            }];
            Ok((
                ledger.treasury,
                ledger.pool_remaining,
                ledger.lifetime_minted,
                node.reward_address.clone(),
            ))
        })
        .unwrap();

    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().status,
        NodeStatus::Active
    );
    service::drain_node(&paths, "node1", password, now + 10).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().status,
        NodeStatus::Draining
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 11).unwrap();

    let ledger = paths.read_ledger().unwrap();
    let node = &ledger.nodes[&1];
    assert_eq!(node.status, NodeStatus::Exited);
    assert_eq!(node.claimable_reward, 10);
    assert_eq!(node.service_bond, 0);
    assert_eq!(node.service_bond_unlock_at, None);
    assert!(node.reward_vesting_schedules.is_empty());
    assert_eq!(node.offline_slashed_at, Some(now + 11));
    assert_eq!(node.offline_slashed_service_bond, 100);
    assert_eq!(node.offline_slashed_vesting_reward, 60);
    assert_eq!(ledger.treasury, treasury_before + 160);
    assert_eq!(ledger.pool_remaining, pool_before);
    assert_eq!(ledger.lifetime_minted, lifetime_minted_before);
    assert_eq!(ledger.accounts[&reward_address].balance, 0);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, Some(now + 11));
    assert_eq!(
        ledger.finalized_checkpoint.as_ref().unwrap().nodes[&1].offline_slashed_at,
        Some(now + 11)
    );
    assert!(service::verify_blockchain(&paths).unwrap().ok);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_node_installs_only_an_explicitly_pinned_bootstrap_checkpoint() {
    let source_root = temp_root("bootstrap-source");
    let target_root = temp_root("bootstrap-target");
    let source = DataPaths::new(Some(source_root.clone())).unwrap();
    let target = DataPaths::new(Some(target_root.clone())).unwrap();
    let password = "bootstrap-integration-password";
    let now = Utc::now().timestamp();
    register(&source, "node1", password, "wss://1.1.1.1/v1/relay", now);
    service::produce_node1_block(&source, "node1", password, false, now + 1).unwrap();
    service::init_node(&target, "joining", password).unwrap();
    let snapshot = service::bootstrap_snapshot(&source).unwrap();

    assert!(
        service::install_bootstrap_snapshot(
            &target,
            "joining",
            "wss://1.1.1.1/v1/rpc",
            &format!("state_{}", "0".repeat(64)),
            false,
            None,
            snapshot.clone(),
        )
        .is_err()
    );
    assert!(target.read_ledger().unwrap().genesis_authority.is_none());

    let trusted_root = snapshot.state_root.clone();
    let report = service::install_bootstrap_snapshot(
        &target,
        "joining",
        "1.1.1.1",
        &trusted_root,
        false,
        None,
        snapshot,
    )
    .unwrap();
    assert_eq!(report.height, 1);
    assert_eq!(service::block_status(&target, now + 2).unwrap().height, 1);
    assert_eq!(
        target
            .read_node_config("joining")
            .unwrap()
            .bootstrap_peer
            .as_deref(),
        Some("wss://1.1.1.1/v1/rpc")
    );
    let verified = service::verify_blockchain(&target).unwrap();
    assert!(verified.ok, "{}", verified.detail);

    let backup_path = target_root.join("backups").join("checkpoint.json");
    let backup_report = service::backup_ledger(&target, Some(&backup_path), now + 3).unwrap();
    let backup: service::LedgerBackup =
        serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
    assert_eq!(backup_report.height, 1);
    assert_eq!(
        backup.checksum,
        mrk::crypto::sha256_full_id("backup", &serde_json::to_vec(&backup.payload).unwrap())
    );
    assert!(service::backup_ledger(&target, Some(&backup_path), now + 4).is_err());

    let verified =
        service::verify_ledger_backup(&backup_path, Some(&backup_report.state_root)).unwrap();
    assert_eq!(verified.checksum, backup_report.checksum);
    let tampered_path = target_root.join("backups").join("tampered.json");
    let mut tampered = backup.clone();
    tampered.payload.height += 1;
    std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(service::verify_ledger_backup(&tampered_path, None).is_err());

    target
        .with_ledger_mut(|ledger| {
            ledger.blocks.clear();
            Ok(())
        })
        .unwrap();
    let restored =
        service::restore_ledger_backup(&target, "joining", &backup_path, &backup_report.state_root)
            .unwrap();
    assert_eq!(restored.height, 1);
    assert_eq!(service::verify_blockchain(&target).unwrap().height, 1);

    std::fs::remove_dir_all(source_root).unwrap();
    std::fs::remove_dir_all(target_root).unwrap();
}

#[test]
fn node1_builds_signed_linked_blocks_and_detects_operation_tampering() {
    let root = temp_root("node1-blocks");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "block-integration-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    register(&paths, "node2", password, "wss://8.8.8.8/v1/relay", now);

    let before = paths.read_ledger().unwrap();
    assert_eq!(before.pending_operation_ids.len(), 2);
    assert!(
        before
            .operations
            .values()
            .all(|operation| matches!(operation.status, OperationStatus::Pending))
    );

    let denied = service::produce_node1_block(&paths, "node2", password, false, now + 1);
    assert!(denied.is_err());
    assert!(
        denied
            .unwrap_err()
            .to_string()
            .contains("only the immutable Genesis Node 1")
    );

    let first = service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    assert_eq!(first.height, 1);
    assert_eq!(first.previous_block_hash, "GENESIS");
    assert_eq!(first.operation_ids.len(), 2);
    assert_eq!(first.block_hash.len(), 68);
    assert_eq!(first.state_root.len(), 70);
    let after_first = paths.read_ledger().unwrap();
    assert!(after_first.pending_operation_ids.is_empty());
    assert!(after_first.operations.values().all(|operation| {
        matches!(operation.status, OperationStatus::Finalized) && operation.block_height == Some(1)
    }));

    let governance = service::governance_set_parameter(
        &paths,
        "node1",
        password,
        "block-interval-seconds",
        "5",
        now + 2,
    )
    .unwrap();
    assert!(matches!(governance.status, OperationStatus::Pending));
    let second = service::produce_node1_block(&paths, "node1", password, false, now + 2).unwrap();
    assert_eq!(second.height, 2);
    assert_eq!(second.previous_block_hash, first.block_hash);
    assert_eq!(second.operation_ids, vec![governance.operation_id.clone()]);

    let report = service::verify_blockchain(&paths).unwrap();
    assert!(report.ok, "{}", report.detail);
    assert_eq!(report.height, 2);
    assert_eq!(report.checked_operations, 3);
    assert_eq!(report.legacy_unverified_operations, 0);

    paths
        .with_ledger_mut(|ledger| {
            ledger.blocks.get_mut(1).unwrap().previous_block_hash = "tampered".to_owned();
            Ok(())
        })
        .unwrap();
    let broken_link = service::verify_blockchain(&paths).unwrap();
    assert!(!broken_link.ok);
    assert!(broken_link.detail.contains("does not link"));
    paths
        .with_ledger_mut(|ledger| {
            ledger.blocks.get_mut(1).unwrap().previous_block_hash = first.block_hash.clone();
            Ok(())
        })
        .unwrap();

    assert!(
        service::produce_node1_block_if_due(&paths, "node1", password, now + 3)
            .unwrap()
            .is_none()
    );
    let automatic = service::produce_node1_block_if_due(&paths, "node1", password, now + 2 + 5)
        .unwrap()
        .unwrap();
    assert_eq!(automatic.height, 3);
    assert!(automatic.operation_ids.is_empty());

    paths
        .with_ledger_mut(|ledger| {
            ledger
                .operations
                .get_mut(&governance.operation_id)
                .unwrap()
                .payload = serde_json::json!({"tampered": true});
            Ok(())
        })
        .unwrap();
    let corrupted = service::verify_blockchain(&paths).unwrap();
    assert!(!corrupted.ok);
    assert!(corrupted.detail.contains("signed commitment"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn node1_replays_candidates_and_excludes_duplicate_network_aliases() {
    let root = temp_root("node1-duplicate-network");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "node1-duplicate-network-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    let ledger_id = paths.read_ledger().unwrap().ledger_id;
    let first_owner = service::create_local_account(&paths, "first-owner", password).unwrap();
    let second_owner = service::create_local_account(&paths, "second-owner", password).unwrap();
    let (first_network_id, first_commitment) = service::new_network_identity().unwrap();
    let first_operation = service::sign_public_operation(
        &first_owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &ledger_id,
            module: "NetworkRegistry",
            action: "CreateNetwork",
            nonce: 1,
            valid_until: now + 600,
            payload: serde_json::json!({
                "alias": "duplicate-alias",
                "network_id": first_network_id,
                "network_commitment": first_commitment,
            }),
        },
    )
    .unwrap();
    let (second_network_id, second_commitment) = service::new_network_identity().unwrap();
    let second_operation = service::sign_public_operation(
        &second_owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &ledger_id,
            module: "NetworkRegistry",
            action: "CreateNetwork",
            nonce: 1,
            valid_until: now + 600,
            payload: serde_json::json!({
                "alias": "duplicate-alias",
                "network_id": second_network_id,
                "network_commitment": second_commitment,
            }),
        },
    )
    .unwrap();
    let first_id = service::submit_consensus_operation(
        &paths,
        mrk::consensus::PendingOperationEnvelope {
            public_key: first_owner.public_key,
            operation: first_operation,
        },
        now + 2,
    )
    .unwrap();
    let second_id = service::submit_consensus_operation(
        &paths,
        mrk::consensus::PendingOperationEnvelope {
            public_key: second_owner.public_key,
            operation: second_operation,
        },
        now + 2,
    )
    .unwrap();
    assert_eq!(paths.read_ledger().unwrap().pending_operation_ids.len(), 2);

    let block = service::produce_node1_block(&paths, "node1", password, false, now + 2).unwrap();
    assert_eq!(block.operation_ids.len(), 1);
    let expected_commitment = if block.operation_ids[0] == first_id {
        &first_commitment
    } else {
        assert_eq!(block.operation_ids[0], second_id);
        &second_commitment
    };
    assert_eq!(
        service::network_by_alias(&paths, "duplicate-alias")
            .unwrap()
            .commitment,
        *expected_commitment
    );
    assert!(
        paths
            .read_ledger()
            .unwrap()
            .pending_operation_ids
            .is_empty()
    );

    let third_owner = service::create_local_account(&paths, "third-owner", password).unwrap();
    let (third_network_id, third_commitment) = service::new_network_identity().unwrap();
    let third_operation = service::sign_public_operation(
        &third_owner,
        password,
        service::PublicOperationSigningRequest {
            ledger_id: &ledger_id,
            module: "NetworkRegistry",
            action: "CreateNetwork",
            nonce: 1,
            valid_until: now + 600,
            payload: serde_json::json!({
                "alias": "duplicate-alias",
                "network_id": third_network_id,
                "network_commitment": third_commitment,
            }),
        },
    )
    .unwrap();
    let duplicate = service::submit_consensus_operation(
        &paths,
        mrk::consensus::PendingOperationEnvelope {
            public_key: third_owner.public_key,
            operation: third_operation,
        },
        now + 3,
    )
    .unwrap_err();
    assert!(duplicate.to_string().contains("already exists"));
    assert!(
        paths
            .read_ledger()
            .unwrap()
            .pending_operation_ids
            .is_empty()
    );

    let verified = service::verify_blockchain(&paths).unwrap();
    assert!(verified.ok, "{}", verified.detail);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_block_migrates_operations_from_the_pre_block_ledger() {
    let root = temp_root("legacy-block-migration");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "legacy-block-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger.pending_operation_ids.clear();
            for operation in ledger.operations.values_mut() {
                operation.status = OperationStatus::Finalized;
                operation.block_height = None;
                operation.signed_operation = None;
            }
            Ok(())
        })
        .unwrap();

    let status = service::block_status(&paths, now + 1).unwrap();
    assert_eq!(status.pending_operation_count, 1);
    let block = service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    assert_eq!(block.operation_ids.len(), 1);
    let report = service::verify_blockchain(&paths).unwrap();
    assert!(report.ok, "{}", report.detail);
    assert_eq!(report.legacy_unverified_operations, 1);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn node1_produces_until_four_validators_and_restores_below_twenty_nodes() {
    let root = temp_root("block-threshold");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "block-threshold-password";
    let now = Utc::now().timestamp();
    let endpoints = [
        "wss://1.1.1.1/v1/relay",
        "wss://8.8.8.8/v1/relay",
        "wss://9.9.9.9/v1/relay",
        "wss://208.67.222.222/v1/relay",
    ];
    let mut registered = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        registered.push(register(
            &paths,
            &format!("node{}", index + 1),
            password,
            endpoint,
            now,
        ));
    }
    let node1 = registered[0].clone();
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.validator_bond = 10;
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
                    .balance = 10;
            }
            for node_id in 5..=20 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("11.0.0.{node_id}");
                node.ip_slot = format!("v4:11.0.0.{node_id}");
                node.status = NodeStatus::Active;
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

    let status = service::block_status(&paths, now + 1).unwrap();
    assert_eq!(status.mode, "NODE1_SINGLE_PRODUCER");
    assert!(status.node1_production_enabled);
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    for node_id in 1..=3 {
        service::join_validator_pool(&paths, &format!("node{node_id}"), password, now + 2).unwrap();
    }
    let status = service::block_status(&paths, now + 2).unwrap();
    assert_eq!(status.mode, "NODE1_SINGLE_PRODUCER");
    assert!(status.node1_production_enabled);
    service::join_validator_pool(&paths, "node4", password, now + 2).unwrap();
    let status = service::block_status(&paths, now + 2).unwrap();
    assert_eq!(status.mode, "MULTI_VALIDATOR");
    assert!(!status.node1_production_enabled);
    let blocked = service::produce_node1_block(&paths, "node1", password, false, now + 2);
    assert!(blocked.is_err());
    assert!(
        blocked
            .unwrap_err()
            .to_string()
            .contains("multi-Validator consensus is required")
    );

    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&20).unwrap().status = NodeStatus::WarmingUp;
            Ok(())
        })
        .unwrap();
    let status = service::block_status(&paths, now + 2).unwrap();
    assert_eq!(status.mode, "NODE1_SINGLE_PRODUCER");
    let block = service::produce_node1_block(&paths, "node1", password, false, now + 3).unwrap();
    assert_eq!(block.producer_node_id, 1);
    assert!(service::verify_blockchain(&paths).unwrap().ok);

    std::fs::remove_dir_all(root).unwrap();
}
