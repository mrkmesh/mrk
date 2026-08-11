use chrono::Utc;
use mrk_core::{
    amount::{MRK_SCALE, parse_mrk},
    model::{IpSlotRecord, NodeStatus, OperationStatus, RewardVestingBucket},
    rpc, service,
    storage::DataPaths,
};

fn temp_root(label: &str) -> std::path::PathBuf {
    let random = mrk_core::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-{label}-{}",
        mrk_core::crypto::hex_lower(&random)
    ))
}

fn register(
    paths: &DataPaths,
    name: &str,
    password: &str,
    endpoint: &str,
    now: i64,
) -> mrk_core::model::NodeRecord {
    service::init_node(paths, name, password).unwrap();
    service::join_node(paths, name, password, endpoint, Some("0.02MRK"), now).unwrap()
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
            ledger.settings.fee_policy.base_fee_per_unit = 0;
            Ok(())
        })
        .unwrap();

    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let (treasury_before_exit, pool_before_exit, lifetime_minted_before_exit) = paths
        .with_ledger_mut(|ledger| {
            let node = ledger.nodes.get_mut(&1).unwrap();
            node.service_bond = 100;
            node.claimable_reward = 10;
            node.reward_vesting_buckets = vec![RewardVestingBucket {
                unlock_at: now + 1_000,
                amount: 60,
            }];
            Ok((
                ledger.treasury,
                ledger.pool_remaining,
                ledger.lifetime_minted,
            ))
        })
        .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    let conflicting = register(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1:9443/v1/relay",
        now + 2,
    );
    assert_eq!(conflicting.node_id, 2);
    service::produce_node1_block(&paths, "node1", password, false, now + 3).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert!(ledger.nodes.contains_key(&2));
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 1);

    let slot_seconds = paths
        .read_ledger()
        .unwrap()
        .settings
        .availability_slot_seconds;
    let epoch_started_at = paths.read_ledger().unwrap().epoch_started_at;
    let mut probe_now = Utc::now().timestamp();
    let (request, response) = loop {
        let request =
            service::availability_probe_request(&paths, "node1", password, 2, probe_now).unwrap();
        let response =
            service::node_probe_response(&paths, "node2", password, &request.challenge).unwrap();
        if response
            .timestamp
            .saturating_sub(epoch_started_at)
            .div_euclid(slot_seconds)
            == request.slot
        {
            break (request, response);
        }
        probe_now = response.timestamp;
    };
    let probe_now = response.timestamp;
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
            now: probe_now,
        },
    )
    .unwrap();
    assert_eq!(attestation.credited_seconds, 0);
    assert_eq!(
        service::node_record(&paths, "node2").unwrap().status,
        NodeStatus::WarmingUp
    );

    let timeline = probe_now;
    service::drain_node(&paths, "node1", password, timeline + 5).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().status,
        NodeStatus::Draining
    );
    service::produce_node1_block(&paths, "node1", password, false, timeline + 6).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].status, NodeStatus::Exited);
    assert_eq!(ledger.nodes[&1].claimable_reward, 10);
    assert_eq!(ledger.nodes[&1].service_bond, 100);
    assert_eq!(ledger.nodes[&1].service_bond_unlock_at, Some(timeline + 26));
    assert!(ledger.nodes[&1].reward_vesting_buckets.is_empty());
    assert_eq!(ledger.treasury, treasury_before_exit + 60);
    assert_eq!(ledger.pool_remaining, pool_before_exit);
    assert_eq!(ledger.lifetime_minted, lifetime_minted_before_exit);
    assert_eq!(
        ledger.finalized_checkpoint.as_ref().unwrap().nodes[&1].status,
        NodeStatus::Exited
    );
    assert_eq!(
        ledger.ip_slots["v4:1.1.1.1"].released_at,
        Some(timeline + 6)
    );

    service::update_reward_ip(&paths, "node2", password, "1.1.1.1", timeline + 10).unwrap();
    assert_eq!(
        service::node_record(&paths, "node2").unwrap().endpoint,
        "wss://1.1.1.1/v1/relay"
    );
    service::produce_node1_block(&paths, "node1", password, false, timeline + 11).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 1);
    assert_eq!(
        ledger.ip_slots["v4:1.1.1.1"].released_at,
        Some(timeline + 6)
    );

    service::update_reward_ip(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1/v1/relay",
        timeline + 15,
    )
    .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, timeline + 16).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].node_id, 2);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].bound_at, timeline + 16);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, None);
    assert_eq!(ledger.nodes[&2].status, NodeStatus::WarmingUp);
    assert!(service::withdraw_service_bond(&paths, "node1", password, timeline + 25).is_err());
    let reward_address = ledger.nodes[&1].reward_address.clone();
    let reward_balance_before = ledger.accounts[&reward_address].balance;
    drop(ledger);

    let (_, withdrawn) =
        service::withdraw_service_bond(&paths, "node1", password, timeline + 27).unwrap();
    assert_eq!(withdrawn, 100);
    service::produce_node1_block(&paths, "node1", password, false, timeline + 28).unwrap();
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
fn active_node_wss_endpoint_cannot_be_registered_or_adopted() {
    let root = temp_root("duplicate-wss-endpoint");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "duplicate-wss-endpoint-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    service::init_node(&paths, "node2", password).unwrap();

    let error = service::join_node(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1/",
        Some("0.02MRK"),
        now + 1,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "WSS endpoint is already registered by Node 1"
    );
    assert_eq!(paths.read_ledger().unwrap().next_node_id, 2);
    assert_eq!(
        paths.read_node_config("node2").unwrap().node_id,
        None,
        "failed registration must not attach the local Node to an ID"
    );

    let node2 = service::join_node(
        &paths,
        "node2",
        password,
        "wss://8.8.8.8/v1/relay",
        Some("0.02MRK"),
        now + 2,
    )
    .unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .get_mut(&node2.reward_address)
                .unwrap()
                .balance = MRK_SCALE;
            Ok(())
        })
        .unwrap();
    assert_eq!(node2.node_id, 2);
    let error =
        service::update_reward_ip(&paths, "node2", password, "wss://1.1.1.1/v1/relay", now + 3)
            .unwrap_err();
    assert_eq!(
        error.to_string(),
        "WSS endpoint is already registered by Node 1"
    );

    service::drain_node(&paths, "node1", password, now + 4).unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 10).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().status,
        NodeStatus::Exited
    );
    let (_, node2) = service::update_reward_ip(
        &paths,
        "node2",
        password,
        "wss://1.1.1.1/v1/relay",
        now + 11,
    )
    .unwrap();
    assert_eq!(node2.endpoint, "wss://1.1.1.1/v1/relay");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn node_price_updates_are_owner_signed_and_finalized_deterministically() {
    let root = temp_root("node-price-update");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "node-price-update-password";
    let now = Utc::now().timestamp();
    let original = register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .get_mut(&original.reward_address)
                .unwrap()
                .balance = MRK_SCALE;
            Ok(())
        })
        .unwrap();

    let updated_price = parse_mrk("0.05MRK").unwrap();
    let (operation_id, node) =
        service::update_node_price(&paths, "node1", password, "0.05MRK", now + 1).unwrap();
    assert_eq!(node.price_per_gib, updated_price);
    assert_eq!(node.endpoint, original.endpoint);
    assert_eq!(node.reward_ip, original.reward_ip);
    assert_eq!(node.ip_slot, original.ip_slot);
    assert_eq!(node.status, original.status);
    assert_eq!(node.warmup_until, original.warmup_until);
    assert_eq!(node.last_probe_success, original.last_probe_success);

    let ledger = paths.read_ledger().unwrap();
    let operation = &ledger.operations[&operation_id];
    assert_eq!(operation.kind, "NodeRegistry.UpdatePrice");
    assert_eq!(
        operation.payload["price_per_gib_base_units"],
        updated_price.to_string()
    );
    assert!(matches!(operation.status, OperationStatus::Pending));
    drop(ledger);

    service::produce_node1_block(&paths, "node1", password, false, now + 2).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].price_per_gib, updated_price);
    assert_eq!(
        ledger.finalized_checkpoint.as_ref().unwrap().nodes[&1].price_per_gib,
        updated_price
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
            node.reward_vesting_buckets = vec![RewardVestingBucket {
                unlock_at: now + 1_000,
                amount: 60,
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
    assert!(node.reward_vesting_buckets.is_empty());
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
fn finalized_offline_timeout_starts_at_registration_before_first_probe() {
    let root = temp_root("offline-before-first-probe");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "offline-before-first-probe-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.block_interval_seconds = 1;
            ledger.settings.offline_slash_seconds = 10;
            Ok(())
        })
        .unwrap();

    service::produce_node1_block(&paths, "node1", password, true, now + 9).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].status, NodeStatus::Active);
    assert_eq!(ledger.nodes[&1].last_probe_success, None);
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, None);
    drop(ledger);

    service::produce_node1_block(&paths, "node1", password, true, now + 10).unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.nodes[&1].status, NodeStatus::Exited);
    assert_eq!(ledger.nodes[&1].offline_slashed_at, Some(now + 10));
    assert_eq!(ledger.ip_slots["v4:1.1.1.1"].released_at, Some(now + 10));
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
    let first_snapshot = service::bootstrap_snapshot(&source).unwrap();
    service::produce_node1_block(&source, "node1", password, true, now + 2).unwrap();
    assert_eq!(
        source.latest_bootstrap_checkpoint().unwrap().unwrap().0,
        1,
        "automatic checkpoints inside the scheduled interval must be skipped"
    );
    let latest_snapshot = service::bootstrap_snapshot(&source).unwrap();
    assert_eq!(latest_snapshot.height, 2);
    drop(source);
    let source = DataPaths::new(Some(source_root.clone())).unwrap();
    let snapshot = service::bootstrap_snapshot_at(&source, 1).unwrap();
    assert_eq!(snapshot.state_root, first_snapshot.state_root);

    assert!(
        service::install_bootstrap_snapshot(
            &target,
            service::BootstrapInstallRequest {
                name: "joining",
                peer: "wss://1.1.1.1/v1/rpc",
                expected_height: snapshot.height + 1,
                expected_state_root: &snapshot.state_root,
                allow_insecure_local: false,
                tls_ca: None,
            },
            snapshot.clone(),
        )
        .is_err()
    );
    assert!(target.read_ledger().unwrap().genesis_authority.is_none());

    assert!(
        service::install_bootstrap_snapshot(
            &target,
            service::BootstrapInstallRequest {
                name: "joining",
                peer: "wss://1.1.1.1/v1/rpc",
                expected_height: snapshot.height,
                expected_state_root: &format!("state_{}", "0".repeat(64)),
                allow_insecure_local: false,
                tls_ca: None,
            },
            snapshot.clone(),
        )
        .is_err()
    );
    assert!(target.read_ledger().unwrap().genesis_authority.is_none());

    let trusted_root = snapshot.state_root.clone();
    let report = service::install_bootstrap_snapshot(
        &target,
        service::BootstrapInstallRequest {
            name: "joining",
            peer: "1.1.1.1",
            expected_height: snapshot.height,
            expected_state_root: &trusted_root,
            allow_insecure_local: false,
            tls_ca: None,
        },
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
    assert_eq!(
        target
            .read_node_config("joining")
            .unwrap()
            .trusted_checkpoint_height,
        Some(1)
    );
    let verified = service::verify_blockchain(&target).unwrap();
    assert!(verified.ok, "{}", verified.detail);

    let catch_up =
        service::consensus_catch_up_chunk(&source, 1, mrk_core::consensus::MAX_CATCH_UP_BLOCKS)
            .unwrap();
    assert_eq!(catch_up.blocks.len(), 1);
    let caught_up_height = service::apply_consensus_catch_up(
        &target,
        catch_up.blocks,
        catch_up.operations,
        *catch_up.finalized_checkpoint.unwrap(),
    )
    .unwrap();
    assert_eq!(caught_up_height, 2);

    let backup_path = target_root.join("backups").join("checkpoint.json");
    let backup_report = service::backup_ledger(&target, Some(&backup_path), now + 3).unwrap();
    let backup: service::LedgerBackup =
        serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
    assert_eq!(backup_report.height, 2);
    assert_eq!(
        backup.checksum,
        mrk_core::crypto::sha256_full_id("backup", &serde_json::to_vec(&backup.payload).unwrap())
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
    assert_eq!(restored.height, 2);
    assert_eq!(service::verify_blockchain(&target).unwrap().height, 2);

    std::fs::remove_dir_all(source_root).unwrap();
    std::fs::remove_dir_all(target_root).unwrap();
}

#[test]
fn registered_node_can_recover_a_deleted_ledger_from_a_pinned_checkpoint() {
    let source_root = temp_root("registered-bootstrap-source");
    let target_root = temp_root("registered-bootstrap-target");
    let source = DataPaths::new(Some(source_root.clone())).unwrap();
    let target = DataPaths::new(Some(target_root.clone())).unwrap();
    let password = "registered-bootstrap-password";
    let now = Utc::now().timestamp();
    register(&source, "node1", password, "wss://1.1.1.1/v1/relay", now);
    service::produce_node1_block(&source, "node1", password, false, now + 1).unwrap();
    let snapshot = service::bootstrap_snapshot(&source).unwrap();
    service::init_node(&target, "node2", password).unwrap();

    let mut config = target.read_node_config("node2").unwrap();
    config.node_id = Some(1);
    target.write_node_config(&config).unwrap();
    assert!(
        service::install_bootstrap_snapshot(
            &target,
            service::BootstrapInstallRequest {
                name: "node2",
                peer: "seed.example.com",
                expected_height: snapshot.height,
                expected_state_root: &snapshot.state_root,
                allow_insecure_local: false,
                tls_ca: None,
            },
            snapshot.clone(),
        )
        .is_err(),
        "recovery must reject a checkpoint that assigns the local Node ID to another Owner"
    );

    config.node_id = Some(2);
    target.write_node_config(&config).unwrap();
    let trusted_root = snapshot.state_root.clone();
    let report = service::install_bootstrap_snapshot(
        &target,
        service::BootstrapInstallRequest {
            name: "node2",
            peer: "seed.example.com",
            expected_height: snapshot.height,
            expected_state_root: &trusted_root,
            allow_insecure_local: false,
            tls_ca: None,
        },
        snapshot,
    )
    .unwrap();
    assert_eq!(report.height, 1);
    assert_eq!(target.read_node_config("node2").unwrap().node_id, Some(2));
    assert_eq!(service::verify_blockchain(&target).unwrap().height, 1);

    std::fs::remove_dir_all(source_root).unwrap();
    std::fs::remove_dir_all(target_root).unwrap();
}

#[test]
fn exited_owner_joins_with_a_new_node_id_and_fresh_lifecycle() {
    let root = temp_root("node-owner-join-again");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "node-owner-join-again-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let previous = register(&paths, "node2", password, "wss://2.2.2.2/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .get_mut(&previous.reward_address)
                .unwrap()
                .balance = 2 * MRK_SCALE;
            Ok(())
        })
        .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    service::drain_node(&paths, "node2", password, now + 2).unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 3).unwrap();
    assert_eq!(
        paths.read_ledger().unwrap().nodes[&previous.node_id].status,
        NodeStatus::Exited
    );

    let replacement = service::join_node(
        &paths,
        "node2",
        password,
        "wss://2.2.2.2/v1/relay",
        Some("0.02MRK"),
        now + 4,
    )
    .unwrap();
    assert_eq!(replacement.node_id, previous.node_id + 1);
    assert_eq!(replacement.previous_node_id, Some(previous.node_id));
    assert_eq!(replacement.owner_address, previous.owner_address);
    assert_eq!(replacement.status, NodeStatus::WarmingUp);
    assert_eq!(
        paths.read_node_config("node2").unwrap().node_id,
        Some(replacement.node_id)
    );
    assert!(
        service::join_node(
            &paths,
            "node2",
            password,
            "wss://2.2.2.2/v1/relay",
            Some("0.02MRK"),
            now + 5,
        )
        .is_err(),
        "a live replacement Node cannot join again"
    );
    service::produce_node1_block(&paths, "node1", password, false, now + 5).unwrap();
    assert!(service::verify_blockchain(&paths).unwrap().ok);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn automatic_bootstrap_checkpoints_follow_block_cadence() {
    let root = temp_root("scheduled-checkpoint");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "scheduled-checkpoint-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);

    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    service::produce_node1_block(&paths, "node1", password, true, now + 2).unwrap();
    assert_eq!(paths.latest_bootstrap_checkpoint().unwrap().unwrap().0, 1);
    let checkpoints = service::bootstrap_checkpoints(&paths).unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].height, 1);
    assert_eq!(checkpoints[0].finalized_at, now + 1);

    service::produce_node1_block(&paths, "node1", password, true, now + 6 * 3_600 + 1).unwrap();
    assert_eq!(paths.latest_bootstrap_checkpoint().unwrap().unwrap().0, 3);
    let checkpoints = service::bootstrap_checkpoints(&paths).unwrap();
    assert_eq!(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.height)
            .collect::<Vec<_>>(),
        vec![3, 1]
    );
    assert_eq!(
        checkpoints[0].state_root,
        service::block_by_height(&paths, 3).unwrap().state_root
    );
    let rpc_checkpoints = rpc::execute(
        &paths,
        rpc::Request {
            id: 1,
            method: "chain.checkpoints".to_owned(),
            params: serde_json::Value::Null,
        },
    )
    .unwrap();
    assert_eq!(rpc_checkpoints[0]["height"], 3);
    assert_eq!(rpc_checkpoints[1]["height"], 1);

    std::fs::remove_dir_all(root).unwrap();
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

    let block_tamper = paths.with_ledger_mut(|ledger| {
        ledger.blocks.get_mut(1).unwrap().previous_block_hash = "tampered".to_owned();
        Ok(())
    });
    assert!(block_tamper.is_err());

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

    let tamper = paths.with_ledger_mut(|ledger| {
        ledger
            .operations
            .get_mut(&governance.operation_id)
            .unwrap()
            .payload = serde_json::json!({"tampered": true});
        Ok(())
    });
    assert!(tamper.is_err());
    let intact = service::verify_blockchain(&paths).unwrap();
    assert!(intact.ok, "{}", intact.detail);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn node1_replays_candidates_and_excludes_duplicate_network_aliases() {
    let root = temp_root("node1-duplicate-network");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "node1-duplicate-network-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let first_owner = service::create_local_account(&paths, "first-owner", password).unwrap();
    let second_owner = service::create_local_account(&paths, "second-owner", password).unwrap();
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .entry(first_owner.address.clone())
                .or_default()
                .balance = MRK_SCALE;
            ledger
                .accounts
                .entry(second_owner.address.clone())
                .or_default()
                .balance = MRK_SCALE;
            Ok(())
        })
        .unwrap();
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    let ledger_id = paths.read_ledger().unwrap().ledger_id;
    let (first_network_id, first_commitment) = service::new_network_identity().unwrap();
    let first_operation = service::sign_public_operation(
        &first_owner,
        password,
        service::PublicOperationSigningRequest {
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
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
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
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
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: first_owner.public_key,
            operation: first_operation,
        },
        now + 2,
    )
    .unwrap();
    let second_id = service::submit_consensus_operation(
        &paths,
        mrk_core::consensus::PendingOperationEnvelope {
            public_key: second_owner.public_key,
            operation: second_operation,
        },
        now + 2,
    )
    .unwrap();
    assert_eq!(paths.read_ledger().unwrap().pending_operation_ids.len(), 2);

    let block = service::produce_node1_block(&paths, "node1", password, false, now + 2).unwrap();
    assert_eq!(block.operation_ids.len(), 2);
    let ledger = paths.read_ledger().unwrap();
    let finalized_id = [&first_id, &second_id]
        .into_iter()
        .find(|operation_id| {
            matches!(
                ledger.operations[*operation_id].status,
                OperationStatus::Finalized
            )
        })
        .unwrap();
    let rejected_id = if finalized_id == &first_id {
        &second_id
    } else {
        &first_id
    };
    assert!(matches!(
        ledger.operations[rejected_id].status,
        OperationStatus::Rejected
    ));
    assert!(
        ledger.operations[rejected_id]
            .error
            .as_deref()
            .unwrap()
            .contains("already exists")
    );
    assert!(ledger.operations[rejected_id].fee_charged > 0);
    let expected_commitment = if finalized_id == &first_id {
        &first_commitment
    } else {
        &second_commitment
    };
    drop(ledger);
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
            max_fee_base_units: u128::MAX,
            fee_policy_version: 1,
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
        mrk_core::consensus::PendingOperationEnvelope {
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
fn operation_bodies_are_immutable_after_submission() {
    let root = temp_root("immutable-operation-body");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "legacy-block-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let mutation = paths.with_ledger_mut(|ledger| {
        for operation in ledger.operations.values_mut() {
            operation.signed_operation = None;
        }
        Ok(())
    });
    assert!(mutation.is_err());
    assert_eq!(paths.read_ledger().unwrap().pending_operation_ids.len(), 1);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn finalized_blocks_are_append_only() {
    let root = temp_root("append-only-block");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "append-only-block-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();

    let mutation = paths.with_ledger_mut(|ledger| {
        ledger.blocks[0].state_root = format!("state_{}", "0".repeat(64));
        Ok(())
    });
    assert!(mutation.is_err());
    assert_ne!(
        paths.read_ledger().unwrap().blocks[0].state_root,
        format!("state_{}", "0".repeat(64))
    );

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
            ledger.settings.required_governance_bond = 0;
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
                    .balance = MRK_SCALE;
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
