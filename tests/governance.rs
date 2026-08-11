use chrono::Utc;
use mrk_core::{
    amount::MRK_SCALE,
    model::{IpSlotRecord, NodeStatus},
    service,
    storage::DataPaths,
};

fn temp_root(label: &str) -> std::path::PathBuf {
    let random = mrk_core::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-{label}-{}",
        mrk_core::crypto::hex_lower(&random)
    ))
}

#[test]
fn governance_bond_matures_after_sixty_days_and_unlocks_after_thirty() {
    let root = temp_root("governance-bond");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "governance-bond-password";
    let now = Utc::now().timestamp();
    let node = register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            assert_eq!(ledger.settings.required_governance_bond, 10_000 * MRK_SCALE);
            assert_eq!(
                ledger.settings.governance_bond_maturity_seconds,
                60 * 86_400
            );
            assert_eq!(ledger.settings.governance_bond_unlock_seconds, 30 * 86_400);
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.fee_policy.base_fee_per_unit = 0;
            ledger
                .nodes
                .get_mut(&node.node_id)
                .unwrap()
                .last_probe_success = Some(now);
            ledger
                .accounts
                .get_mut(&node.reward_address)
                .unwrap()
                .balance = 10_000 * MRK_SCALE;
            Ok(())
        })
        .unwrap();

    service::produce_node1_block(&paths, "node1", password, false, now + 1).unwrap();
    let bonded_at = now + 2;
    let receipt = service::bond_governance(&paths, "node1", password, bonded_at).unwrap();
    assert_eq!(receipt.bonded, 10_000 * MRK_SCALE);
    assert_eq!(receipt.matures_at, bonded_at + 60 * 86_400);
    let bond_block =
        service::produce_node1_block(&paths, "node1", password, false, bonded_at + 1).unwrap();
    assert_eq!(bond_block.operation_ids, vec![receipt.operation_id]);
    assert_eq!(
        paths.read_ledger().unwrap().accounts[&node.reward_address].balance,
        0
    );
    assert!(
        !service::governance_bond_status(&paths, "node1", bonded_at)
            .unwrap()
            .eligible
    );

    let matures_at = bonded_at + 60 * 86_400;
    paths
        .with_ledger_mut(|ledger| {
            ledger
                .nodes
                .get_mut(&node.node_id)
                .unwrap()
                .last_probe_success = Some(matures_at);
            Ok(())
        })
        .unwrap();
    assert!(
        !service::governance_bond_status(&paths, "node1", matures_at - 1)
            .unwrap()
            .eligible
    );
    assert!(
        service::governance_bond_status(&paths, "node1", matures_at)
            .unwrap()
            .eligible
    );

    service::request_governance_exit(&paths, "node1", password, matures_at).unwrap();
    let status = service::governance_bond_status(&paths, "node1", matures_at).unwrap();
    assert!(!status.eligible);
    assert_eq!(status.bond_unlock_at, Some(matures_at + 30 * 86_400));
    assert!(
        service::withdraw_governance_bond(&paths, "node1", password, matures_at + 30 * 86_400 - 1,)
            .is_err()
    );
    let (_, withdrawn) =
        service::withdraw_governance_bond(&paths, "node1", password, matures_at + 30 * 86_400)
            .unwrap();
    assert_eq!(withdrawn, 10_000 * MRK_SCALE);
    assert_eq!(
        paths.read_ledger().unwrap().accounts[&node.reward_address].balance,
        10_000 * MRK_SCALE
    );

    std::fs::remove_dir_all(root).unwrap();
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
fn node1_direct_governance_switches_at_fifty_eligible_nodes_and_restores() {
    let root = temp_root("governance-threshold");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "governance-integration-password";
    let now = Utc::now().timestamp();
    let node1 = register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    let node2 = register(&paths, "node2", password, "wss://8.8.8.8/v1/relay", now);
    assert!(matches!(node1.status, NodeStatus::Active));
    assert_eq!(node1.warmup_until, now);
    assert_eq!(node1.active_since, Some(now));
    assert_eq!(node1.last_probe_success, None);
    assert_eq!(node1.total_eligible_seconds, 0);
    assert!(matches!(node2.status, NodeStatus::WarmingUp));
    assert_eq!(node2.warmup_until, now + 86_400);

    let ledger = paths.read_ledger().unwrap();
    let genesis = ledger.genesis_authority.unwrap();
    assert_eq!(genesis.node_id, 1);
    assert_eq!(genesis.owner_address, node1.owner_address);

    let non_genesis = service::governance_set_parameter(
        &paths,
        "node2",
        password,
        "warmup-seconds",
        "60",
        now + 1,
    );
    assert!(non_genesis.is_err());
    assert!(
        non_genesis
            .unwrap_err()
            .to_string()
            .contains("only the immutable Genesis Node 1")
    );

    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.required_governance_bond = 0;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.probe_validity_seconds = 300;
            for node in ledger.nodes.values_mut() {
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
            }
            for node_id in 3..=19 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.9.{node_id}");
                node.ip_slot = format!("v4:9.9.9.{node_id}");
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
            ledger.next_node_id = 20;
            Ok(())
        })
        .unwrap();

    let status = service::governance_status(&paths, now + 2).unwrap();
    assert_eq!(status.governance_eligible_count, 19);
    assert_eq!(status.mode, "NODE1_DIRECT");
    assert!(status.node1_direct_actions_enabled);
    service::governance_set_parameter(&paths, "node1", password, "warmup-seconds", "120", now + 2)
        .unwrap();
    assert_eq!(
        service::node_record(&paths, "node1").unwrap().warmup_until,
        node1.warmup_until
    );

    paths
        .with_ledger_mut(|ledger| {
            for node_id in 20..=49 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.8.{node_id}");
                node.ip_slot = format!("v4:9.9.8.{node_id}");
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now + 2);
                node.last_probe_success = Some(now + 2);
                let ip_slot = node.ip_slot.clone();
                ledger.nodes.insert(node_id, node);
                ledger.ip_slots.insert(
                    ip_slot,
                    IpSlotRecord {
                        node_id,
                        bound_at: now + 2,
                        released_at: None,
                    },
                );
            }
            ledger.next_node_id = 50;
            Ok(())
        })
        .unwrap();
    let status = service::governance_status(&paths, now + 3).unwrap();
    assert_eq!(status.governance_eligible_count, 49);
    assert_eq!(status.mode, "HYBRID");
    assert!(status.node1_direct_actions_enabled);
    service::governance_set_parameter(&paths, "node1", password, "warmup-seconds", "150", now + 3)
        .unwrap();

    paths
        .with_ledger_mut(|ledger| {
            let mut node = node2.clone();
            node.node_id = 50;
            node.name = "node50".to_owned();
            node.owner_address = "owner50".to_owned();
            node.owner_public_key = "owner-key50".to_owned();
            node.relay_public_key = "relay-key50".to_owned();
            node.reward_address = "reward50".to_owned();
            node.reward_ip = "9.9.9.50".to_owned();
            node.ip_slot = "v4:9.9.9.50".to_owned();
            node.status = NodeStatus::Active;
            node.last_heartbeat = Some(now + 3);
            node.last_probe_success = Some(now + 3);
            let ip_slot = node.ip_slot.clone();
            ledger.nodes.insert(50, node);
            ledger.ip_slots.insert(
                ip_slot,
                IpSlotRecord {
                    node_id: 50,
                    bound_at: now + 3,
                    released_at: None,
                },
            );
            ledger.next_node_id = 51;
            Ok(())
        })
        .unwrap();

    let status = service::governance_status(&paths, now + 4).unwrap();
    assert_eq!(status.governance_eligible_count, 50);
    assert_eq!(status.mode, "NODE_VOTING");
    assert!(!status.node1_direct_actions_enabled);
    let blocked = service::governance_set_parameter(
        &paths,
        "node1",
        password,
        "warmup-seconds",
        "180",
        now + 4,
    );
    assert!(blocked.is_err());
    assert!(
        blocked
            .unwrap_err()
            .to_string()
            .contains("node voting is required")
    );

    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&50).unwrap().status = NodeStatus::WarmingUp;
            Ok(())
        })
        .unwrap();
    let status = service::governance_status(&paths, now + 5).unwrap();
    assert_eq!(status.governance_eligible_count, 49);
    assert_eq!(status.mode, "HYBRID");
    service::governance_set_parameter(&paths, "node1", password, "warmup-seconds", "180", now + 5)
        .unwrap();
    assert_eq!(paths.read_ledger().unwrap().settings.warmup_seconds, 180);
    let newcomer = register(
        &paths,
        "newcomer",
        password,
        "wss://4.4.4.4/v1/relay",
        now + 5,
    );
    assert_eq!(newcomer.warmup_until, now + 5 + 180);
    assert!(
        service::governance_set_parameter(
            &paths,
            "node1",
            password,
            "warmup-seconds",
            "31536001",
            now + 5,
        )
        .is_err()
    );

    paths
        .with_ledger_mut(|ledger| {
            ledger.genesis_authority.as_mut().unwrap().owner_address = "tampered".to_owned();
            Ok(())
        })
        .unwrap();
    let corrupted = service::governance_set_parameter(
        &paths,
        "node1",
        password,
        "warmup-seconds",
        "240",
        now + 5,
    );
    assert!(corrupted.is_err());
    assert!(
        corrupted
            .unwrap_err()
            .to_string()
            .contains("does not match the registry")
    );
    assert_eq!(paths.read_ledger().unwrap().settings.warmup_seconds, 180);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_heartbeat_never_mints_eligible_time() {
    let root = temp_root("governance-pause");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "governance-pause-password";
    let now = Utc::now().timestamp();
    register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.warmup_seconds = 0;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.probe_validity_seconds = 300;
            Ok(())
        })
        .unwrap();
    service::node_tick(&paths, "node1", now).unwrap();
    service::node_tick(&paths, "node1", now + 10).unwrap();

    service::governance_pause_emission(
        &paths,
        "node1",
        password,
        "emergency maintenance",
        now + 10,
    )
    .unwrap();
    service::node_tick(&paths, "node1", now + 40).unwrap();
    assert_eq!(
        service::node_record(&paths, "node1")
            .unwrap()
            .total_eligible_seconds,
        0
    );

    service::governance_resume_emission(&paths, "node1", password, now + 40).unwrap();
    service::node_tick(&paths, "node1", now + 50).unwrap();
    let node = service::node_record(&paths, "node1").unwrap();
    assert_eq!(node.total_eligible_seconds, 0);
    let ledger = paths.read_ledger().unwrap();
    assert!(!ledger.governance.emission_paused);
    assert_eq!(ledger.governance.actions.len(), 2);
    assert_eq!(ledger.operations.len(), 3);

    std::fs::remove_dir_all(root).unwrap();
}
