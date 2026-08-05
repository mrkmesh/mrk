use mrk::{
    model::{IpSlotRecord, NodeStatus},
    service,
    storage::DataPaths,
};

fn temp_root() -> std::path::PathBuf {
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-registry-{}", mrk::crypto::hex_lower(&random)))
}

#[test]
fn registry_pages_filters_and_discovers_only_reachable_active_relays() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "integration-test-password";
    let now = 2_000_000_000;
    service::init_node(&paths, "node1", password).unwrap();
    let node1 = service::register_node(
        &paths,
        "node1",
        password,
        "wss://1.1.1.1/v1/relay",
        "0.02MRK",
        now - 100,
    )
    .unwrap();

    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.probe_validity_seconds = 300;

            let first = ledger.nodes.get_mut(&1).unwrap();
            first.last_probe_success = Some(now - 10);
            first.validator = true;

            let mut second = node1.clone();
            second.node_id = 2;
            second.name = "node2".to_owned();
            second.endpoint = "wss://8.8.8.8/v1/relay".to_owned();
            second.reward_ip = "8.8.8.8".to_owned();
            second.ip_slot = "v4:8.8.8.8".to_owned();
            second.last_probe_success = Some(now - 301);
            second.validator = false;

            let mut third = node1.clone();
            third.node_id = 3;
            third.name = "node3".to_owned();
            third.endpoint = "wss://9.9.9.9/v1/relay".to_owned();
            third.reward_ip = "9.9.9.9".to_owned();
            third.ip_slot = "v4:9.9.9.9".to_owned();
            third.status = NodeStatus::Draining;
            third.last_probe_success = Some(now - 5);
            third.validator = false;

            ledger.nodes.insert(2, second);
            ledger.nodes.insert(3, third);
            ledger.ip_slots.insert(
                "v4:8.8.8.8".to_owned(),
                IpSlotRecord {
                    node_id: 2,
                    bound_at: now - 100,
                    released_at: None,
                },
            );
            ledger.ip_slots.insert(
                "v4:9.9.9.9".to_owned(),
                IpSlotRecord {
                    node_id: 3,
                    bound_at: now - 100,
                    released_at: None,
                },
            );
            ledger.next_node_id = 4;
            Ok(())
        })
        .unwrap();

    let first_page = service::registry_nodes(&paths, None, false, None, 2).unwrap();
    assert_eq!(
        first_page
            .nodes
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(first_page.next_cursor, Some(2));
    let second_page =
        service::registry_nodes(&paths, None, false, first_page.next_cursor, 2).unwrap();
    assert_eq!(second_page.nodes[0].node_id, 3);
    assert_eq!(second_page.next_cursor, None);

    let active =
        service::registry_nodes(&paths, Some(NodeStatus::Active), false, None, 50).unwrap();
    assert_eq!(active.nodes.len(), 2);
    let validators = service::registry_nodes(&paths, None, true, None, 50).unwrap();
    assert_eq!(validators.nodes.len(), 1);
    assert_eq!(validators.nodes[0].node_id, 1);

    let discovered = service::discover_relays(&paths, None, 50, now).unwrap();
    assert_eq!(discovered.relays.len(), 1);
    assert_eq!(discovered.relays[0].node_id, 1);
    assert_eq!(discovered.relays[0].probe_valid_until, now + 290);

    paths
        .with_ledger_mut(|ledger| {
            ledger.ip_slots.get_mut("v4:1.1.1.1").unwrap().released_at = Some(now);
            Ok(())
        })
        .unwrap();
    assert!(
        service::discover_relays(&paths, None, 50, now)
            .unwrap()
            .relays
            .is_empty()
    );

    std::fs::remove_dir_all(root).unwrap();
}
