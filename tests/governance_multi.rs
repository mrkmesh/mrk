use chrono::Utc;
use mrk::{
    amount::MRK_SCALE,
    model::{
        GovernanceProposalAction, GovernanceProposalKind, GovernanceProposalStatus,
        GovernanceVoteChoice, GovernanceVoteRecord, IpSlotRecord, NodeStatus,
    },
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

fn make_fresh(paths: &DataPaths, now: i64) {
    paths
        .with_ledger_mut(|ledger| {
            for node in ledger.nodes.values_mut() {
                if matches!(node.status, NodeStatus::Active) {
                    node.last_heartbeat = Some(now);
                    node.last_probe_success = Some(now);
                }
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn critical_governance_uses_snapshot_power_timelock_and_cancels_below_twenty() {
    let root = temp_root("distributed-governance");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "distributed-governance-password";
    let now = Utc::now().timestamp();
    let node1 = register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    register(&paths, "node2", password, "wss://8.8.8.8/v1/relay", now);
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.required_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.probe_validity_seconds = 300;
            for node in ledger.nodes.values_mut() {
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                node.total_eligible_seconds = 180 * 86_400;
            }
            for node_id in 3..=20 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.6.{node_id}");
                node.ip_slot = format!("v4:9.9.6.{node_id}");
                node.status = NodeStatus::Active;
                node.service_bond = 0;
                node.validator_bond = 0;
                node.validator = false;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                node.total_eligible_seconds = 180 * 86_400;
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
            let reward = ledger.nodes[&1].reward_address.clone();
            ledger.accounts.get_mut(&reward).unwrap().liquid = 2_000 * MRK_SCALE;
            Ok(())
        })
        .unwrap();

    let invalid_standard = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Standard,
        "unsafe Epoch issuance change",
        GovernanceProposalAction::SetParameter {
            parameter: "epoch-mint-amount".to_owned(),
            value: "450MRK".to_owned(),
        },
        now,
    );
    assert!(invalid_standard.is_err());
    let invalid_epoch_duration = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Standard,
        "unsafe Epoch duration change",
        GovernanceProposalAction::SetParameter {
            parameter: "epoch-seconds".to_owned(),
            value: "43200".to_owned(),
        },
        now,
    );
    assert!(invalid_epoch_duration.is_err());
    let invalid_warmup = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Standard,
        "unsafe Node warmup change",
        GovernanceProposalAction::SetParameter {
            parameter: "warmup-seconds".to_owned(),
            value: "1209600".to_owned(),
        },
        now,
    );
    assert!(invalid_warmup.is_err());

    let proposal = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Critical,
        "change Epoch mint amount",
        GovernanceProposalAction::SetParameter {
            parameter: "epoch-mint-amount".to_owned(),
            value: "450MRK".to_owned(),
        },
        now,
    )
    .unwrap();
    assert_eq!(proposal.power_snapshot.len(), 20);
    assert!(proposal.power_snapshot.values().all(|power| *power > 0));
    let power_values = proposal
        .power_snapshot
        .values()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(power_values.len(), 1);

    service::vote_governance_proposal(
        &paths,
        "node1",
        password,
        proposal.proposal_id,
        GovernanceVoteChoice::Yes,
        now + 1,
    )
    .unwrap();
    service::vote_governance_proposal(
        &paths,
        "node2",
        password,
        proposal.proposal_id,
        GovernanceVoteChoice::Yes,
        now + 1,
    )
    .unwrap();
    paths
        .with_ledger_mut(|ledger| {
            let proposal = ledger
                .governance
                .proposals
                .get_mut(&proposal.proposal_id)
                .unwrap();
            for node_id in 3..=20 {
                let choice = if node_id <= 14 {
                    GovernanceVoteChoice::Yes
                } else {
                    GovernanceVoteChoice::No
                };
                proposal.votes.insert(
                    node_id,
                    GovernanceVoteRecord {
                        node_id,
                        choice,
                        power: proposal.power_snapshot[&node_id],
                        operation_id: format!("synthetic-vote-{node_id}"),
                        voted_at: now + 1,
                    },
                );
            }
            Ok(())
        })
        .unwrap();

    let finalize_at = proposal.voting_ends_at + 1;
    make_fresh(&paths, finalize_at);
    let (_, tally) = service::finalize_governance_proposal(
        &paths,
        "node1",
        password,
        proposal.proposal_id,
        finalize_at,
    )
    .unwrap();
    assert_eq!(tally.status, GovernanceProposalStatus::Passed);
    assert!(tally.yes_power.saturating_mul(3) >= tally.total_power.saturating_mul(2));
    assert!(
        service::execute_governance_proposal(
            &paths,
            "node1",
            password,
            proposal.proposal_id,
            finalize_at,
        )
        .is_err()
    );

    let execute_at = proposal.execute_after + 1;
    make_fresh(&paths, execute_at);
    service::execute_governance_proposal(
        &paths,
        "node2",
        password,
        proposal.proposal_id,
        execute_at,
    )
    .unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.settings.epoch_mint_amount, 450 * MRK_SCALE);
    assert_eq!(
        ledger.governance.proposals[&proposal.proposal_id].status,
        GovernanceProposalStatus::Executed
    );

    let reward_address = ledger.nodes[&1].reward_address.clone();
    drop(ledger);
    make_fresh(&paths, execute_at + 1);
    let cancellable = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Standard,
        "change Probe window",
        GovernanceProposalAction::SetParameter {
            parameter: "probe-validity-seconds".to_owned(),
            value: "600".to_owned(),
        },
        execute_at + 1,
    )
    .unwrap();
    let balance_after_bond = paths.read_ledger().unwrap().accounts[&reward_address].liquid;
    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&20).unwrap().status = NodeStatus::WarmingUp;
            Ok(())
        })
        .unwrap();
    service::governance_set_parameter(
        &paths,
        "node1",
        password,
        "probe-validity-seconds",
        "600",
        execute_at + 2,
    )
    .unwrap();
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(
        ledger.governance.proposals[&cancellable.proposal_id].status,
        GovernanceProposalStatus::Cancelled
    );
    assert_eq!(
        ledger.accounts[&reward_address].liquid,
        balance_after_bond + 1_000 * MRK_SCALE
    );

    std::fs::remove_dir_all(root).unwrap();
}
