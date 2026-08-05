use chrono::Utc;
use mrk::{
    amount::{GENESIS_TREASURY_ALLOCATION, MRK_SCALE, NODE_EMISSION_ALLOCATION},
    model::{
        GovernanceProposalAction, GovernanceProposalKind, GovernanceProposalStatus,
        GovernanceVoteChoice, GovernanceVoteRecord, NodeStatus,
    },
    service,
    storage::DataPaths,
};

fn temp_root() -> std::path::PathBuf {
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-treasury-{}", mrk::crypto::hex_lower(&random)))
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
            ledger.epoch_started_at = now;
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
fn genesis_treasury_requires_critical_governance_and_enforces_one_percent_limit() {
    let root = temp_root();
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "treasury-governance-password";
    let now = Utc::now().timestamp();

    let initial = paths.read_ledger().unwrap();
    assert_eq!(initial.treasury, GENESIS_TREASURY_ALLOCATION);
    assert_eq!(initial.genesis_treasury_minted, GENESIS_TREASURY_ALLOCATION);
    assert_eq!(initial.lifetime_minted, GENESIS_TREASURY_ALLOCATION);
    assert_eq!(initial.pool_remaining, NODE_EMISSION_ALLOCATION);
    drop(initial);

    let recipient = service::create_account(&paths, "recipient", password).unwrap();
    let node1 = register(&paths, "node1", password, "wss://1.1.1.1/v1/relay", now);
    register(&paths, "node2", password, "wss://8.8.8.8/v1/relay", now);
    register(&paths, "node3", password, "wss://9.9.9.9/v1/relay", now);
    register(
        &paths,
        "node4",
        password,
        "wss://208.67.222.222/v1/relay",
        now,
    );
    paths
        .with_ledger_mut(|ledger| {
            ledger.settings.min_service_bond = 0;
            ledger.settings.governance_min_service_seconds = 0;
            ledger.settings.validator_bond = 10;
            ledger.settings.heartbeat_grace_seconds = 120;
            ledger.settings.probe_validity_seconds = 300;
            for node in ledger.nodes.values_mut() {
                node.status = NodeStatus::Active;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                node.total_eligible_seconds = 180 * 86_400;
            }
            for node_id in 5..=20 {
                let mut node = node1.clone();
                node.node_id = node_id;
                node.name = format!("node{node_id}");
                node.owner_address = format!("owner{node_id}");
                node.owner_public_key = format!("owner-key{node_id}");
                node.relay_public_key = format!("relay-key{node_id}");
                node.reward_address = format!("reward{node_id}");
                node.reward_ip = format!("9.9.4.{node_id}");
                node.ip_slot = format!("v4:9.9.4.{node_id}");
                node.status = NodeStatus::Active;
                node.service_bond = 0;
                node.validator_bond = 0;
                node.validator = false;
                node.last_heartbeat = Some(now);
                node.last_probe_success = Some(now);
                node.total_eligible_seconds = 180 * 86_400;
                ledger.nodes.insert(node_id, node);
            }
            ledger.next_node_id = 21;
            for node_id in 1..=4 {
                let reward = ledger.nodes[&node_id].reward_address.clone();
                ledger.accounts.get_mut(&reward).unwrap().liquid =
                    if node_id == 1 { 2_010 * MRK_SCALE } else { 10 };
            }
            Ok(())
        })
        .unwrap();
    for node_id in 1..=4 {
        service::join_validator_pool(&paths, &format!("node{node_id}"), password, now).unwrap();
    }

    let reference = format!("sha256:{}", "a".repeat(64));
    let amount = 1_000_000 * MRK_SCALE;
    let standard = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Standard,
        "invalid standard treasury spend",
        GovernanceProposalAction::TreasurySpend {
            recipient: recipient.address.clone(),
            amount,
            reference_hash: reference.clone(),
        },
        now,
    );
    assert!(standard.is_err());
    let oversized = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Critical,
        "oversized treasury spend",
        GovernanceProposalAction::TreasurySpend {
            recipient: recipient.address.clone(),
            amount: 5_000_001 * MRK_SCALE,
            reference_hash: reference.clone(),
        },
        now,
    );
    assert!(oversized.is_err());

    let proposal = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Critical,
        "audited treasury payment",
        GovernanceProposalAction::TreasurySpend {
            recipient: recipient.address.clone(),
            amount,
            reference_hash: reference.clone(),
        },
        now,
    )
    .unwrap();
    for name in ["node1", "node2", "node3", "node4"] {
        service::vote_governance_proposal(
            &paths,
            name,
            password,
            proposal.proposal_id,
            GovernanceVoteChoice::Yes,
            now + 1,
        )
        .unwrap();
    }
    paths
        .with_ledger_mut(|ledger| {
            let proposal = ledger
                .governance
                .proposals
                .get_mut(&proposal.proposal_id)
                .unwrap();
            for node_id in 5..=20 {
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
                        operation_id: format!("synthetic-treasury-vote-{node_id}"),
                        voted_at: now + 1,
                    },
                );
            }
            Ok(())
        })
        .unwrap();
    for node_id in 1..=4 {
        let choice = if node_id <= 3 {
            GovernanceVoteChoice::Yes
        } else {
            GovernanceVoteChoice::No
        };
        service::validator_vote_governance_proposal(
            &paths,
            &format!("node{node_id}"),
            password,
            proposal.proposal_id,
            choice,
            now + 1,
        )
        .unwrap();
    }

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
    assert_eq!(tally.validator_yes, 3);
    assert_eq!(tally.validator_quorum, 3);
    let execute_at = proposal.execute_after + 1;
    make_fresh(&paths, execute_at);
    let receipt = service::execute_governance_proposal(
        &paths,
        "node2",
        password,
        proposal.proposal_id,
        execute_at,
    )
    .unwrap();
    assert!(
        service::execute_governance_proposal(
            &paths,
            "node2",
            password,
            proposal.proposal_id,
            execute_at + 1,
        )
        .is_err()
    );

    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.treasury, GENESIS_TREASURY_ALLOCATION - amount);
    assert_eq!(ledger.accounts[&recipient.address].liquid, amount);
    assert_eq!(ledger.treasury_spends.len(), 1);
    assert_eq!(ledger.treasury_spends[0].operation_id, receipt.operation_id);
    assert_eq!(ledger.lifetime_minted, GENESIS_TREASURY_ALLOCATION);
    assert_eq!(ledger.pool_remaining, NODE_EMISSION_ALLOCATION);
    drop(ledger);
    let status = service::treasury_status(&paths, execute_at).unwrap();
    assert_eq!(status.total_spent, amount);
    assert!(status.spending_enabled);
    assert_eq!(service::treasury_history(&paths, 20).unwrap().len(), 1);

    let veto_proposal_id = 99;
    paths
        .with_ledger_mut(|ledger| {
            let mut veto_proposal = ledger.governance.proposals[&proposal.proposal_id].clone();
            veto_proposal.proposal_id = veto_proposal_id;
            veto_proposal.title = "timelock veto test".to_owned();
            veto_proposal.status = GovernanceProposalStatus::Passed;
            veto_proposal.execute_after = execute_at + 1_000;
            veto_proposal.executed_at = None;
            veto_proposal.timelock_vetoes.clear();
            for node_id in 2..=7 {
                veto_proposal.timelock_vetoes.insert(
                    node_id,
                    GovernanceVoteRecord {
                        node_id,
                        choice: GovernanceVoteChoice::No,
                        power: veto_proposal.power_snapshot[&node_id],
                        operation_id: format!("synthetic-veto-{node_id}"),
                        voted_at: execute_at + 1,
                    },
                );
            }
            ledger
                .governance
                .proposals
                .insert(veto_proposal_id, veto_proposal);
            Ok(())
        })
        .unwrap();
    make_fresh(&paths, execute_at + 1);
    let (_, veto_tally) = service::veto_treasury_proposal(
        &paths,
        "node1",
        password,
        veto_proposal_id,
        execute_at + 1,
    )
    .unwrap();
    assert_eq!(veto_tally.status, GovernanceProposalStatus::Cancelled);
    assert!(veto_tally.timelock_veto_power.saturating_mul(3) > veto_tally.total_power);
    assert!(
        service::execute_governance_proposal(
            &paths,
            "node2",
            password,
            veto_proposal_id,
            execute_at + 1_001,
        )
        .is_err()
    );

    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&20).unwrap().status = NodeStatus::WarmingUp;
            Ok(())
        })
        .unwrap();
    let frozen = service::create_governance_proposal(
        &paths,
        "node1",
        password,
        GovernanceProposalKind::Critical,
        "frozen treasury payment",
        GovernanceProposalAction::TreasurySpend {
            recipient: recipient.address,
            amount,
            reference_hash: reference,
        },
        execute_at + 2,
    );
    assert!(frozen.is_err());
    assert!(
        !service::treasury_status(&paths, execute_at + 2)
            .unwrap()
            .spending_enabled
    );

    std::fs::remove_dir_all(root).unwrap();
}
