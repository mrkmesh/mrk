use chrono::Utc;
use mrk::{
    crypto::{decrypt_key, sign_bytes},
    model::{
        BlockConsensusMode, ConsensusVote, ConsensusVoteType, IpSlotRecord, NodeStatus,
        OperationStatus,
    },
    service,
    storage::DataPaths,
};
use serde::Serialize;

#[derive(Serialize)]
struct VoteSigningPayload {
    ledger_id: String,
    height: u64,
    round: u32,
    vote_type: ConsensusVoteType,
    block_hash: Option<String>,
    validator_set_hash: String,
    validator_node_id: u64,
    timestamp: i64,
}

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
fn four_validator_committee_requires_three_precommits_to_finalize() {
    let root = temp_root("multi-validator-finality");
    let paths = DataPaths::new(Some(root.clone())).unwrap();
    let password = "consensus-integration-password";
    let now = Utc::now().timestamp();
    let endpoints = [
        "wss://1.1.1.1/v1/relay",
        "wss://8.8.8.8/v1/relay",
        "wss://9.9.9.9/v1/relay",
        "wss://208.67.222.222/v1/relay",
    ];
    for (index, endpoint) in endpoints.iter().enumerate() {
        register(
            &paths,
            &format!("node{}", index + 1),
            password,
            endpoint,
            now,
        );
    }
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
            Ok(())
        })
        .unwrap();
    for node_id in 1..=4 {
        service::join_validator_pool(&paths, &format!("node{node_id}"), password, now).unwrap();
    }
    let template = service::node_record(&paths, "node1").unwrap();
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
                node.reward_ip = format!("9.9.8.{node_id}");
                node.ip_slot = format!("v4:9.9.8.{node_id}");
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
    assert_eq!(committee.active_validator_ids, vec![1, 2, 3, 4]);
    assert_eq!(committee.quorum, 3);
    assert_eq!(committee.proposer_node_id, Some(1));
    let challenge =
        service::create_consensus_challenge(&paths, "node1", password, now + 1).unwrap();
    let hello =
        service::create_consensus_hello(&paths, "node2", password, &challenge, now + 1).unwrap();
    assert_eq!(hello.validator_node_id, 2);
    let mut tampered_challenge = challenge;
    tampered_challenge.challenge.push('0');
    assert!(
        service::create_consensus_hello(&paths, "node2", password, &tampered_challenge, now + 1,)
            .is_err()
    );
    let lagging_root = temp_root("validator-catch-up");
    let lagging_paths = DataPaths::new(Some(lagging_root.clone())).unwrap();
    let lagging_state = paths.read_ledger().unwrap();
    lagging_paths
        .with_ledger_mut(|ledger| {
            *ledger = lagging_state;
            Ok(())
        })
        .unwrap();
    assert!(service::propose_consensus_block(&paths, "node2", password, now + 1).is_err());
    let proposal = service::propose_consensus_block(&paths, "node1", password, now + 1).unwrap();
    assert_eq!(proposal.consensus_mode, BlockConsensusMode::MultiValidator);
    assert_eq!(proposal.validator_node_ids, vec![1, 2, 3, 4]);

    // Heartbeats are operational liveness data and must not invalidate a proposal that was
    // already executed and accepted at PROPOSE time.
    paths
        .with_ledger_mut(|ledger| {
            for node in ledger.nodes.values_mut() {
                node.last_heartbeat = Some(now + 2);
            }
            Ok(())
        })
        .unwrap();

    let premature = service::cast_consensus_vote(
        &paths,
        "node1",
        password,
        ConsensusVoteType::Precommit,
        Some(proposal.block_hash.clone()),
        now + 2,
    );
    assert!(premature.is_err());

    let (node4_prevote, _) = service::cast_consensus_vote(
        &paths,
        "node4",
        password,
        ConsensusVoteType::Prevote,
        Some(proposal.block_hash.clone()),
        now + 2,
    )
    .unwrap();
    let owner_file = paths
        .read_keyfile(&paths.node_owner_key_path("node4").unwrap())
        .unwrap();
    let owner_key = decrypt_key(&owner_file, password).unwrap();
    let conflicting_payload = VoteSigningPayload {
        ledger_id: node4_prevote.ledger_id.clone(),
        height: node4_prevote.height,
        round: node4_prevote.round,
        vote_type: ConsensusVoteType::Prevote,
        block_hash: None,
        validator_set_hash: node4_prevote.validator_set_hash.clone(),
        validator_node_id: 4,
        timestamp: now + 2,
    };
    let conflicting = ConsensusVote {
        ledger_id: conflicting_payload.ledger_id.clone(),
        height: conflicting_payload.height,
        round: conflicting_payload.round,
        vote_type: conflicting_payload.vote_type.clone(),
        block_hash: conflicting_payload.block_hash.clone(),
        validator_set_hash: conflicting_payload.validator_set_hash.clone(),
        validator_node_id: conflicting_payload.validator_node_id,
        timestamp: conflicting_payload.timestamp,
        signature: sign_bytes(
            &owner_key,
            &serde_json::to_vec(&conflicting_payload).unwrap(),
        ),
    };
    let evidence = service::submit_consensus_vote(&paths, conflicting, now + 2).unwrap();
    assert!(evidence.double_sign_detected);
    let ledger = paths.read_ledger().unwrap();
    assert_eq!(ledger.consensus.double_sign_evidence.len(), 1);
    assert_eq!(ledger.nodes[&4].validator_bond, 0);
    assert!(ledger.consensus.proposal.is_none());
    drop(ledger);

    let round = service::advance_consensus_round(&paths, now + 12).unwrap();
    assert_eq!(round, 1);
    let proposal = service::propose_consensus_block(&paths, "node2", password, now + 12).unwrap();
    for node_id in 1..=3 {
        let (_, finalized) = service::cast_consensus_vote(
            &paths,
            &format!("node{node_id}"),
            password,
            ConsensusVoteType::Prevote,
            Some(proposal.block_hash.clone()),
            now + 13,
        )
        .unwrap();
        assert!(finalized.is_none());
    }
    for node_id in 1..=2 {
        let (_, finalized) = service::cast_consensus_vote(
            &paths,
            &format!("node{node_id}"),
            password,
            ConsensusVoteType::Precommit,
            Some(proposal.block_hash.clone()),
            now + 13,
        )
        .unwrap();
        assert!(finalized.is_none());
    }
    assert_eq!(paths.read_ledger().unwrap().blocks.len(), 0);
    let round = service::advance_consensus_round(&paths, now + 34).unwrap();
    assert_eq!(round, 2);
    let locked = paths.read_ledger().unwrap();
    assert_eq!(locked.consensus.valid_round, Some(1));
    assert_eq!(locked.consensus.locks.len(), 2);
    drop(locked);

    let reproposal = service::propose_consensus_block(&paths, "node3", password, now + 34).unwrap();
    assert_eq!(reproposal.consensus_round, 2);
    assert_ne!(reproposal.block_hash, proposal.block_hash);
    assert_eq!(reproposal.operation_ids, proposal.operation_ids);
    assert_eq!(reproposal.state_root, proposal.state_root);
    for node_id in 1..=3 {
        service::cast_consensus_vote(
            &paths,
            &format!("node{node_id}"),
            password,
            ConsensusVoteType::Prevote,
            Some(reproposal.block_hash.clone()),
            now + 35,
        )
        .unwrap();
    }
    let mut block = None;
    for node_id in 1..=3 {
        let (_, finalized) = service::cast_consensus_vote(
            &paths,
            &format!("node{node_id}"),
            password,
            ConsensusVoteType::Precommit,
            Some(reproposal.block_hash.clone()),
            now + 35,
        )
        .unwrap();
        block = block.or(finalized);
    }
    let block = block.unwrap();
    assert_eq!(block.height, 1);
    assert_eq!(block.commit_signatures.len(), 3);
    assert!(
        block
            .commit_signatures
            .iter()
            .all(|vote| vote.vote_type == ConsensusVoteType::Precommit)
    );

    let ledger = paths.read_ledger().unwrap();
    assert!(ledger.pending_operation_ids.is_empty());
    assert!(ledger.operations.values().all(|operation| {
        matches!(operation.status, OperationStatus::Finalized) && operation.block_height == Some(1)
    }));
    let verified = service::verify_blockchain(&paths).unwrap();
    assert!(verified.ok, "{}", verified.detail);

    let catch_up = service::consensus_catch_up_chunk(&paths, 0, 256).unwrap();
    let checkpoint = catch_up.finalized_checkpoint.unwrap();
    assert_eq!(
        service::apply_consensus_catch_up(
            &lagging_paths,
            catch_up.blocks,
            catch_up.operations,
            *checkpoint,
        )
        .unwrap(),
        1
    );
    let caught_up = service::verify_blockchain(&lagging_paths).unwrap();
    assert!(caught_up.ok, "{}", caught_up.detail);
    assert_eq!(caught_up.height, 1);

    let ledger_id = paths.read_ledger().unwrap().ledger_id;
    let mut conflicting = Vec::new();
    for node_id in 1..=2 {
        let owner = paths
            .read_keyfile(
                &paths
                    .node_owner_key_path(&format!("node{node_id}"))
                    .unwrap(),
            )
            .unwrap();
        let nonce = paths.read_ledger().unwrap().accounts[&owner.address].nonce + 1;
        let (network_id, commitment) = service::new_network_identity().unwrap();
        let operation = service::sign_public_operation(
            &owner,
            password,
            service::PublicOperationSigningRequest {
                ledger_id: &ledger_id,
                module: "NetworkRegistry",
                action: "CreateNetwork",
                nonce,
                valid_until: now + 600,
                payload: serde_json::json!({
                    "alias": "conflicting-alias",
                    "network_id": network_id,
                    "network_commitment": commitment,
                }),
            },
        )
        .unwrap();
        conflicting.push(mrk::consensus::PendingOperationEnvelope {
            public_key: owner.public_key,
            operation,
        });
    }
    service::submit_consensus_operation(&paths, conflicting[0].clone(), now + 36).unwrap();
    service::submit_consensus_operation(&paths, conflicting[1].clone(), now + 36).unwrap();
    service::submit_consensus_operation(&lagging_paths, conflicting[1].clone(), now + 36).unwrap();
    service::submit_consensus_operation(&lagging_paths, conflicting[0].clone(), now + 36).unwrap();
    assert_eq!(
        paths.read_ledger().unwrap().pending_operation_ids,
        lagging_paths.read_ledger().unwrap().pending_operation_ids
    );

    assert!(service::propose_consensus_block(&paths, "node2", password, now + 36).is_err());
    let next = service::propose_consensus_block(&paths, "node2", password, now + 44).unwrap();
    assert_eq!(next.height, 2);
    assert_eq!(next.operation_ids.len(), 1);
    assert!(service::submit_consensus_proposal(&lagging_paths, next.clone(), now + 36).is_err());
    assert!(
        service::submit_consensus_proposal(&lagging_paths, next.clone(), now + 44)
            .unwrap()
            .accepted
    );
    paths
        .with_ledger_mut(|ledger| {
            ledger.nodes.get_mut(&20).unwrap().status = NodeStatus::WarmingUp;
            Ok(())
        })
        .unwrap();
    let fallback = service::consensus_status(&paths, now + 44).unwrap();
    assert_eq!(fallback.mode, "NODE1_SINGLE_PRODUCER");
    assert!(fallback.proposal_block_hash.is_none());

    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(lagging_root).unwrap();
}
