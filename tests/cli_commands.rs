use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_root(label: &str) -> std::path::PathBuf {
    let random = mrk_core::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!(
        "mrk-{label}-{}",
        mrk_core::crypto::hex_lower(&random)
    ))
}

fn run(binary: &str, root: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(binary)
        .arg("--data-dir")
        .arg(root)
        .arg("--output")
        .arg("json")
        .args(args)
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .output()
        .unwrap()
}

fn run_with_password_file(
    binary: &str,
    root: &std::path::Path,
    password_file: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    Command::new(binary)
        .arg("--data-dir")
        .arg(root)
        .arg("--output")
        .arg("json")
        .args(args)
        .env_remove("MRK_KEYSTORE_PASSWORD")
        .env("MRK_KEYSTORE_PASSWORD_FILE", password_file)
        .output()
        .unwrap()
}

fn run_mrk_rpc(root: &std::path::Path, port: u16, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(root)
        .arg("--output")
        .arg("json")
        .arg("--rpc-endpoint")
        .arg(format!("ws://127.0.0.1:{port}/v1/rpc"))
        .arg("--rpc-allow-insecure-local")
        .args(args)
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .output()
        .unwrap()
}

fn block_was_produced_or_already_finalized(output: &std::process::Output) -> bool {
    output.status.success()
        || String::from_utf8_lossy(&output.stderr)
            .contains("there are no pending operations to include")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_daemon(root: &std::path::Path) {
    for _ in 0..100 {
        if UnixStream::connect(root.join("mrk.sock")).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("mrk node Unix Socket did not become ready");
}

fn wait_for_health(port: u16) {
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.contains("200 OK") {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("mrk node WSS listener did not become healthy");
}

#[test]
fn data_dir_supports_environment_variable_and_cli_override() {
    let env_root = temp_root("data-dir-env");
    let cli_root = temp_root("data-dir-cli");
    let from_env = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("account")
        .arg("init")
        .arg("--name")
        .arg("from-env")
        .env("MRK_DATA_DIR", &env_root)
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .output()
        .unwrap();
    assert!(
        from_env.status.success(),
        "{}",
        String::from_utf8_lossy(&from_env.stderr)
    );
    assert!(env_root.join("accounts/from-env.json").exists());

    let overridden = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&cli_root)
        .arg("account")
        .arg("init")
        .arg("--name")
        .arg("from-cli")
        .env("MRK_DATA_DIR", &env_root)
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .output()
        .unwrap();
    assert!(
        overridden.status.success(),
        "{}",
        String::from_utf8_lossy(&overridden.stderr)
    );
    assert!(cli_root.join("accounts/from-cli.json").exists());
    assert!(!env_root.join("accounts/from-cli.json").exists());

    std::fs::remove_dir_all(env_root).unwrap();
    std::fs::remove_dir_all(cli_root).unwrap();
}

#[test]
fn node_init_checks_existing_node_and_rolls_back_invalid_password() {
    let root = temp_root("node-init-atomic");
    let invalid = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("node")
        .arg("init")
        .env("MRK_KEYSTORE_PASSWORD", "short")
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("at least 8 characters"),
        "{}",
        String::from_utf8_lossy(&invalid.stderr)
    );
    assert!(!root.join("nodes/default").exists());

    let initialized = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "init", "--ledger-id", "acme-devnet-1"],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let initialized_json: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(initialized_json["ledger_id"], "acme-devnet-1");
    let paths = mrk_core::storage::DataPaths::new(Some(root.clone())).unwrap();
    assert_eq!(paths.read_ledger().unwrap().ledger_id, "acme-devnet-1");
    assert_eq!(paths.initialize_ledger(None).unwrap(), "acme-devnet-1");
    drop(paths);

    let rename = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &[
            "node",
            "--node",
            "second",
            "init",
            "--ledger-id",
            "another-devnet-1",
        ],
    );
    assert!(!rename.status.success());
    assert!(
        String::from_utf8_lossy(&rename.stderr).contains("cannot be renamed"),
        "{}",
        String::from_utf8_lossy(&rename.stderr)
    );
    assert!(!root.join("nodes/second").exists());

    let duplicate = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("node")
        .arg("init")
        .env_remove("MRK_KEYSTORE_PASSWORD")
        .env_remove("MRK_KEYSTORE_PASSWORD_FILE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(
        String::from_utf8_lossy(&duplicate.stderr).contains("node 'default' already exists"),
        "{}",
        String::from_utf8_lossy(&duplicate.stderr)
    );

    let invalid_root = temp_root("invalid-ledger-id");
    let invalid_ledger_id = run(
        env!("CARGO_BIN_EXE_mrk"),
        &invalid_root,
        &["node", "init", "--ledger-id", "Invalid_Name"],
    );
    assert!(!invalid_ledger_id.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_ledger_id.stderr).contains("lowercase ASCII letters"),
        "{}",
        String::from_utf8_lossy(&invalid_ledger_id.stderr)
    );
    assert!(!invalid_root.join("nodes/default").exists());

    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(invalid_root).unwrap();
}

#[test]
fn account_and_node_cli_commands_emit_json() {
    let root = temp_root("cli-flow");
    let account = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["account", "init", "--name", "default"],
    );
    assert!(
        account.status.success(),
        "{}",
        String::from_utf8_lossy(&account.stderr)
    );
    let account_json: serde_json::Value = serde_json::from_slice(&account.stdout).unwrap();
    assert!(
        account_json["address"]
            .as_str()
            .unwrap()
            .starts_with("mrk1")
    );

    let password_file = root.join("automation-password");
    std::fs::write(&password_file, "password-from-private-file\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let file_account = run_with_password_file(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &password_file,
        &["account", "init", "--name", "file-account"],
    );
    assert!(
        file_account.status.success(),
        "{}",
        String::from_utf8_lossy(&file_account.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let insecure = run_with_password_file(
            env!("CARGO_BIN_EXE_mrk"),
            &root,
            &password_file,
            &["account", "init", "--name", "insecure-file-account"],
        );
        assert!(!insecure.status.success());
        assert!(String::from_utf8_lossy(&insecure.stderr).contains("group or others"));
    }

    let init_node = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "init", "--lite"],
    );
    assert!(
        init_node.status.success(),
        "{}",
        String::from_utf8_lossy(&init_node.stderr)
    );
    let node_json: serde_json::Value = serde_json::from_slice(&init_node.stdout).unwrap();
    assert_eq!(node_json["storage_mode"], "LITE");
    assert!(
        node_json["reward_address"]
            .as_str()
            .unwrap()
            .starts_with("mrk1")
    );
    let account_address = account_json["address"].as_str().unwrap();
    let reward_address = node_json["reward_address"].as_str().unwrap();
    mrk_core::storage::DataPaths::new(Some(root.clone()))
        .unwrap()
        .with_ledger_mut(|ledger| {
            ledger
                .accounts
                .entry(account_address.to_owned())
                .or_default()
                .balance = mrk_core::amount::MRK_SCALE;
            ledger
                .accounts
                .entry(reward_address.to_owned())
                .or_default()
                .balance = mrk_core::amount::MRK_SCALE;
            Ok(())
        })
        .unwrap();

    let port = free_port();
    let daemon = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("node")
        .arg("run")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let daemon_guard = ChildGuard(daemon);
    wait_for_daemon(&root);

    let join = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "join", "--endpoint", "1.1.1.1"],
    );
    assert!(
        join.status.success(),
        "{}",
        String::from_utf8_lossy(&join.stderr)
    );
    let join_json: serde_json::Value = serde_json::from_slice(&join.stdout).unwrap();
    assert_eq!(join_json["ip_slot"], "v4:1.1.1.1");
    assert_eq!(join_json["status"], "ACTIVE");
    assert_eq!(join_json["warmup_until"], join_json["registered_at"]);
    assert_eq!(join_json["price_per_gib"], 1_000_000_000);
    wait_for_health(port);

    let balance = run_mrk_rpc(&root, port, &["account", "balance", "--account", "default"]);
    assert!(
        balance.status.success(),
        "{}",
        String::from_utf8_lossy(&balance.stderr)
    );
    let balance_json: serde_json::Value = serde_json::from_slice(&balance.stdout).unwrap();
    assert_eq!(
        balance_json["balance"].as_u64(),
        Some(mrk_core::amount::MRK_SCALE as u64)
    );

    let treasury = run_mrk_rpc(&root, port, &["treasury", "status"]);
    assert!(
        treasury.status.success(),
        "{}",
        String::from_utf8_lossy(&treasury.stderr)
    );
    let treasury_json: serde_json::Value = serde_json::from_slice(&treasury.stdout).unwrap();
    assert_eq!(treasury_json["balance_display"], "500000000 MRK");
    assert_eq!(treasury_json["genesis_allocation_display"], "500000000 MRK");
    assert_eq!(treasury_json["spending_enabled"], false);

    let status = run(env!("CARGO_BIN_EXE_mrk"), &root, &["node", "status"]);
    assert!(status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["node_id"], 1);
    assert_eq!(status_json["storage_mode"], "LITE");
    assert_eq!(status_json["availability_mode"], "NODE1_TRUSTED");
    assert_eq!(status_json["availability_earning_enabled"], true);

    let governance_status = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "governance", "status"],
    );
    assert!(governance_status.status.success());
    let governance_json: serde_json::Value =
        serde_json::from_slice(&governance_status.stdout).unwrap();
    assert_eq!(governance_json["mode"], "NODE1_DIRECT");
    assert_eq!(governance_json["genesis_node_id"], 1);
    assert_eq!(governance_json["threshold"], 20);
    assert_eq!(governance_json["availability_mode"], "NODE1_TRUSTED");
    assert_eq!(
        governance_json["minimum_decentralized_availability_validators"],
        7
    );
    let effective_epoch = governance_json["current_epoch_number"].as_u64().unwrap() + 2;
    let effective_epoch_arg = effective_epoch.to_string();

    let governance_bond_status = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "governance", "bond-status"],
    );
    assert!(governance_bond_status.status.success());
    let governance_bond_json: serde_json::Value =
        serde_json::from_slice(&governance_bond_status.stdout).unwrap();
    assert_eq!(governance_bond_json["governance_bond_display"], "0 MRK");
    assert_eq!(governance_bond_json["required_bond_display"], "10000 MRK");
    assert_eq!(governance_bond_json["matures_at"], serde_json::Value::Null);

    let governance_set = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &[
            "node",
            "governance",
            "set",
            "--parameter",
            "probe-validity-seconds",
            "--value",
            "600",
            "--effective-epoch",
            &effective_epoch_arg,
        ],
    );
    assert!(
        governance_set.status.success(),
        "{}",
        String::from_utf8_lossy(&governance_set.stderr)
    );
    let governance_receipt: serde_json::Value =
        serde_json::from_slice(&governance_set.stdout).unwrap();
    assert_eq!(governance_receipt["action"], "SetParameters");
    assert_eq!(governance_receipt["signer_node_id"], 1);
    assert_eq!(governance_receipt["status"], "PENDING");
    assert_eq!(
        governance_receipt["payload"]["effective_epoch"],
        effective_epoch
    );
    assert_eq!(
        governance_receipt["payload"]["epoch_context_activation"],
        effective_epoch
    );
    let governance_operation_id = governance_receipt["operation_id"].as_str().unwrap();

    let governance_status = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "governance", "status"],
    );
    assert!(governance_status.status.success());
    let governance_status: serde_json::Value =
        serde_json::from_slice(&governance_status.stdout).unwrap();
    assert_eq!(
        governance_status["scheduled_parameter_changes"][&effective_epoch_arg]["probe-validity-seconds"],
        "600"
    );

    let block_status = run_mrk_rpc(&root, port, &["block", "status"]);
    assert!(block_status.status.success());
    let block_status_json: serde_json::Value =
        serde_json::from_slice(&block_status.stdout).unwrap();
    assert_eq!(block_status_json["mode"], "NODE1_SINGLE_PRODUCER");
    assert_eq!(block_status_json["availability_mode"], "NODE1_TRUSTED");
    assert_eq!(block_status_json["availability_earning_enabled"], true);
    assert!(
        block_status_json["pending_operation_count"]
            .as_u64()
            .is_some()
    );

    let produced = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "block", "produce"],
    );
    assert!(
        block_was_produced_or_already_finalized(&produced),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let operation_status = run_mrk_rpc(
        &root,
        port,
        &["block", "operation", "status", governance_operation_id],
    );
    assert!(operation_status.status.success());
    let operation_status: serde_json::Value =
        serde_json::from_slice(&operation_status.stdout).unwrap();
    let operation_height = operation_status["block_height"]
        .as_u64()
        .unwrap()
        .to_string();
    let produced = run_mrk_rpc(
        &root,
        port,
        &["block", "show", "--height", &operation_height],
    );
    assert!(produced.status.success());
    let produced_json: serde_json::Value = serde_json::from_slice(&produced.stdout).unwrap();
    assert!(produced_json["height"].as_u64().unwrap() >= 1);
    assert_eq!(produced_json["producer_node_id"], 1);
    assert!(
        !produced_json["operation_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let finalized = run_mrk_rpc(
        &root,
        port,
        &["block", "operation", "status", governance_operation_id],
    );
    assert!(finalized.status.success());
    let finalized_json: serde_json::Value = serde_json::from_slice(&finalized.stdout).unwrap();
    assert_eq!(finalized_json["status"], "FINALIZED");
    assert!(finalized_json["block_height"].as_u64().unwrap() >= 1);

    let checkpoints = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "block", "checkpoints"],
    );
    assert!(checkpoints.status.success());
    let checkpoints: serde_json::Value = serde_json::from_slice(&checkpoints.stdout).unwrap();
    let checkpoint_height = checkpoints[0]["height"].as_u64().unwrap();
    assert!(checkpoint_height <= produced_json["height"].as_u64().unwrap());
    let checkpoint_height_arg = checkpoint_height.to_string();
    let checkpoint_block = run_mrk_rpc(
        &root,
        port,
        &["block", "show", "--height", &checkpoint_height_arg],
    );
    assert!(checkpoint_block.status.success());
    let checkpoint_block: serde_json::Value =
        serde_json::from_slice(&checkpoint_block.stdout).unwrap();
    assert_eq!(checkpoints[0]["state_root"], checkpoint_block["state_root"]);

    let governance_status = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "governance", "status"],
    );
    assert!(governance_status.status.success());
    let governance_status: serde_json::Value =
        serde_json::from_slice(&governance_status.stdout).unwrap();
    assert_eq!(
        governance_status["scheduled_parameter_changes"][&effective_epoch_arg]["probe-validity-seconds"],
        "600"
    );

    let create_network = run_mrk_rpc(
        &root,
        port,
        &[
            "network",
            "create",
            "--name",
            "team",
            "--account",
            "default",
        ],
    );
    assert!(
        create_network.status.success(),
        "{}",
        String::from_utf8_lossy(&create_network.stderr)
    );
    let produced = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "block", "produce"],
    );
    assert!(
        block_was_produced_or_already_finalized(&produced),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );

    let network = run_mrk_rpc(&root, port, &["network", "show", "--network", "team"]);
    assert!(
        network.status.success(),
        "{}",
        String::from_utf8_lossy(&network.stderr)
    );
    let network_json: serde_json::Value = serde_json::from_slice(&network.stdout).unwrap();
    assert_eq!(network_json["alias"], "team");
    assert_eq!(network_json["escrow_balance"], 0);

    let network_text = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("--rpc-endpoint")
        .arg(format!("ws://127.0.0.1:{port}/v1/rpc"))
        .arg("--rpc-allow-insecure-local")
        .args(["network", "show", "--network", "team"])
        .output()
        .unwrap();
    assert!(
        network_text.status.success(),
        "{}",
        String::from_utf8_lossy(&network_text.stderr)
    );
    let network_text = String::from_utf8_lossy(&network_text.stdout);
    assert!(network_text.contains("Network:      team"));
    assert!(network_text.contains("Fund balance: 0 MRK"));

    let issue = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("--output")
        .arg("json")
        .arg("--rpc-endpoint")
        .arg(format!("ws://127.0.0.1:{port}/v1/rpc"))
        .arg("--rpc-allow-insecure-local")
        .args([
            "member",
            "issue",
            "--network",
            "team",
            "--name",
            "client-a",
            "--account",
            "default",
        ])
        .env("MRK_KEYSTORE_PASSWORD", "cli-integration-password")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pending_path = root.join("networks/team/.client-a.issue.pending.json");
    for _ in 0..200 {
        if pending_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(pending_path.exists());
    let pending: mrk_core::storage::PendingMemberIssue =
        serde_json::from_slice(&std::fs::read(&pending_path).unwrap()).unwrap();
    for _ in 0..100 {
        let status = run_mrk_rpc(
            &root,
            port,
            &["block", "operation", "status", &pending.operation_id],
        );
        if status.status.success() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let duplicate_issue = run_mrk_rpc(
        &root,
        port,
        &[
            "member",
            "issue",
            "--network",
            "team",
            "--name",
            "client-a",
            "--account",
            "default",
        ],
    );
    assert!(!duplicate_issue.status.success());
    assert!(
        String::from_utf8_lossy(&duplicate_issue.stderr)
            .contains("already being issued by another local process")
    );
    let produced = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "block", "produce"],
    );
    assert!(
        block_was_produced_or_already_finalized(&produced),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let issued = issue.wait_with_output().unwrap();
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let issued_json: serde_json::Value = serde_json::from_slice(&issued.stdout).unwrap();
    assert_eq!(issued_json["status"], "FINALIZED");
    assert!(!pending_path.exists());
    assert!(root.join("networks/team/client-a.key.json").exists());
    assert!(root.join("networks/team/client-a.credential.json").exists());

    let overwrite = run_mrk_rpc(
        &root,
        port,
        &[
            "member",
            "issue",
            "--network",
            "team",
            "--name",
            "client-a",
            "--account",
            "default",
        ],
    );
    assert!(!overwrite.status.success());
    assert!(String::from_utf8_lossy(&overwrite.stderr).contains("already exists"));

    let history_text = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--data-dir")
        .arg(&root)
        .arg("--rpc-endpoint")
        .arg(format!("ws://127.0.0.1:{port}/v1/rpc"))
        .arg("--rpc-allow-insecure-local")
        .args(["account", "history", "--account", "default"])
        .output()
        .unwrap();
    assert!(
        history_text.status.success(),
        "{}",
        String::from_utf8_lossy(&history_text.stderr)
    );
    let history_text = String::from_utf8_lossy(&history_text.stdout);
    assert!(history_text.contains("Operations: 2"));
    assert!(history_text.contains("FINALIZED  NetworkRegistry.CreateNetwork"));
    assert!(history_text.contains("Details:   {\"alias\":\"team\""));

    let registry = run_mrk_rpc(&root, port, &["registry", "list", "--status", "active"]);
    assert!(
        registry.status.success(),
        "{}",
        String::from_utf8_lossy(&registry.stderr)
    );
    let registry_json: serde_json::Value = serde_json::from_slice(&registry.stdout).unwrap();
    assert_eq!(registry_json["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(registry_json["nodes"][0]["node_id"], 1);
    assert_eq!(registry_json["nodes"][0]["status"], "ACTIVE");

    let registered_node = run_mrk_rpc(&root, port, &["registry", "show", "--node-id", "1"]);
    assert!(registered_node.status.success());
    let registered_node_json: serde_json::Value =
        serde_json::from_slice(&registered_node.stdout).unwrap();
    assert_eq!(registered_node_json["endpoint"], "wss://1.1.1.1/v1/relay");

    let discovered = run_mrk_rpc(&root, port, &["discover"]);
    assert!(discovered.status.success());
    let discovered_json: serde_json::Value = serde_json::from_slice(&discovered.stdout).unwrap();
    assert!(discovered_json["relays"].as_array().unwrap().is_empty());

    let verified = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "block", "verify"],
    );
    assert!(verified.status.success());
    let verified_json: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified_json["ok"], true);
    assert!(verified_json["height"].as_u64().unwrap() >= 1);

    let update_price = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &["node", "update-price", "--price-per-gib", "0.03MRK"],
    );
    assert!(
        update_price.status.success(),
        "{}",
        String::from_utf8_lossy(&update_price.stderr)
    );
    let update_price_json: serde_json::Value =
        serde_json::from_slice(&update_price.stdout).unwrap();
    assert_eq!(update_price_json["status"], "PENDING");
    assert_eq!(update_price_json["node"]["price_per_gib"], 3_000_000);
    let status = run(env!("CARGO_BIN_EXE_mrk"), &root, &["node", "status"]);
    assert!(status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["price_per_gib"], 3_000_000);

    let node_doctor = run(env!("CARGO_BIN_EXE_mrk"), &root, &["node", "doctor"]);
    assert!(!node_doctor.status.success());
    let node_doctor_json: serde_json::Value = serde_json::from_slice(&node_doctor.stdout).unwrap();
    assert_eq!(node_doctor_json["ok"], false);
    assert!(
        node_doctor_json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "probe_freshness" && check["ok"] == false)
    );

    let daemon_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("node")
        .arg("--help")
        .output()
        .unwrap();
    assert!(daemon_help.status.success());
    let daemon_help = String::from_utf8_lossy(&daemon_help.stdout);
    assert!(daemon_help.contains("init"));
    assert!(daemon_help.contains("join"));
    assert!(daemon_help.contains("update-price"));
    assert!(daemon_help.contains("run"));
    assert!(daemon_help.contains("status"));
    assert!(daemon_help.contains("rewards"));
    assert!(daemon_help.contains("probe"));
    assert!(daemon_help.contains("claim"));
    assert!(daemon_help.contains("drain"));
    assert!(daemon_help.contains("block"));
    assert!(daemon_help.contains("validator"));
    assert!(daemon_help.contains("consensus"));
    assert!(daemon_help.contains("governance"));

    let block_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .args(["node", "block", "--help"])
        .output()
        .unwrap();
    assert!(block_help.status.success());
    let block_help = String::from_utf8_lossy(&block_help.stdout);
    assert!(block_help.contains("checkpoints"));

    let client_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(client_help.status.success());
    let client_help = String::from_utf8_lossy(&client_help.stdout);
    assert!(client_help.contains("node"));
    assert!(!client_help.contains("validator"));
    assert!(!client_help.contains("consensus"));
    assert!(!client_help.contains("governance"));
    assert!(!client_help.contains("doctor"));

    let governance_set_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .args(["node", "governance", "set", "--help"])
        .output()
        .unwrap();
    assert!(governance_set_help.status.success());
    let governance_set_help = String::from_utf8_lossy(&governance_set_help.stdout);
    assert!(governance_set_help.contains("--effective-epoch <EFFECTIVE_EPOCH>"));

    let account_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .args(["account", "--help"])
        .output()
        .unwrap();
    assert!(account_help.status.success());
    let account_help = String::from_utf8_lossy(&account_help.stdout);
    assert!(account_help.contains("init"));
    assert!(account_help.contains("address"));
    assert!(account_help.contains("balance"));
    assert!(account_help.contains("transfer"));
    assert!(account_help.contains("history"));

    let network_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .args(["network", "--help"])
        .output()
        .unwrap();
    assert!(network_help.status.success());
    let network_help = String::from_utf8_lossy(&network_help.stdout);
    assert!(network_help.contains("create"));
    assert!(network_help.contains("fund"));
    assert!(network_help.contains("show"));

    let block_help = Command::new(env!("CARGO_BIN_EXE_mrk"))
        .args(["block", "--help"])
        .output()
        .unwrap();
    assert!(block_help.status.success());
    let block_help = String::from_utf8_lossy(&block_help.stdout);
    assert!(block_help.contains("status"));
    assert!(block_help.contains("show"));
    assert!(block_help.contains("operation"));

    drop(daemon_guard);
    std::fs::remove_dir_all(root).unwrap();
}
