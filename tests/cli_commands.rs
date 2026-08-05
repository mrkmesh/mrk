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
    let random = mrk::crypto::random_bytes::<8>().unwrap();
    std::env::temp_dir().join(format!("mrk-{label}-{}", mrk::crypto::hex_lower(&random)))
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

    let initialized = run(env!("CARGO_BIN_EXE_mrk"), &root, &["node", "init"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

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

    std::fs::remove_dir_all(root).unwrap();
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

    let register = run(
        env!("CARGO_BIN_EXE_mrk"),
        &root,
        &[
            "node",
            "register",
            "--endpoint",
            "wss://1.1.1.1/v1/relay",
            "--price-per-gib",
            "0.02MRK",
        ],
    );
    assert!(
        register.status.success(),
        "{}",
        String::from_utf8_lossy(&register.stderr)
    );
    let register_json: serde_json::Value = serde_json::from_slice(&register.stdout).unwrap();
    assert_eq!(register_json["ip_slot"], "v4:1.1.1.1");
    assert_eq!(register_json["status"], "ACTIVE");
    assert_eq!(
        register_json["warmup_until"],
        register_json["registered_at"]
    );
    wait_for_health(port);

    let balance = run_mrk_rpc(&root, port, &["account", "balance", "--account", "default"]);
    assert!(
        balance.status.success(),
        "{}",
        String::from_utf8_lossy(&balance.stderr)
    );
    let balance_json: serde_json::Value = serde_json::from_slice(&balance.stdout).unwrap();
    assert_eq!(balance_json["liquid"], 0);

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
        ],
    );
    assert!(
        governance_set.status.success(),
        "{}",
        String::from_utf8_lossy(&governance_set.stderr)
    );
    let governance_receipt: serde_json::Value =
        serde_json::from_slice(&governance_set.stdout).unwrap();
    assert_eq!(governance_receipt["action"], "SetParameter");
    assert_eq!(governance_receipt["signer_node_id"], 1);
    assert_eq!(governance_receipt["status"], "PENDING");

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
        produced.status.success(),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let produced_json: serde_json::Value = serde_json::from_slice(&produced.stdout).unwrap();
    assert!(produced_json["height"].as_u64().unwrap() >= 1);
    assert_eq!(produced_json["producer_node_id"], 1);
    assert!(
        !produced_json["operation_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let governance_operation_id = governance_receipt["operation_id"].as_str().unwrap();
    let finalized = run_mrk_rpc(
        &root,
        port,
        &["block", "operation", "status", governance_operation_id],
    );
    assert!(finalized.status.success());
    let finalized_json: serde_json::Value = serde_json::from_slice(&finalized.stdout).unwrap();
    assert_eq!(finalized_json["status"], "FINALIZED");
    assert!(finalized_json["block_height"].as_u64().unwrap() >= 1);

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
    assert!(daemon_help.contains("register"));
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
