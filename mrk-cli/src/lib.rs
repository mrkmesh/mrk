use std::{
    io::{self, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use mrk_core::{
    Error, Result,
    amount::{format_mrk, parse_mrk},
    crypto::validate_keystore_password,
    model::DEFAULT_OPERATION_VALIDITY_SECONDS,
    relay_client, service,
    storage::DataPaths,
};
use serde::{Deserialize, Serialize};

use mrk_node as node_cli;

mod pipe;

use pipe::{RecoverySettlementOptions, StdioPipeOptions, run_recovery_settlement, run_stdio_pipe};

#[derive(Parser)]
#[command(
    name = "mrk",
    version,
    about = "MRK public chain client and Node daemon"
)]
struct Cli {
    #[arg(long, global = true, env = "MRK_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true, env = "MRK_RPC_ENDPOINT")]
    rpc_endpoint: Option<String>,
    #[arg(long, global = true)]
    rpc_allow_insecure_local: bool,
    #[arg(long, global = true)]
    rpc_tls_ca: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = Output::Text)]
    output: Output,
    #[arg(long, global = true)]
    yes: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    Node {
        #[arg(long, default_value = "default")]
        node: String,
        #[command(subcommand)]
        command: node_cli::DaemonCommand,
    },
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    Discover {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limit: u64,
        #[arg(long)]
        cursor: Option<u64>,
    },
    Member {
        #[command(subcommand)]
        command: MemberCommand,
    },
    Payment {
        #[command(subcommand)]
        command: PaymentCommand,
    },
    Pipe {
        #[arg(long)]
        network: String,
        #[arg(long)]
        member: String,
        #[arg(long)]
        endpoint: String,
        #[arg(
            long,
            value_name = "MEMBER_NAME_OR_ID",
            help = "Target Member name or member_id"
        )]
        peer: Option<String>,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        max_auto_recovery_bytes: u64,
    },
    Block {
        #[command(subcommand)]
        command: PublicBlockCommand,
    },
    Treasury {
        #[command(subcommand)]
        command: node_cli::TreasuryCommand,
    },
}

#[derive(Subcommand)]
enum PublicBlockCommand {
    Status,
    Show {
        #[arg(long)]
        height: u64,
    },
    Operation {
        #[command(subcommand)]
        command: OperationCommand,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    Init {
        #[arg(long, default_value = "default")]
        name: String,
    },
    Address {
        #[arg(long, default_value = "default")]
        account: String,
    },
    Balance(AccountOrAddress),
    Transfer {
        #[arg(long, default_value = "default")]
        account: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        dry_run: bool,
    },
    History {
        #[command(flatten)]
        target: AccountOrAddress,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Args)]
struct AccountOrAddress {
    #[arg(long, default_value = "default", conflicts_with = "address")]
    account: String,
    #[arg(long)]
    address: Option<String>,
}

#[derive(Subcommand)]
enum OperationCommand {
    Status { operation_id: String },
}

#[derive(Subcommand)]
enum NetworkCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "default")]
        account: String,
    },
    Fund {
        #[arg(long)]
        network: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "default")]
        account: String,
    },
    Show {
        #[arg(long)]
        network: String,
    },
    Policy {
        #[command(subcommand)]
        command: NetworkPolicyCommand,
    },
}

#[derive(Subcommand)]
enum NetworkPolicyCommand {
    Show {
        #[arg(long)]
        network: String,
    },
    Set {
        #[arg(long)]
        network: String,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        max_session_amount: Option<String>,
        #[arg(long)]
        max_member_reserved: Option<String>,
        #[arg(long)]
        max_node_price_per_gib: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=43200))]
        max_session_minutes: Option<u32>,
        #[arg(long, default_value = "default")]
        account: String,
    },
}

#[derive(Subcommand)]
enum RegistryCommand {
    List {
        #[arg(long, value_enum)]
        status: Option<RegistryNodeStatus>,
        #[arg(long)]
        validator: bool,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limit: u64,
        #[arg(long)]
        cursor: Option<u64>,
    },
    Show {
        #[arg(long)]
        node_id: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RegistryNodeStatus {
    Initialized,
    WarmingUp,
    Active,
    Draining,
    Exited,
    Suspended,
}

impl RegistryNodeStatus {
    fn as_rpc_str(self) -> &'static str {
        match self {
            Self::Initialized => "INITIALIZED",
            Self::WarmingUp => "WARMING_UP",
            Self::Active => "ACTIVE",
            Self::Draining => "DRAINING",
            Self::Exited => "EXITED",
            Self::Suspended => "SUSPENDED",
        }
    }
}

#[derive(Subcommand)]
enum MemberCommand {
    /// List registered members and their live presence on the selected Relay Node.
    List {
        #[arg(long)]
        network: String,
    },
    Issue {
        #[arg(long)]
        network: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "default")]
        account: String,
        #[arg(long, default_value_t = 7)]
        valid_days: i64,
    },
    Revoke {
        #[arg(long)]
        network: String,
        #[arg(long)]
        serial: u64,
        #[arg(long, default_value = "default")]
        account: String,
    },
    Show {
        #[arg(long)]
        network: String,
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum PaymentCommand {
    Status {
        #[arg(value_name = "AUTHORIZATION_ID_OR_SESSION_ID")]
        identifier: String,
    },
    History {
        #[arg(long)]
        network: String,
        #[arg(long)]
        member: Option<String>,
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limit: u64,
    },
    Refund {
        authorization_id: String,
        #[arg(long, default_value = "default")]
        account: String,
    },
    Unsettled {
        #[arg(long)]
        network: String,
        #[arg(long)]
        member: String,
    },
    Settle {
        authorization_id: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        member: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        max_auto_recovery_bytes: u64,
    },
}

pub fn main_entry() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let paths = DataPaths::new(cli.data_dir)?;
    let rpc = RpcOptions {
        endpoint: cli.rpc_endpoint,
        allow_insecure_local: cli.rpc_allow_insecure_local,
        tls_ca: cli.rpc_tls_ca,
    };
    match cli.command {
        Command::Node { node, command } => {
            node_cli::run_node_command(
                &paths,
                node,
                matches!(cli.output, Output::Json),
                cli.yes,
                command,
            )?;
        }
        Command::Account { command } => match command {
            AccountCommand::Init { name } => {
                let password = read_new_password()?;
                let keyfile = service::create_local_account(&paths, &name, &password)?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "account": name,
                        "address": keyfile.address,
                        "keyfile": paths.account_key_path(&name)?.display().to_string(),
                    }),
                    || {
                        format!(
                            "Account: {name}\nAddress: {}\nKeyfile: {}",
                            keyfile.address,
                            paths.account_key_path(&name).unwrap().display()
                        )
                    },
                )?;
            }
            AccountCommand::Address { account } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "account": account,
                        "address": keyfile.address,
                    }),
                    || keyfile.address.clone(),
                )?;
            }
            AccountCommand::Balance(target) => {
                let address = resolve_address(&paths, &target)?;
                let view =
                    rpc.call("account.balance", serde_json::json!({ "address": address }))?;
                print_rpc_value(cli.output, &view)?;
            }
            AccountCommand::Transfer {
                account,
                to,
                amount,
                dry_run,
            } => {
                let now = Utc::now().timestamp();
                let keyfile = service::account_keyfile(&paths, &account)?;
                let balance = rpc.call(
                    "account.balance",
                    serde_json::json!({ "address": keyfile.address }),
                )?;
                let chain = rpc.call("system.ping", serde_json::json!({}))?;
                let amount_value = parse_mrk(&amount)?;
                let transfer_payload = serde_json::json!({
                    "to": to,
                    "amount_base_units": amount_value.to_string(),
                });
                let fee_quote = rpc_fee_quote(&rpc, "Asset", "Transfer", &transfer_payload)?;
                let total = amount_value
                    .checked_add(fee_quote.fee)
                    .ok_or_else(|| Error::msg("transfer total overflow"))?;
                let available = json_u128(&balance, "balance")?;
                if available < total {
                    return Err(Error::msg(format!(
                        "insufficient spendable MRK: available {}, required {}",
                        format_mrk(available),
                        format_mrk(total)
                    )));
                }
                let preview = service::TransferPreview {
                    ledger_id: json_str(&chain, "ledger_id")?.to_owned(),
                    from: keyfile.address.clone(),
                    to: to.clone(),
                    amount: amount_value,
                    fee: fee_quote.fee,
                    total,
                    nonce: json_u64(&balance, "nonce")?.saturating_add(1),
                    valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
                };
                if dry_run {
                    print_value(cli.output, &preview, || transfer_preview_text(&preview))?;
                    return Ok(());
                }
                let password = read_password("Keystore password: ")?;
                let (public_key, operation) = service::sign_transfer_for_submission(
                    &keyfile,
                    &password,
                    service::TransferSigningRequest {
                        ledger_id: &preview.ledger_id,
                        to: &to,
                        amount_text: &amount,
                        nonce: preview.nonce,
                        valid_until: preview.valid_until,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                    },
                )?;
                eprintln!("{}", transfer_preview_text(&preview));
                confirm_service_fee(&fee_quote, cli.yes)?;
                let receipt = rpc.call(
                    "operation.submit",
                    serde_json::json!({
                        "public_key": public_key,
                        "operation": operation,
                    }),
                )?;
                print_value(cli.output, &receipt, || {
                    serde_json::to_string_pretty(&receipt)
                        .expect("JSON value serialization cannot fail")
                })?;
            }
            AccountCommand::History { target, limit } => {
                let address = resolve_address(&paths, &target)?;
                let value = rpc.call(
                    "account.history",
                    serde_json::json!({ "address": address, "limit": limit.min(1_000) }),
                )?;
                let history: Vec<mrk_core::model::OperationRecord> =
                    serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || {
                    account_history_text(&address, &history)
                })?;
            }
        },
        Command::Network { command } => match command {
            NetworkCommand::Create { name, account } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let (network_id, commitment) = service::new_network_identity()?;
                let payload = serde_json::json!({
                    "alias": name,
                    "network_id": network_id,
                    "network_commitment": commitment,
                });
                let fee_quote = rpc_fee_quote(&rpc, "NetworkRegistry", "CreateNetwork", &payload)?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkRegistry",
                        action: "CreateNetwork",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                        payload,
                    },
                )?;
                confirm_service_fee(&fee_quote, cli.yes)?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({ "public_key": keyfile.public_key, "operation": operation }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
            NetworkCommand::Fund {
                network,
                amount,
                account,
            } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                let record: mrk_core::model::NetworkRecord = serde_json::from_value(
                    rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                )?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let payload = serde_json::json!({
                    "network_commitment": record.commitment,
                    "amount_base_units": parse_mrk(&amount)?.to_string(),
                });
                let fee_quote = rpc_fee_quote(&rpc, "NetworkEscrow", "FundNetwork", &payload)?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkEscrow",
                        action: "FundNetwork",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                        payload,
                    },
                )?;
                confirm_service_fee(&fee_quote, cli.yes)?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({ "public_key": keyfile.public_key, "operation": operation }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
            NetworkCommand::Show { network } => {
                let value = rpc.call("network.get", serde_json::json!({ "alias": network }))?;
                let network: mrk_core::model::NetworkRecord =
                    serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || network_text(&network))?;
            }
            NetworkCommand::Policy { command } => match command {
                NetworkPolicyCommand::Show { network } => {
                    let record: mrk_core::model::NetworkRecord = serde_json::from_value(
                        rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                    )?;
                    print_value(cli.output, &record.spending_policy, || {
                        spending_policy_text(&record.spending_policy)
                    })?;
                }
                NetworkPolicyCommand::Set {
                    network,
                    enabled,
                    max_session_amount,
                    max_member_reserved,
                    max_node_price_per_gib,
                    max_session_minutes,
                    account,
                } => {
                    if enabled.is_none()
                        && max_session_amount.is_none()
                        && max_member_reserved.is_none()
                        && max_node_price_per_gib.is_none()
                        && max_session_minutes.is_none()
                    {
                        return Err(Error::msg("no spending policy changes were specified"));
                    }
                    let record: mrk_core::model::NetworkRecord = serde_json::from_value(
                        rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                    )?;
                    let current = record.spending_policy;
                    let policy = mrk_core::model::NetworkSpendingPolicy {
                        revision: current.revision.saturating_add(1),
                        enabled: enabled.unwrap_or(current.enabled),
                        max_session_amount: max_session_amount
                            .as_deref()
                            .map(parse_mrk)
                            .transpose()?
                            .unwrap_or(current.max_session_amount),
                        max_member_reserved: max_member_reserved
                            .as_deref()
                            .map(parse_mrk)
                            .transpose()?
                            .unwrap_or(current.max_member_reserved),
                        max_node_price_per_gib: max_node_price_per_gib
                            .as_deref()
                            .map(parse_mrk)
                            .transpose()?
                            .unwrap_or(current.max_node_price_per_gib),
                        max_session_minutes: max_session_minutes
                            .unwrap_or(current.max_session_minutes),
                    };
                    let keyfile = service::account_keyfile(&paths, &account)?;
                    if keyfile.address != record.owner_address {
                        return Err(Error::msg(
                            "only the Network Owner account can update its spending policy",
                        ));
                    }
                    let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                    let password = read_password("Owner account password: ")?;
                    let payload = serde_json::json!({
                        "network_commitment": record.commitment,
                        "revision": policy.revision,
                        "enabled": policy.enabled,
                        "max_session_amount_base_units": policy.max_session_amount.to_string(),
                        "max_member_reserved_base_units": policy.max_member_reserved.to_string(),
                        "max_node_price_per_gib_base_units": policy.max_node_price_per_gib.to_string(),
                        "max_session_minutes": policy.max_session_minutes,
                    });
                    let fee_quote =
                        rpc_fee_quote(&rpc, "NetworkEscrow", "SetSpendingPolicy", &payload)?;
                    let operation = service::sign_public_operation(
                        &keyfile,
                        &password,
                        service::PublicOperationSigningRequest {
                            ledger_id: &ledger_id,
                            module: "NetworkEscrow",
                            action: "SetSpendingPolicy",
                            nonce,
                            valid_until: Utc::now().timestamp()
                                + DEFAULT_OPERATION_VALIDITY_SECONDS,
                            max_fee_base_units: fee_quote.recommended_max_fee,
                            fee_policy_version: fee_quote.policy_version,
                            payload,
                        },
                    )?;
                    confirm_service_fee(&fee_quote, cli.yes)?;
                    let result = rpc.call(
                        "operation.submit",
                        serde_json::json!({
                            "public_key": keyfile.public_key,
                            "operation": operation,
                        }),
                    )?;
                    print_rpc_value(cli.output, &result)?;
                }
            },
        },
        Command::Registry { command } => match command {
            RegistryCommand::List {
                status,
                validator,
                limit,
                cursor,
            } => {
                let value = rpc.call(
                    "node.list",
                    serde_json::json!({
                        "status": status.map(RegistryNodeStatus::as_rpc_str),
                        "validator": validator,
                        "limit": limit,
                        "cursor": cursor,
                    }),
                )?;
                let view: service::RegistryNodeListView = serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || registry_list_text(&view))?;
            }
            RegistryCommand::Show { node_id } => {
                let value = rpc.call("node.get", serde_json::json!({ "node_id": node_id }))?;
                let view: service::RegistryNodeView = serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || registry_node_text(&view))?;
            }
        },
        Command::Discover { limit, cursor } => {
            let value = rpc.call(
                "node.discover",
                serde_json::json!({ "limit": limit, "cursor": cursor }),
            )?;
            let view: service::RelayDiscoveryListView = serde_json::from_value(value.clone())?;
            print_value(cli.output, &value, || relay_discovery_text(&view))?;
        }
        Command::Member { command } => match command {
            MemberCommand::List { network } => {
                let value = rpc.call("member.list", serde_json::json!({ "network": network }))?;
                let view: service::MemberPresenceListView = serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || member_presence_text(&view))?;
            }
            MemberCommand::Issue {
                network,
                name,
                account,
                valid_days,
            } => {
                let _issue_lock = paths.acquire_member_issue_lock(&network, &name)?;
                if let Some(pending) = paths.pending_member_issue(&network, &name)? {
                    return match finalize_pending_member_issue(&paths, &rpc, &pending) {
                        Ok(path) => print_finalized_member_issue(cli.output, &pending, &path, true),
                        Err(error) => {
                            let pending_path = paths.pending_member_issue_path(&network, &name)?;
                            if pending_path.exists() {
                                Err(Error::msg(format!(
                                    "{error}; pending member key remains at {}",
                                    pending_path.display()
                                )))
                            } else {
                                Err(error)
                            }
                        }
                    };
                }
                let key_path = paths.member_key_path(&network, &name)?;
                let credential_path = paths.member_credential_path(&network, &name)?;
                if key_path.exists() || credential_path.exists() {
                    return Err(Error::msg(format!(
                        "local member '{name}' already exists; revoke or choose another name"
                    )));
                }
                let owner_file = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &owner_file.address)?;
                let network_record: mrk_core::model::NetworkRecord = serde_json::from_value(
                    rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                )?;
                let password = read_password("Owner account password: ")?;
                let now = Utc::now().timestamp();
                let fee_quote = rpc_fee_quote(
                    &rpc,
                    "NetworkRegistry",
                    "IssueMember",
                    &serde_json::Value::Null,
                )?;
                let (member_file, credential, operation) = service::prepare_member_issue(
                    &owner_file,
                    &password,
                    service::MemberIssueSigningRequest {
                        ledger_id: &ledger_id,
                        network: &network_record,
                        member_name: &name,
                        valid_days,
                        nonce,
                        now,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                    },
                )?;
                confirm_service_fee(&fee_quote, cli.yes)?;
                let operation_id =
                    mrk_core::crypto::sha256_id("op", &serde_json::to_vec(&operation)?);
                let pending = mrk_core::storage::PendingMemberIssue {
                    operation_id,
                    network,
                    network_commitment: network_record.commitment,
                    member: name,
                    owner_public_key: owner_file.public_key,
                    operation,
                    keyfile: member_file,
                    credential,
                    created_at: now,
                };
                let pending_path = paths.store_pending_member_issue(&pending)?;
                match finalize_pending_member_issue(&paths, &rpc, &pending) {
                    Ok(path) => print_finalized_member_issue(cli.output, &pending, &path, false)?,
                    Err(error) => {
                        if pending_path.exists() {
                            return Err(Error::msg(format!(
                                "{error}; pending member key preserved at {} — rerun the same member issue command to resume",
                                pending_path.display()
                            )));
                        }
                        return Err(error);
                    }
                }
            }
            MemberCommand::Revoke {
                network,
                serial,
                account,
            } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                let record: mrk_core::model::NetworkRecord = serde_json::from_value(
                    rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                )?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let payload = serde_json::json!({
                    "network_commitment": record.commitment,
                    "serial": serial,
                });
                let fee_quote = rpc_fee_quote(&rpc, "NetworkRegistry", "RevokeMember", &payload)?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkRegistry",
                        action: "RevokeMember",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                        payload,
                    },
                )?;
                confirm_service_fee(&fee_quote, cli.yes)?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({ "public_key": keyfile.public_key, "operation": operation }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
            MemberCommand::Show { network, name } => {
                let credential = service::member_credential(&paths, &network, &name)?;
                print_value(cli.output, &credential, || {
                    format!(
                        "Member: {name}\nMember ID: {}\nSerial: {}\nExpires: {}",
                        credential.member_id, credential.serial, credential.expires_at
                    )
                })?;
            }
        },
        Command::Payment { command } => match command {
            PaymentCommand::Status { identifier } => {
                let value = rpc.call(
                    "payment.status",
                    serde_json::json!({ "identifier": identifier }),
                )?;
                print_rpc_value(cli.output, &value)?;
            }
            PaymentCommand::History {
                network,
                member,
                limit,
            } => {
                let value = rpc.call(
                    "payment.history",
                    serde_json::json!({
                        "network": network,
                        "member": member,
                        "limit": limit,
                    }),
                )?;
                let history: service::PaymentHistoryView = serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || payment_history_text(&history))?;
            }
            PaymentCommand::Refund {
                authorization_id,
                account,
            } => {
                let owner_file = service::account_keyfile(&paths, &account)?;
                let status: service::PaymentAuthorizationStatusView =
                    serde_json::from_value(rpc.call(
                        "payment.status",
                        serde_json::json!({ "identifier": authorization_id }),
                    )?)?;
                if !matches!(status.status, mrk_core::model::OperationStatus::Finalized) {
                    return Err(Error::msg("payment authorization is not finalized"));
                }
                let authorization = status
                    .authorization
                    .ok_or_else(|| Error::msg("payment authorization state is unavailable"))?;
                if authorization.payer_address != owner_file.address {
                    return Err(Error::msg(
                        "only the payment owner account can request a refund",
                    ));
                }
                if authorization.refunded_at.is_some() {
                    return Err(Error::msg("payment authorization was already refunded"));
                }
                if authorization.reserved_remaining == 0 {
                    return Err(Error::msg(
                        "payment authorization has no remaining MRK to refund",
                    ));
                }
                let now = Utc::now().timestamp();
                if now <= authorization.claim_until {
                    let claim_until =
                        chrono::DateTime::<Utc>::from_timestamp(authorization.claim_until, 0)
                            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                            .unwrap_or_else(|| authorization.claim_until.to_string());
                    return Err(Error::msg(format!(
                        "payment authorization claim window is still open until {claim_until}"
                    )));
                }
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &owner_file.address)?;
                let password = read_password("Owner account password: ")?;
                let payload = serde_json::json!({
                    "authorization_id": authorization_id,
                });
                let fee_quote = rpc_fee_quote(&rpc, "TrafficPayment", "Refund", &payload)?;
                let operation = service::sign_public_operation(
                    &owner_file,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "TrafficPayment",
                        action: "Refund",
                        nonce,
                        valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        max_fee_base_units: fee_quote.recommended_max_fee,
                        fee_policy_version: fee_quote.policy_version,
                        payload,
                    },
                )?;
                confirm_service_fee(&fee_quote, cli.yes)?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({
                        "public_key": owner_file.public_key,
                        "operation": operation,
                    }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
            PaymentCommand::Unsettled { network, member } => {
                let local_member_id =
                    service::member_credential(&paths, &network, &member)?.member_id;
                let value = rpc.call(
                    "payment.unsettled",
                    serde_json::json!({
                        "network": network,
                        "member": member,
                    }),
                )?;
                let unsettled: Vec<service::UnsettledPaymentView> =
                    serde_json::from_value(value.clone())?;
                print_value(cli.output, &value, || {
                    if unsettled.is_empty() {
                        return "No unsettled Relay sessions.".to_owned();
                    }
                    unsettled
                        .iter()
                        .map(|item| {
                            format!(
                                "{}  node={}  peer={}  reserved={}  disconnected_at={}",
                                item.session.authorization_id,
                                item.session.node_id,
                                if item.authorization.sender_member_id == local_member_id {
                                    &item.authorization.receiver_member_id
                                } else {
                                    &item.authorization.sender_member_id
                                },
                                format_mrk(item.authorization.reserved_remaining),
                                item.session.disconnected_at,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })?;
            }
            PaymentCommand::Settle {
                authorization_id,
                network,
                member,
                endpoint,
                allow_insecure_local,
                tls_ca,
                max_auto_recovery_bytes,
            } => {
                let password = read_password("Member keystore password: ")?;
                run_recovery_settlement(RecoverySettlementOptions {
                    paths,
                    network,
                    member,
                    password,
                    endpoint,
                    authorization_id: authorization_id.clone(),
                    allow_insecure_local,
                    tls_ca,
                    max_auto_recovery_bytes,
                })?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "authorization_id": authorization_id,
                        "status": "RECEIPTS_PERSISTED",
                    }),
                    || {
                        format!(
                            "SETTLED\nAuthorization: {authorization_id}\nFinal receipts persisted by Node"
                        )
                    },
                )?;
            }
        },
        Command::Pipe {
            network,
            member,
            endpoint,
            peer,
            allow_insecure_local,
            tls_ca,
            max_auto_recovery_bytes,
        } => {
            let password = read_password("Member keystore password: ")?;
            run_stdio_pipe(StdioPipeOptions {
                paths,
                network,
                member,
                password,
                endpoint,
                peer,
                allow_insecure_local,
                tls_ca,
                max_auto_recovery_bytes,
                yes: cli.yes,
            })?;
        }
        Command::Block { command } => match command {
            PublicBlockCommand::Status => {
                let status = rpc.call("chain.status", serde_json::json!({}))?;
                print_rpc_value(cli.output, &status)?;
            }
            PublicBlockCommand::Show { height } => {
                let block = rpc.call("block.get", serde_json::json!({ "height": height }))?;
                print_rpc_value(cli.output, &block)?;
            }
            PublicBlockCommand::Operation { command } => match command {
                OperationCommand::Status { operation_id } => {
                    let record = rpc.call(
                        "operation.get",
                        serde_json::json!({ "operation_id": operation_id }),
                    )?;
                    print_rpc_value(cli.output, &record)?;
                }
            },
        },
        Command::Treasury { command } => match command {
            node_cli::TreasuryCommand::Status => {
                let status = rpc.call("treasury.status", serde_json::json!({}))?;
                print_rpc_value(cli.output, &status)?;
            }
            node_cli::TreasuryCommand::History { limit } => {
                let history =
                    rpc.call("treasury.history", serde_json::json!({ "limit": limit }))?;
                print_rpc_value(cli.output, &history)?;
            }
        },
    }
    Ok(())
}

struct RpcOptions {
    endpoint: Option<String>,
    allow_insecure_local: bool,
    tls_ca: Option<PathBuf>,
}

impl RpcOptions {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let endpoint = self
            .endpoint
            .as_deref()
            .ok_or_else(|| Error::msg("this command requires --rpc-endpoint <node>"))?;
        relay_client::run_rpc_call(
            endpoint,
            method,
            params,
            self.allow_insecure_local,
            self.tls_ca.as_deref(),
        )
    }
}

fn finalize_pending_member_issue(
    paths: &DataPaths,
    rpc: &RpcOptions,
    pending: &mrk_core::storage::PendingMemberIssue,
) -> Result<PathBuf> {
    let expected_operation_id =
        mrk_core::crypto::sha256_id("op", &serde_json::to_vec(&pending.operation)?);
    if pending.operation_id != expected_operation_id
        || pending.operation.unsigned.module != "NetworkRegistry"
        || pending.operation.unsigned.action != "IssueMember"
        || pending
            .operation
            .unsigned
            .payload
            .get("network_commitment")
            .and_then(serde_json::Value::as_str)
            != Some(pending.network_commitment.as_str())
        || pending
            .operation
            .unsigned
            .payload
            .get("member_name")
            .and_then(serde_json::Value::as_str)
            != Some(pending.member.as_str())
    {
        return Err(Error::msg("pending member issue record is inconsistent"));
    }
    match rpc.call(
        "operation.submit",
        serde_json::json!({
            "public_key": pending.owner_public_key,
            "operation": pending.operation,
        }),
    ) {
        Ok(submission) => {
            let returned_id = json_str(&submission, "operation_id")?;
            if returned_id != pending.operation_id {
                return Err(Error::msg(
                    "RPC returned another operation ID for the pending member issue",
                ));
            }
        }
        Err(error) if error.to_string().starts_with("RPC ") => {
            paths.remove_pending_member_issue(&pending.network, &pending.member)?;
            return Err(error);
        }
        Err(_) => {}
    }

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(value) = rpc.call(
            "operation.get",
            serde_json::json!({ "operation_id": pending.operation_id }),
        ) {
            let operation: mrk_core::model::OperationRecord = serde_json::from_value(value)?;
            match operation.status {
                mrk_core::model::OperationStatus::Finalized => {
                    let network: mrk_core::model::NetworkRecord =
                        serde_json::from_value(rpc.call(
                            "network.get",
                            serde_json::json!({ "alias": pending.network }),
                        )?)?;
                    let member = network.members.get(&pending.member).ok_or_else(|| {
                        Error::msg(
                            "member issue finalized but the member is missing from Network state",
                        )
                    })?;
                    let credential = &pending.credential;
                    if credential.network_id != network.network_id
                        || member.member_id != credential.member_id
                        || member.public_key != credential.member_public_key
                        || member.serial != credential.serial
                        || member.issued_at != credential.issued_at
                        || member.expires_at != credential.expires_at
                        || member.credential_signature != credential.owner_signature
                    {
                        return Err(Error::msg(
                            "finalized Network member does not match the pending local key",
                        ));
                    }
                    let path = service::store_member_files(
                        paths,
                        &pending.network,
                        &pending.member,
                        &pending.keyfile,
                        credential,
                    )?;
                    paths.remove_pending_member_issue(&pending.network, &pending.member)?;
                    return Ok(path);
                }
                mrk_core::model::OperationStatus::Rejected
                | mrk_core::model::OperationStatus::Expired => {
                    paths.remove_pending_member_issue(&pending.network, &pending.member)?;
                    return Err(Error::msg(format!(
                        "member issue operation {} ended as {}",
                        pending.operation_id,
                        operation_status_text(&operation.status),
                    )));
                }
                mrk_core::model::OperationStatus::Pending => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::msg(format!(
                "timed out waiting for member issue operation {} to finalize",
                pending.operation_id
            )));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn print_finalized_member_issue(
    output: Output,
    pending: &mrk_core::storage::PendingMemberIssue,
    path: &std::path::Path,
    resumed: bool,
) -> Result<()> {
    print_value(
        output,
        &serde_json::json!({
            "credential": pending.credential,
            "operation_id": pending.operation_id,
            "status": "FINALIZED",
            "resumed": resumed,
            "path": path.display().to_string(),
        }),
        || {
            format!(
                "Member finalized\nMember: {}\nMember ID: {}\nSerial: {}\nOperation: {}\nCredential: {}",
                pending.member,
                pending.credential.member_id,
                pending.credential.serial,
                pending.operation_id,
                path.display(),
            )
        },
    )
}

fn print_rpc_value(output: Output, value: &serde_json::Value) -> Result<()> {
    print_value(output, value, || {
        serde_json::to_string_pretty(value).expect("JSON value serialization cannot fail")
    })
}

fn json_str<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::msg(format!("RPC response is missing '{name}'")))
}

fn json_u64(value: &serde_json::Value, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::msg(format!("RPC response has invalid '{name}'")))
}

fn json_u128(value: &serde_json::Value, name: &str) -> Result<u128> {
    value
        .get(name)
        .ok_or_else(|| Error::msg(format!("RPC response is missing '{name}'")))?
        .to_string()
        .parse()
        .map_err(|_| Error::msg(format!("RPC response has invalid '{name}'")))
}

fn rpc_signing_context(rpc: &RpcOptions, address: &str) -> Result<(String, u64)> {
    let balance = rpc.call("account.balance", serde_json::json!({ "address": address }))?;
    let chain = rpc.call("system.ping", serde_json::json!({}))?;
    Ok((
        json_str(&chain, "ledger_id")?.to_owned(),
        json_u64(&balance, "nonce")?.saturating_add(1),
    ))
}

#[derive(Deserialize)]
struct RpcFeeQuote {
    policy_version: u64,
    fee: u128,
    recommended_max_fee: u128,
}

fn rpc_fee_quote(
    rpc: &RpcOptions,
    module: &str,
    action: &str,
    payload: &serde_json::Value,
) -> Result<RpcFeeQuote> {
    serde_json::from_value(rpc.call(
        "fee.quote",
        serde_json::json!({
            "module": module,
            "action": action,
            "payload": payload,
        }),
    )?)
    .map_err(Into::into)
}

fn confirm_service_fee(quote: &RpcFeeQuote, yes: bool) -> Result<()> {
    confirm_service_fee_amounts(quote.fee, quote.recommended_max_fee, yes)
}

fn confirm_service_fee_amounts(fee: u128, recommended_max_fee: u128, yes: bool) -> Result<()> {
    if fee == 0 {
        return Ok(());
    }
    eprintln!("Service fee: {}", format_mrk(fee));
    eprintln!("Maximum service fee: {}", format_mrk(recommended_max_fee));
    if yes {
        return Ok(());
    }
    eprint!("Type \"yes\" to confirm and submit: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() != "yes" {
        return Err(Error::msg("operation cancelled"));
    }
    Ok(())
}

fn resolve_address(paths: &DataPaths, target: &AccountOrAddress) -> Result<String> {
    match &target.address {
        Some(address) => Ok(address.clone()),
        None => Ok(service::account_keyfile(paths, &target.account)?.address),
    }
}

fn network_text(network: &mrk_core::model::NetworkRecord) -> String {
    format!(
        "Network:      {}\nCommitment:   {}\nOwner:        {}\nFund balance: {}\nMember spend: {} (policy revision {})",
        network.alias,
        network.commitment,
        network.owner_address,
        format_mrk(network.escrow_balance),
        if network.spending_policy.enabled {
            "enabled"
        } else {
            "disabled"
        },
        network.spending_policy.revision,
    )
}

fn member_presence_text(view: &service::MemberPresenceListView) -> String {
    if view.members.is_empty() {
        return format!("No registered members in Network '{}'.", view.network);
    }
    let mut lines = vec![format!(
        "Network: {}\nRelay Node: {}\nObserved at: {}\n\nNAME\tMEMBER ID\tSERIAL\tCREDENTIAL\tPRESENCE\tCONNECTIONS",
        view.network, view.relay_node_id, view.observed_at,
    )];
    lines.extend(view.members.iter().map(|member| {
        let credential = if member.revoked_at.is_some() {
            "REVOKED"
        } else if member.expires_at <= view.observed_at {
            "EXPIRED"
        } else {
            "ACTIVE"
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            member.name,
            member.member_id,
            member.serial,
            credential,
            if member.online { "ONLINE" } else { "OFFLINE" },
            member.connection_count,
        )
    }));
    lines.join("\n")
}

fn spending_policy_text(policy: &mrk_core::model::NetworkSpendingPolicy) -> String {
    format!(
        "Revision:             {}\nMember spending:      {}\nMax session amount:   {}\nMax member reserved:  {}\nMax Node price/GiB:   {}\nMax session duration: {} minutes",
        policy.revision,
        if policy.enabled {
            "enabled"
        } else {
            "disabled"
        },
        format_mrk(policy.max_session_amount),
        format_mrk(policy.max_member_reserved),
        format_mrk(policy.max_node_price_per_gib),
        policy.max_session_minutes,
    )
}

fn account_history_text(address: &str, history: &[mrk_core::model::OperationRecord]) -> String {
    if history.is_empty() {
        return format!("No account history for {address}.");
    }

    let mut output = format!("Account: {address}\nOperations: {}", history.len());
    for (index, operation) in history.iter().enumerate() {
        let created_at = chrono::DateTime::<Utc>::from_timestamp(operation.created_at, 0)
            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| operation.created_at.to_string());
        let block = operation
            .block_height
            .map_or_else(|| "-".to_owned(), |height| height.to_string());
        let details = serde_json::to_string(&operation.payload)
            .expect("operation payload serialization cannot fail");
        output.push_str(&format!(
            "\n\n{}. {}  {}\n   Operation: {}\n   Created:   {}\n   Block:     {}\n   Signer:    {}\n   Nonce:     {}\n   Details:   {}",
            index + 1,
            operation_status_text(&operation.status),
            operation.kind,
            operation.operation_id,
            created_at,
            block,
            operation.signer,
            operation.nonce,
            details
        ));
    }
    output
}

fn operation_status_text(status: &mrk_core::model::OperationStatus) -> &'static str {
    match status {
        mrk_core::model::OperationStatus::Pending => "PENDING",
        mrk_core::model::OperationStatus::Finalized => "FINALIZED",
        mrk_core::model::OperationStatus::Rejected => "REJECTED",
        mrk_core::model::OperationStatus::Expired => "EXPIRED",
    }
}

fn payment_history_text(history: &service::PaymentHistoryView) -> String {
    let mut output = format!(
        "Network: {}\nFund balance: {}\nSettled in view: {}\nReserved in view: {}\nSessions: {}",
        history.network,
        format_mrk(history.fund_balance),
        format_mrk(history.total_settled),
        format_mrk(history.total_reserved),
        history.authorizations.len(),
    );
    for authorization in &history.authorizations {
        let created_at = chrono::DateTime::<Utc>::from_timestamp(authorization.created_at, 0)
            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| authorization.created_at.to_string());
        output.push_str(&format!(
            "\n\n{}\n  Session: {}\n  Initiator: {}\n  Members: {} -> {}\n  Node: {}\n  Reserved: {} / {}\n  Settled: {}\n  Created: {}\n  Policy revision: {}",
            authorization.authorization_id,
            authorization.session_id,
            authorization.initiator_member_id,
            authorization.sender_member_id,
            authorization.receiver_member_id,
            authorization.node_id,
            format_mrk(authorization.reserved_remaining),
            format_mrk(authorization.max_amount),
            format_mrk(authorization.settled_amount),
            created_at,
            authorization.spending_policy_revision,
        ));
    }
    output
}

fn transfer_preview_text(preview: &service::TransferPreview) -> String {
    format!(
        "Ledger:      {}\nFrom:        {}\nTo:          {}\nAmount:      {}\nFee:         {}\nTotal:       {}\nNonce:       {}\nValid until: {}",
        preview.ledger_id,
        preview.from,
        preview.to,
        format_mrk(preview.amount),
        format_mrk(preview.fee),
        format_mrk(preview.total),
        preview.nonce,
        preview.valid_until
    )
}

fn registry_list_text(view: &service::RegistryNodeListView) -> String {
    if view.nodes.is_empty() {
        return "No registered Nodes.".to_owned();
    }
    let mut lines = vec!["NODE ID\tSTATUS\tENDPOINT\tPRICE/GiB\tVALIDATOR".to_owned()];
    lines.extend(view.nodes.iter().map(|node| {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            node.node_id,
            node.status,
            node.endpoint,
            node.price_per_gib_display,
            if node.validator { "yes" } else { "no" }
        )
    }));
    if let Some(cursor) = view.next_cursor {
        lines.push(format!("Next cursor: {cursor}"));
    }
    lines.join("\n")
}

fn registry_node_text(node: &service::RegistryNodeView) -> String {
    format!(
        "Node ID: {}\nPrevious Node ID: {}\nName: {}\nStatus: {}\nEndpoint: {}\nReward IP: {}\nPrice/GiB: {}\nOwner: {}\nReward address: {}\nRegistered at: {}\nLast Probe: {}\nValidator: {}\nValidator candidate: {}",
        node.node_id,
        node.previous_node_id
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        node.name,
        node.status,
        node.endpoint,
        node.reward_ip,
        node.price_per_gib_display,
        node.owner_address,
        node.reward_address,
        node.registered_at,
        node.last_probe_success
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        if node.validator { "yes" } else { "no" },
        if node.validator_candidate {
            "yes"
        } else {
            "no"
        },
    )
}

fn relay_discovery_text(view: &service::RelayDiscoveryListView) -> String {
    if view.relays.is_empty() {
        return "No currently discoverable Relays.".to_owned();
    }
    let mut lines = vec!["NODE ID\tENDPOINT\tPRICE/GiB\tPROBE VALID UNTIL\tVALIDATOR".to_owned()];
    lines.extend(view.relays.iter().map(|relay| {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            relay.node_id,
            relay.endpoint,
            relay.price_per_gib_display,
            relay.probe_valid_until,
            if relay.validator { "yes" } else { "no" }
        )
    }));
    if let Some(cursor) = view.next_cursor {
        lines.push(format!("Next cursor: {cursor}"));
    }
    lines.join("\n")
}

fn read_new_password() -> Result<String> {
    if let Some(password) = password_from_environment()? {
        validate_keystore_password(&password)?;
        return Ok(password);
    }
    let first = read_password("New keystore password: ")?;
    let second = read_password("Confirm keystore password: ")?;
    if first != second {
        return Err(Error::msg("keystore passwords do not match"));
    }
    validate_keystore_password(&first)?;
    Ok(first)
}

fn read_password(prompt: &str) -> Result<String> {
    if let Some(password) = password_from_environment()? {
        return Ok(password);
    }
    rpassword::prompt_password(prompt).map_err(Error::from)
}

fn password_from_environment() -> Result<Option<String>> {
    if let Ok(path) = std::env::var("MRK_KEYSTORE_PASSWORD_FILE") {
        let metadata = std::fs::metadata(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::msg(
                    "MRK_KEYSTORE_PASSWORD_FILE must not be accessible by group or others",
                ));
            }
        }
        if metadata.len() > 4_096 {
            return Err(Error::msg("keystore password file exceeds 4 KiB"));
        }
        let password = std::fs::read_to_string(path)?;
        let password = password.trim_end_matches(['\r', '\n']).to_owned();
        if password.is_empty() {
            return Err(Error::msg("keystore password file is empty"));
        }
        return Ok(Some(password));
    }
    Ok(std::env::var("MRK_KEYSTORE_PASSWORD").ok())
}

fn print_value<T: Serialize>(
    output: Output,
    value: &T,
    text: impl FnOnce() -> String,
) -> Result<()> {
    match output {
        Output::Text => println!("{}", text()),
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}
