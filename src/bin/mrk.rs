use std::{
    io::{self, Write},
    path::PathBuf,
};

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use mrk::{
    Error, Result,
    amount::{format_mrk, parse_mrk},
    crypto::validate_keystore_password,
    model::{DEFAULT_OPERATION_VALIDITY_SECONDS, TRANSFER_FEE},
    relay_client, service,
    storage::DataPaths,
};
use serde::Serialize;

#[path = "../node_cli.rs"]
mod node_cli;

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
        #[arg(long)]
        peer: Option<String>,
        #[arg(long, requires = "peer")]
        authorization: Option<String>,
        #[arg(long, default_value = "stdio")]
        metadata: String,
        #[arg(long)]
        allow_insecure_local: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
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
        yes: bool,
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
    Authorize {
        #[arg(long)]
        network: String,
        #[arg(long)]
        node_id: u64,
        #[arg(long)]
        sender: String,
        #[arg(long)]
        receiver: String,
        #[arg(long)]
        max_amount: String,
        #[arg(long, default_value_t = 1440)]
        valid_minutes: i64,
        #[arg(long, default_value = "default")]
        account: String,
    },
    Status {
        authorization_id: String,
    },
    Refund {
        authorization_id: String,
        #[arg(long, default_value = "default")]
        account: String,
    },
}

fn main() {
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
            node_cli::run_node_command(&paths, node, matches!(cli.output, Output::Json), command)?;
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
                yes,
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
                let total = amount_value
                    .checked_add(TRANSFER_FEE)
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
                    fee: TRANSFER_FEE,
                    total,
                    nonce: json_u64(&balance, "nonce")?.saturating_add(1),
                    valid_until: now + DEFAULT_OPERATION_VALIDITY_SECONDS,
                };
                if dry_run {
                    print_value(cli.output, &preview, || transfer_preview_text(&preview))?;
                    return Ok(());
                }
                if !yes {
                    println!("{}", transfer_preview_text(&preview));
                    print!("\nType \"yes\" to sign and submit: ");
                    io::stdout().flush()?;
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    if answer.trim() != "yes" {
                        return Err(Error::msg("transfer cancelled"));
                    }
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
                    },
                )?;
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
                let history = rpc.call(
                    "account.history",
                    serde_json::json!({ "address": address, "limit": limit.min(1_000) }),
                )?;
                print_rpc_value(cli.output, &history)?;
            }
        },
        Command::Network { command } => match command {
            NetworkCommand::Create { name, account } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let (network_id, commitment) = service::new_network_identity()?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkRegistry",
                        action: "CreateNetwork",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        payload: serde_json::json!({
                            "alias": name,
                            "network_id": network_id,
                            "network_commitment": commitment,
                        }),
                    },
                )?;
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
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkEscrow",
                        action: "FundNetwork",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        payload: serde_json::json!({
                            "network": network,
                            "amount_base_units": parse_mrk(&amount)?.to_string(),
                        }),
                    },
                )?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({ "public_key": keyfile.public_key, "operation": operation }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
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
            MemberCommand::Issue {
                network,
                name,
                account,
                valid_days,
            } => {
                let owner_file = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &owner_file.address)?;
                let network_record: mrk::model::NetworkRecord = serde_json::from_value(
                    rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                )?;
                let password = read_password("Owner account password: ")?;
                let now = Utc::now().timestamp();
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
                    },
                )?;
                let accepted = rpc.call(
                    "operation.submit",
                    serde_json::json!({
                        "public_key": owner_file.public_key,
                        "operation": operation,
                    }),
                )?;
                let path = service::store_member_files(
                    &paths,
                    &network,
                    &name,
                    &member_file,
                    &credential,
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({
                        "credential": credential,
                        "submission": accepted,
                        "path": path.display().to_string(),
                    }),
                    || {
                        format!(
                            "Member: {name}\nMember ID: {}\nSerial: {}\nCredential: {}",
                            credential.member_id,
                            credential.serial,
                            path.display()
                        )
                    },
                )?;
            }
            MemberCommand::Revoke {
                network,
                serial,
                account,
            } => {
                let keyfile = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &keyfile.address)?;
                let password = read_password("Owner account password: ")?;
                let operation = service::sign_public_operation(
                    &keyfile,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "NetworkRegistry",
                        action: "RevokeMember",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        payload: serde_json::json!({ "network": network, "serial": serial }),
                    },
                )?;
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
            PaymentCommand::Authorize {
                network,
                node_id,
                sender,
                receiver,
                max_amount,
                valid_minutes,
                account,
            } => {
                let owner_file = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &owner_file.address)?;
                let network_record: mrk::model::NetworkRecord = serde_json::from_value(
                    rpc.call("network.get", serde_json::json!({ "alias": network }))?,
                )?;
                let password = read_password("Owner account password: ")?;
                let (session_id, operation) = service::prepare_payment_authorization(
                    &owner_file,
                    &password,
                    service::PaymentAuthorizationSigningRequest {
                        ledger_id: &ledger_id,
                        network: &network_record,
                        node_id,
                        sender_member_name: &sender,
                        receiver_member_name: &receiver,
                        max_amount_text: &max_amount,
                        valid_minutes,
                        nonce,
                        now: Utc::now().timestamp(),
                    },
                )?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({
                        "public_key": owner_file.public_key,
                        "operation": operation,
                    }),
                )?;
                print_value(
                    cli.output,
                    &serde_json::json!({"submission": result, "session_id": session_id}),
                    || format!("Payment authorization submitted\nSession: {session_id}\n{result}"),
                )?;
            }
            PaymentCommand::Status { authorization_id } => {
                let value = rpc.call(
                    "payment.get",
                    serde_json::json!({ "authorization_id": authorization_id }),
                )?;
                print_rpc_value(cli.output, &value)?;
            }
            PaymentCommand::Refund {
                authorization_id,
                account,
            } => {
                let owner_file = service::account_keyfile(&paths, &account)?;
                let (ledger_id, nonce) = rpc_signing_context(&rpc, &owner_file.address)?;
                let password = read_password("Owner account password: ")?;
                let operation = service::sign_public_operation(
                    &owner_file,
                    &password,
                    service::PublicOperationSigningRequest {
                        ledger_id: &ledger_id,
                        module: "TrafficPayment",
                        action: "Refund",
                        nonce,
                        valid_until: Utc::now().timestamp() + DEFAULT_OPERATION_VALIDITY_SECONDS,
                        payload: serde_json::json!({
                            "authorization_id": authorization_id,
                        }),
                    },
                )?;
                let result = rpc.call(
                    "operation.submit",
                    serde_json::json!({
                        "public_key": owner_file.public_key,
                        "operation": operation,
                    }),
                )?;
                print_rpc_value(cli.output, &result)?;
            }
        },
        Command::Pipe {
            network,
            member,
            endpoint,
            peer,
            authorization,
            metadata,
            allow_insecure_local,
            tls_ca,
        } => {
            let password = read_password("Member keystore password: ")?;
            relay_client::run_stdio_pipe(relay_client::StdioPipeOptions {
                paths,
                network,
                member,
                password,
                endpoint,
                peer,
                authorization,
                metadata,
                allow_insecure_local,
                tls_ca,
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

fn resolve_address(paths: &DataPaths, target: &AccountOrAddress) -> Result<String> {
    match &target.address {
        Some(address) => Ok(address.clone()),
        None => Ok(service::account_keyfile(paths, &target.account)?.address),
    }
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
        "Node ID: {}\nName: {}\nStatus: {}\nEndpoint: {}\nReward IP: {}\nPrice/GiB: {}\nOwner: {}\nReward address: {}\nRegistered at: {}\nLast Probe: {}\nValidator: {}\nValidator candidate: {}",
        node.node_id,
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
