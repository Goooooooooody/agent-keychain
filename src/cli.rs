use crate::config::ConfigStore;
use crate::daemon::{
    daemon_status, disable_grants, enable_grant, grant_status, lock_daemon, request_secret,
    request_secrets, run_daemon, search_secret_names, stop_daemon, unlock_daemon, AgentResponse,
    BatchSecretResult,
};
use crate::paths::{config_path, socket_path, vault_path};
use crate::tui::run_tui;
use crate::vault::{AuditAction, AuditFilter, KdfSettings, SecretMetadata, VaultStore};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "akc",
    version,
    about = "Agent-friendly encrypted local keychain"
)]
pub struct Cli {
    /// Convenience add form: akc --add 'secret-value' --name 'secret-name'. Prefer prompt/stdin to avoid shell history leaks.
    #[arg(long = "add", value_name = "SECRET_VALUE", global = false)]
    pub add_inline: Option<String>,

    /// Secret name for the root --add convenience form.
    #[arg(long, global = false)]
    pub name: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        value: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(long)]
        expires_at: Option<DateTime<Utc>>,
        #[arg(long)]
        rotate_after: Option<DateTime<Utc>>,
        #[arg(long)]
        one_time: bool,
        /// Self-reported client labels; these are policy labels, not verified executable identities.
        #[arg(long = "allow-client")]
        allowed_clients: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        url: Option<String>,
    },
    Get {
        #[arg(long)]
        name: String,
    },
    List,
    Remove {
        #[arg(long)]
        name: String,
    },
    Daemon {
        #[command(subcommand)]
        command: Option<DaemonCommand>,
    },
    /// Immediately zeroize the daemon's in-memory unlocked vault and grants.
    Lock,
    Tui,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    AgentGet {
        #[arg(long, required = true, num_args = 1..)]
        name: Vec<String>,
        #[arg(long, default_value = "agent")]
        agent: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        command_context: Option<String>,
    },
    /// Fuzzy-search eligible secret names through the audited daemon without returning values.
    AgentSearch {
        #[arg(long)]
        query: String,
        #[arg(long, default_value = "agent")]
        agent: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Supply one approved secret to a command through its standard input, never argv/env/stdout.
    Exec {
        #[arg(long)]
        secret: String,
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
    },
    Rekey {
        #[arg(long, default_value_t = 65_536)]
        memory_kib: u32,
        #[arg(long, default_value_t = 3)]
        iterations: u32,
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },
    Backup {
        #[arg(long)]
        output: PathBuf,
    },
    Restore {
        #[arg(long)]
        input: PathBuf,
        /// Required acknowledgement: authenticate and validate the complete backup before replacement.
        #[arg(long)]
        verify: bool,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    List {
        #[arg(long)]
        since: Option<DateTime<Utc>>,
        #[arg(long, alias = "client")]
        actor: Option<String>,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long)]
        decision: Option<String>,
    },
    Export {
        #[arg(long)]
        output: PathBuf,
    },
    Prune {
        #[arg(long = "verified-export")]
        verified_export: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    Status,
    Lock,
    Unlock,
    Stop,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    AutoApprove {
        #[command(subcommand)]
        command: AutoApproveCommand,
    },
    /// Configure daemon idle auto-lock (30 seconds to 24 hours).
    IdleLock { seconds: u64 },
}

#[derive(Debug, Subcommand)]
pub enum AutoApproveCommand {
    Enable {
        /// Lifetime of this daemon-session grant (maximum 900 seconds).
        #[arg(long, default_value_t = 300)]
        ttl_seconds: u64,
        /// Exact self-reported client label to permit.
        #[arg(long)]
        client: Option<String>,
        /// Exact secret name to permit.
        #[arg(long)]
        secret: Option<String>,
        /// Maximum successful matches before the grant is revoked.
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
    },
    Disable,
    Status,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}

pub fn run_cli(cli: Cli) -> Result<()> {
    if let Some(mut value) = cli.add_inline {
        eprintln!("warning: inline secrets can be captured by shell history; prefer `akc add --name ...` and enter the value at the prompt");
        let name = cli
            .name
            .ok_or_else(|| anyhow!("--name is required with --add"))?;
        add_secret(
            name,
            Some(std::mem::take(&mut value)),
            SecretMetadata::default(),
        )?;
        value.zeroize();
        return Ok(());
    }

    match cli.command.unwrap_or(Command::List) {
        Command::Init => init_vault(),
        Command::Add {
            name,
            value,
            tags,
            expires_at,
            rotate_after,
            one_time,
            allowed_clients,
            notes,
            url,
        } => add_secret(
            name,
            value,
            SecretMetadata {
                tags,
                expires_at,
                rotate_after,
                one_time,
                allowed_clients,
                notes,
                url,
                ..Default::default()
            },
        ),
        Command::Get { name } => get_secret(name),
        Command::List => list_secrets(),
        Command::Remove { name } => remove_secret(name),
        Command::Daemon { command: None } => {
            run_daemon(vault_path()?, socket_path()?, config_path()?)
        }
        Command::Daemon {
            command: Some(command),
        } => daemon_command(command),
        Command::Lock => daemon_ack(lock_daemon(socket_path()?)?),
        Command::Tui => run_tui(vault_path()?),
        Command::Config { command } => configure(command),
        Command::AgentGet {
            name,
            agent,
            reason,
            command_context,
        } => {
            let response = if name.len() == 1 {
                request_secret(
                    socket_path()?,
                    agent,
                    name[0].clone(),
                    reason,
                    command_context,
                )?
            } else {
                request_secrets(socket_path()?, agent, name, reason, command_context)?
            };
            match response {
                AgentResponse::Approved { mut value } => {
                    println!("{value}");
                    value.zeroize();
                    Ok(())
                }
                AgentResponse::Denied { message } => Err(anyhow!(message)),
                AgentResponse::Error { message, .. } => Err(anyhow!(message)),
                AgentResponse::Batch { mut results } => {
                    let mut denied = 0;
                    for result in &mut results {
                        match result {
                            BatchSecretResult::Approved { name, value } => {
                                println!("{name}={value}");
                                value.zeroize();
                            }
                            BatchSecretResult::Denied { name, message } => {
                                denied += 1;
                                eprintln!("{name}: {message}");
                            }
                        }
                    }
                    if denied > 0 {
                        Err(anyhow!("{denied} batch request(s) denied"))
                    } else {
                        Ok(())
                    }
                }
                _ => Err(anyhow!("unexpected daemon response")),
            }
        }
        Command::AgentSearch {
            query,
            agent,
            reason,
            json,
        } => match search_secret_names(socket_path()?, agent, query, reason)? {
            AgentResponse::SearchResults { names } => {
                if json {
                    println!("{}", serde_json::to_string(&names)?);
                } else {
                    for name in names {
                        println!("{name}");
                    }
                }
                Ok(())
            }
            AgentResponse::Error { message, .. } => Err(anyhow!(message)),
            _ => Err(anyhow!("unexpected daemon response")),
        },
        Command::Exec { secret, command } => exec_with_secret(secret, command),
        Command::Rekey {
            memory_kib,
            iterations,
            parallelism,
        } => rekey(memory_kib, iterations, parallelism),
        Command::Backup { output } => backup(output),
        Command::Restore { input, verify } => restore(input, verify),
        Command::Audit { command } => audit_command(command),
    }
}

fn init_vault() -> Result<()> {
    let passphrase = Zeroizing::new(prompt_new_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    store.init(&passphrase)?;
    println!("initialized encrypted vault at {}", store.path().display());
    Ok(())
}

fn add_secret(name: String, value: Option<String>, metadata: SecretMetadata) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    let mut secret = Zeroizing::new(match value {
        Some(value) => value,
        None => prompt_secret_value()?,
    });
    store.transaction(&passphrase, |vault| {
        vault.add_secret_with_metadata(name.clone(), std::mem::take(&mut *secret), metadata.clone())
    })?;
    println!("added secret '{name}'");
    Ok(())
}

fn get_secret(name: String) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    let mut value =
        store.transaction(&passphrase, |vault| vault.get_secret(&name, "user", None))?;
    println!("{value}");
    value.zeroize();
    Ok(())
}

fn list_secrets() -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    let vault = store.load(&passphrase)?;
    for record in vault.list_records() {
        let mut status = Vec::new();
        if record.metadata.one_time {
            status.push("one-time".to_string());
        }
        if let Some(expiry) = record.metadata.expires_at {
            status.push(format!("expires={expiry}"));
        }
        if let Some(rotation) = record.metadata.rotate_after {
            status.push(format!(
                "rotate_after={rotation}{}",
                if rotation <= Utc::now() { " (due)" } else { "" }
            ));
        }
        if !record.metadata.tags.is_empty() {
            status.push(format!("tags={}", record.metadata.tags.join(",")));
        }
        if status.is_empty() {
            println!("{}", record.name);
        } else {
            println!("{}\t{}", record.name, status.join("; "));
        }
    }
    Ok(())
}

fn remove_secret(name: String) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    store.transaction(&passphrase, |vault| vault.remove_secret(&name))?;
    println!("removed secret '{name}'");
    Ok(())
}

fn coordinate_daemon_lock() {
    // Rekey/restore must invalidate a cached daemon session. A missing daemon is normal.
    let _ = socket_path().and_then(lock_daemon);
}

fn rekey(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<()> {
    coordinate_daemon_lock();
    let old = Zeroizing::new(prompt_passphrase()?);
    let new = Zeroizing::new(prompt_new_passphrase_named("AKC_NEW_MASTER_PASSPHRASE")?);
    VaultStore::new(vault_path()?).rekey(
        &old,
        &new,
        KdfSettings {
            memory_cost_kib: memory_kib,
            time_cost: iterations,
            parallelism,
        },
    )?;
    println!("vault rekeyed and verified; daemon remains locked");
    Ok(())
}

fn backup(output: PathBuf) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    VaultStore::new(vault_path()?).backup_verified(&passphrase, &output)?;
    println!("verified encrypted backup written to {}", output.display());
    Ok(())
}

fn restore(input: PathBuf, verify: bool) -> Result<()> {
    if !verify {
        return Err(anyhow!("restore requires --verify"));
    }
    coordinate_daemon_lock();
    let destination = Zeroizing::new(prompt_passphrase()?);
    let source = Zeroizing::new(
        std::env::var("AKC_BACKUP_PASSPHRASE").unwrap_or_else(|_| destination.to_string()),
    );
    VaultStore::new(vault_path()?).restore_verified(&input, &source, &destination)?;
    println!("backup verified and restored; daemon remains locked");
    Ok(())
}

fn audit_command(command: AuditCommand) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path()?);
    match command {
        AuditCommand::List {
            since,
            actor,
            secret,
            decision,
        } => {
            let action = decision.as_deref().map(parse_audit_action).transpose()?;
            for event in store.audit_events(
                &passphrase,
                &AuditFilter {
                    since,
                    actor,
                    secret,
                    action,
                },
            )? {
                println!(
                    "{}\t{:?}\t{}\t{}",
                    event.at,
                    event.action,
                    event.secret_name.as_deref().unwrap_or("-"),
                    event.actor
                );
            }
        }
        AuditCommand::Export { output } => {
            let count = store.export_audit(&passphrase, &output)?;
            println!(
                "exported and verified {count} audit events to {}",
                output.display()
            );
        }
        AuditCommand::Prune { verified_export } => {
            let count = store.prune_archived_audit(&passphrase, &verified_export)?;
            println!("pruned {count} archived audit events after verified export");
        }
    }
    Ok(())
}

fn parse_audit_action(value: &str) -> Result<AuditAction> {
    Ok(
        match value.to_ascii_lowercase().replace('-', "_").as_str() {
            "init" => AuditAction::Init,
            "add" => AuditAction::Add,
            "update" => AuditAction::Update,
            "get" => AuditAction::Get,
            "remove" => AuditAction::Remove,
            "request" | "agent_request" => AuditAction::AgentRequest,
            "search" | "agent_search" => AuditAction::AgentSearch,
            "approve" | "agent_approve" => AuditAction::AgentApprove,
            "deny" | "agent_deny" => AuditAction::AgentDeny,
            "error" | "agent_error" => AuditAction::AgentError,
            "rekey" => AuditAction::Rekey,
            "backup" => AuditAction::Backup,
            "restore" => AuditAction::Restore,
            "export" | "audit_export" => AuditAction::AuditExport,
            "prune" | "audit_prune" => AuditAction::AuditPrune,
            _ => return Err(anyhow!("unknown audit decision '{value}'")),
        },
    )
}

pub fn prompt_passphrase() -> Result<String> {
    if let Ok(passphrase) = std::env::var("AKC_MASTER_PASSPHRASE") {
        return Ok(passphrase);
    }
    rpassword::prompt_password("Master passphrase: ").map_err(Into::into)
}

fn prompt_new_passphrase() -> Result<String> {
    prompt_new_passphrase_named("AKC_MASTER_PASSPHRASE")
}

fn prompt_new_passphrase_named(environment: &str) -> Result<String> {
    if let Ok(passphrase) = std::env::var(environment) {
        return Ok(passphrase);
    }
    let first = Zeroizing::new(rpassword::prompt_password("New master passphrase: ")?);
    let second = Zeroizing::new(rpassword::prompt_password("Confirm master passphrase: ")?);
    if first != second {
        return Err(anyhow!("passphrases do not match"));
    }
    Ok(first.to_string())
}

fn prompt_secret_value() -> Result<String> {
    if atty_stdin() {
        return rpassword::prompt_password("Secret value: ").map_err(Into::into);
    }
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let trimmed_len = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(trimmed_len);
    Ok(value)
}

fn atty_stdin() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal()
}

pub fn prompt_approval(prompt: &str) -> Result<bool> {
    print!("{prompt} [y/N]: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn configure(command: ConfigCommand) -> Result<()> {
    let store = ConfigStore::new(config_path()?);
    match command {
        ConfigCommand::AutoApprove { command } => match command {
            AutoApproveCommand::Enable {
                ttl_seconds,
                client,
                secret,
                max_uses,
            } => {
                require_interactive_terminal()?;
                let client = client.ok_or_else(|| anyhow!("--client is required"))?;
                let secret = secret.ok_or_else(|| anyhow!("--secret is required"))?;
                let mut passphrase =
                    Zeroizing::new(rpassword::prompt_password("Master passphrase: ")?);
                let response = enable_grant(
                    socket_path()?,
                    std::mem::take(&mut *passphrase),
                    client,
                    secret,
                    ttl_seconds,
                    max_uses,
                );
                match response? {
                    AgentResponse::GrantCreated {
                        token,
                        remaining_seconds,
                        remaining_uses,
                    } => {
                        println!("{token}");
                        eprintln!(
                            "capability created for {remaining_seconds} seconds and {remaining_uses} uses; it will not be shown again"
                        );
                    }
                    AgentResponse::Error { message, .. } => return Err(anyhow!(message)),
                    _ => return Err(anyhow!("unexpected daemon response")),
                }
            }
            AutoApproveCommand::Disable => {
                store.set_auto_approve(false)?;
                match disable_grants(socket_path()?) {
                    Ok(AgentResponse::GrantStatus { enabled: false, .. }) | Err(_) => {
                        println!("scoped grants disabled")
                    }
                    Ok(AgentResponse::Error { message, .. }) => return Err(anyhow!(message)),
                    _ => return Err(anyhow!("unexpected daemon response")),
                }
            }
            AutoApproveCommand::Status => {
                let config = store.load()?;
                if config.auto_approve_agent_requests {
                    eprintln!("warning: legacy persistent auto-approve is ignored");
                }
                match grant_status(socket_path()?) {
                    Ok(AgentResponse::GrantStatus {
                        enabled: true,
                        remaining_seconds,
                        remaining_uses,
                    }) => println!(
                        "scoped grants: enabled ({remaining_seconds} seconds, {remaining_uses} uses remaining)"
                    ),
                    Ok(AgentResponse::GrantStatus { enabled: false, .. }) | Err(_) => {
                        println!("scoped grants: disabled")
                    }
                    Ok(AgentResponse::Error { message, .. }) => return Err(anyhow!(message)),
                    Ok(_) => return Err(anyhow!("unexpected daemon response")),
                }
            }
        },
        ConfigCommand::IdleLock { seconds } => {
            if !(30..=24 * 60 * 60).contains(&seconds) {
                return Err(anyhow!("idle lock must be between 30 and 86400 seconds"));
            }
            store.set_idle_lock_seconds(seconds)?;
            println!(
                "daemon idle lock configured for {seconds} seconds; restart the daemon to apply"
            );
        }
    }
    Ok(())
}

fn daemon_command(command: DaemonCommand) -> Result<()> {
    match command {
        DaemonCommand::Status => match daemon_status(socket_path()?)? {
            AgentResponse::DaemonStatus {
                locked,
                protocol_version,
                active_grants,
                queue_capacity,
                idle_lock_seconds,
                vault_revision,
                metrics,
            } => {
                println!(
                    "daemon: {}; protocol: {protocol_version}; grants: {active_grants}; queue capacity: {queue_capacity}; idle lock: {idle_lock_seconds}s; vault revision: {}",
                    if locked { "locked" } else { "unlocked" },
                    vault_revision.map_or_else(|| "-".into(), |revision| revision.to_string())
                );
                if let Some(metrics) = metrics {
                    println!(
                        "metrics: requests={}; latency_us={}; lock_wait_us={}; queue_rejections={}; timeouts={}; vault_bytes={}; archives={}",
                        metrics.requests,
                        metrics.total_request_latency_us,
                        metrics.total_state_lock_wait_us,
                        metrics.queue_rejections,
                        metrics.io_timeouts,
                        metrics.vault_bytes,
                        metrics.audit_archives,
                    );
                }
                Ok(())
            }
            AgentResponse::Error { message, .. } => Err(anyhow!(message)),
            _ => Err(anyhow!("unexpected daemon response")),
        },
        DaemonCommand::Lock => daemon_ack(lock_daemon(socket_path()?)?),
        DaemonCommand::Unlock => {
            let passphrase = Zeroizing::new(prompt_passphrase()?);
            daemon_ack(unlock_daemon(socket_path()?, passphrase.to_string())?)
        }
        DaemonCommand::Stop => daemon_ack(stop_daemon(socket_path()?)?),
    }
}

fn daemon_ack(response: AgentResponse) -> Result<()> {
    match response {
        AgentResponse::Ack { message } => {
            println!("{message}");
            Ok(())
        }
        AgentResponse::Error { message, .. } => Err(anyhow!(message)),
        _ => Err(anyhow!("unexpected daemon response")),
    }
}

fn exec_with_secret(secret_name: String, command: Vec<String>) -> Result<()> {
    let response = request_secret(
        socket_path()?,
        "akc-exec".into(),
        secret_name,
        Some("deliver secret to child standard input".into()),
        command.first().cloned(),
    )?;
    let AgentResponse::Approved { value } = response else {
        return match response {
            AgentResponse::Denied { message } | AgentResponse::Error { message, .. } => {
                Err(anyhow!(message))
            }
            _ => Err(anyhow!("unexpected daemon response")),
        };
    };
    run_child_with_secret_value(value, command)
}

fn run_child_with_secret_value(
    mut secret: crate::daemon::SecretValue,
    command: Vec<String>,
) -> Result<()> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| anyhow!("exec requires a command"))?;
    let mut child = ProcessCommand::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| anyhow!("start child command: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("open child stdin"))?;
    stdin.write_all(secret.as_bytes())?;
    secret.zeroize();
    drop(stdin);
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("child command exited with {status}"));
    }
    Ok(())
}

#[cfg(test)]
fn run_child_with_secret(mut secret: Zeroizing<String>, command: Vec<String>) -> Result<()> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| anyhow!("exec requires a command"))?;
    let mut child = ProcessCommand::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| anyhow!("start child command: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("open child stdin"))?;
    stdin.write_all(secret.as_bytes())?;
    secret.zeroize();
    drop(stdin);
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("child command exited with {status}"));
    }
    Ok(())
}

fn require_interactive_terminal() -> Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(anyhow!(
            "enabling auto-approval requires an interactive terminal"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_search_cli_captures_query_identity_reason_and_json_mode() {
        let cli = Cli::try_parse_from([
            "akc",
            "agent-search",
            "--query",
            "github prod",
            "--agent",
            "codex",
            "--reason",
            "deploy",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::AgentSearch {
                query,
                agent,
                reason: Some(reason),
                json: true,
            }) if query == "github prod" && agent == "codex" && reason == "deploy"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn exec_secret_is_delivered_only_to_child_stdin() {
        let temp = tempfile::TempDir::new().unwrap();
        let marker = temp.path().join("received");
        run_child_with_secret(
            Zeroizing::new("top-secret".into()),
            vec![
                "sh".into(),
                "-c".into(),
                format!("cat > '{}'", marker.display()),
            ],
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "top-secret");
    }
}
