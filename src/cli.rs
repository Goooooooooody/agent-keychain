use crate::config::ConfigStore;
use crate::daemon::{request_secret, run_daemon, AgentResponse};
use crate::paths::{config_path, socket_path, vault_path};
use crate::tui::run_tui;
use crate::vault::VaultStore;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use zeroize::Zeroize;

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
    Daemon,
    Tui,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    AgentGet {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "agent")]
        agent: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        command_context: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    AutoApprove {
        #[command(subcommand)]
        command: AutoApproveCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AutoApproveCommand {
    Enable,
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
        add_secret(name, Some(std::mem::take(&mut value)))?;
        value.zeroize();
        return Ok(());
    }

    match cli.command.unwrap_or(Command::List) {
        Command::Init => init_vault(),
        Command::Add { name, value } => add_secret(name, value),
        Command::Get { name } => get_secret(name),
        Command::List => list_secrets(),
        Command::Remove { name } => remove_secret(name),
        Command::Daemon => run_daemon(vault_path()?, socket_path()?, config_path()?),
        Command::Tui => run_tui(vault_path()?),
        Command::Config { command } => configure(command),
        Command::AgentGet {
            name,
            agent,
            reason,
            command_context,
        } => {
            let response = request_secret(socket_path()?, agent, name, reason, command_context)?;
            match response {
                AgentResponse::Approved { value } => {
                    println!("{value}");
                    Ok(())
                }
                AgentResponse::Denied { message } => Err(anyhow!(message)),
                AgentResponse::Error { message } => Err(anyhow!(message)),
            }
        }
    }
}

fn init_vault() -> Result<()> {
    let passphrase = prompt_new_passphrase()?;
    let store = VaultStore::new(vault_path()?);
    store.init(&passphrase)?;
    println!("initialized encrypted vault at {}", store.path().display());
    Ok(())
}

fn add_secret(name: String, value: Option<String>) -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path()?);
    let mut vault = store.load(&passphrase)?;
    let mut secret = match value {
        Some(value) => value,
        None => prompt_secret_value()?,
    };
    vault.add_secret(name.clone(), std::mem::take(&mut secret))?;
    secret.zeroize();
    store.save(&vault, &passphrase)?;
    println!("added secret '{name}'");
    Ok(())
}

fn get_secret(name: String) -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path()?);
    let mut vault = store.load(&passphrase)?;
    let value = vault.get_secret(&name, "user", None)?;
    store.save(&vault, &passphrase)?;
    println!("{value}");
    Ok(())
}

fn list_secrets() -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path()?);
    let vault = store.load(&passphrase)?;
    for name in vault.list_names() {
        println!("{name}");
    }
    Ok(())
}

fn remove_secret(name: String) -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path()?);
    let mut vault = store.load(&passphrase)?;
    vault.remove_secret(&name)?;
    store.save(&vault, &passphrase)?;
    println!("removed secret '{name}'");
    Ok(())
}

pub fn prompt_passphrase() -> Result<String> {
    if let Ok(passphrase) = std::env::var("AKC_MASTER_PASSPHRASE") {
        return Ok(passphrase);
    }
    rpassword::prompt_password("Master passphrase: ").map_err(Into::into)
}

fn prompt_new_passphrase() -> Result<String> {
    if let Ok(passphrase) = std::env::var("AKC_MASTER_PASSPHRASE") {
        return Ok(passphrase);
    }
    let first = rpassword::prompt_password("New master passphrase: ")?;
    let second = rpassword::prompt_password("Confirm master passphrase: ")?;
    if first != second {
        return Err(anyhow!("passphrases do not match"));
    }
    Ok(first)
}

fn prompt_secret_value() -> Result<String> {
    if atty_stdin() {
        return rpassword::prompt_password("Secret value: ").map_err(Into::into);
    }
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .to_string())
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
            AutoApproveCommand::Enable => {
                store.set_auto_approve(true)?;
                println!(
                    "agent request auto-approval enabled at {}",
                    store.path().display()
                );
            }
            AutoApproveCommand::Disable => {
                store.set_auto_approve(false)?;
                println!(
                    "agent request auto-approval disabled at {}",
                    store.path().display()
                );
            }
            AutoApproveCommand::Status => {
                let config = store.load()?;
                println!(
                    "agent request auto-approval: {}",
                    if config.auto_approve_agent_requests {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            }
        },
    }
    Ok(())
}
