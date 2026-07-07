use crate::cli::{prompt_approval, prompt_passphrase};
use crate::config::ConfigStore;
use crate::vault::{AgentRequest, AuditAction, VaultStore};
use anyhow::{Context, Result};
use interprocess::local_socket::{
    prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions, Name, Stream,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentCommand {
    GetSecret(AgentRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    Approved { value: String },
    Denied { message: String },
    Error { message: String },
}

pub fn request_secret(
    socket_path: PathBuf,
    agent: String,
    secret_name: String,
    reason: Option<String>,
    command_context: Option<String>,
) -> Result<AgentResponse> {
    let request = AgentCommand::GetSecret(AgentRequest {
        agent,
        pid: Some(std::process::id()),
        secret_name,
        reason,
        command_context,
    });
    send_request(socket_path, &request)
}

pub fn run_daemon(vault_path: PathBuf, socket_path: PathBuf, config_path: PathBuf) -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path);
    let config_store = ConfigStore::new(config_path);
    let _ = store
        .load(&passphrase)
        .context("unlock vault before starting daemon")?;

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create IPC directory {}", parent.display()))?;
    }

    let name = ipc_name(socket_path.clone())?;
    let listener = ListenerOptions::new()
        .name(name)
        .create_sync()
        .with_context(|| format!("bind local IPC endpoint {}", ipc_display(&socket_path)))?;
    println!("akc daemon listening on {}", ipc_display(&socket_path));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_client(stream, &store, &config_store, &passphrase) {
                    eprintln!("agent request failed: {error:#}");
                }
            }
            Err(error) => eprintln!("IPC accept failed: {error}"),
        }
    }
    Ok(())
}

fn send_request(socket_path: PathBuf, command: &AgentCommand) -> Result<AgentResponse> {
    let name = ipc_name(socket_path.clone())?;
    let stream = Stream::connect(name)
        .with_context(|| format!("connect to akc daemon at {}", ipc_display(&socket_path)))?;
    let mut conn = BufReader::new(stream);
    writeln!(conn.get_mut(), "{}", serde_json::to_string(command)?)?;
    conn.get_mut().flush()?;

    let mut line = String::new();
    conn.read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("parse daemon response")
}

fn handle_client(
    stream: Stream,
    store: &VaultStore,
    config_store: &ConfigStore,
    passphrase: &str,
) -> Result<()> {
    let mut conn = BufReader::new(stream);
    let mut line = String::new();
    conn.read_line(&mut line)?;
    let command: AgentCommand = serde_json::from_str(line.trim()).context("parse agent request")?;
    let response = match command {
        AgentCommand::GetSecret(request) => {
            handle_get_secret(store, config_store, passphrase, request)
        }
    };
    writeln!(conn.get_mut(), "{}", serde_json::to_string(&response)?)?;
    conn.get_mut().flush()?;
    Ok(())
}

fn handle_get_secret(
    store: &VaultStore,
    config_store: &ConfigStore,
    passphrase: &str,
    request: AgentRequest,
) -> AgentResponse {
    let prompt = format!(
        "Agent '{}' requests secret '{}'{}",
        request.agent,
        request.secret_name,
        request
            .reason
            .as_ref()
            .map(|reason| format!(" for: {reason}"))
            .unwrap_or_default()
    );

    let mut vault = match store.load(passphrase) {
        Ok(vault) => vault,
        Err(error) => {
            return AgentResponse::Error {
                message: error.to_string(),
            }
        }
    };
    vault.audit(
        AuditAction::AgentRequest,
        Some(request.secret_name.clone()),
        &request.agent,
        request.reason.clone(),
    );

    let auto_approve = match config_store.load() {
        Ok(config) => config.auto_approve_agent_requests,
        Err(error) => {
            return AgentResponse::Error {
                message: error.to_string(),
            }
        }
    };

    let approved = if auto_approve {
        println!(
            "auto-approved agent '{}' request for secret '{}'{}",
            request.agent,
            request.secret_name,
            request
                .reason
                .as_ref()
                .map(|reason| format!("; reason: {reason}"))
                .unwrap_or_default()
        );
        true
    } else {
        match prompt_approval(&prompt) {
            Ok(approved) => approved,
            Err(error) => {
                return AgentResponse::Error {
                    message: error.to_string(),
                }
            }
        }
    };

    complete_get_secret(store, passphrase, vault, request, approved, auto_approve)
}

fn complete_get_secret(
    store: &VaultStore,
    passphrase: &str,
    mut vault: crate::vault::Vault,
    request: AgentRequest,
    approved: bool,
    auto_approved: bool,
) -> AgentResponse {
    if !approved {
        vault.audit(
            AuditAction::AgentDeny,
            Some(request.secret_name.clone()),
            &request.agent,
            None,
        );
        let _ = store.save(&vault, passphrase);
        return AgentResponse::Denied {
            message: "request denied by user".into(),
        };
    }

    match vault.get_secret(
        &request.secret_name,
        &request.agent,
        Some(access_detail(&request, auto_approved)),
    ) {
        Ok(value) => {
            vault.audit(
                AuditAction::AgentApprove,
                Some(request.secret_name),
                &request.agent,
                None,
            );
            if let Err(error) = store.save(&vault, passphrase) {
                return AgentResponse::Error {
                    message: error.to_string(),
                };
            }
            AgentResponse::Approved { value }
        }
        Err(error) => {
            let _ = store.save(&vault, passphrase);
            AgentResponse::Error {
                message: error.to_string(),
            }
        }
    }
}

fn access_detail(request: &AgentRequest, auto_approved: bool) -> String {
    let mode = if auto_approved {
        "auto-approved one-time access"
    } else {
        "user-approved one-time access"
    };
    match &request.reason {
        Some(reason) => format!("{mode}; reason: {reason}"),
        None => mode.to_string(),
    }
}

fn ipc_name(socket_path: PathBuf) -> Result<Name<'static>> {
    if GenericNamespaced::is_supported() {
        return Ok("dev.goody.agent-keychain.akc"
            .to_string()
            .to_ns_name::<GenericNamespaced>()?
            .into_owned());
    }

    Ok(socket_path.to_fs_name::<GenericFilePath>()?.into_owned())
}

fn ipc_display(socket_path: &std::path::Path) -> String {
    if GenericNamespaced::is_supported() {
        "local:dev.goody.agent-keychain.akc".to_string()
    } else {
        socket_path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_response_serializes() {
        let response = AgentResponse::Denied {
            message: "no".into(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("denied"));
    }

    #[test]
    fn denied_agent_request_returns_no_secret_and_is_audited() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        let passphrase = "passphrase";
        store.init(passphrase).unwrap();
        let mut vault = store.load(passphrase).unwrap();
        vault.add_secret("thing".into(), "value".into()).unwrap();
        store.save(&vault, passphrase).unwrap();

        let request = AgentRequest {
            agent: "codex".into(),
            pid: Some(123),
            secret_name: "thing".into(),
            reason: Some("test".into()),
            command_context: None,
        };
        let response = complete_get_secret(&store, passphrase, vault, request, false, false);

        assert_eq!(
            response,
            AgentResponse::Denied {
                message: "request denied by user".into()
            }
        );
        let vault = store.load(passphrase).unwrap();
        assert!(vault
            .audit
            .iter()
            .any(|event| event.action == AuditAction::AgentDeny));
    }

    #[test]
    fn approved_agent_request_returns_secret_once_and_is_audited() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        let passphrase = "passphrase";
        store.init(passphrase).unwrap();
        let mut vault = store.load(passphrase).unwrap();
        vault.add_secret("thing".into(), "value".into()).unwrap();
        store.save(&vault, passphrase).unwrap();

        let request = AgentRequest {
            agent: "codex".into(),
            pid: Some(123),
            secret_name: "thing".into(),
            reason: Some("test".into()),
            command_context: None,
        };
        let response = complete_get_secret(&store, passphrase, vault, request, true, false);

        assert_eq!(
            response,
            AgentResponse::Approved {
                value: "value".into()
            }
        );
        let vault = store.load(passphrase).unwrap();
        assert!(vault
            .audit
            .iter()
            .any(|event| event.action == AuditAction::AgentApprove));
    }

    #[test]
    fn auto_approved_agent_request_logs_reason_in_get_audit() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        let passphrase = "passphrase";
        store.init(passphrase).unwrap();
        let mut vault = store.load(passphrase).unwrap();
        vault.add_secret("thing".into(), "value".into()).unwrap();
        store.save(&vault, passphrase).unwrap();

        let request = AgentRequest {
            agent: "codex".into(),
            pid: Some(123),
            secret_name: "thing".into(),
            reason: Some("deploy token needed".into()),
            command_context: None,
        };
        let response = complete_get_secret(&store, passphrase, vault, request, true, true);

        assert_eq!(
            response,
            AgentResponse::Approved {
                value: "value".into()
            }
        );
        let vault = store.load(passphrase).unwrap();
        assert!(vault.audit.iter().any(|event| {
            event.action == AuditAction::Get
                && event.actor == "codex"
                && event.detail.as_deref().is_some_and(|detail| {
                    detail.contains("auto-approved") && detail.contains("deploy token needed")
                })
        }));
    }
}
