use crate::cli::{prompt_approval, prompt_passphrase};
use crate::config::ConfigStore;
use crate::vault::{AgentRequest, AuditAction, VaultSession, VaultStore};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use interprocess::local_socket::{
    prelude::*, GenericFilePath, GenericNamespaced, ListenerNonblockingMode, ListenerOptions, Name,
    Stream,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_VERSION: u8 = 2;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_AGENT_CHARS: usize = 128;
const MAX_SECRET_NAME_CHARS: usize = 256;
const MAX_REASON_CHARS: usize = 1024;
const MAX_CONTEXT_CHARS: usize = 4096;
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_COUNT: usize = 4;
const CONNECTION_QUEUE: usize = 16;
const MAX_GRANT_SECONDS: u64 = 15 * 60;
const MAX_GRANT_USES: u32 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentCommand {
    GetSecret(AgentRequest),
    GetSecrets {
        agent: String,
        pid: Option<u32>,
        secret_names: Vec<String>,
        reason: Option<String>,
        command_context: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_token: Option<String>,
    },
    EnableGrant {
        passphrase: String,
        client_label: String,
        secret_name: String,
        ttl_seconds: u64,
        max_uses: u32,
    },
    DisableGrants,
    GrantStatus,
    Status,
    Lock,
    Unlock {
        passphrase: String,
    },
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    AuthenticationFailed,
    Locked,
    Denied,
    NotFound,
    PersistenceFailed,
    Internal,
    Busy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    Approved {
        value: SecretValue,
    },
    Batch {
        results: Vec<BatchSecretResult>,
    },
    Denied {
        message: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
    GrantStatus {
        enabled: bool,
        remaining_seconds: u64,
        remaining_uses: u32,
    },
    GrantCreated {
        /// Returned exactly once. The daemon stores only its SHA-256 digest.
        token: String,
        remaining_seconds: u64,
        remaining_uses: u32,
    },
    DaemonStatus {
        locked: bool,
        protocol_version: u8,
        active_grants: usize,
        queue_capacity: usize,
        idle_lock_seconds: u64,
        vault_revision: Option<u64>,
        metrics: Option<DaemonMetricsSnapshot>,
    },
    Ack {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DaemonMetricsSnapshot {
    pub requests: u64,
    pub total_request_latency_us: u64,
    pub total_state_lock_wait_us: u64,
    pub queue_rejections: u64,
    pub io_timeouts: u64,
    pub vault_bytes: u64,
    pub audit_archives: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchSecretResult {
    Approved { name: String, value: SecretValue },
    Denied { name: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<String>);

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl std::fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl Serialize for SecretValue {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Into::into)
    }
}
impl Zeroize for SecretValue {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl SecretValue {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Zeroize for BatchSecretResult {
    fn zeroize(&mut self) {
        if let Self::Approved { value, .. } = self {
            value.zeroize();
        }
    }
}

#[derive(Serialize)]
struct RequestEnvelope<'a> {
    request_id: &'a str,
    #[serde(flatten)]
    command: &'a AgentCommand,
}

#[derive(Deserialize)]
struct OwnedRequestEnvelope {
    #[serde(default)]
    request_id: Option<String>,
    #[serde(flatten)]
    command: AgentCommand,
}

#[derive(Deserialize)]
struct ResponseEnvelope {
    request_id: String,
    #[serde(rename = "protocol")]
    protocol_version: u8,
    #[serde(flatten)]
    response: AgentResponse,
}

#[derive(Serialize)]
struct ResponseEnvelopeRef<'a> {
    request_id: &'a str,
    #[serde(rename = "protocol")]
    protocol_version: u8,
    #[serde(flatten)]
    response: &'a AgentResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerIdentity {
    pid: Option<u32>,
    principal: u64,
}

struct ScopedGrant {
    token_hash: [u8; 32],
    client_label: String,
    secret_name: String,
    expires_at: Instant,
    remaining_uses: u32,
}

struct DaemonState {
    store: VaultStore,
    session: Option<VaultSession>,
    last_secret_activity: Instant,
    idle_timeout: Duration,
    grants: Vec<ScopedGrant>,
    shutdown: bool,
    metrics_enabled: bool,
    metrics: DaemonMetricsSnapshot,
}

struct ResponseZeroizeGuard<'a>(&'a mut AgentResponse);
impl Drop for ResponseZeroizeGuard<'_> {
    fn drop(&mut self) {
        if let AgentResponse::Approved { value } = self.0 {
            value.zeroize();
        } else if let AgentResponse::Batch { results } = self.0 {
            for result in results {
                if let BatchSecretResult::Approved { value, .. } = result {
                    value.zeroize();
                }
            }
        }
    }
}

pub fn request_secrets(
    socket_path: PathBuf,
    agent: String,
    secret_names: Vec<String>,
    reason: Option<String>,
    command_context: Option<String>,
) -> Result<AgentResponse> {
    let grant_token = std::env::var("AKC_GRANT_TOKEN").ok();
    send_request(
        socket_path,
        &AgentCommand::GetSecrets {
            agent,
            pid: Some(std::process::id()),
            secret_names,
            reason,
            command_context,
            grant_token,
        },
    )
}

pub fn request_secret(
    socket_path: PathBuf,
    agent: String,
    secret_name: String,
    reason: Option<String>,
    command_context: Option<String>,
) -> Result<AgentResponse> {
    let grant_token = std::env::var("AKC_GRANT_TOKEN").ok();
    send_request(
        socket_path,
        &AgentCommand::GetSecret(AgentRequest {
            agent,
            pid: Some(std::process::id()),
            secret_name,
            reason,
            command_context,
            grant_token,
        }),
    )
}

pub fn enable_grant(
    socket_path: PathBuf,
    mut passphrase: String,
    client_label: String,
    secret_name: String,
    ttl_seconds: u64,
    max_uses: u32,
) -> Result<AgentResponse> {
    let mut command = AgentCommand::EnableGrant {
        passphrase: std::mem::take(&mut passphrase),
        client_label,
        secret_name,
        ttl_seconds,
        max_uses,
    };
    let result = send_request(socket_path, &command);
    if let AgentCommand::EnableGrant { passphrase, .. } = &mut command {
        passphrase.zeroize();
    }
    passphrase.zeroize();
    result
}

pub fn disable_grants(socket_path: PathBuf) -> Result<AgentResponse> {
    send_request(socket_path, &AgentCommand::DisableGrants)
}
pub fn grant_status(socket_path: PathBuf) -> Result<AgentResponse> {
    send_request(socket_path, &AgentCommand::GrantStatus)
}
pub fn daemon_status(socket_path: PathBuf) -> Result<AgentResponse> {
    send_request(socket_path, &AgentCommand::Status)
}
pub fn lock_daemon(socket_path: PathBuf) -> Result<AgentResponse> {
    send_request(socket_path, &AgentCommand::Lock)
}
pub fn unlock_daemon(socket_path: PathBuf, passphrase: String) -> Result<AgentResponse> {
    let mut command = AgentCommand::Unlock { passphrase };
    let result = send_request(socket_path, &command);
    if let AgentCommand::Unlock { passphrase } = &mut command {
        passphrase.zeroize();
    }
    result
}
pub fn stop_daemon(socket_path: PathBuf) -> Result<AgentResponse> {
    send_request(socket_path, &AgentCommand::Stop)
}

pub fn run_daemon(vault_path: PathBuf, socket_path: PathBuf, config_path: PathBuf) -> Result<()> {
    let passphrase = Zeroizing::new(prompt_passphrase()?);
    let store = VaultStore::new(vault_path);
    let session = store
        .unlock(&passphrase)
        .context("unlock vault before starting daemon")?;
    let config_store = ConfigStore::new(config_path);
    let config = config_store.load()?;

    if let Some(parent) = socket_path.parent() {
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)
            .with_context(|| format!("create IPC directory {}", parent.display()))?;
        if !parent_existed {
            secure_ipc_directory(parent)?;
        }
    }
    let name = ipc_name(socket_path.clone())?;
    let listener = ListenerOptions::new()
        .name(name)
        .create_sync()
        .with_context(|| format!("bind local IPC endpoint {}", ipc_display(&socket_path)))?;
    listener.set_nonblocking(ListenerNonblockingMode::Both)?;
    secure_ipc_endpoint(&socket_path)?;
    println!("akc daemon listening on {}", ipc_display(&socket_path));

    if config.auto_approve_agent_requests {
        eprintln!("warning: ignored legacy persistent auto-approve setting; grants are scoped and daemon-session only");
        config_store.set_auto_approve(false)?;
    }

    let state = Arc::new(Mutex::new(DaemonState {
        store,
        session: Some(session),
        last_secret_activity: Instant::now(),
        idle_timeout: Duration::from_secs(config.idle_lock_seconds),
        grants: Vec::new(),
        shutdown: false,
        metrics_enabled: std::env::var_os("AKC_METRICS").is_some(),
        metrics: DaemonMetricsSnapshot::default(),
    }));
    let timer_state = Arc::clone(&state);
    thread::Builder::new()
        .name("akc-idle-lock".into())
        .spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            let Ok(mut state) = timer_state.lock() else {
                return;
            };
            expire_idle_session(&mut state);
            if state.shutdown {
                return;
            }
        })?;

    let (sender, receiver) = mpsc::sync_channel::<Stream>(CONNECTION_QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    for worker_id in 0..WORKER_COUNT {
        let state = Arc::clone(&state);
        let receiver = Arc::clone(&receiver);
        thread::Builder::new()
            .name(format!("akc-ipc-{worker_id}"))
            .spawn(move || loop {
                let stream = match receiver.lock() {
                    Ok(receiver) => receiver.recv(),
                    Err(_) => return,
                };
                match stream {
                    Ok(stream) => {
                        if let Err(error) = handle_client(stream, &state) {
                            if is_timeout_error(&error) {
                                if let Ok(mut state) = state.lock() {
                                    state.metrics.io_timeouts =
                                        state.metrics.io_timeouts.saturating_add(1);
                                }
                            }
                            eprintln!("agent request failed: {error:#}");
                        }
                    }
                    Err(_) => return,
                }
            })?;
    }

    loop {
        if state
            .lock()
            .map_err(|_| anyhow!("daemon state lock poisoned"))?
            .shutdown
        {
            break;
        }
        match listener.accept() {
            Ok(stream) => match sender.try_send(stream) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(stream)) => {
                    if let Ok(mut state) = state.lock() {
                        state.metrics.queue_rejections =
                            state.metrics.queue_rejections.saturating_add(1);
                    }
                    let _ = stream.set_send_timeout(Some(IPC_TIMEOUT));
                    let mut conn = BufReader::new(stream);
                    let _ = write_error_response(
                        &mut conn,
                        &new_request_id(),
                        ErrorCode::Busy,
                        "daemon request queue is full",
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => break,
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => eprintln!("IPC accept failed: {error}"),
        }
    }
    if let Ok(mut state) = state.lock() {
        state.session = None;
        state.grants.clear();
    }
    Ok(())
}

fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn send_request(socket_path: PathBuf, command: &AgentCommand) -> Result<AgentResponse> {
    let name = ipc_name(socket_path.clone())?;
    let stream = Stream::connect(name)
        .with_context(|| format!("connect to akc daemon at {}", ipc_display(&socket_path)))?;
    stream.set_recv_timeout(Some(IPC_TIMEOUT))?;
    stream.set_send_timeout(Some(IPC_TIMEOUT))?;
    let mut conn = BufReader::new(stream);
    let request_id = new_request_id();
    writeln!(
        conn.get_mut(),
        "{}",
        serde_json::to_string(&RequestEnvelope {
            request_id: &request_id,
            command
        })?
    )?;
    conn.get_mut().flush()?;
    let line = Zeroizing::new(read_request_frame(&mut conn)?);
    let response: ResponseEnvelope =
        serde_json::from_slice(&line).context("parse daemon response")?;
    if response.request_id != request_id {
        bail!("daemon response request ID mismatch");
    }
    if response.protocol_version != PROTOCOL_VERSION {
        bail!(
            "unsupported daemon protocol version {}",
            response.protocol_version
        );
    }
    Ok(response.response)
}

fn handle_client(stream: Stream, state: &Arc<Mutex<DaemonState>>) -> Result<()> {
    let started = Instant::now();
    let peer = authorize_peer(&stream)?;
    stream.set_recv_timeout(Some(IPC_TIMEOUT))?;
    stream.set_send_timeout(Some(IPC_TIMEOUT))?;
    let mut conn = BufReader::new(stream);
    let line = match read_request_frame(&mut conn) {
        Ok(line) => Zeroizing::new(line),
        Err(error) => {
            return write_error_response(
                &mut conn,
                &new_request_id(),
                ErrorCode::InvalidRequest,
                error,
            );
        }
    };
    let (request_id, command) = match parse_command(&line) {
        Ok(parsed) => parsed,
        Err(error) => {
            let request_id = serde_json::from_slice::<serde_json::Value>(&line)
                .ok()
                .and_then(|value| value.get("request_id")?.as_str().map(str::to_owned))
                .unwrap_or_else(new_request_id);
            return write_error_response(&mut conn, &request_id, ErrorCode::InvalidRequest, error);
        }
    };
    let lock_started = Instant::now();
    let mut response = {
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("daemon state lock poisoned"))?;
        state.metrics.total_state_lock_wait_us =
            state.metrics.total_state_lock_wait_us.saturating_add(
                lock_started
                    .elapsed()
                    .as_micros()
                    .try_into()
                    .unwrap_or(u64::MAX),
            );
        expire_idle_session(&mut state);
        handle_command(&mut state, command, peer)
    };
    let guard = ResponseZeroizeGuard(&mut response);
    let encoded = Zeroizing::new(serde_json::to_vec(&ResponseEnvelopeRef {
        request_id: &request_id,
        protocol_version: PROTOCOL_VERSION,
        response: guard.0,
    })?);
    drop(guard);
    conn.get_mut().write_all(&encoded)?;
    conn.get_mut().write_all(b"\n")?;
    conn.get_mut().flush()?;
    if let Ok(mut state) = state.lock() {
        state.metrics.requests = state.metrics.requests.saturating_add(1);
        state.metrics.total_request_latency_us = state
            .metrics
            .total_request_latency_us
            .saturating_add(started.elapsed().as_micros().try_into().unwrap_or(u64::MAX));
    }
    Ok(())
}

fn is_timeout_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        })
    })
}

fn write_error_response(
    conn: &mut BufReader<Stream>,
    request_id: &str,
    code: ErrorCode,
    error: impl std::fmt::Display,
) -> Result<()> {
    let mut message = error.to_string();
    message.truncate(256);
    let response = AgentResponse::Error { code, message };
    let encoded = serde_json::to_vec(&ResponseEnvelopeRef {
        request_id,
        protocol_version: PROTOCOL_VERSION,
        response: &response,
    })?;
    conn.get_mut().write_all(&encoded)?;
    conn.get_mut().write_all(b"\n")?;
    conn.get_mut().flush().map_err(Into::into)
}

fn handle_command(
    state: &mut DaemonState,
    command: AgentCommand,
    peer: PeerIdentity,
) -> AgentResponse {
    match command {
        AgentCommand::GetSecret(request) => match normalize_request(request, peer.pid) {
            Ok(request) => handle_get_secret(state, request, peer),
            Err(error) => error_response(ErrorCode::InvalidRequest, error),
        },
        AgentCommand::GetSecrets {
            agent,
            pid,
            secret_names,
            reason,
            command_context,
            grant_token,
        } => {
            let mut requests = Vec::new();
            for secret_name in secret_names {
                match normalize_request(
                    AgentRequest {
                        agent: agent.clone(),
                        pid,
                        secret_name,
                        reason: reason.clone(),
                        command_context: command_context.clone(),
                        grant_token: grant_token.clone(),
                    },
                    peer.pid,
                ) {
                    Ok(request) => requests.push(request),
                    Err(error) => return error_response(ErrorCode::InvalidRequest, error),
                }
            }
            handle_get_secrets(state, requests, peer)
        }
        AgentCommand::EnableGrant {
            mut passphrase,
            client_label,
            secret_name,
            ttl_seconds,
            max_uses,
        } => {
            let response = enable_scoped_grant(
                state,
                peer,
                &passphrase,
                client_label,
                secret_name,
                ttl_seconds,
                max_uses,
            );
            passphrase.zeroize();
            response
        }
        AgentCommand::DisableGrants => {
            state.grants.clear();
            AgentResponse::GrantStatus {
                enabled: false,
                remaining_seconds: 0,
                remaining_uses: 0,
            }
        }
        AgentCommand::GrantStatus => grant_status_response(state, peer),
        AgentCommand::Status => AgentResponse::DaemonStatus {
            locked: state.session.is_none(),
            protocol_version: PROTOCOL_VERSION,
            active_grants: active_grants(state),
            queue_capacity: CONNECTION_QUEUE,
            idle_lock_seconds: state.idle_timeout.as_secs(),
            vault_revision: state.session.as_ref().map(VaultSession::revision),
            metrics: state.metrics_enabled.then(|| {
                let mut metrics = state.metrics.clone();
                metrics.vault_bytes = state.store.storage_metrics().0;
                metrics.audit_archives = state.store.storage_metrics().1;
                metrics
            }),
        },
        AgentCommand::Lock => {
            state.session = None;
            state.grants.clear();
            AgentResponse::Ack {
                message: "daemon locked".into(),
            }
        }
        AgentCommand::Unlock { mut passphrase } => {
            let result = state.store.unlock(&passphrase);
            passphrase.zeroize();
            match result {
                Ok(session) => {
                    state.session = Some(session);
                    state.last_secret_activity = Instant::now();
                    AgentResponse::Ack {
                        message: "daemon unlocked".into(),
                    }
                }
                Err(_) => AgentResponse::Error {
                    code: ErrorCode::AuthenticationFailed,
                    message: "authentication failed".into(),
                },
            }
        }
        AgentCommand::Stop => {
            state.session = None;
            state.grants.clear();
            state.shutdown = true;
            AgentResponse::Ack {
                message: "daemon stopping".into(),
            }
        }
    }
}

fn handle_get_secrets(
    state: &mut DaemonState,
    requests: Vec<AgentRequest>,
    _peer: PeerIdentity,
) -> AgentResponse {
    if requests.is_empty() || requests.len() > 64 {
        return error_response(
            ErrorCode::InvalidRequest,
            "batch must contain 1..=64 secrets",
        );
    }
    if state.session.is_none() {
        return error_response(
            ErrorCode::Locked,
            "daemon is locked; run `akc daemon unlock`",
        );
    }
    prune_grants(state);
    let all_granted = batch_is_fully_granted(&state.grants, &requests);
    let names = requests
        .iter()
        .map(|r| r.secret_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let approved = all_granted
        || prompt_approval(&format!(
            "Agent '{}' requests {} secrets: {}",
            requests[0].agent,
            requests.len(),
            names
        ))
        .unwrap_or(false);
    state.last_secret_activity = Instant::now();
    let Some(session) = state.session.as_mut() else {
        return error_response(ErrorCode::Locked, "daemon is locked");
    };
    let outcome =
        session.transaction(|vault| fulfill_batch(vault, &requests, approved, all_granted));
    match outcome {
        Ok(results) => {
            if all_granted {
                // A capability use is committed only after the approved value was durably
                // audited and is ready to be returned. Denied/missing items do not consume it.
                for (request, result) in requests.iter().zip(&results) {
                    if matches!(result, BatchSecretResult::Approved { .. }) {
                        consume_matching_grant(state, request);
                    }
                }
            }
            AgentResponse::Batch { results }
        }
        Err(error) => error_response(
            ErrorCode::PersistenceFailed,
            format!("audit persistence failed: {error:#}"),
        ),
    }
}

fn batch_is_fully_granted(grants: &[ScopedGrant], requests: &[AgentRequest]) -> bool {
    let mut available_uses: Vec<u32> = grants.iter().map(|grant| grant.remaining_uses).collect();
    requests.iter().all(|request| {
        let match_index = grants
            .iter()
            .enumerate()
            .position(|(index, grant)| grant_matches(grant, request) && available_uses[index] > 0);
        match match_index {
            Some(index) => {
                available_uses[index] -= 1;
                true
            }
            None => false,
        }
    })
}

fn fulfill_batch(
    vault: &mut crate::vault::Vault,
    requests: &[AgentRequest],
    approved: bool,
    auto_approved: bool,
) -> Result<Vec<BatchSecretResult>> {
    let mut results = Vec::new();
    for request in requests {
        if !approved {
            vault.audit_with_peer(
                AuditAction::AgentDeny,
                Some(request.secret_name.clone()),
                &request.agent,
                Some("batch denied by user".into()),
                request.pid,
            );
            results.push(BatchSecretResult::Denied {
                name: request.secret_name.clone(),
                message: "batch denied by user".into(),
            });
            continue;
        }
        match vault.get_secret_for_peer_action(
            &request.secret_name,
            &request.agent,
            Some(access_detail(request, auto_approved)),
            request.pid,
            AuditAction::AgentApprove,
        ) {
            Ok(value) => {
                results.push(BatchSecretResult::Approved {
                    name: request.secret_name.clone(),
                    value: value.into(),
                });
            }
            Err(error) => {
                vault.audit_with_peer(
                    AuditAction::AgentError,
                    Some(request.secret_name.clone()),
                    &request.agent,
                    Some(error.to_string()),
                    request.pid,
                );
                results.push(BatchSecretResult::Denied {
                    name: request.secret_name.clone(),
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(results)
}

fn expire_idle_session(state: &mut DaemonState) {
    prune_grants(state);
    if state.session.is_some() && state.last_secret_activity.elapsed() >= state.idle_timeout {
        state.session = None;
        state.grants.clear();
    }
}

fn handle_get_secret(
    state: &mut DaemonState,
    request: AgentRequest,
    _peer: PeerIdentity,
) -> AgentResponse {
    if state.session.is_none() {
        return AgentResponse::Error {
            code: ErrorCode::Locked,
            message: "daemon is locked; run `akc daemon unlock`".into(),
        };
    }
    let auto_approved = state
        .grants
        .iter()
        .any(|grant| grant_matches(grant, &request));
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
    let approved = if auto_approved {
        println!(
            "used scoped grant for agent '{}' and secret '{}'",
            request.agent, request.secret_name
        );
        true
    } else {
        match prompt_approval(&prompt) {
            Ok(approved) => approved,
            Err(error) => return audit_request_error(state, &request, error.to_string()),
        }
    };
    state.last_secret_activity = Instant::now();
    let response = complete_get_secret(state, request.clone(), approved, auto_approved);
    if auto_approved && matches!(response, AgentResponse::Approved { .. }) {
        consume_matching_grant(state, &request);
    }
    response
}

fn audit_request_error(
    state: &mut DaemonState,
    request: &AgentRequest,
    message: String,
) -> AgentResponse {
    let Some(session) = state.session.as_mut() else {
        return AgentResponse::Error {
            code: ErrorCode::Locked,
            message: "daemon is locked".into(),
        };
    };
    match session.transaction(|vault| {
        vault.audit_with_peer(
            AuditAction::AgentRequest,
            Some(request.secret_name.clone()),
            &request.agent,
            request.reason.clone(),
            request.pid,
        );
        vault.audit_with_peer(
            AuditAction::AgentError,
            Some(request.secret_name.clone()),
            &request.agent,
            Some(message.clone()),
            request.pid,
        );
        Ok(())
    }) {
        Ok(()) => AgentResponse::Error {
            code: ErrorCode::Internal,
            message,
        },
        Err(error) => AgentResponse::Error {
            code: ErrorCode::PersistenceFailed,
            message: format!("audit persistence failed: {error:#}; original error: {message}"),
        },
    }
}

fn enable_scoped_grant(
    state: &mut DaemonState,
    _peer: PeerIdentity,
    passphrase: &str,
    client_label: String,
    secret_name: String,
    ttl_seconds: u64,
    max_uses: u32,
) -> AgentResponse {
    if ttl_seconds == 0
        || ttl_seconds > MAX_GRANT_SECONDS
        || max_uses == 0
        || max_uses > MAX_GRANT_USES
    {
        return AgentResponse::Error {
            code: ErrorCode::InvalidRequest,
            message: format!(
                "ttl_seconds must be 1..={MAX_GRANT_SECONDS} and max_uses 1..={MAX_GRANT_USES}"
            ),
        };
    }
    if validate_field("client_label", &client_label, MAX_AGENT_CHARS, true).is_err()
        || validate_field("secret_name", &secret_name, MAX_SECRET_NAME_CHARS, true).is_err()
    {
        return AgentResponse::Error {
            code: ErrorCode::InvalidRequest,
            message: "invalid grant selector".into(),
        };
    }
    if state.store.load(passphrase).is_err() {
        return AgentResponse::Error {
            code: ErrorCode::AuthenticationFailed,
            message: "authentication failed".into(),
        };
    }
    prune_grants(state);
    let mut token = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(token.as_mut());
    let token_text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token.as_ref());
    let token_hash: [u8; 32] = Sha256::digest(token_text.as_bytes()).into();
    state.grants.push(ScopedGrant {
        token_hash,
        client_label,
        secret_name,
        expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
        remaining_uses: max_uses,
    });
    AgentResponse::GrantCreated {
        token: token_text,
        remaining_seconds: ttl_seconds,
        remaining_uses: max_uses,
    }
}

fn consume_matching_grant(state: &mut DaemonState, request: &AgentRequest) -> bool {
    prune_grants(state);
    let Some(index) = state
        .grants
        .iter()
        .position(|grant| grant_matches(grant, request))
    else {
        return false;
    };
    state.grants[index].remaining_uses -= 1;
    if state.grants[index].remaining_uses == 0 {
        state.grants.remove(index);
    }
    true
}

fn grant_matches(grant: &ScopedGrant, request: &AgentRequest) -> bool {
    let Some(token) = request.grant_token.as_deref() else {
        return false;
    };
    let candidate: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    // Constant-time digest comparison without retaining the presented capability.
    let mut difference = 0u8;
    for (left, right) in grant.token_hash.iter().zip(candidate.iter()) {
        difference |= left ^ right;
    }
    difference == 0
        && grant.client_label == request.agent
        && grant.secret_name == request.secret_name
}

fn prune_grants(state: &mut DaemonState) {
    let now = Instant::now();
    state
        .grants
        .retain(|grant| grant.expires_at > now && grant.remaining_uses > 0);
}
fn active_grants(state: &mut DaemonState) -> usize {
    prune_grants(state);
    state.grants.len()
}
fn grant_status_response(state: &mut DaemonState, _peer: PeerIdentity) -> AgentResponse {
    prune_grants(state);
    let grants: Vec<_> = state.grants.iter().collect();
    AgentResponse::GrantStatus {
        enabled: !grants.is_empty(),
        remaining_seconds: grants
            .iter()
            .filter_map(|grant| grant.expires_at.checked_duration_since(Instant::now()))
            .map(|d| d.as_secs().saturating_add(1))
            .max()
            .unwrap_or(0),
        remaining_uses: grants.iter().map(|grant| grant.remaining_uses).sum(),
    }
}

fn complete_get_secret(
    state: &mut DaemonState,
    request: AgentRequest,
    approved: bool,
    auto_approved: bool,
) -> AgentResponse {
    enum Outcome {
        Approved(String),
        Denied,
        Error(String),
    }
    impl Zeroize for Outcome {
        fn zeroize(&mut self) {
            if let Self::Approved(value) = self {
                value.zeroize();
            }
        }
    }
    let Some(session) = state.session.as_mut() else {
        return AgentResponse::Error {
            code: ErrorCode::Locked,
            message: "daemon is locked".into(),
        };
    };
    let outcome = session.transaction(|vault| {
        vault.audit_with_peer(
            AuditAction::AgentRequest,
            Some(request.secret_name.clone()),
            &request.agent,
            request.reason.clone(),
            request.pid,
        );
        if approved {
            match vault.get_secret_for_peer(
                &request.secret_name,
                &request.agent,
                Some(access_detail(&request, auto_approved)),
                request.pid,
            ) {
                Ok(value) => {
                    vault.audit_with_peer(
                        AuditAction::AgentApprove,
                        Some(request.secret_name.clone()),
                        &request.agent,
                        None,
                        request.pid,
                    );
                    Ok(Outcome::Approved(value))
                }
                Err(error) => {
                    vault.audit_with_peer(
                        AuditAction::AgentError,
                        Some(request.secret_name.clone()),
                        &request.agent,
                        Some(error.to_string()),
                        request.pid,
                    );
                    Ok(Outcome::Error(error.to_string()))
                }
            }
        } else {
            vault.audit_with_peer(
                AuditAction::AgentDeny,
                Some(request.secret_name.clone()),
                &request.agent,
                None,
                request.pid,
            );
            Ok(Outcome::Denied)
        }
    });
    match outcome {
        Ok(Outcome::Approved(value)) => AgentResponse::Approved {
            value: value.into(),
        },
        Ok(Outcome::Denied) => AgentResponse::Denied {
            message: "request denied by user".into(),
        },
        Ok(Outcome::Error(message)) => AgentResponse::Error {
            code: ErrorCode::NotFound,
            message,
        },
        Err(error) => AgentResponse::Error {
            code: ErrorCode::PersistenceFailed,
            message: format!("audit persistence failed: {error:#}"),
        },
    }
}

fn error_response(code: ErrorCode, error: impl std::fmt::Display) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: error.to_string(),
    }
}
fn access_detail(request: &AgentRequest, auto_approved: bool) -> String {
    let mode = if auto_approved {
        "scoped-grant access"
    } else {
        "user-approved one-time access"
    };
    match &request.reason {
        Some(reason) => format!("{mode}; reason: {reason}"),
        None => mode.to_string(),
    }
}

fn read_request_frame(mut reader: impl BufRead) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    reader
        .by_ref()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .context("read IPC request")?;
    if frame.len() > MAX_REQUEST_BYTES {
        bail!("IPC request exceeds {MAX_REQUEST_BYTES} bytes");
    }
    if frame.last() != Some(&b'\n') {
        bail!("IPC request must be newline terminated");
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    Ok(frame)
}
fn parse_command(frame: &[u8]) -> Result<(String, AgentCommand)> {
    let envelope: OwnedRequestEnvelope =
        serde_json::from_slice(frame).context("parse agent request")?;
    Ok((
        envelope.request_id.unwrap_or_else(new_request_id),
        envelope.command,
    ))
}
fn normalize_request(mut request: AgentRequest, peer_pid: Option<u32>) -> Result<AgentRequest> {
    validate_field("agent", &request.agent, MAX_AGENT_CHARS, false)?;
    validate_field(
        "secret_name",
        &request.secret_name,
        MAX_SECRET_NAME_CHARS,
        true,
    )?;
    if let Some(reason) = &request.reason {
        validate_field("reason", reason, MAX_REASON_CHARS, false)?;
    }
    if let Some(context) = &request.command_context {
        validate_field("command_context", context, MAX_CONTEXT_CHARS, false)?;
    }
    request.agent = terminal_safe(&request.agent);
    request.reason = request.reason.as_deref().map(terminal_safe);
    request.command_context = request.command_context.as_deref().map(terminal_safe);
    request.pid = peer_pid;
    Ok(request)
}
fn validate_field(name: &str, value: &str, max_chars: usize, reject_controls: bool) -> Result<()> {
    if value.chars().count() > max_chars {
        bail!("{name} exceeds {max_chars} characters");
    }
    if reject_controls && value.chars().any(char::is_control) {
        bail!("{name} contains control characters");
    }
    Ok(())
}
fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\r' | '\t' => ' ',
            character if character.is_control() => '?',
            character => character,
        })
        .collect()
}
fn authorize_peer(stream: &Stream) -> Result<PeerIdentity> {
    let credentials = stream.peer_creds().context("read IPC peer credentials")?;
    let pid = credentials.pid().and_then(|pid| u32::try_from(pid).ok());
    #[cfg(unix)]
    {
        let peer_uid = credentials
            .euid()
            .ok_or_else(|| anyhow!("IPC peer did not provide an effective user ID"))?;
        let daemon_uid = unsafe { libc::geteuid() };
        if peer_uid != daemon_uid {
            bail!("IPC peer belongs to a different OS user");
        }
        Ok(PeerIdentity {
            pid,
            principal: peer_uid as u64,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(PeerIdentity {
            pid,
            principal: pid.unwrap_or(0) as u64,
        })
    }
}

#[cfg(unix)]
fn secure_ipc_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure IPC directory {}", path.display()))
}
#[cfg(not(unix))]
fn secure_ipc_directory(_path: &Path) -> Result<()> {
    Ok(())
}
#[cfg(unix)]
fn secure_ipc_endpoint(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !GenericNamespaced::is_supported() && path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure IPC endpoint {}", path.display()))?;
    }
    Ok(())
}
#[cfg(not(unix))]
fn secure_ipc_endpoint(_path: &Path) -> Result<()> {
    Ok(())
}

fn endpoint_hash(path: &Path) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
fn ipc_name(socket_path: PathBuf) -> Result<Name<'static>> {
    if GenericNamespaced::is_supported() {
        return Ok(format!(
            "dev.goody.agent-keychain.akc.{:016x}",
            endpoint_hash(&socket_path)
        )
        .to_ns_name::<GenericNamespaced>()?
        .into_owned());
    }
    Ok(socket_path.to_fs_name::<GenericFilePath>()?.into_owned())
}
fn ipc_display(socket_path: &Path) -> String {
    if GenericNamespaced::is_supported() {
        format!(
            "local:dev.goody.agent-keychain.akc.{:016x}",
            endpoint_hash(socket_path)
        )
    } else {
        socket_path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip_raw_frame(frame: Vec<u8>) -> serde_json::Value {
        let socket_temp = tempfile::TempDir::new().unwrap();
        let path = socket_temp
            .path()
            .join(format!("ipc-{}.sock", new_request_id()));
        let listener = ListenerOptions::new()
            .name(ipc_name(path.clone()).unwrap())
            .create_sync()
            .unwrap();
        let client = thread::spawn(move || {
            let mut stream = Stream::connect(ipc_name(path).unwrap()).unwrap();
            stream.write_all(&frame).unwrap();
            stream.flush().unwrap();
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).unwrap();
            serde_json::from_str(&response).unwrap()
        });
        let stream = listener.accept().unwrap();
        let (_vault_temp, state) = state_with_secret();
        handle_client(stream, &Arc::new(Mutex::new(state))).unwrap();
        client.join().unwrap()
    }

    fn state_with_secret() -> (tempfile::TempDir, DaemonState) {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("correct").unwrap();
        store
            .transaction("correct", |vault| {
                vault.add_secret("thing".into(), "value".into())
            })
            .unwrap();
        let session = store.unlock("correct").unwrap();
        (
            temp,
            DaemonState {
                store,
                session: Some(session),
                last_secret_activity: Instant::now(),
                idle_timeout: Duration::from_secs(900),
                grants: vec![],
                shutdown: false,
                metrics_enabled: false,
                metrics: DaemonMetricsSnapshot::default(),
            },
        )
    }

    #[test]
    fn frames_are_bounded() {
        assert!(read_request_frame(Cursor::new(vec![b'a'; MAX_REQUEST_BYTES + 1])).is_err());
        assert!(read_request_frame(Cursor::new(br#"{"type":"status"}"#.to_vec())).is_err());
    }

    #[test]
    fn malformed_and_oversized_real_ipc_frames_get_bounded_structured_errors() {
        for frame in [b"not-json\n".to_vec(), vec![b'x'; MAX_REQUEST_BYTES + 2]] {
            let response = round_trip_raw_frame(frame);
            assert_eq!(response["status"], "error");
            assert_eq!(response["code"], "invalid_request");
            assert!(response["message"].as_str().unwrap().len() <= 256);
            assert!(response["request_id"].is_string());
        }
    }
    #[test]
    fn request_fields_are_bounded_and_terminal_safe() {
        let request = AgentRequest {
            agent: "codex\u{1b}[2J\nspoof".into(),
            pid: Some(1),
            secret_name: "thing".into(),
            reason: Some("deploy\r\nallow?".into()),
            command_context: None,
            grant_token: None,
        };
        let normalized = normalize_request(request, Some(456)).unwrap();
        assert_eq!(normalized.agent, "codex?[2J spoof");
        assert_eq!(normalized.pid, Some(456));
    }
    #[test]
    fn scoped_grant_expires_and_honors_use_limit_and_selector() {
        let (_temp, mut state) = state_with_secret();
        let peer = PeerIdentity {
            pid: Some(1),
            principal: 42,
        };
        let token = match enable_scoped_grant(
            &mut state,
            peer,
            "correct",
            "codex".into(),
            "thing".into(),
            30,
            1,
        ) {
            AgentResponse::GrantCreated { token, .. } => token,
            response => panic!("unexpected response: {response:?}"),
        };
        let request = |agent: &str, token: Option<String>| AgentRequest {
            agent: agent.into(),
            pid: None,
            secret_name: "thing".into(),
            reason: None,
            command_context: None,
            grant_token: token,
        };
        assert!(!consume_matching_grant(
            &mut state,
            &request("other", Some(token.clone()))
        ));
        assert!(!consume_matching_grant(
            &mut state,
            &request("codex", Some("forged".into()))
        ));
        assert!(consume_matching_grant(
            &mut state,
            &request("codex", Some(token.clone()))
        ));
        assert!(!consume_matching_grant(
            &mut state,
            &request("codex", Some(token.clone()))
        ));
        state.grants.push(ScopedGrant {
            token_hash: Sha256::digest(token.as_bytes()).into(),
            client_label: "codex".into(),
            secret_name: "thing".into(),
            expires_at: Instant::now() - Duration::from_secs(1),
            remaining_uses: 1,
        });
        assert!(!consume_matching_grant(
            &mut state,
            &request("codex", Some(token))
        ));
    }
    #[test]
    fn manual_and_idle_lock_drop_session_and_grants() {
        let (_temp, mut state) = state_with_secret();
        state.grants.push(ScopedGrant {
            token_hash: [0; 32],
            client_label: "codex".into(),
            secret_name: "thing".into(),
            expires_at: Instant::now() + Duration::from_secs(10),
            remaining_uses: 1,
        });
        state.idle_timeout = Duration::from_secs(1);
        state.last_secret_activity = Instant::now() - Duration::from_secs(2);
        expire_idle_session(&mut state);
        assert!(state.session.is_none());
        assert!(state.grants.is_empty());
    }
    #[test]
    fn configured_paths_have_distinct_stable_endpoint_names() {
        let a = PathBuf::from("/tmp/profile-a.sock");
        let b = PathBuf::from("/tmp/profile-b.sock");
        assert_ne!(ipc_display(&a), ipc_display(&b));
        assert_eq!(ipc_display(&a), ipc_display(&a));
    }
    #[test]
    fn response_envelope_has_request_id_protocol_and_structured_error() {
        let response = AgentResponse::Error {
            code: ErrorCode::Locked,
            message: "locked".into(),
        };
        let envelope = ResponseEnvelopeRef {
            request_id: "abc",
            protocol_version: PROTOCOL_VERSION,
            response: &response,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("request_id"));
        assert!(json.contains("locked"));
    }

    #[test]
    fn approved_batch_returns_allowed_items_and_denies_failures_individually() {
        let mut vault = crate::vault::Vault::new();
        vault.add_secret("present".into(), "value".into()).unwrap();
        let request = |name: &str| AgentRequest {
            agent: "codex".into(),
            pid: None,
            secret_name: name.into(),
            reason: None,
            command_context: None,
            grant_token: None,
        };
        let results = fulfill_batch(
            &mut vault,
            &[request("present"), request("missing")],
            true,
            false,
        )
        .unwrap();
        assert!(
            matches!(&results[0], BatchSecretResult::Approved { name, .. } if name == "present")
        );
        assert!(matches!(&results[1], BatchSecretResult::Denied { name, .. } if name == "missing"));
        let events: Vec<_> = vault
            .audit
            .iter()
            .filter(|event| {
                matches!(
                    event.action,
                    AuditAction::AgentApprove | AuditAction::AgentError
                )
            })
            .collect();
        assert_eq!(
            events.len(),
            2,
            "batch writes exactly one outcome event per secret"
        );
    }

    #[test]
    fn denied_batch_returns_no_values_and_audits_each_secret_once() {
        let mut vault = crate::vault::Vault::new();
        vault.add_secret("one".into(), "first".into()).unwrap();
        vault.add_secret("two".into(), "second".into()).unwrap();
        let requests = ["one", "two"].map(|name| AgentRequest {
            agent: "codex".into(),
            pid: None,
            secret_name: name.into(),
            reason: None,
            command_context: None,
            grant_token: None,
        });
        let results = fulfill_batch(&mut vault, &requests, false, false).unwrap();
        assert!(results
            .iter()
            .all(|result| matches!(result, BatchSecretResult::Denied { .. })));
        assert_eq!(
            vault
                .audit
                .iter()
                .filter(|e| e.action == AuditAction::AgentDeny)
                .count(),
            2
        );
    }

    #[test]
    fn batch_grants_require_enough_uses_for_duplicate_requests() {
        let token = "capability";
        let grants = vec![ScopedGrant {
            token_hash: Sha256::digest(token.as_bytes()).into(),
            client_label: "codex".into(),
            secret_name: "one".into(),
            expires_at: Instant::now() + Duration::from_secs(30),
            remaining_uses: 1,
        }];
        let request = || AgentRequest {
            agent: "codex".into(),
            pid: None,
            secret_name: "one".into(),
            reason: None,
            command_context: None,
            grant_token: Some(token.into()),
        };
        assert!(!batch_is_fully_granted(&grants, &[request(), request()]));
    }

    #[test]
    fn capability_use_is_consumed_only_after_successful_approved_return() {
        let (_temp, mut state) = state_with_secret();
        let peer = PeerIdentity {
            pid: Some(9),
            principal: 42,
        };
        let token = match enable_scoped_grant(
            &mut state,
            peer,
            "correct",
            "codex".into(),
            "missing".into(),
            30,
            2,
        ) {
            AgentResponse::GrantCreated { token, .. } => token,
            response => panic!("unexpected response: {response:?}"),
        };
        let request = AgentRequest {
            agent: "codex".into(),
            pid: None,
            secret_name: "missing".into(),
            reason: None,
            command_context: None,
            grant_token: Some(token),
        };
        assert!(matches!(
            handle_get_secret(&mut state, request, peer),
            AgentResponse::Error {
                code: ErrorCode::NotFound,
                ..
            }
        ));
        assert_eq!(state.grants[0].remaining_uses, 2);
    }
}
