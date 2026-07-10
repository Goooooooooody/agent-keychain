pub use crate::crypto::KdfSettings;
use crate::crypto::{
    decrypt_json, encrypt_json, encrypt_json_with_kdf, EncryptedBlob, UnlockedCipher,
};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_LIVE_AUDIT_EVENTS: usize = 1_000;
const AUDIT_ROTATION_BATCH: usize = 250;
const VAULT_FORMAT_VERSION: u8 = 1;
const AUDIT_ARCHIVE_VERSION: u8 = 2;
const BACKUP_FORMAT_VERSION: u8 = 1;

fn vault_format_version() -> u8 {
    VAULT_FORMAT_VERSION
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default = "vault_format_version")]
    pub format_version: u8,
    #[serde(default)]
    pub revision: u64,
    pub records: Vec<SecretRecord>,
    pub audit: Vec<AuditEvent>,
    /// Authenticated by the encrypted vault and advanced for every audit event.
    #[serde(default)]
    pub audit_head: Option<String>,
    #[serde(default)]
    pub audit_count: u64,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            format_version: VAULT_FORMAT_VERSION,
            revision: 0,
            records: Vec::new(),
            audit: Vec::new(),
            audit_head: None,
            audit_count: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub metadata: SecretMetadata,
}

fn metadata_version() -> u8 {
    1
}

/// Versioned, non-secret policy and lifecycle information. `allowed_clients` contains
/// self-reported labels only; it is not executable identity verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    #[serde(default = "metadata_version")]
    pub version: u8,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rotate_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub one_time: bool,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

impl Default for SecretMetadata {
    fn default() -> Self {
        Self {
            version: metadata_version(),
            tags: Vec::new(),
            expires_at: None,
            rotate_after: None,
            one_time: false,
            allowed_clients: Vec::new(),
            notes: None,
            url: None,
        }
    }
}

impl Drop for SecretRecord {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Init,
    Add,
    Update,
    Get,
    Remove,
    AgentRequest,
    AgentApprove,
    AgentDeny,
    AgentError,
    Rekey,
    Backup,
    Restore,
    AuditExport,
    AuditPrune,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub action: AuditAction,
    pub secret_name: Option<String>,
    pub actor: String,
    pub detail: Option<String>,
    /// OS-verified IPC peer PID when available; never taken from request JSON.
    #[serde(default)]
    pub peer_pid: Option<u32>,
    #[serde(default)]
    pub predecessor_digest: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub agent: String,
    pub pid: Option<u32>,
    pub secret_name: String,
    pub reason: Option<String>,
    pub command_context: Option<String>,
    /// An unguessable daemon-session capability. Never written to the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_token: Option<String>,
}

pub struct VaultStore {
    path: PathBuf,
}

/// Owns the decrypted vault and derived encryption key for one daemon unlock lifetime.
/// The contained records and key are zeroized by their respective Drop implementations.
pub struct VaultSession {
    store: VaultStore,
    vault: Vault,
    cipher: UnlockedCipher,
    generation: FileGeneration,
    poisoned: bool,
    #[cfg(test)]
    fail_next_persist: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileGeneration {
    len: u64,
    modified_nanos: u128,
}

#[derive(Serialize, Deserialize)]
struct AuditArchive {
    version: u8,
    vault_revision: u64,
    events: Vec<AuditEvent>,
}

#[derive(Serialize, Deserialize)]
struct BackupBundle {
    version: u8,
    created_at: DateTime<Utc>,
    vault: Vault,
    archived_audit: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub since: Option<DateTime<Utc>>,
    pub actor: Option<String>,
    pub secret: Option<String>,
    pub action: Option<AuditAction>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditExport {
    pub version: u8,
    pub exported_at: DateTime<Utc>,
    pub events: Vec<AuditEvent>,
}

impl Vault {
    pub fn new() -> Self {
        let mut vault = Self::default();
        vault.audit(
            AuditAction::Init,
            None,
            "user",
            Some("vault initialized".into()),
        );
        vault
    }

    pub fn add_secret(&mut self, name: String, value: String) -> Result<()> {
        self.add_secret_with_metadata(name, value, SecretMetadata::default())
    }

    pub fn add_secret_with_metadata(
        &mut self,
        name: String,
        value: String,
        mut metadata: SecretMetadata,
    ) -> Result<()> {
        let mut value = Zeroizing::new(value);
        validate_name(&name)?;
        validate_metadata(&mut metadata)?;
        if self.records.iter().any(|record| record.name == name) {
            return Err(anyhow!("secret '{name}' already exists"));
        }
        let now = Utc::now();
        self.records.push(SecretRecord {
            name: name.clone(),
            value: std::mem::take(&mut *value),
            created_at: now,
            updated_at: now,
            metadata,
        });
        self.audit(AuditAction::Add, Some(name), "user", None);
        Ok(())
    }

    pub fn get_secret(
        &mut self,
        name: &str,
        actor: &str,
        detail: Option<String>,
    ) -> Result<String> {
        self.get_secret_for_peer(name, actor, detail, None)
    }

    pub fn get_secret_for_peer(
        &mut self,
        name: &str,
        actor: &str,
        detail: Option<String>,
        peer_pid: Option<u32>,
    ) -> Result<String> {
        self.get_secret_for_peer_action(name, actor, detail, peer_pid, AuditAction::Get)
    }

    pub fn get_secret_for_peer_action(
        &mut self,
        name: &str,
        actor: &str,
        detail: Option<String>,
        peer_pid: Option<u32>,
        action: AuditAction,
    ) -> Result<String> {
        let index = self
            .records
            .iter()
            .position(|record| record.name == name)
            .ok_or_else(|| anyhow!("secret '{name}' not found"))?;
        let metadata = &self.records[index].metadata;
        if metadata
            .expires_at
            .is_some_and(|expiry| expiry <= Utc::now())
        {
            return Err(anyhow!("secret '{name}' expired"));
        }
        if actor != "user"
            && !metadata.allowed_clients.is_empty()
            && !metadata
                .allowed_clients
                .iter()
                .any(|client| client == actor)
        {
            return Err(anyhow!(
                "client label '{actor}' is not allowed for secret '{name}'"
            ));
        }
        let value = self.records[index].value.clone();
        let one_time = metadata.one_time;
        if one_time {
            let mut consumed = self.records.remove(index);
            consumed.value.zeroize();
        }
        self.audit_with_peer(action, Some(name.to_string()), actor, detail, peer_pid);
        Ok(value)
    }

    pub fn update_secret(&mut self, name: &str, value: String) -> Result<()> {
        let mut value = Zeroizing::new(value);
        let record = self
            .records
            .iter_mut()
            .find(|record| record.name == name)
            .ok_or_else(|| anyhow!("secret '{name}' not found"))?;
        record.value.zeroize();
        record.value = std::mem::take(&mut *value);
        record.updated_at = Utc::now();
        self.audit(
            AuditAction::Update,
            Some(name.to_string()),
            "user",
            Some("secret updated".into()),
        );
        Ok(())
    }

    pub fn remove_secret(&mut self, name: &str) -> Result<()> {
        let index = self
            .records
            .iter()
            .position(|record| record.name == name)
            .ok_or_else(|| anyhow!("secret '{name}' not found"))?;
        let mut removed = self.records.remove(index);
        removed.value.zeroize();
        self.audit(AuditAction::Remove, Some(name.to_string()), "user", None);
        Ok(())
    }

    pub fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .records
            .iter()
            .map(|record| record.name.clone())
            .collect();
        names.sort();
        names
    }

    pub fn list_records(&self) -> Vec<&SecretRecord> {
        let mut records: Vec<_> = self.records.iter().collect();
        records.sort_by(|a, b| a.name.cmp(&b.name));
        records
    }

    pub fn audit(
        &mut self,
        action: AuditAction,
        secret_name: Option<String>,
        actor: &str,
        detail: Option<String>,
    ) {
        self.audit_with_peer(action, secret_name, actor, detail, None);
    }

    pub fn audit_with_peer(
        &mut self,
        action: AuditAction,
        secret_name: Option<String>,
        actor: &str,
        detail: Option<String>,
        peer_pid: Option<u32>,
    ) {
        let mut event = AuditEvent {
            at: Utc::now(),
            action,
            secret_name,
            actor: actor.to_string(),
            detail,
            peer_pid,
            predecessor_digest: self.audit_head.clone(),
            digest: None,
        };
        let digest = audit_event_digest(&event);
        event.digest = Some(digest.clone());
        self.audit_head = Some(digest);
        self.audit_count = self.audit_count.saturating_add(1);
        self.audit.push(event);
    }
}

fn audit_event_digest(event: &AuditEvent) -> String {
    let mut canonical = event.clone();
    canonical.digest = None;
    let bytes = serde_json::to_vec(&canonical).expect("audit event serialization is infallible");
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_audit_chain(vault: &Vault, archived: &[AuditEvent]) -> Result<()> {
    let mut predecessor: Option<String> = None;
    let mut count = 0u64;
    let mut saw_legacy = false;
    for event in archived.iter().chain(&vault.audit) {
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("audit count overflow"))?;
        match (&event.predecessor_digest, &event.digest) {
            (None, None) => {
                // Version-1 archives are authenticated individually but were not chained. They
                // remain readable only as a legacy prefix; `akc rekey` rewrites them into the
                // current chain format.
                saw_legacy = true;
                predecessor = Some(audit_event_digest(event));
            }
            (actual_predecessor, Some(actual_digest)) => {
                if actual_predecessor != &predecessor {
                    return Err(anyhow!("audit chain predecessor mismatch at event {count}"));
                }
                let expected = audit_event_digest(event);
                if actual_digest != &expected {
                    return Err(anyhow!("audit chain digest mismatch at event {count}"));
                }
                predecessor = Some(actual_digest.clone());
            }
            _ => return Err(anyhow!("incomplete audit chain metadata at event {count}")),
        }
    }
    if !saw_legacy && (vault.audit_count != count || vault.audit_head != predecessor) {
        return Err(anyhow!(
            "audit chain count/head mismatch; history may be missing or reordered"
        ));
    }
    Ok(())
}

impl VaultStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists() || self.backup_path().exists()
    }

    pub fn storage_metrics(&self) -> (u64, u64) {
        let vault_bytes = fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        let archive_count = fs::read_dir(self.audit_archive_dir())
            .map(|entries| entries.filter_map(Result::ok).count() as u64)
            .unwrap_or(0);
        (vault_bytes, archive_count)
    }

    pub fn init(&self, passphrase: &str) -> Result<()> {
        let lock = self.lock_exclusive()?;
        if self.exists() {
            return Err(anyhow!("vault already exists at {}", self.path.display()));
        }
        let mut vault = Vault::new();
        self.persist_locked(&mut vault, passphrase, None)?;
        drop(lock);
        Ok(())
    }

    pub fn load(&self, passphrase: &str) -> Result<Vault> {
        let lock = self.lock_exclusive()?;
        let vault = self.load_locked(passphrase)?;
        let archived = self.load_archived_audit(passphrase)?;
        validate_audit_chain(&vault, &archived)?;
        drop(lock);
        Ok(vault)
    }

    pub fn unlock(&self, passphrase: &str) -> Result<VaultSession> {
        let lock = self.lock_exclusive()?;
        let bytes = self.read_primary_or_backup()?;
        let blob: EncryptedBlob =
            serde_json::from_slice(&bytes).context("vault file is not valid encrypted json")?;
        let cipher = UnlockedCipher::unlock(&blob, passphrase)?;
        let vault: Vault = cipher.decrypt_json(&blob)?;
        validate_vault_format(&vault)?;
        let archived = self.load_archived_audit_with_cipher(passphrase, Some(&cipher))?;
        validate_audit_chain(&vault, &archived)?;
        let generation = file_generation(&self.path)?;
        drop(lock);
        Ok(VaultSession {
            store: Self::new(&self.path),
            vault,
            cipher,
            generation,
            poisoned: false,
            #[cfg(test)]
            fail_next_persist: false,
        })
    }

    fn read_primary_or_backup(&self) -> Result<Vec<u8>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(bytes),
            Err(primary_error) if !self.path.exists() && self.backup_path().exists() => {
                fs::read(self.backup_path()).with_context(|| {
                    format!("read vault backup after primary read failed: {primary_error}")
                })
            }
            Err(error) => Err(error).with_context(|| format!("read vault {}", self.path.display())),
        }
    }

    fn load_locked(&self, passphrase: &str) -> Result<Vault> {
        let bytes = self.read_primary_or_backup()?;
        let blob: EncryptedBlob =
            serde_json::from_slice(&bytes).context("vault file is not valid encrypted json")?;
        let vault: Vault = decrypt_json(&blob, passphrase)?;
        validate_vault_format(&vault)?;
        Ok(vault)
    }

    pub fn save(&self, vault: &mut Vault, passphrase: &str) -> Result<()> {
        let lock = self.lock_exclusive()?;
        let current = self.load_locked(passphrase)?;
        let archived = self.load_archived_audit(passphrase)?;
        validate_audit_chain(&current, &archived)?;
        if current.revision != vault.revision {
            return Err(anyhow!(
                "vault revision conflict: loaded revision {}, current revision {}",
                vault.revision,
                current.revision
            ));
        }
        self.persist_locked(vault, passphrase, Some(current.revision))?;
        drop(lock);
        Ok(())
    }

    pub fn transaction<T: Zeroize>(
        &self,
        passphrase: &str,
        mutate: impl FnOnce(&mut Vault) -> Result<T>,
    ) -> Result<T> {
        let lock = self.lock_exclusive()?;
        let mut vault = self.load_locked(passphrase)?;
        let archived = self.load_archived_audit(passphrase)?;
        validate_audit_chain(&vault, &archived)?;
        let expected_revision = vault.revision;
        let mut result = mutate(&mut vault)?;
        if let Err(error) = self.persist_locked(&mut vault, passphrase, Some(expected_revision)) {
            result.zeroize();
            return Err(error);
        }
        drop(lock);
        Ok(result)
    }

    pub fn backup_verified(&self, passphrase: &str, destination: &Path) -> Result<()> {
        self.ensure_external_destination(destination)?;
        let lock = self.lock_exclusive()?;
        let mut vault = self.load_locked(passphrase)?;
        let archived_audit = self.load_archived_audit(passphrase)?;
        validate_audit_chain(&vault, &archived_audit)?;
        vault.audit(
            AuditAction::Backup,
            None,
            "user",
            Some("verified encrypted backup".into()),
        );
        let mut bundle = BackupBundle {
            version: BACKUP_FORMAT_VERSION,
            created_at: Utc::now(),
            vault,
            archived_audit,
        };
        let blob = encrypt_json(&bundle, passphrase)?;
        let bytes = serde_json::to_vec_pretty(&blob).context("serialize encrypted backup")?;
        write_private_atomic(destination, &bytes)?;
        let check_blob: EncryptedBlob = serde_json::from_slice(&fs::read(destination)?)?;
        let check: BackupBundle = decrypt_json(&check_blob, passphrase)
            .context("verify encrypted backup after writing")?;
        validate_backup(&check)?;
        let expected_revision = bundle.vault.revision;
        self.persist_locked(&mut bundle.vault, passphrase, Some(expected_revision))?;
        drop(lock);
        Ok(())
    }

    pub fn restore_verified(
        &self,
        source: &Path,
        backup_passphrase: &str,
        destination_passphrase: &str,
    ) -> Result<()> {
        let source_blob: EncryptedBlob = serde_json::from_slice(&fs::read(source)?)
            .context("backup is not valid encrypted json")?;
        let mut bundle: BackupBundle = decrypt_json(&source_blob, backup_passphrase)
            .context("backup integrity verification failed")?;
        validate_backup(&bundle)?;
        let lock = self.lock_exclusive()?;
        let rollback = fs::read(&self.path).ok();
        let archive_dir = self.audit_archive_dir();
        let archive_rollback = self.path.with_extension("restore-audit.bak");
        if archive_rollback.is_dir() {
            fs::remove_dir_all(&archive_rollback)?;
        }
        if archive_dir.is_dir() {
            fs::rename(&archive_dir, &archive_rollback)
                .context("stage current audit archives for restore rollback")?;
        }
        bundle.archived_audit.append(&mut bundle.vault.audit);
        bundle.vault.audit = std::mem::take(&mut bundle.archived_audit);
        rechain_audit(&mut bundle.vault)?;
        bundle.vault.audit(
            AuditAction::Restore,
            None,
            "user",
            Some("verified backup restored".into()),
        );
        if let Err(error) = self.persist_locked(&mut bundle.vault, destination_passphrase, None) {
            if let Some(bytes) = rollback {
                let _ = write_private_atomic(&self.path, &bytes);
            }
            if archive_dir.is_dir() {
                let _ = fs::remove_dir_all(&archive_dir);
            }
            if archive_rollback.is_dir() {
                let _ = fs::rename(&archive_rollback, &archive_dir);
            }
            return Err(error).context("restore failed; prior vault generation rolled back");
        }
        drop(lock);
        Ok(())
    }

    pub fn rekey(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
        settings: KdfSettings,
    ) -> Result<()> {
        let lock = self.lock_exclusive()?;
        let mut vault = self.load_locked(old_passphrase)?;
        let mut archived = self.load_archived_audit(old_passphrase)?;
        validate_audit_chain(&vault, &archived)?;
        let old_primary = fs::read(&self.path).context("read vault before rekey")?;
        archived.append(&mut vault.audit);
        vault.audit = archived;
        rechain_audit(&mut vault)?;
        vault.audit(
            AuditAction::Rekey,
            None,
            "user",
            Some("encryption key and KDF rotated".into()),
        );
        vault.revision = vault
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("vault revision exhausted"))?;
        let staged_archives = unique_path(
            self.path.parent().unwrap_or_else(|| Path::new(".")),
            ".rekey-audit-staging",
        );
        if vault.audit.len() > MAX_LIVE_AUDIT_EVENTS {
            let overflow_count = vault.audit.len() - MAX_LIVE_AUDIT_EVENTS;
            let archive = AuditArchive {
                version: AUDIT_ARCHIVE_VERSION,
                vault_revision: vault.revision,
                events: vault.audit.drain(..overflow_count).collect(),
            };
            fs::create_dir_all(&staged_archives)?;
            secure_private_directory(&staged_archives)?;
            let archive_blob = encrypt_json_with_kdf(&archive, new_passphrase, settings)?;
            write_private_atomic(
                &staged_archives.join(format!("audit-{:020}.json", vault.revision)),
                &serde_json::to_vec_pretty(&archive_blob)?,
            )?;
        }
        let blob = encrypt_json_with_kdf(&vault, new_passphrase, settings)?;
        let bytes = serde_json::to_vec_pretty(&blob)?;
        let verified: Vault =
            decrypt_json(&blob, new_passphrase).context("verify staged rekeyed vault")?;
        validate_vault_format(&verified)?;
        let archive_dir = self.audit_archive_dir();
        let old_archive_backup = self.path.with_extension("rekey-audit.bak");
        if old_archive_backup.is_dir() {
            fs::remove_dir_all(&old_archive_backup)?;
        }
        // Finish every independently fallible preparation before changing the live generation.
        write_private_atomic(&self.backup_path(), &old_primary)?;
        if archive_dir.is_dir() {
            fs::rename(&archive_dir, &old_archive_backup)
                .context("retain old-key audit archives for rollback")?;
        }
        if staged_archives.is_dir() {
            if let Err(error) = fs::rename(&staged_archives, &archive_dir) {
                if old_archive_backup.is_dir() {
                    let _ = fs::rename(&old_archive_backup, &archive_dir);
                }
                return Err(error)
                    .context("install rekeyed audit archives; old generation restored");
            }
        }
        if let Err(error) = write_private_atomic(&self.path, &bytes) {
            let primary_rollback = write_private_atomic(&self.path, &old_primary);
            if archive_dir.is_dir() {
                let _ = fs::remove_dir_all(&archive_dir);
            }
            let archive_rollback = if old_archive_backup.is_dir() {
                fs::rename(&old_archive_backup, &archive_dir).map_err(anyhow::Error::from)
            } else {
                Ok(())
            };
            if primary_rollback.is_err() || archive_rollback.is_err() {
                return Err(error)
                    .context("rekey commit and rollback failed; recovery backup retained");
            }
            return Err(error).context("rekey commit failed; old generation restored");
        }
        drop(lock);
        Ok(())
    }

    pub fn audit_events(&self, passphrase: &str, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let lock = self.lock_exclusive()?;
        let vault = self.load_locked(passphrase)?;
        let mut events = self.load_archived_audit(passphrase)?;
        validate_audit_chain(&vault, &events)?;
        events.extend(vault.audit);
        events.retain(|event| {
            filter.since.is_none_or(|since| event.at >= since)
                && filter
                    .actor
                    .as_ref()
                    .is_none_or(|actor| &event.actor == actor)
                && filter
                    .secret
                    .as_ref()
                    .is_none_or(|secret| event.secret_name.as_ref() == Some(secret))
                && filter
                    .action
                    .as_ref()
                    .is_none_or(|action| &event.action == action)
        });
        events.sort_by_key(|event| event.at);
        drop(lock);
        Ok(events)
    }

    pub fn export_audit(&self, passphrase: &str, destination: &Path) -> Result<usize> {
        self.ensure_external_destination(destination)?;
        let events = self.audit_events(passphrase, &AuditFilter::default())?;
        let export = AuditExport {
            version: 1,
            exported_at: Utc::now(),
            events,
        };
        let bytes = serde_json::to_vec_pretty(&export)?;
        write_private_atomic(destination, &bytes)?;
        let verified: AuditExport = serde_json::from_slice(&fs::read(destination)?)?;
        if verified.version != 1 || verified.events.len() != export.events.len() {
            return Err(anyhow!("audit export verification failed"));
        }
        self.transaction(passphrase, |vault| {
            vault.audit(
                AuditAction::AuditExport,
                None,
                "user",
                Some(format!(
                    "verified export of {} events to {}",
                    export.events.len(),
                    destination.display()
                )),
            );
            Ok(())
        })?;
        Ok(export.events.len())
    }

    pub fn prune_archived_audit(&self, passphrase: &str, verified_export: &Path) -> Result<usize> {
        let export: AuditExport = serde_json::from_slice(&fs::read(verified_export)?)
            .context("verified export is not a valid audit export")?;
        if export.version != 1 {
            return Err(anyhow!("unsupported audit export version"));
        }
        let lock = self.lock_exclusive()?;
        let archived = self.load_archived_audit(passphrase)?;
        let current = self.load_locked(passphrase)?;
        validate_audit_chain(&current, &archived)?;
        let covers_all = archived.iter().all(|event| export.events.contains(event));
        if !covers_all {
            return Err(anyhow!(
                "export does not contain every archived audit event"
            ));
        }
        let count = archived.len();
        let archive_dir = self.audit_archive_dir();
        let staged_dir = unique_path(
            archive_dir.parent().unwrap_or_else(|| Path::new(".")),
            ".audit-prune-rollback",
        );
        if archive_dir.is_dir() {
            fs::rename(&archive_dir, &staged_dir).context("stage audit archives for safe prune")?;
        }
        let mut vault = self.load_locked(passphrase)?;
        let expected_revision = vault.revision;
        // The verified export is now the checkpoint for the intentionally removed prefix.
        // Start a new authenticated live chain so subsequent reads do not mistake pruning for
        // undeclared deletion.
        rechain_audit(&mut vault)?;
        vault.audit(
            AuditAction::AuditPrune,
            None,
            "user",
            Some(format!(
                "pruned {count} archived events after verified export {}",
                verified_export.display()
            )),
        );
        if let Err(error) = self.persist_locked(&mut vault, passphrase, Some(expected_revision)) {
            if staged_dir.is_dir() {
                let _ = fs::rename(&staged_dir, &archive_dir);
            }
            return Err(error).context("audit prune checkpoint failed; archives restored");
        }
        if staged_dir.is_dir() {
            fs::remove_dir_all(&staged_dir).context("remove exported audit archives")?;
        }
        drop(lock);
        Ok(count)
    }

    fn load_archived_audit(&self, passphrase: &str) -> Result<Vec<AuditEvent>> {
        self.load_archived_audit_with_cipher(passphrase, None)
    }

    fn load_archived_audit_with_cipher(
        &self,
        passphrase: &str,
        cipher: Option<&UnlockedCipher>,
    ) -> Result<Vec<AuditEvent>> {
        let directory = self.audit_archive_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut paths: Vec<_> = fs::read_dir(&directory)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();
        paths.sort();
        let mut events = Vec::new();
        for path in paths {
            let blob: EncryptedBlob = serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("invalid audit archive {}", path.display()))?;
            let archive: AuditArchive =
                match cipher.and_then(|cipher| cipher.decrypt_json(&blob).ok()) {
                    Some(archive) => archive,
                    None => decrypt_json(&blob, passphrase)
                        .with_context(|| format!("verify audit archive {}", path.display()))?,
                };
            if archive.version != 1 && archive.version != AUDIT_ARCHIVE_VERSION {
                return Err(anyhow!("unsupported audit archive version"));
            }
            events.extend(archive.events);
        }
        Ok(events)
    }

    fn ensure_external_destination(&self, destination: &Path) -> Result<()> {
        let absolute = |path: &Path| -> Result<PathBuf> {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()?.join(path)
            };
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            Ok(parent
                .canonicalize()
                .unwrap_or_else(|_| parent.to_path_buf())
                .join(path.file_name().unwrap_or_default()))
        };
        let destination = absolute(destination)?;
        let vault = absolute(&self.path)?;
        let reserved = [
            vault.clone(),
            self.backup_path(),
            self.path.with_extension("lock"),
        ];
        if reserved
            .iter()
            .any(|path| absolute(path).is_ok_and(|path| path == destination))
        {
            return Err(anyhow!(
                "destination must not overwrite the vault, lock, or recovery backup"
            ));
        }
        Ok(())
    }

    fn persist_locked(
        &self,
        vault: &mut Vault,
        passphrase: &str,
        expected_revision: Option<u64>,
    ) -> Result<()> {
        if vault.format_version != VAULT_FORMAT_VERSION {
            return Err(anyhow!("cannot persist unsupported vault format"));
        }
        if let Some(expected) = expected_revision {
            if vault.revision != expected {
                return Err(anyhow!("vault revision changed during transaction"));
            }
        }
        let current_blob = if self.path.is_file() {
            Some(
                serde_json::from_slice::<EncryptedBlob>(&fs::read(&self.path)?)
                    .context("read current encrypted vault for cached persistence key")?,
            )
        } else {
            None
        };
        let cipher = current_blob
            .as_ref()
            .map(|blob| UnlockedCipher::unlock(blob, passphrase))
            .transpose()?;
        self.archive_audit_overflow(vault, passphrase, cipher.as_ref())?;
        vault.revision = vault
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("vault revision exhausted"))?;
        let blob = match cipher.as_ref() {
            Some(cipher) => cipher.encrypt_json(vault)?,
            None => encrypt_json(vault, passphrase)?,
        };
        let bytes = serde_json::to_vec_pretty(&blob).context("serialize encrypted vault")?;
        if self.path.is_file() {
            let old = fs::read(&self.path).context("read prior vault generation")?;
            serde_json::from_slice::<EncryptedBlob>(&old)
                .context("refuse to back up invalid prior vault generation")?;
            write_private_atomic(&self.backup_path(), &old)?;
        }
        write_private_atomic(&self.path, &bytes)
    }

    fn archive_audit_overflow(
        &self,
        vault: &mut Vault,
        passphrase: &str,
        cipher: Option<&UnlockedCipher>,
    ) -> Result<()> {
        if vault.audit.len() <= MAX_LIVE_AUDIT_EVENTS {
            return Ok(());
        }
        // Rotate a batch rather than one event per subsequent mutation. This bounds the live vault
        // while avoiding a second Argon2 derivation on every request after the first rotation.
        let overflow_count = vault.audit.len() - MAX_LIVE_AUDIT_EVENTS + AUDIT_ROTATION_BATCH;
        let events: Vec<_> = vault.audit.drain(..overflow_count).collect();
        let archive = AuditArchive {
            version: AUDIT_ARCHIVE_VERSION,
            vault_revision: vault.revision,
            events,
        };
        let blob = match cipher {
            Some(cipher) => cipher.encrypt_json(&archive)?,
            None => encrypt_json(&archive, passphrase)?,
        };
        let bytes =
            serde_json::to_vec_pretty(&blob).context("serialize encrypted audit archive")?;
        let directory = self.audit_archive_dir();
        fs::create_dir_all(&directory).context("create audit archive directory")?;
        secure_private_directory(&directory)?;
        let name = format!("audit-{:020}.json", vault.revision);
        let path = unique_path(&directory, &name);
        write_private_atomic(&path, &bytes)
            .with_context(|| format!("persist audit archive {}", path.display()))
    }

    fn lock_exclusive(&self) -> Result<File> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("create vault directory {}", parent.display()))?;
        let lock_path = self.path.with_extension("lock");
        let file = open_private_lock(&lock_path)?;
        file.lock_exclusive()
            .with_context(|| format!("lock vault {}", self.path.display()))?;
        Ok(file)
    }

    fn backup_path(&self) -> PathBuf {
        self.path.with_extension("bak")
    }

    fn audit_archive_dir(&self) -> PathBuf {
        self.path.with_extension("audit.d")
    }

    #[cfg(test)]
    fn audit_archive_count(&self) -> Result<usize> {
        Ok(fs::read_dir(self.audit_archive_dir())?.count())
    }
}

fn rechain_audit(vault: &mut Vault) -> Result<()> {
    vault.audit_head = None;
    vault.audit_count = 0;
    for event in &mut vault.audit {
        event.predecessor_digest = vault.audit_head.clone();
        event.digest = None;
        let digest = audit_event_digest(event);
        event.digest = Some(digest.clone());
        vault.audit_head = Some(digest);
        vault.audit_count = vault
            .audit_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("audit count overflow"))?;
    }
    Ok(())
}

impl VaultSession {
    pub fn revision(&self) -> u64 {
        self.vault.revision
    }

    pub fn transaction<T: Zeroize>(
        &mut self,
        mutate: impl FnOnce(&mut Vault) -> Result<T>,
    ) -> Result<T> {
        if self.poisoned {
            return Err(anyhow!(
                "vault session is poisoned; lock and unlock before retrying"
            ));
        }
        let lock = self.store.lock_exclusive()?;
        let current_generation = file_generation(&self.store.path)?;
        if current_generation != self.generation {
            return Err(anyhow!(
                "vault changed outside this daemon session; lock and unlock again before retrying"
            ));
        }
        let expected_revision = self.vault.revision;
        // Mutate an isolated zeroizing serialization clone. The live session is swapped only
        // after every encrypted artifact has been durably installed.
        let encoded = Zeroizing::new(serde_json::to_vec(&self.vault)?);
        let mut staged: Vault = serde_json::from_slice(&encoded)?;
        let mut result = mutate(&mut staged)?;
        if let Err(error) = self.persist_staged(&mut staged, expected_revision) {
            result.zeroize();
            return Err(error);
        }
        let generation = match file_generation(&self.store.path) {
            Ok(generation) => generation,
            Err(error) => {
                self.poisoned = true;
                result.zeroize();
                return Err(error)
                    .context("committed vault but failed to refresh generation; session poisoned");
            }
        };
        self.vault = staged;
        self.generation = generation;
        drop(lock);
        Ok(result)
    }

    fn persist_staged(&mut self, staged: &mut Vault, expected_revision: u64) -> Result<()> {
        if staged.revision != expected_revision {
            return Err(anyhow!("vault revision changed during session transaction"));
        }
        let installed_archive = self.stage_audit_overflow(staged)?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_persist) {
            if let Some(path) = installed_archive.as_ref() {
                fs::remove_file(path)?;
            }
            return Err(anyhow!("injected persistence failure"));
        }
        staged.revision = staged
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("vault revision exhausted"))?;
        let blob = self.cipher.encrypt_json(staged)?;
        let bytes = serde_json::to_vec_pretty(&blob).context("serialize encrypted vault")?;
        let persist = (|| -> Result<()> {
            if self.store.path.is_file() {
                let old = fs::read(&self.store.path).context("read prior vault generation")?;
                serde_json::from_slice::<EncryptedBlob>(&old)
                    .context("refuse to back up invalid prior vault generation")?;
                write_private_atomic(&self.store.backup_path(), &old)?;
            }
            write_private_atomic(&self.store.path, &bytes)
        })();
        if let Err(error) = persist {
            if let Some(path) = installed_archive {
                if fs::remove_file(&path).is_err() {
                    self.poisoned = true;
                    return Err(error).context(
                        "vault persistence failed and audit rollback failed; session poisoned",
                    );
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn stage_audit_overflow(&self, staged: &mut Vault) -> Result<Option<PathBuf>> {
        if staged.audit.len() <= MAX_LIVE_AUDIT_EVENTS {
            return Ok(None);
        }
        let overflow_count = staged.audit.len() - MAX_LIVE_AUDIT_EVENTS + AUDIT_ROTATION_BATCH;
        let events: Vec<_> = staged.audit.drain(..overflow_count).collect();
        let archive = AuditArchive {
            version: AUDIT_ARCHIVE_VERSION,
            vault_revision: staged.revision,
            events,
        };
        let blob = self.cipher.encrypt_json(&archive)?;
        let bytes =
            serde_json::to_vec_pretty(&blob).context("serialize encrypted audit archive")?;
        let directory = self.store.audit_archive_dir();
        fs::create_dir_all(&directory).context("create audit archive directory")?;
        secure_private_directory(&directory)?;
        let name = format!("audit-{:020}.json", staged.revision);
        let path = unique_path(&directory, &name);
        write_private_atomic(&path, &bytes)
            .with_context(|| format!("persist audit archive {}", path.display()))?;
        Ok(Some(path))
    }

    #[cfg(test)]
    fn inject_persist_failure(&mut self) {
        self.fail_next_persist = true;
    }
}

fn validate_vault_format(vault: &Vault) -> Result<()> {
    if vault.format_version != VAULT_FORMAT_VERSION {
        return Err(anyhow!(
            "unsupported decrypted vault format version {}",
            vault.format_version
        ));
    }
    Ok(())
}

fn validate_backup(bundle: &BackupBundle) -> Result<()> {
    if bundle.version != BACKUP_FORMAT_VERSION {
        return Err(anyhow!("unsupported backup version {}", bundle.version));
    }
    validate_vault_format(&bundle.vault)
}

fn file_generation(path: &Path) -> Result<FileGeneration> {
    let metadata = fs::metadata(path).with_context(|| format!("stat vault {}", path.display()))?;
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    Ok(FileGeneration {
        len: metadata.len(),
        modified_nanos,
    })
}

fn unique_path(directory: &Path, base: &str) -> PathBuf {
    let mut random = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut random);
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    directory.join(format!("{base}.{suffix}"))
}

#[cfg(unix)]
fn secure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("secure audit archive directory {}", path.display()))
}

#[cfg(not(unix))]
fn secure_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn open_private_lock(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open vault lock {}", path.display()))
}

#[cfg(not(unix))]
fn open_private_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open vault lock {}", path.display()))
}

#[cfg(unix)]
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = unique_path(
        parent,
        &format!(
            ".{}.tmp",
            path.file_name().unwrap_or_default().to_string_lossy()
        ),
    );
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("write vault temp file {}", tmp.display()))?;
    file.write_all(bytes).context("write encrypted vault")?;
    file.sync_all().context("sync encrypted vault")?;
    fs::rename(&tmp, path).context("replace encrypted vault")?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync vault directory")?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = unique_path(parent, ".vault.tmp");
    let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if path.exists() {
        fs::remove_file(path)
            .context("remove previous vault on platform without atomic replace")?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replace vault {}", path.display()))
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("secret name cannot be empty"));
    }
    Ok(())
}

fn validate_metadata(metadata: &mut SecretMetadata) -> Result<()> {
    if metadata.version != metadata_version() {
        return Err(anyhow!(
            "unsupported secret metadata version {}",
            metadata.version
        ));
    }
    for value in metadata.tags.iter().chain(metadata.allowed_clients.iter()) {
        if value.trim().is_empty()
            || value.chars().count() > 128
            || value.chars().any(char::is_control)
        {
            return Err(anyhow!(
                "metadata tags and client labels must be 1..=128 printable characters"
            ));
        }
    }
    if metadata
        .notes
        .as_ref()
        .is_some_and(|v| v.chars().count() > 4096)
        || metadata
            .url
            .as_ref()
            .is_some_and(|v| v.chars().count() > 2048)
    {
        return Err(anyhow!("secret metadata is too long"));
    }
    metadata.tags.sort();
    metadata.tags.dedup();
    metadata.allowed_clients.sort();
    metadata.allowed_clients.dedup();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn secret_names_are_unique() {
        let mut vault = Vault::new();
        vault.add_secret("thing".into(), "one".into()).unwrap();
        assert!(vault.add_secret("thing".into(), "two".into()).is_err());
    }

    #[test]
    fn metadata_is_typed_backward_compatible_and_enforced() {
        let legacy: SecretRecord = serde_json::from_str(
            r#"{"name":"legacy","value":"v","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","metadata":{}}"#,
        )
        .unwrap();
        assert_eq!(legacy.metadata.version, 1);

        let mut vault = Vault::new();
        vault
            .add_secret_with_metadata(
                "once".into(),
                "value".into(),
                SecretMetadata {
                    one_time: true,
                    allowed_clients: vec!["codex".into()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(vault
            .get_secret("once", "other-agent", None)
            .unwrap_err()
            .to_string()
            .contains("not allowed"));
        assert_eq!(vault.get_secret("once", "codex", None).unwrap(), "value");
        assert!(vault.get_secret("once", "codex", None).is_err());
    }

    #[test]
    fn expired_secrets_are_never_returned() {
        let mut vault = Vault::new();
        vault
            .add_secret_with_metadata(
                "expired".into(),
                "value".into(),
                SecretMetadata {
                    expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(vault
            .get_secret("expired", "user", None)
            .unwrap_err()
            .to_string()
            .contains("expired"));
    }

    #[test]
    fn verified_backup_restore_and_rekey_round_trip() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("vault.db");
        let backup = temp.path().join("export.akc-backup");
        let store = VaultStore::new(&path);
        store.init("old-passphrase").unwrap();
        store
            .transaction("old-passphrase", |vault| {
                vault.add_secret("one".into(), "value".into())
            })
            .unwrap();
        store.backup_verified("old-passphrase", &backup).unwrap();
        store
            .rekey("old-passphrase", "new-passphrase", KdfSettings::default())
            .unwrap();
        assert!(store.load("old-passphrase").is_err());
        assert_eq!(
            store.load("new-passphrase").unwrap().list_names(),
            vec!["one"]
        );
        store
            .transaction("new-passphrase", |vault| vault.remove_secret("one"))
            .unwrap();
        store
            .restore_verified(&backup, "old-passphrase", "new-passphrase")
            .unwrap();
        assert_eq!(
            store.load("new-passphrase").unwrap().list_names(),
            vec!["one"]
        );
    }

    #[test]
    fn audit_events_are_recorded() {
        let mut vault = Vault::new();
        vault.add_secret("thing".into(), "one".into()).unwrap();
        let _ = vault.get_secret("thing", "user", None).unwrap();
        vault.remove_secret("thing").unwrap();
        assert!(vault
            .audit
            .iter()
            .any(|event| event.action == AuditAction::Add));
        assert!(vault
            .audit
            .iter()
            .any(|event| event.action == AuditAction::Get));
        assert!(vault
            .audit
            .iter()
            .any(|event| event.action == AuditAction::Remove));
    }

    #[test]
    fn concurrent_transactions_do_not_lose_updates() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = Arc::new(VaultStore::new(temp.path().join("vault.db")));
        store.init("passphrase").unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .transaction("passphrase", |vault| {
                        vault.add_secret(format!("secret-{index}"), format!("value-{index}"))
                    })
                    .unwrap();
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().unwrap();
        }
        let vault = store.load("passphrase").unwrap();
        assert_eq!(vault.list_names(), vec!["secret-0", "secret-1"]);
    }

    #[test]
    fn stale_generation_is_rejected_instead_of_overwriting_newer_data() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        let mut stale = store.load("passphrase").unwrap();
        store
            .transaction("passphrase", |vault| {
                vault.add_secret("new".into(), "value".into())
            })
            .unwrap();
        assert!(store.save(&mut stale, "passphrase").is_err());
        assert_eq!(store.load("passphrase").unwrap().list_names(), vec!["new"]);
    }

    #[test]
    fn unrelated_interrupted_temp_file_does_not_replace_valid_vault() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("vault.db");
        let store = VaultStore::new(&path);
        store.init("passphrase").unwrap();
        fs::write(temp.path().join(".vault.db.interrupted.tmp"), b"partial").unwrap();
        assert!(store.load("passphrase").is_ok());
    }

    #[test]
    fn missing_primary_can_recover_the_validated_prior_generation() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("vault.db");
        let store = VaultStore::new(&path);
        store.init("passphrase").unwrap();
        store
            .transaction("passphrase", |vault| {
                vault.add_secret("first".into(), "value".into())
            })
            .unwrap();
        assert!(store.backup_path().exists());
        fs::remove_file(&path).unwrap();
        let recovered = store.load("passphrase").unwrap();
        assert!(recovered.revision > 0);
    }

    #[test]
    fn legacy_decrypted_vaults_default_to_format_one_and_revision_zero() {
        let vault: Vault = serde_json::from_str(r#"{"records":[],"audit":[]}"#).unwrap();
        assert_eq!(vault.format_version, VAULT_FORMAT_VERSION);
        assert_eq!(vault.revision, 0);
    }

    #[test]
    fn audit_overflow_is_archived_without_growing_the_live_vault_forever() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        store
            .transaction("passphrase", |vault| {
                for index in 0..(MAX_LIVE_AUDIT_EVENTS + 1) {
                    vault.audit(
                        AuditAction::Get,
                        Some(format!("secret-{index}")),
                        "test",
                        None,
                    );
                }
                Ok(())
            })
            .unwrap();
        let vault = store.load("passphrase").unwrap();
        assert!(vault.audit.len() <= MAX_LIVE_AUDIT_EVENTS);
        assert_eq!(store.audit_archive_count().unwrap(), 1);
    }

    #[test]
    fn audit_prune_requires_a_covering_verified_export_and_checkpoints() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        let export = temp.path().join("audit.json");
        store.init("passphrase").unwrap();
        store
            .transaction("passphrase", |vault| {
                for index in 0..=MAX_LIVE_AUDIT_EVENTS {
                    vault.audit(
                        AuditAction::Get,
                        Some(format!("secret-{index}")),
                        "test",
                        None,
                    );
                }
                Ok(())
            })
            .unwrap();
        store.export_audit("passphrase", &export).unwrap();
        assert!(store.prune_archived_audit("passphrase", &export).unwrap() > 0);
        assert_eq!(store.audit_archive_count().unwrap_or(0), 0);
        assert!(store
            .load("passphrase")
            .unwrap()
            .audit
            .iter()
            .any(|event| event.action == AuditAction::AuditPrune));
    }

    #[test]
    fn exports_cannot_overwrite_vault_or_recovery_files() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("vault.db");
        let store = VaultStore::new(&path);
        store.init("passphrase").unwrap();
        assert!(store.export_audit("passphrase", &path).is_err());
        assert!(store
            .backup_verified("passphrase", &path.with_extension("bak"))
            .is_err());
        assert!(store.load("passphrase").is_ok());
    }

    #[test]
    fn unlocked_session_persists_repeated_mutations_without_reloading() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        let mut session = store.unlock("passphrase").unwrap();
        session
            .transaction(|vault| vault.add_secret("one".into(), "value".into()))
            .unwrap();
        session
            .transaction(|vault| vault.add_secret("two".into(), "value".into()))
            .unwrap();
        assert_eq!(
            store.load("passphrase").unwrap().list_names(),
            vec!["one", "two"]
        );
    }

    #[test]
    fn unlocked_session_refuses_to_overwrite_an_external_generation() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        let mut session = store.unlock("passphrase").unwrap();
        store
            .transaction("passphrase", |vault| {
                vault.add_secret("external".into(), "value".into())
            })
            .unwrap();
        assert!(session
            .transaction(|vault| vault.add_secret("stale".into(), "value".into()))
            .unwrap_err()
            .to_string()
            .contains("changed outside"));
    }

    #[test]
    fn failed_cached_transaction_does_not_leak_mutation_or_drained_audit() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        let mut session = store.unlock("passphrase").unwrap();
        let before_revision = session.revision();
        session.inject_persist_failure();
        let failure = session.transaction(|vault| {
            vault.add_secret("must-not-leak".into(), "secret".into())?;
            for _ in 0..=MAX_LIVE_AUDIT_EVENTS {
                vault.audit(AuditAction::Get, None, "test", None);
            }
            Ok(())
        });
        assert!(failure.is_err());
        assert_eq!(session.revision(), before_revision);
        assert!(!store
            .load("passphrase")
            .unwrap()
            .list_names()
            .contains(&"must-not-leak".into()));
        assert_eq!(store.audit_archive_count().unwrap_or(0), 0);
    }

    #[test]
    fn audit_chain_detects_archive_deletion_before_unlock() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = VaultStore::new(temp.path().join("vault.db"));
        store.init("passphrase").unwrap();
        let mut session = store.unlock("passphrase").unwrap();
        session
            .transaction(|vault| {
                for _ in 0..=MAX_LIVE_AUDIT_EVENTS {
                    vault.audit(AuditAction::Get, None, "test", None);
                }
                Ok(())
            })
            .unwrap();
        let archive = fs::read_dir(store.audit_archive_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::remove_file(archive).unwrap();
        assert!(store.unlock("passphrase").is_err());
    }
}
