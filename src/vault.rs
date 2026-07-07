use crate::crypto::{decrypt_json, encrypt_json, EncryptedBlob};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    pub records: Vec<SecretRecord>,
    pub audit: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub action: AuditAction,
    pub secret_name: Option<String>,
    pub actor: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub agent: String,
    pub pid: Option<u32>,
    pub secret_name: String,
    pub reason: Option<String>,
    pub command_context: Option<String>,
}

pub struct VaultStore {
    path: PathBuf,
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

    pub fn add_secret(&mut self, name: String, mut value: String) -> Result<()> {
        validate_name(&name)?;
        if self.records.iter().any(|record| record.name == name) {
            value.zeroize();
            return Err(anyhow!("secret '{name}' already exists"));
        }
        let now = Utc::now();
        self.records.push(SecretRecord {
            name: name.clone(),
            value,
            created_at: now,
            updated_at: now,
            metadata: serde_json::json!({}),
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
        let value = self
            .records
            .iter()
            .find(|record| record.name == name)
            .map(|record| record.value.clone())
            .ok_or_else(|| anyhow!("secret '{name}' not found"))?;
        self.audit(AuditAction::Get, Some(name.to_string()), actor, detail);
        Ok(value)
    }

    pub fn update_secret(&mut self, name: &str, mut value: String) -> Result<()> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.name == name)
            .ok_or_else(|| anyhow!("secret '{name}' not found"))?;
        record.value.zeroize();
        record.value = std::mem::take(&mut value);
        record.updated_at = Utc::now();
        value.zeroize();
        self.audit(
            AuditAction::Update,
            Some(name.to_string()),
            "user",
            Some("secret updated".into()),
        );
        Ok(())
    }

    pub fn remove_secret(&mut self, name: &str) -> Result<()> {
        let before = self.records.len();
        self.records.retain(|record| record.name != name);
        if self.records.len() == before {
            return Err(anyhow!("secret '{name}' not found"));
        }
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

    pub fn audit(
        &mut self,
        action: AuditAction,
        secret_name: Option<String>,
        actor: &str,
        detail: Option<String>,
    ) {
        self.audit.push(AuditEvent {
            at: Utc::now(),
            action,
            secret_name,
            actor: actor.to_string(),
            detail,
        });
    }
}

impl VaultStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn init(&self, passphrase: &str) -> Result<()> {
        if self.exists() {
            return Err(anyhow!("vault already exists at {}", self.path.display()));
        }
        self.save(&Vault::new(), passphrase)
    }

    pub fn load(&self, passphrase: &str) -> Result<Vault> {
        let bytes =
            fs::read(&self.path).with_context(|| format!("read vault {}", self.path.display()))?;
        let blob: EncryptedBlob =
            serde_json::from_slice(&bytes).context("vault file is not valid encrypted json")?;
        decrypt_json(&blob, passphrase)
    }

    pub fn save(&self, vault: &Vault, passphrase: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create vault directory {}", parent.display()))?;
        }
        let blob = encrypt_json(vault, passphrase)?;
        let bytes = serde_json::to_vec_pretty(&blob).context("serialize encrypted vault")?;
        write_private(&self.path, &bytes)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("write vault temp file {}", tmp.display()))?;
    file.write_all(bytes).context("write encrypted vault")?;
    file.sync_all().context("sync encrypted vault")?;
    fs::rename(&tmp, path).context("replace encrypted vault")?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("write vault {}", path.display()))
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("secret name cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_are_unique() {
        let mut vault = Vault::new();
        vault.add_secret("thing".into(), "one".into()).unwrap();
        assert!(vault.add_secret("thing".into(), "two".into()).is_err());
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
}
