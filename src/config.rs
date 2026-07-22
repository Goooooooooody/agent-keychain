use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

fn default_idle_lock_seconds() -> u64 {
    15 * 60
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Legacy setting retained only so older configuration files still parse.
    /// Persistent auto-approval is intentionally never effective.
    #[serde(default)]
    pub auto_approve_agent_requests: bool,
    /// Drop the daemon's decrypted vault and derived key after this much secret-access inactivity.
    /// Zero disables idle locking; use only on a trusted, single-user machine.
    #[serde(default = "default_idle_lock_seconds")]
    pub idle_lock_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auto_approve_agent_requests: false,
            idle_lock_seconds: default_idle_lock_seconds(),
        }
    }
}

impl Config {
    pub fn effective_auto_approve(&self) -> bool {
        false
    }
}

pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Config> {
        if !self.path.exists() {
            return Ok(Config::default());
        }
        let bytes =
            fs::read(&self.path).with_context(|| format!("read config {}", self.path.display()))?;
        serde_json::from_slice(&bytes).context("parse akc config")
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create config directory {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(config).context("serialize akc config")?;
        fs::write(&self.path, bytes)
            .with_context(|| format!("write config {}", self.path.display()))
    }

    pub fn set_auto_approve(&self, enabled: bool) -> Result<Config> {
        let mut config = self.load()?;
        config.auto_approve_agent_requests = enabled;
        self.save(&config)?;
        Ok(config)
    }

    pub fn set_idle_lock_seconds(&self, seconds: u64) -> Result<Config> {
        let mut config = self.load()?;
        config.idle_lock_seconds = seconds;
        self.save(&config)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_defaults_to_no_auto_approve() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ConfigStore::new(temp.path().join("config.json"));
        assert!(!store.load().unwrap().auto_approve_agent_requests);
    }

    #[test]
    fn auto_approve_round_trips() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ConfigStore::new(temp.path().join("config.json"));
        store.set_auto_approve(true).unwrap();
        assert!(store.load().unwrap().auto_approve_agent_requests);
    }

    #[test]
    fn legacy_persistent_auto_approve_is_not_effective() {
        let config = Config {
            auto_approve_agent_requests: true,
            ..Config::default()
        };
        assert!(!config.effective_auto_approve());
    }

    #[test]
    fn idle_lock_has_safe_default_and_can_be_configured() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = ConfigStore::new(temp.path().join("config.json"));
        assert_eq!(store.load().unwrap().idle_lock_seconds, 900);
        store.set_idle_lock_seconds(120).unwrap();
        assert_eq!(store.load().unwrap().idle_lock_seconds, 120);
    }
}
