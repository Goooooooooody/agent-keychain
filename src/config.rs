use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Config {
    #[serde(default)]
    pub auto_approve_agent_requests: bool,
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
}
