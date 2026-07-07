use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use std::env;
use std::path::PathBuf;

pub fn vault_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("AKC_VAULT_PATH") {
        return Ok(PathBuf::from(path));
    }
    Ok(project_dirs()?.data_local_dir().join("vault.db"))
}

pub fn config_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("AKC_CONFIG_PATH") {
        return Ok(PathBuf::from(path));
    }
    Ok(project_dirs()?.config_dir().join("config.json"))
}

pub fn socket_path() -> Result<PathBuf> {
    if let Ok(path) = env::var("AKC_SOCKET_PATH") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(runtime) = env::var("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("akc.sock"));
    }
    Ok(project_dirs()?.data_local_dir().join("akc.sock"))
}

fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("dev", "agent-keychain", "akc")
        .ok_or_else(|| anyhow!("could not resolve user data directory"))
}
