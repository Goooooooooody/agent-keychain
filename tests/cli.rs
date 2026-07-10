use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn akc(temp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("akc").unwrap();
    cmd.env("AKC_MASTER_PASSPHRASE", "correct horse battery staple")
        .env("AKC_VAULT_PATH", temp.path().join("vault.db"));
    cmd
}

#[test]
fn cli_init_add_get_list_remove() {
    let temp = TempDir::new().unwrap();

    akc(&temp).arg("init").assert().success();
    akc(&temp)
        .args([
            "add",
            "--name",
            "secret-for-thing",
            "--value",
            "secret-key-value",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("added secret"));
    akc(&temp)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret-for-thing"));
    akc(&temp)
        .args(["get", "--name", "secret-for-thing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret-key-value"));
    akc(&temp)
        .args(["remove", "--name", "secret-for-thing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed secret"));
}

#[test]
fn root_add_form_warns_about_shell_history() {
    let temp = TempDir::new().unwrap();

    akc(&temp).arg("init").assert().success();
    akc(&temp)
        .args(["--add", "secret-key-value", "--name", "secret-for-thing"])
        .assert()
        .success()
        .stderr(predicate::str::contains("shell history"));
}

#[test]
fn corrupt_vault_returns_safe_error() {
    let temp = TempDir::new().unwrap();
    std::fs::write(temp.path().join("vault.db"), b"not encrypted json").unwrap();

    akc(&temp)
        .args(["list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "vault file is not valid encrypted json",
        ));
}

#[test]
fn noninteractive_auto_approve_enable_is_rejected() {
    let temp = TempDir::new().unwrap();
    let mut cmd = akc(&temp);
    cmd.env("AKC_CONFIG_PATH", temp.path().join("config.json"))
        .args(["config", "auto-approve", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));

    let mut cmd = akc(&temp);
    cmd.env("AKC_CONFIG_PATH", temp.path().join("config.json"))
        .args(["config", "auto-approve", "enable"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("interactive terminal"));

    // Revocation remains safe and idempotent even if no daemon is running.
    let mut cmd = akc(&temp);
    cmd.env("AKC_CONFIG_PATH", temp.path().join("config.json"))
        .args(["config", "auto-approve", "disable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));
}

#[test]
fn metadata_is_listed_without_exposing_secret_value() {
    let temp = TempDir::new().unwrap();
    akc(&temp).arg("init").assert().success();
    akc(&temp)
        .args([
            "add",
            "--name",
            "deploy",
            "--value",
            "never-print",
            "--tags",
            "prod,api",
            "--one-time",
            "--allow-client",
            "codex",
        ])
        .assert()
        .success();
    akc(&temp)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("deploy"))
        .stdout(predicate::str::contains("one-time"))
        .stdout(predicate::str::contains("never-print").not());
}

#[test]
fn restore_requires_explicit_verification_flag() {
    let temp = TempDir::new().unwrap();
    akc(&temp).arg("init").assert().success();
    akc(&temp)
        .args(["restore", "--input", "missing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires --verify"));
}
