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
fn cli_config_auto_approve_enable_disable_status() {
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
        .success()
        .stdout(predicate::str::contains("enabled"));

    let mut cmd = akc(&temp);
    cmd.env("AKC_CONFIG_PATH", temp.path().join("config.json"))
        .args(["config", "auto-approve", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"));

    let mut cmd = akc(&temp);
    cmd.env("AKC_CONFIG_PATH", temp.path().join("config.json"))
        .args(["config", "auto-approve", "disable"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));
}
