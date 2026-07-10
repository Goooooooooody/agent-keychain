use agent_keychain::{Vault, VaultStore};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn vault_operations(c: &mut Criterion) {
    let mut vault = Vault::new();
    for index in 0..1_000 {
        vault
            .add_secret(format!("secret-{index:04}"), "benchmark-value".into())
            .unwrap();
    }
    c.bench_function("list 1000 cached records", |b| {
        b.iter(|| black_box(vault.list_names()))
    });

    let temporary = tempfile::tempdir().unwrap();
    let store = VaultStore::new(temporary.path().join("vault.json"));
    store.init("benchmark-passphrase").unwrap();
    let mut session = store.unlock("benchmark-passphrase").unwrap();
    c.bench_function("cached encrypted transaction", |b| {
        b.iter(|| {
            session
                .transaction(|vault| {
                    vault.audit(agent_keychain::AuditAction::Get, None, "benchmark", None);
                    Ok(())
                })
                .unwrap()
        })
    });
}

criterion_group!(benches, vault_operations);
criterion_main!(benches);
