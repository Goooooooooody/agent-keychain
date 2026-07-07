use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub version: u8,
    pub kdf: KdfParams,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

pub fn encrypt_json<T: Serialize>(value: &T, passphrase: &str) -> Result<EncryptedBlob> {
    let plaintext = serde_json::to_vec(value).context("serialize vault")?;
    encrypt_bytes(&plaintext, passphrase)
}

pub fn decrypt_json<T: for<'de> Deserialize<'de>>(
    blob: &EncryptedBlob,
    passphrase: &str,
) -> Result<T> {
    let plaintext = decrypt_bytes(blob, passphrase)?;
    serde_json::from_slice(&plaintext).context("decrypt produced invalid vault json")
}

pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<EncryptedBlob> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let params = default_argon2_params()?;
    let mut key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).context("create cipher")?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("failed to encrypt vault"))?;
    key.zeroize();

    Ok(EncryptedBlob {
        version: 1,
        kdf: KdfParams {
            algorithm: "argon2id".to_string(),
            salt: B64.encode(salt),
            memory_cost_kib: params.m_cost(),
            time_cost: params.t_cost(),
            parallelism: params.p_cost(),
        },
        cipher: "XChaCha20-Poly1305".to_string(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn decrypt_bytes(blob: &EncryptedBlob, passphrase: &str) -> Result<Vec<u8>> {
    if blob.version != 1 {
        return Err(anyhow!("unsupported vault version {}", blob.version));
    }
    if blob.kdf.algorithm != "argon2id" {
        return Err(anyhow!("unsupported kdf {}", blob.kdf.algorithm));
    }
    if blob.cipher != "XChaCha20-Poly1305" {
        return Err(anyhow!("unsupported cipher {}", blob.cipher));
    }

    let salt = B64.decode(&blob.kdf.salt).context("decode salt")?;
    let nonce = B64.decode(&blob.nonce).context("decode nonce")?;
    let ciphertext = B64.decode(&blob.ciphertext).context("decode ciphertext")?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(anyhow!("invalid encrypted vault parameters"));
    }

    let params = Params::new(
        blob.kdf.memory_cost_kib,
        blob.kdf.time_cost,
        blob.kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| anyhow!("invalid kdf parameters: {error:?}"))?;
    let mut key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).context("create cipher")?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("wrong passphrase or corrupted vault"))?;
    key.zeroize();
    Ok(plaintext)
}

fn default_argon2_params() -> Result<Params> {
    Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|error| anyhow!("create argon2 parameters: {error:?}"))
}

fn derive_key(passphrase: &str, salt: &[u8], params: &Params) -> Result<[u8; KEY_LEN]> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow!("derive vault key: {error:?}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Fixture {
        secret: String,
    }

    #[test]
    fn encryption_round_trips() {
        let blob = encrypt_json(
            &Fixture {
                secret: "value".into(),
            },
            "passphrase",
        )
        .unwrap();
        let decoded: Fixture = decrypt_json(&blob, "passphrase").unwrap();
        assert_eq!(decoded.secret, "value");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt_json(
            &Fixture {
                secret: "value".into(),
            },
            "passphrase",
        )
        .unwrap();
        assert!(decrypt_json::<Fixture>(&blob, "wrong").is_err());
    }
}
