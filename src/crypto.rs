use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const MIN_MEMORY_COST_KIB: u32 = 8 * 1024;
// Parsing an attacker-controlled vault must not be able to request unbounded workstation memory.
// Existing/default vaults use 64 MiB and remain compatible.
const MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
const MIN_TIME_COST: u32 = 1;
const MAX_TIME_COST: u32 = 5;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 16;

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

#[derive(Debug, Clone, Copy)]
pub struct KdfSettings {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            memory_cost_kib: 64 * 1024,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

/// An unlocked vault cipher. The expensive passphrase KDF is evaluated only when this value is
/// created; each subsequent encryption still uses a fresh random nonce. Dropping the value
/// zeroizes the derived key.
pub struct UnlockedCipher {
    kdf: KdfParams,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl UnlockedCipher {
    pub fn unlock(blob: &EncryptedBlob, passphrase: &str) -> Result<Self> {
        validate_blob(blob)?;
        let salt = B64.decode(&blob.kdf.salt).context("decode salt")?;
        if salt.len() != SALT_LEN {
            return Err(anyhow!("invalid encrypted vault parameters"));
        }
        let params = Params::new(
            blob.kdf.memory_cost_kib,
            blob.kdf.time_cost,
            blob.kdf.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|error| anyhow!("invalid kdf parameters: {error:?}"))?;
        Ok(Self {
            kdf: blob.kdf.clone(),
            key: derive_key(passphrase, &salt, &params)?,
        })
    }

    pub fn decrypt_json<T: for<'de> Deserialize<'de>>(&self, blob: &EncryptedBlob) -> Result<T> {
        validate_blob(blob)?;
        if blob.kdf.salt != self.kdf.salt
            || blob.kdf.memory_cost_kib != self.kdf.memory_cost_kib
            || blob.kdf.time_cost != self.kdf.time_cost
            || blob.kdf.parallelism != self.kdf.parallelism
        {
            return Err(anyhow!(
                "vault encryption key changed while session was unlocked"
            ));
        }
        let nonce = B64.decode(&blob.nonce).context("decode nonce")?;
        let ciphertext = B64.decode(&blob.ciphertext).context("decode ciphertext")?;
        if nonce.len() != NONCE_LEN {
            return Err(anyhow!("invalid encrypted vault parameters"));
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).context("create cipher")?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|_| anyhow!("wrong passphrase or corrupted vault"))?,
        );
        serde_json::from_slice(&plaintext).context("decrypt produced invalid vault json")
    }

    pub fn encrypt_json<T: Serialize>(&self, value: &T) -> Result<EncryptedBlob> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value).context("serialize vault")?);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).context("create cipher")?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| anyhow!("failed to encrypt vault"))?;
        Ok(EncryptedBlob {
            version: 1,
            kdf: self.kdf.clone(),
            cipher: "XChaCha20-Poly1305".to_string(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        })
    }
}

pub fn encrypt_json<T: Serialize>(value: &T, passphrase: &str) -> Result<EncryptedBlob> {
    let plaintext = Zeroizing::new(serde_json::to_vec(value).context("serialize vault")?);
    encrypt_bytes(&plaintext, passphrase)
}

pub fn encrypt_json_with_kdf<T: Serialize>(
    value: &T,
    passphrase: &str,
    settings: KdfSettings,
) -> Result<EncryptedBlob> {
    let plaintext = Zeroizing::new(serde_json::to_vec(value).context("serialize vault")?);
    encrypt_bytes_with_kdf(&plaintext, passphrase, settings)
}

pub fn decrypt_json<T: for<'de> Deserialize<'de>>(
    blob: &EncryptedBlob,
    passphrase: &str,
) -> Result<T> {
    let plaintext = Zeroizing::new(decrypt_bytes(blob, passphrase)?);
    serde_json::from_slice(&plaintext).context("decrypt produced invalid vault json")
}

pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<EncryptedBlob> {
    encrypt_bytes_with_kdf(plaintext, passphrase, KdfSettings::default())
}

fn encrypt_bytes_with_kdf(
    plaintext: &[u8],
    passphrase: &str,
    settings: KdfSettings,
) -> Result<EncryptedBlob> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        salt: B64.encode(salt),
        memory_cost_kib: settings.memory_cost_kib,
        time_cost: settings.time_cost,
        parallelism: settings.parallelism,
    };
    validate_kdf_costs(&kdf)?;
    let params = Params::new(
        settings.memory_cost_kib,
        settings.time_cost,
        settings.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| anyhow!("invalid kdf parameters: {error:?}"))?;
    let key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).context("create cipher")?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("failed to encrypt vault"))?;
    Ok(EncryptedBlob {
        version: 1,
        kdf,
        cipher: "XChaCha20-Poly1305".to_string(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn decrypt_bytes(blob: &EncryptedBlob, passphrase: &str) -> Result<Vec<u8>> {
    validate_blob(blob)?;

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
    let key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).context("create cipher")?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("wrong passphrase or corrupted vault"))?;
    Ok(plaintext)
}

fn validate_blob(blob: &EncryptedBlob) -> Result<()> {
    if blob.version != 1 {
        return Err(anyhow!("unsupported vault version {}", blob.version));
    }
    if blob.kdf.algorithm != "argon2id" {
        return Err(anyhow!("unsupported kdf {}", blob.kdf.algorithm));
    }
    if blob.cipher != "XChaCha20-Poly1305" {
        return Err(anyhow!("unsupported cipher {}", blob.cipher));
    }
    validate_kdf_costs(&blob.kdf)
}

fn validate_kdf_costs(kdf: &KdfParams) -> Result<()> {
    let valid = (MIN_MEMORY_COST_KIB..=MAX_MEMORY_COST_KIB).contains(&kdf.memory_cost_kib)
        && (MIN_TIME_COST..=MAX_TIME_COST).contains(&kdf.time_cost)
        && (MIN_PARALLELISM..=MAX_PARALLELISM).contains(&kdf.parallelism);
    if !valid {
        return Err(anyhow!(
            "kdf parameters outside supported bounds (memory {}..={} KiB, time {}..={}, parallelism {}..={})",
            MIN_MEMORY_COST_KIB,
            MAX_MEMORY_COST_KIB,
            MIN_TIME_COST,
            MAX_TIME_COST,
            MIN_PARALLELISM,
            MAX_PARALLELISM
        ));
    }
    Ok(())
}

fn derive_key(passphrase: &str, salt: &[u8], params: &Params) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
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

    #[test]
    fn rejects_unsupported_versions_and_hostile_kdf_costs_before_derivation() {
        let mut blob = encrypt_json(
            &Fixture {
                secret: "value".into(),
            },
            "passphrase",
        )
        .unwrap();

        blob.version = 2;
        assert!(decrypt_json::<Fixture>(&blob, "passphrase")
            .unwrap_err()
            .to_string()
            .contains("unsupported vault version"));

        blob.version = 1;
        blob.kdf.memory_cost_kib = u32::MAX;
        assert!(decrypt_json::<Fixture>(&blob, "passphrase")
            .unwrap_err()
            .to_string()
            .contains("outside supported bounds"));

        blob.kdf.memory_cost_kib = 64 * 1024;
        blob.kdf.time_cost = u32::MAX;
        assert!(decrypt_json::<Fixture>(&blob, "passphrase")
            .unwrap_err()
            .to_string()
            .contains("outside supported bounds"));

        blob.kdf.time_cost = 3;
        blob.kdf.parallelism = u32::MAX;
        assert!(decrypt_json::<Fixture>(&blob, "passphrase")
            .unwrap_err()
            .to_string()
            .contains("outside supported bounds"));
    }

    #[test]
    fn unlocked_cipher_reuses_the_kdf_key_but_rotates_nonces() {
        let original = encrypt_json(
            &Fixture {
                secret: "one".into(),
            },
            "passphrase",
        )
        .unwrap();
        let cipher = UnlockedCipher::unlock(&original, "passphrase").unwrap();
        let decoded: Fixture = cipher.decrypt_json(&original).unwrap();
        assert_eq!(decoded.secret, "one");
        let first = cipher
            .encrypt_json(&Fixture {
                secret: "two".into(),
            })
            .unwrap();
        let second = cipher
            .encrypt_json(&Fixture {
                secret: "two".into(),
            })
            .unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(first.kdf.salt, original.kdf.salt);
        let decoded: Fixture = cipher.decrypt_json(&first).unwrap();
        assert_eq!(decoded.secret, "two");
    }
}
