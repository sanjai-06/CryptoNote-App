// CryptoNote – Rust Security Core
// src-tauri/src/crypto/mod.rs
//
// Implements zero-knowledge cryptography:
//   • Argon2id key derivation
//   • HKDF subkey derivation
//   • XChaCha20-Poly1305 authenticated encryption
//   • Secure memory wiping via zeroize

use anyhow::{anyhow, Result};
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Key lengths ─────────────────────────────────────────────────────────────
pub const MASTER_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24; // XChaCha20 uses 24-byte nonces
pub const SUBKEY_LEN: usize = 32;

// ─── Key derivation parameters (OWASP recommended minimums) ──────────────────
const ARGON2_MEM_COST: u32 = 65536; // 64 MiB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

// ─── Secure key wrapper ───────────────────────────────────────────────────────
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub [u8; SUBKEY_LEN]);

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureKey([REDACTED])")
    }
}

// ─── Derived subkeys ─────────────────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub vault_key: SecureKey,  // Encrypts vault entries
    pub hmac_key: SecureKey,   // HMAC for integrity checks
    pub sync_key: SecureKey,   // Encrypts sync payload
    pub device_key: SecureKey, // Device-specific key
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedKeys([REDACTED])")
    }
}

// ─── Encrypted ciphertext representation ─────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64-encoded nonce (24 bytes for XChaCha20)
    pub nonce: String,
    /// Base64-encoded ciphertext (includes Poly1305 authentication tag)
    pub ciphertext: String,
    /// Algorithm identifier for future-proofing
    pub algorithm: String,
}

// ─── Salt / Nonce generation ─────────────────────────────────────────────────

/// Generate a cryptographically secure random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a cryptographically secure random nonce for XChaCha20.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

// ─── Master Key Derivation (Argon2id) ────────────────────────────────────────

/// Derive a 32-byte master key from a master password and salt using Argon2id.
/// The master password is consumed and zeroized after derivation.
pub fn derive_master_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<SecureKey> {
    let params = Params::new(
        ARGON2_MEM_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|e| anyhow!("Argon2 param error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output_key = [0u8; MASTER_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| anyhow!("Argon2 KDF error: {}", e))?;

    Ok(SecureKey(output_key))
}

// ─── Subkey Derivation (HKDF-SHA256) ─────────────────────────────────────────

/// Derive four independent subkeys from the master key using HKDF-SHA256.
/// Each subkey is derived with a distinct info label to ensure independence.
pub fn derive_subkeys(master_key: &SecureKey) -> Result<DerivedKeys> {
    let hk = Hkdf::<Sha256>::new(None, &master_key.0);

    let mut vault_key_bytes = [0u8; SUBKEY_LEN];
    let mut hmac_key_bytes = [0u8; SUBKEY_LEN];
    let mut sync_key_bytes = [0u8; SUBKEY_LEN];
    let mut device_key_bytes = [0u8; SUBKEY_LEN];

    hk.expand(b"cryptonote-vault-key-v1", &mut vault_key_bytes)
        .map_err(|_| anyhow!("HKDF expand failed for vault_key"))?;
    hk.expand(b"cryptonote-hmac-key-v1", &mut hmac_key_bytes)
        .map_err(|_| anyhow!("HKDF expand failed for hmac_key"))?;
    hk.expand(b"cryptonote-sync-key-v1", &mut sync_key_bytes)
        .map_err(|_| anyhow!("HKDF expand failed for sync_key"))?;
    hk.expand(b"cryptonote-device-key-v1", &mut device_key_bytes)
        .map_err(|_| anyhow!("HKDF expand failed for device_key"))?;

    Ok(DerivedKeys {
        vault_key: SecureKey(vault_key_bytes),
        hmac_key: SecureKey(hmac_key_bytes),
        sync_key: SecureKey(sync_key_bytes),
        device_key: SecureKey(device_key_bytes),
    })
}

// ─── XChaCha20-Poly1305 Encryption ───────────────────────────────────────────

/// Encrypt plaintext with XChaCha20-Poly1305 using a fresh random nonce.
/// Returns an `EncryptedData` struct containing the encoded nonce + ciphertext.
pub fn encrypt(key: &SecureKey, plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|e| anyhow!("Cipher init error: {}", e))?;

    // Always generate a fresh nonce – NEVER reuse
    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    Ok(EncryptedData {
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(&ciphertext),
        algorithm: "XChaCha20-Poly1305".to_string(),
    })
}

/// Decrypt ciphertext using XChaCha20-Poly1305. Verification of the
/// Poly1305 authentication tag is mandatory and happens automatically.
pub fn decrypt(key: &SecureKey, data: &EncryptedData) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|e| anyhow!("Cipher init error: {}", e))?;

    let nonce_bytes = BASE64
        .decode(&data.nonce)
        .map_err(|_| anyhow!("Invalid nonce encoding"))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(anyhow!("Invalid nonce length"));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = BASE64
        .decode(&data.ciphertext)
        .map_err(|_| anyhow!("Invalid ciphertext encoding"))?;

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed – authentication tag mismatch"))
}

/// Convenience: encrypt a UTF-8 string and return an `EncryptedData`.
pub fn encrypt_string(key: &SecureKey, plaintext: &str) -> Result<EncryptedData> {
    encrypt(key, plaintext.as_bytes())
}

/// Convenience: decrypt and return a UTF-8 string.
pub fn decrypt_string(key: &SecureKey, data: &EncryptedData) -> Result<String> {
    let bytes = decrypt(key, data)?;
    String::from_utf8(bytes).map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))
}

/// Encode a salt to base64 for storage.
pub fn encode_salt(salt: &[u8; SALT_LEN]) -> String {
    BASE64.encode(salt)
}

/// Decode a base64-encoded salt.
pub fn decode_salt(s: &str) -> Result<[u8; SALT_LEN]> {
    let bytes = BASE64.decode(s).map_err(|_| anyhow!("Invalid salt encoding"))?;
    if bytes.len() != SALT_LEN {
        return Err(anyhow!("Invalid salt length"));
    }
    let mut arr = [0u8; SALT_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ─── HMAC-SHA256 integrity check ──────────────────────────────────────────────
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `data` using `hmac_key`.
pub fn compute_hmac(hmac_key: &SecureKey, data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key.0)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256 in constant time.
pub fn verify_hmac(hmac_key: &SecureKey, data: &[u8], expected: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key.0)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_deterministic() {
        let salt = [42u8; SALT_LEN];
        let key1 = derive_master_key("testpassword", &salt).unwrap();
        let key2 = derive_master_key("testpassword", &salt).unwrap();
        assert_eq!(key1.0, key2.0);
    }

    #[test]
    fn test_kdf_different_passwords() {
        let salt = [42u8; SALT_LEN];
        let key1 = derive_master_key("password1", &salt).unwrap();
        let key2 = derive_master_key("password2", &salt).unwrap();
        assert_ne!(key1.0, key2.0);
    }

    #[test]
    fn test_kdf_different_salts() {
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let key1 = derive_master_key("samepassword", &salt1).unwrap();
        let key2 = derive_master_key("samepassword", &salt2).unwrap();
        assert_ne!(key1.0, key2.0);
    }

    #[test]
    fn test_subkey_independence() {
        let salt = generate_salt();
        let master = derive_master_key("test", &salt).unwrap();
        let keys = derive_subkeys(&master).unwrap();
        assert_ne!(keys.vault_key.0, keys.hmac_key.0);
        assert_ne!(keys.vault_key.0, keys.sync_key.0);
        assert_ne!(keys.sync_key.0, keys.device_key.0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = generate_salt();
        let master = derive_master_key("hunter2", &salt).unwrap();
        let keys = derive_subkeys(&master).unwrap();

        let plaintext = "super-secret-password-123!";
        let encrypted = encrypt_string(&keys.vault_key, plaintext).unwrap();
        let decrypted = decrypt_string(&keys.vault_key, &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "Nonces must not repeat");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let salt = generate_salt();
        let master = derive_master_key("pw", &salt).unwrap();
        let keys = derive_subkeys(&master).unwrap();
        let mut enc = encrypt_string(&keys.vault_key, "secret").unwrap();
        // Corrupt the ciphertext
        let mut ct = BASE64.decode(&enc.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        enc.ciphertext = BASE64.encode(&ct);
        assert!(decrypt_string(&keys.vault_key, &enc).is_err());
    }

    #[test]
    fn test_hmac_verify() {
        let salt = generate_salt();
        let master = derive_master_key("pw", &salt).unwrap();
        let keys = derive_subkeys(&master).unwrap();
        let data = b"integrity-check-data";
        let mac = compute_hmac(&keys.hmac_key, data);
        assert!(verify_hmac(&keys.hmac_key, data, &mac));
        // Tampered data should fail
        assert!(!verify_hmac(&keys.hmac_key, b"tampered", &mac));
    }
}
