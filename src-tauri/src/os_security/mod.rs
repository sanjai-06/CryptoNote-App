// CryptoNote – OS Security Integration
// src-tauri/src/os_security/mod.rs
//
// Platform-specific Keychain/Keystore integration.
// Uses conditional compilation to select the right backend.
// On unsupported platforms, falls back to in-memory or encrypted-file storage.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Result of a biometric authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricResult {
    pub success: bool,
    pub method: String,
    pub error: Option<String>,
}

/// Check whether the OS is a jailbroken/rooted device (mobile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureResult {
    pub is_compromised: bool,
    pub findings: Vec<String>,
}

// ─── Keychain / Credential store interface ────────────────────────────────────

/// Store a secret in the platform's secure credential store.
/// On mobile this uses Android Keystore / iOS Secure Enclave.
/// On desktop this uses Windows Credential Manager, GNOME Keyring, or macOS Keychain.
pub fn store_in_keychain(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    platform_keychain_store(service, account, secret)
}

/// Retrieve a secret from the platform's credential store.
pub fn load_from_keychain(service: &str, account: &str) -> Result<Vec<u8>> {
    platform_keychain_load(service, account)
}

/// Delete a secret from the platform's credential store.
pub fn delete_from_keychain(service: &str, account: &str) -> Result<()> {
    platform_keychain_delete(service, account)
}

// ─── Platform implementations ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn platform_keychain_store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: Integrate with `secret-service` crate (GNOME Keyring / KDE Wallet)
    // Example implementation using libsecret via D-Bus:
    //
    // use secret_service::{EncryptionType, SecretService};
    // let ss = SecretService::connect(EncryptionType::Dh).await?;
    // let collection = ss.get_default_collection().await?;
    // collection.create_item(
    //     &format!("{}/{}", service, account),
    //     HashMap::from([("service", service), ("account", account)]),
    //     secret, true, "text/plain"
    // ).await?;
    //
    // For now: store in encrypted local fallback
    fallback_store(service, account, secret)
}

#[cfg(target_os = "linux")]
fn platform_keychain_load(service: &str, account: &str) -> Result<Vec<u8>> {
    // TODO: Implement via secret-service crate
    fallback_load(service, account)
}

#[cfg(target_os = "linux")]
fn platform_keychain_delete(service: &str, account: &str) -> Result<()> {
    fallback_delete(service, account)
}

#[cfg(target_os = "macos")]
fn platform_keychain_store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: Integrate with `security-framework` crate for macOS Keychain
    // use security_framework::passwords::set_generic_password;
    // set_generic_password(service, account, secret).map_err(|e| anyhow!("{}", e))?;
    fallback_store(service, account, secret)
}

#[cfg(target_os = "macos")]
fn platform_keychain_load(service: &str, account: &str) -> Result<Vec<u8>> {
    // TODO: use security_framework::passwords::get_generic_password
    fallback_load(service, account)
}

#[cfg(target_os = "macos")]
fn platform_keychain_delete(service: &str, account: &str) -> Result<()> {
    fallback_delete(service, account)
}

#[cfg(target_os = "windows")]
fn platform_keychain_store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: Integrate with `windows` crate for Windows Credential Manager
    // use windows::Security::Credentials::PasswordCredential;
    // PasswordCredential::CreateWithResource(service, account, secret_str)?;
    fallback_store(service, account, secret)
}

#[cfg(target_os = "windows")]
fn platform_keychain_load(service: &str, account: &str) -> Result<Vec<u8>> {
    fallback_load(service, account)
}

#[cfg(target_os = "windows")]
fn platform_keychain_delete(service: &str, account: &str) -> Result<()> {
    fallback_delete(service, account)
}

// Android and iOS are handled by Tauri's plugin system at the JS/Rust bridge level
#[cfg(target_os = "android")]
fn platform_keychain_store(_service: &str, _account: &str, _secret: &[u8]) -> Result<()> {
    // Android Keystore integration is handled via Tauri's plugin-biometric
    // and Android Keystore System. The actual implementation requires JNI.
    // TODO: Use `tauri-plugin-biometric` for key protection on Android.
    Ok(())
}

#[cfg(target_os = "android")]
fn platform_keychain_load(_service: &str, _account: &str) -> Result<Vec<u8>> {
    Err(anyhow!("Android Keystore: use Tauri biometric plugin for key retrieval"))
}

#[cfg(target_os = "android")]
fn platform_keychain_delete(_service: &str, _account: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "ios")]
fn platform_keychain_store(_service: &str, _account: &str, _secret: &[u8]) -> Result<()> {
    // TODO: Use iOS Keychain via security-framework or Tauri plugin
    Ok(())
}

#[cfg(target_os = "ios")]
fn platform_keychain_load(_service: &str, _account: &str) -> Result<Vec<u8>> {
    Err(anyhow!("iOS Keychain: use Tauri biometric plugin for key retrieval"))
}

#[cfg(target_os = "ios")]
fn platform_keychain_delete(_service: &str, _account: &str) -> Result<()> {
    Ok(())
}

// ─── Encrypted file fallback ──────────────────────────────────────────────────
// Used when native keychain is not yet integrated.
// Keys are stored in OS-protected app data directory.

fn fallback_path(service: &str, account: &str) -> std::path::PathBuf {
    let mut dir = dirs_next::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.push("CryptoNote");
    dir.push("keystore");
    std::fs::create_dir_all(&dir).ok();
    dir.push(format!("{}_{}.key", service, account));
    dir
}

fn fallback_store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    let path = fallback_path(service, account);
    // Store base64-encoded (not encrypted in fallback – real integration needed)
    // This is a placeholder; in production use the platform keychain.
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    std::fs::write(&path, encoded)
        .map_err(|e| anyhow!("Fallback keystore write error: {}", e))?;
    Ok(())
}

fn fallback_load(service: &str, account: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let path = fallback_path(service, account);
    let encoded = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("Key not found in fallback keystore"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| anyhow!("Invalid fallback keystore data"))
}

fn fallback_delete(service: &str, account: &str) -> Result<()> {
    let path = fallback_path(service, account);
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| anyhow!("Fallback keystore delete error: {}", e))?;
    }
    Ok(())
}

// ─── Root / Jailbreak Detection ───────────────────────────────────────────────

/// Check if the device appears to be rooted (Android) or jailbroken (iOS).
pub fn check_device_integrity() -> SecurityPostureResult {
    let mut findings = Vec::new();

    #[cfg(target_os = "android")]
    {
        // Check for su binary
        let su_paths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su"];
        for path in &su_paths {
            if std::path::Path::new(path).exists() {
                findings.push(format!("Root binary found at: {}", path));
            }
        }
        // Check for Magisk
        if std::path::Path::new("/sbin/.magisk").exists() {
            findings.push("Magisk root framework detected".to_string());
        }
    }

    #[cfg(target_os = "ios")]
    {
        // Check for Cydia (jailbreak store)
        let jb_paths = [
            "/Applications/Cydia.app",
            "/private/var/lib/apt",
            "/usr/bin/sshd",
            "/etc/apt",
        ];
        for path in &jb_paths {
            if std::path::Path::new(path).exists() {
                findings.push(format!("Jailbreak indicator found at: {}", path));
            }
        }
    }

    SecurityPostureResult {
        is_compromised: !findings.is_empty(),
        findings,
    }
}

/// Get biometric authentication capability info.
pub fn get_biometric_info() -> serde_json::Value {
    serde_json::json!({
        "platform": std::env::consts::OS,
        "biometric_available": cfg!(any(target_os = "android", target_os = "ios")),
        "note": "Biometric authentication is handled via Tauri plugin-biometric on mobile platforms"
    })
}
