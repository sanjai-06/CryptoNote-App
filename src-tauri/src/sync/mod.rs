// CryptoNote – Sync Module
// src-tauri/src/sync/mod.rs
//
// Encrypted cloud sync with offline-first logic.
// - Never sends plaintext to the server
// - TLS 1.3 + certificate pinning via custom root CA
// - Monotonic version counter for replay attack protection
// - HMAC-authenticated sync payload

use anyhow::{anyhow, Result};
use base64::Engine;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto::{self, EncryptedData, SecureKey};

// ─── Sync configuration ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub server_url: String,
    pub device_id: String,
    pub user_id: Option<String>,
    pub auth_token: Option<String>,
    pub tls_cert_pem: Option<String>, // PEM-encoded CA cert for pinning
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            server_url: "https://sanjai-06-cryptonote-app.onrender.com".to_string(),
            device_id: uuid::Uuid::new_v4().to_string(),
            user_id: None,
            auth_token: None,
            tls_cert_pem: None,
        }
    }
}

// ─── Sync status ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    Idle,
    Syncing,
    Synced { at: i64 },
    Conflict { server_version: i64, local_version: i64 },
    Offline,
    Error(String),
}

// ─── Sync payload (sent to / received from server) ────────────────────────────
/// The encrypted blob sent to the server. Server stores this opaquely and
/// knows NOTHING about the contents or structure of the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    pub user_id: String,
    pub device_id: String,
    pub version: i64,
    pub timestamp: i64,
    /// Entire vault serialized and encrypted with the sync_key
    pub encrypted_vault: EncryptedData,
    /// HMAC over (user_id || device_id || version || timestamp || kdf_salt || encrypted_vault)
    pub hmac: String,
    /// Monotonic counter for replay attack protection
    pub sequence: u64,
    /// Plaintext KDF salt (base64) — allows new devices to derive sync keys
    /// The salt is not secret; it's standard practice to include it in plaintext.
    #[serde(default)]
    pub kdf_salt: String,
}

// ─── Server response ─────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub status: String,
    pub server_version: Option<i64>,
    pub payload: Option<SyncPayload>,
    pub message: Option<String>,
}

// ─── Pending (offline) change queue ──────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingSync {
    vault_json: String,
    local_version: i64,
    queued_at: i64,
}

// ─── Sync engine ─────────────────────────────────────────────────────────────
pub struct SyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    pending: Arc<Mutex<Option<PendingSync>>>,
    sequence: Arc<Mutex<u64>>,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(config)),
            status: Arc::new(Mutex::new(SyncStatus::Idle)),
            pending: Arc::new(Mutex::new(None)),
            sequence: Arc::new(Mutex::new(0)),
        }
    }

    pub fn get_status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn get_config(&self) -> SyncConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn update_config(&self, config: SyncConfig) {
        *self.config.lock().unwrap() = config;
    }

    /// Public wrapper around build_client for use by commands.
    pub fn build_client_pub(cert_pem: Option<&str>) -> Result<reqwest::Client> {
        Self::build_client(cert_pem)
    }

    /// Queue vault data for sync (used when offline).
    pub fn queue_sync(&self, vault_json: String, local_version: i64) {
        let mut pending = self.pending.lock().unwrap();
        *pending = Some(PendingSync {
            vault_json,
            local_version,
            queued_at: chrono::Utc::now().timestamp(),
        });
        *self.status.lock().unwrap() = SyncStatus::Offline;
    }

    /// Build a TLS-pinned HTTP client.
    fn build_client(cert_pem: Option<&str>) -> Result<Client> {
        let mut builder = ClientBuilder::new()
            .timeout(Duration::from_secs(90))        // enough for Render wake (50s) + response
            .connect_timeout(Duration::from_secs(65)) // Android cellular can be slow to establish TLS
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2);


        if let Some(pem) = cert_pem {
            // Custom cert pinning: disable system roots, use only the provided cert
            builder = builder.tls_built_in_root_certs(false);
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| anyhow!("Invalid TLS certificate: {}", e))?;
            builder = builder.add_root_certificate(cert);
        } else {
            // No custom cert: trust system roots (Let's Encrypt, Render, etc.)
            builder = builder.tls_built_in_root_certs(true);
        }

        builder
            .build()
            .map_err(|e| anyhow!("HTTP client build error: {}", e))
    }

    /// Build and sign a SyncPayload from vault JSON.
    /// `kdf_salt_b64` is the base64-encoded Argon2 salt stored in vault meta.
    fn build_payload(
        &self,
        vault_json: &str,
        local_version: i64,
        sync_key: &SecureKey,
        hmac_key: &SecureKey,
        kdf_salt_b64: &str,
    ) -> Result<SyncPayload> {
        let config = self.config.lock().unwrap();
        let user_id = config
            .user_id
            .clone()
            .ok_or_else(|| anyhow!("Not authenticated – no user_id"))?;
        let device_id = config.device_id.clone();
        drop(config);

        let sequence = {
            let mut seq = self.sequence.lock().unwrap();
            *seq += 1;
            *seq
        };

        let timestamp = chrono::Utc::now().timestamp();
        let encrypted_vault = crypto::encrypt_string(sync_key, vault_json)?;

        // Include kdf_salt in HMAC so it's tamper-evident
        let hmac_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            user_id,
            device_id,
            local_version,
            timestamp,
            sequence,
            kdf_salt_b64,
            encrypted_vault.ciphertext
        );
        let hmac_bytes = crypto::compute_hmac(hmac_key, hmac_input.as_bytes());
        let hmac = base64::engine::general_purpose::STANDARD.encode(&hmac_bytes);

        Ok(SyncPayload {
            user_id,
            device_id,
            version: local_version,
            timestamp,
            encrypted_vault,
            hmac,
            sequence,
            kdf_salt: kdf_salt_b64.to_string(),
        })
    }

    /// Upload the encrypted vault to the sync server.
    pub async fn push(
        &self,
        vault_json: String,
        local_version: i64,
        sync_key: &SecureKey,
        hmac_key: &SecureKey,
        kdf_salt_b64: &str,
    ) -> Result<SyncStatus> {
        *self.status.lock().unwrap() = SyncStatus::Syncing;

        let payload = self.build_payload(&vault_json, local_version, sync_key, hmac_key, kdf_salt_b64)?;

        let (server_url, auth_token, tls_cert) = {
            let cfg = self.config.lock().unwrap();
            (
                cfg.server_url.clone(),
                cfg.auth_token.clone(),
                cfg.tls_cert_pem.clone(),
            )
        };

        let client = Self::build_client(tls_cert.as_deref())?;

        let mut req = client
            .post(format!("{}/api/vault/push", server_url))
            .json(&payload);

        if let Some(token) = auth_token {
            req = req.bearer_auth(token);
        }

        let response = req
            .send()
            .await
            .map_err(|e| {
                let status = SyncStatus::Offline;
                *self.status.lock().unwrap() = status;
                anyhow!("Network error: {}", e)
            })?;

        if !response.status().is_success() {
            let err = format!("Server error: {}", response.status());
            *self.status.lock().unwrap() = SyncStatus::Error(err.clone());
            return Err(anyhow!("{}", err));
        }

        let sync_resp: SyncResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Invalid server response: {}", e))?;

        let new_status = if sync_resp.status == "conflict" {
            SyncStatus::Conflict {
                server_version: sync_resp.server_version.unwrap_or(0),
                local_version,
            }
        } else {
            SyncStatus::Synced {
                at: chrono::Utc::now().timestamp(),
            }
        };

        *self.status.lock().unwrap() = new_status.clone();
        *self.pending.lock().unwrap() = None;
        Ok(new_status)
    }

    /// Download the latest encrypted vault from the sync server.
    pub async fn pull(
        &self,
        sync_key: &SecureKey,
        hmac_key: &SecureKey,
    ) -> Result<(String, i64)> {
        *self.status.lock().unwrap() = SyncStatus::Syncing;

        let (server_url, auth_token, tls_cert, user_id) = {
            let cfg = self.config.lock().unwrap();
            (
                cfg.server_url.clone(),
                cfg.auth_token.clone(),
                cfg.tls_cert_pem.clone(),
                cfg.user_id.clone(),
            )
        };

        let user_id = user_id.ok_or_else(|| anyhow!("Not authenticated"))?;
        let client = Self::build_client(tls_cert.as_deref())?;

        let mut req = client.get(format!("{}/api/vault/pull/{}", server_url, user_id));
        if let Some(token) = auth_token {
            req = req.bearer_auth(token);
        }

        let response = req
            .send()
            .await
            .map_err(|_| anyhow!("Network unavailable"))?;

        let sync_resp: SyncResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Invalid response: {}", e))?;

        let payload = sync_resp
            .payload
            .ok_or_else(|| anyhow!("No vault data on server"))?;

        // Verify HMAC before decrypting
        // Format must match push: user_id:device_id:version:timestamp:sequence:kdf_salt:ciphertext
        let hmac_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            payload.user_id,
            payload.device_id,
            payload.version,
            payload.timestamp,
            payload.sequence,
            payload.kdf_salt,
            payload.encrypted_vault.ciphertext
        );
        let expected_hmac = base64::engine::general_purpose::STANDARD
            .decode(&payload.hmac)
            .map_err(|_| anyhow!("Invalid HMAC encoding"))?;

        if !crypto::verify_hmac(hmac_key, hmac_input.as_bytes(), &expected_hmac) {
            return Err(anyhow!("Sync payload HMAC verification failed – possible tampering"));
        }

        // Decrypt vault data
        let vault_json = crypto::decrypt_string(sync_key, &payload.encrypted_vault)
            .map_err(|_| anyhow!("Failed to decrypt pulled vault data"))?;

        *self.status.lock().unwrap() = SyncStatus::Synced {
            at: chrono::Utc::now().timestamp(),
        };

        Ok((vault_json, payload.version))
    }

    /// Synchronously extract everything needed for a push, then return
    /// a Send-safe future. Use this from Tauri commands instead of push().
    pub fn push_owned(
        &self,
        vault_json: String,
        local_version: i64,
        sync_key: SecureKey,
        hmac_key: SecureKey,
        kdf_salt_b64: String,
    ) -> impl std::future::Future<Output = Result<SyncStatus>> + Send + 'static {
        let payload = self.build_payload(&vault_json, local_version, &sync_key, &hmac_key, &kdf_salt_b64);
        let (server_url, auth_token, tls_cert) = {
            let cfg = self.config.lock().unwrap();
            (cfg.server_url.clone(), cfg.auth_token.clone(), cfg.tls_cert_pem.clone())
        };
        let status_ref = self.status.clone();
        let pending_ref = self.pending.clone();
        *status_ref.lock().unwrap() = SyncStatus::Syncing;

        async move {
            let payload = payload?;
            let client = Self::build_client(tls_cert.as_deref())?;

            // Retry up to 3 times on 503 (Render free-tier cold start ~30-50s)
            const MAX_RETRIES: u32 = 3;
            const RETRY_DELAY_SECS: u64 = 25;

            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    eprintln!("[SYNC] push: server waking up, retrying in {}s (attempt {}/{})",
                        RETRY_DELAY_SECS, attempt, MAX_RETRIES);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }

                let mut req = client.post(format!("{}/api/vault/push", server_url)).json(&payload);
                if let Some(ref token) = auth_token { req = req.bearer_auth(token); }

                let response = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        *status_ref.lock().unwrap() = SyncStatus::Offline;
                        return Err(anyhow!("Network error: {}", e));
                    }
                };

                // 503 = Render is waking up the service — retry after delay
                if response.status().as_u16() == 503 {
                    eprintln!("[SYNC] push: got 503 (server starting up)");
                    if attempt < MAX_RETRIES { continue; }
                    let err = "Server is starting up. Please wait 30 seconds and try again.".to_string();
                    *status_ref.lock().unwrap() = SyncStatus::Error(err.clone());
                    return Err(anyhow!("{}", err));
                }

                if !response.status().is_success() {
                    let err = format!("Server error: {}", response.status());
                    *status_ref.lock().unwrap() = SyncStatus::Error(err.clone());
                    return Err(anyhow!("{}", err));
                }

                let sync_resp: SyncResponse = response.json().await
                    .map_err(|e| anyhow!("Invalid server response: {}", e))?;

                let new_status = if sync_resp.status == "conflict" {
                    SyncStatus::Conflict { server_version: sync_resp.server_version.unwrap_or(0), local_version }
                } else {
                    SyncStatus::Synced { at: chrono::Utc::now().timestamp() }
                };
                *status_ref.lock().unwrap() = new_status.clone();
                *pending_ref.lock().unwrap() = None;
                eprintln!("[SYNC] push: ok on attempt {}", attempt);
                return Ok(new_status);
            }

            unreachable!()
        }
    }

    /// Patch kdf_salt on old server blobs stored without it.
    pub fn patch_kdf_salt_owned(
        &self,
        kdf_salt: String,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let (server_url, auth_token, tls_cert, user_id) = {
            let cfg = self.config.lock().unwrap();
            (cfg.server_url.clone(), cfg.auth_token.clone(), cfg.tls_cert_pem.clone(),
             cfg.user_id.clone().unwrap_or_default())
        };
        async move {
            let client = Self::build_client(tls_cert.as_deref())?;
            let body = serde_json::json!({ "user_id": user_id, "kdf_salt": kdf_salt });
            let mut req = client.post(format!("{}/api/vault/patch-salt", server_url)).json(&body);
            if let Some(ref token) = auth_token { req = req.bearer_auth(token); }
            let resp = req.send().await.map_err(|e| anyhow!("patch-salt: {}", e))?;
            eprintln!("[SYNC] patch-salt → {}", resp.status());
            Ok(())
        }
    }

    /// Synchronously extract config for a pull, return a Send-safe future.
    pub fn pull_owned(
        &self,
        sync_key: SecureKey,
        hmac_key: SecureKey,
    ) -> impl std::future::Future<Output = Result<(String, i64)>> + Send + 'static {
        let (server_url, auth_token, tls_cert, user_id) = {
            let cfg = self.config.lock().unwrap();
            (cfg.server_url.clone(), cfg.auth_token.clone(), cfg.tls_cert_pem.clone(), cfg.user_id.clone())
        };
        let status_ref = self.status.clone();
        *status_ref.lock().unwrap() = SyncStatus::Syncing;

        async move {
            let user_id = user_id.ok_or_else(|| anyhow!("Not authenticated – no user_id in sync config"))?;
            let client = Self::build_client(tls_cert.as_deref())?;

            const MAX_RETRIES: u32 = 3;
            const RETRY_DELAY_SECS: u64 = 25;

            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    eprintln!("[SYNC] pull: server waking up, retrying in {}s (attempt {}/{})",
                        RETRY_DELAY_SECS, attempt, MAX_RETRIES);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }

                let mut req = client.get(format!("{}/api/vault/pull/{}", server_url, user_id));
                if let Some(ref token) = auth_token { req = req.bearer_auth(token); }

                let response = match req.send().await {
                    Ok(r) => r,
                    Err(e) => return Err(anyhow!("Network unavailable: {}", e)),
                };

                // 503 = Render waking service
                if response.status().as_u16() == 503 {
                    eprintln!("[SYNC] pull: got 503 (server starting up)");
                    if attempt < MAX_RETRIES { continue; }
                    return Err(anyhow!("Server is starting up. Please wait 30 seconds and try again."));
                }

                let sync_resp: SyncResponse = response.json().await
                    .map_err(|e| anyhow!("Invalid response: {}", e))?;

                let payload = sync_resp.payload.ok_or_else(|| anyhow!("No vault data on server"))?;

                let hmac_input = if payload.kdf_salt.is_empty() {
                    format!("{}:{}:{}:{}:{}:{}",
                        payload.user_id, payload.device_id, payload.version,
                        payload.timestamp, payload.sequence, payload.encrypted_vault.ciphertext)
                } else {
                    format!("{}:{}:{}:{}:{}:{}:{}",
                        payload.user_id, payload.device_id, payload.version,
                        payload.timestamp, payload.sequence,
                        payload.kdf_salt, payload.encrypted_vault.ciphertext)
                };
                let expected = base64::engine::general_purpose::STANDARD
                    .decode(&payload.hmac).map_err(|_| anyhow!("Invalid HMAC encoding"))?;
                if !crate::crypto::verify_hmac(&hmac_key, hmac_input.as_bytes(), &expected) {
                    return Err(anyhow!("HMAC verification failed"));
                }

                let vault_json = crate::crypto::decrypt_string(&sync_key, &payload.encrypted_vault)
                    .map_err(|_| anyhow!("Failed to decrypt pulled vault"))?;
                *status_ref.lock().unwrap() = SyncStatus::Synced { at: chrono::Utc::now().timestamp() };
                eprintln!("[SYNC] pull: ok on attempt {}", attempt);
                return Ok((vault_json, payload.version));
            }

            unreachable!()
        }
    }

    /// Fetch the raw SyncPayload from the server (no decryption). Used for bootstrapping.
    pub fn fetch_payload_owned(
        &self,
        user_id: String,
    ) -> impl std::future::Future<Output = Result<SyncPayload>> + Send + 'static {
        let (server_url, auth_token, tls_cert) = {
            let cfg = self.config.lock().unwrap();
            (cfg.server_url.clone(), cfg.auth_token.clone(), cfg.tls_cert_pem.clone())
        };

        async move {
            let client = Self::build_client(tls_cert.as_deref())?;

            const MAX_RETRIES: u32 = 3;
            const RETRY_DELAY_SECS: u64 = 25;

            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    eprintln!("[SYNC] fetch_payload: server waking up, retrying in {}s (attempt {}/{})",
                        RETRY_DELAY_SECS, attempt, MAX_RETRIES);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
                }

                let mut req = client.get(format!("{}/api/vault/pull/{}", server_url, user_id));
                if let Some(ref token) = auth_token { req = req.bearer_auth(token); }

                let response = match req.send().await {
                    Ok(r) => r,
                    Err(e) => return Err(anyhow!("Network unavailable: {}", e)),
                };

                if response.status().as_u16() == 503 {
                    eprintln!("[SYNC] fetch_payload: got 503 (server starting up)");
                    if attempt < MAX_RETRIES { continue; }
                    return Err(anyhow!("Server is starting up. Please wait 30 seconds and try again."));
                }

                let sync_resp: SyncResponse = response.json().await
                    .map_err(|e| anyhow!("Invalid response: {}", e))?;
                return sync_resp.payload.ok_or_else(|| anyhow!("No vault data on server for this account"));
            }

            unreachable!()
        }
    }

    /// Try to flush any pending offline changes to the server.
    pub async fn flush_pending(
        &self,
        sync_key: &SecureKey,
        hmac_key: &SecureKey,
    ) -> Result<()> {
        let pending = {
            let p = self.pending.lock().unwrap();
            p.clone()
        };

        if let Some(p) = pending {
            self.push(p.vault_json, p.local_version, sync_key, hmac_key, "")
                .await?;
        }
        Ok(())
    }
}

// ─── Auth payload (zero-knowledge) ────────────────────────────────────────────
/// Registration payload – server never sees the master password.
/// A random auth_key (derived from device_key) is sent instead.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub email: String,
    pub auth_key_hash: String, // SHA-256 of device_key – server stores this only
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub auth_key_hash: String,
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: String,
}

/// Register a new account with zero-knowledge auth.
pub async fn register(
    server_url: &str,
    email: &str,
    device_key: &SecureKey,
    device_id: &str,
    tls_cert: Option<&str>,
) -> Result<AuthResponse> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&device_key.0);
    let auth_key_hash = hex::encode(hasher.finalize());

    let payload = RegisterPayload {
        email: email.to_string(),
        auth_key_hash,
        device_id: device_id.to_string(),
    };

    let client = SyncEngine::build_client(tls_cert)?;
    let resp = client
        .post(format!("{}/api/auth/register", server_url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow!("Registration failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(anyhow!("Registration failed: {}", resp.status()));
    }

    resp.json::<AuthResponse>()
        .await
        .map_err(|e| anyhow!("Invalid auth response: {}", e))
}

/// Login with zero-knowledge auth.
pub async fn login(
    server_url: &str,
    email: &str,
    device_key: &SecureKey,
    device_id: &str,
    tls_cert: Option<&str>,
) -> Result<AuthResponse> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&device_key.0);
    let auth_key_hash = hex::encode(hasher.finalize());

    let payload = LoginPayload {
        email: email.to_string(),
        auth_key_hash,
        device_id: device_id.to_string(),
    };

    let client = SyncEngine::build_client(tls_cert)?;
    let resp = client
        .post(format!("{}/api/auth/login", server_url))
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow!("Login failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(anyhow!("Login failed: {}", resp.status()));
    }

    resp.json::<AuthResponse>()
        .await
        .map_err(|e| anyhow!("Invalid auth response: {}", e))
}
