use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use tauri::{State, Emitter};
use crate::{AppState, CmdResult, map_err};
use crate::ai::{AnomalyResult, PhishingResult};
use crate::sync::{SyncConfig, SyncStatus};
use crate::vault::{EntryListItem, PasswordOptions, VaultEntry, VaultMeta};

// ═══════════════════════════════════════════════════════════════════════════════
//  VAULT COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn vault_exists(path: String) -> bool {
    std::path::Path::new(&path).exists()
}

#[tauri::command]
pub fn vault_is_initialized(state: State<'_, AppState>) -> CmdResult<bool> {
    let vault = state.vault.lock().map_err(map_err)?;
    Ok(vault.is_initialized())
}

#[tauri::command]
pub async fn vault_create(
    master_password: String,
    state: State<'_, AppState>,
) -> CmdResult<VaultMeta> {
    if master_password.len() < 12 {
        return Err("Master password must be at least 12 characters".to_string());
    }
    let vault = state.vault.lock().map_err(map_err)?;
    let meta = vault.create(&master_password).map_err(map_err)?;
    state.touch();
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    let device_id = format!("device-{}", uuid::Uuid::new_v4());
    det.register_device(&device_id);
    Ok(meta)
}

#[tauri::command]
pub async fn vault_unlock(
    master_password: String,
    state: State<'_, AppState>,
) -> CmdResult<VaultMeta> {
    let vault = state.vault.lock().map_err(map_err)?;
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    match vault.unlock(&master_password) {
        Ok(meta) => {
            let anomaly = det.record_unlock(true);
            state.touch();
            if anomaly.should_lock {
                vault.lock();
                return Err(format!("Security lock: {}", anomaly.message));
            }
            Ok(meta)
        }
        Err(e) => {
            det.record_unlock(false);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    vault.lock();
    Ok(())
}

#[tauri::command]
pub fn vault_is_locked(state: State<'_, AppState>) -> CmdResult<bool> {
    let vault = state.vault.lock().map_err(map_err)?;
    Ok(vault.is_locked())
}

#[tauri::command]
pub fn vault_list_entries(state: State<'_, AppState>) -> CmdResult<Vec<EntryListItem>> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.list_entries().map_err(map_err)
}

#[tauri::command]
pub fn vault_get_entry(id: String, state: State<'_, AppState>) -> CmdResult<VaultEntry> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.get_entry(&id).map_err(map_err)
}

#[tauri::command]
pub fn vault_add_entry(entry: VaultEntry, state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.add_entry(&entry).map_err(map_err)
}

#[tauri::command]
pub fn vault_update_entry(entry: VaultEntry, state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.update_entry(&entry).map_err(map_err)
}

#[tauri::command]
pub fn vault_delete_entry(id: String, state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.delete_entry(&id).map_err(map_err)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PASSWORD GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn generate_password(options: PasswordOptions) -> CmdResult<String> {
    crate::vault::generate_password(&options).map_err(map_err)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AI SECURITY COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn ai_check_phishing(url: String, state: State<'_, AppState>) -> CmdResult<PhishingResult> {
    Ok(state.phishing_detector.analyze(&url))
}

#[tauri::command]
pub fn ai_get_anomaly_status(state: State<'_, AppState>) -> CmdResult<AnomalyResult> {
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    Ok(det.record_unlock(true))
}

#[tauri::command]
pub fn ai_record_export(state: State<'_, AppState>) -> CmdResult<AnomalyResult> {
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    Ok(det.record_export())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SYNC COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn sync_configure(config: SyncConfig, state: State<'_, AppState>) -> CmdResult<()> {
    let engine = state.sync_engine.lock().map_err(map_err)?;
    engine.update_config(config);
    Ok(())
}

#[tauri::command]
pub fn sync_get_status(state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    let engine = state.sync_engine.lock().map_err(map_err)?;
    Ok(engine.get_status())
}

/// Ping the sync server and return a diagnostic string.
/// Used by the Settings UI "Test Connection" button.
#[tauri::command]
pub async fn sync_ping(state: State<'_, AppState>) -> CmdResult<String> {
    let (server_url, tls_cert) = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        let cfg = engine.get_config();
        (cfg.server_url, cfg.tls_cert_pem)
    };

    let client = crate::sync::SyncEngine::build_client_pub(tls_cert.as_deref())
        .map_err(map_err)?;

    match client.get(&server_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 503 {
                Ok(format!("Server is waking up (503) — retry in ~30s"))
            } else {
                Ok(format!("Connected ✓ (HTTP {})", status))
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("dns") || msg.contains("resolve") {
                Err(format!("DNS error — cannot resolve server hostname. Check your internet connection."))
            } else if msg.contains("tls") || msg.contains("ssl") || msg.contains("certificate") {
                Err(format!("TLS error: {}", msg))
            } else if msg.contains("timeout") || msg.contains("timed out") {
                Err(format!("Connection timed out — server may be starting, try again in 30s"))
            } else {
                Err(format!("Network error: {}", msg))
            }
        }
    }
}

#[tauri::command]
pub async fn sync_register(
    email: String,
    master_password: String,
    _state: State<'_, AppState>,
) -> CmdResult<String> {
    let server_url = "https://sanjai-06-cryptonote-app.onrender.com".to_string();
    let device_id = uuid::Uuid::new_v4().to_string();

    let salt = crate::crypto::generate_salt();
    let master_key = crate::crypto::derive_master_key(&master_password, &salt).map_err(map_err)?;
    let keys = crate::crypto::derive_subkeys(&master_key).map_err(map_err)?;

    let auth_resp = crate::sync::register(
        &server_url,
        &email,
        &keys.device_key,
        &device_id,
        None,
    )
    .await
    .map_err(map_err)?;

    Ok(auth_resp.token)
}

#[tauri::command]
pub async fn sync_push(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    eprintln!("[SYNC] sync_push called");
    let (sync_key, hmac_key, vault_json, local_version, kdf_salt) = {
        let vault = state.vault.lock().map_err(map_err)?;
        let (sk, hk) = vault.get_sync_keys().map_err(|e| {
            eprintln!("[SYNC] get_sync_keys failed: {}", e);
            map_err(e)
        })?;
        let vj = vault.export_json().map_err(map_err)?;
        let lv = vault.version();
        let salt = vault.get_kdf_salt().unwrap_or_default();
        (sk, hk, vj, lv, salt)
    };

    eprintln!("[SYNC] vault exported v{}, kdf_salt present={}", local_version, !kdf_salt.is_empty());

    let push_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.push_owned(vault_json, local_version, sync_key, hmac_key, kdf_salt.clone(), false)
    };

    match push_fut.await {
        Ok(s) => {
            eprintln!("[SYNC] push ok: {:?}", s);
            // After push, also patch kdf_salt on existing blob in case server had old blob without it
            if !kdf_salt.is_empty() {
                let patch_fut = {
                    let engine = state.sync_engine.lock().map_err(map_err)?;
                    engine.patch_kdf_salt_owned(kdf_salt)
                };
                if let Err(e) = patch_fut.await {
                    eprintln!("[SYNC] patch-salt failed (non-fatal): {}", e);
                }
            }
            let _ = app.emit("vault://changed", ());
            Ok(())
        }
        Err(e) => { eprintln!("[SYNC] push FAILED: {}", e); Err(map_err(e)) }
    }
}

/// Called on app start / sync enable to patch kdf_salt on server for old blobs.
#[tauri::command]
pub async fn sync_patch_salt(state: State<'_, AppState>) -> CmdResult<()> {
    let kdf_salt = {
        let vault = state.vault.lock().map_err(map_err)?;
        vault.get_kdf_salt().unwrap_or_default()
    };
    if kdf_salt.is_empty() { return Ok(()); }
    let patch_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.patch_kdf_salt_owned(kdf_salt)
    };
    patch_fut.await.map_err(|e| {
        eprintln!("[SYNC] patch-salt: {e}");
        map_err(e)
    })?;
    Ok(())
}

/// Force-push: overrides server version conflict. Use when local vault should be master.
#[tauri::command]
pub async fn sync_force_push(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    eprintln!("[SYNC] sync_force_push called");
    let (sync_key, hmac_key, vault_json, local_version, kdf_salt) = {
        let vault = state.vault.lock().map_err(map_err)?;
        let (sk, hk) = vault.get_sync_keys().map_err(map_err)?;
        let vj = vault.export_json().map_err(map_err)?;
        let lv = vault.version();
        let salt = vault.get_kdf_salt().unwrap_or_default();
        (sk, hk, vj, lv, salt)
    };
    let push_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.push_owned(vault_json, local_version, sync_key, hmac_key, kdf_salt.clone(), true)
    };
    match push_fut.await {
        Ok(s) => {
            eprintln!("[SYNC] force push ok: {:?}", s);
            // Also patch kdf_salt on old blob (non-fatal)
            if !kdf_salt.is_empty() {
                let pf = {
                    let engine = state.sync_engine.lock().map_err(map_err)?;
                    engine.patch_kdf_salt_owned(kdf_salt)
                };
                let _ = pf.await;
            }
            let _ = app.emit("vault://changed", ());
            Ok(())
        }
        Err(e) => { eprintln!("[SYNC] force push FAILED: {}", e); Err(map_err(e)) }
    }
}

#[tauri::command]
pub async fn sync_pull(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    // Extract keys (sync, no await)
    let (sync_key, hmac_key) = {
        let vault = state.vault.lock().map_err(map_err)?;
        vault.get_sync_keys().map_err(map_err)?
    };

    let pull_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.pull_owned(sync_key, hmac_key)
    };

    let (vault_json, server_version) = pull_fut.await.map_err(map_err)?;

    {
        let vault = state.vault.lock().map_err(map_err)?;
        let local_version = vault.version();
        eprintln!("[SYNC] pull: server_version={}, local_version={}", server_version, local_version);
        // Only import when server is strictly newer — equal versions mean we're in sync.
        // New-device bootstrap uses vault_restore_from_sync instead (reads kdf_salt from payload).
        if server_version > local_version {
            vault.import_json(&vault_json).map_err(map_err)?;
            eprintln!("[SYNC] pull: imported {} bytes of vault data", vault_json.len());
        } else {
            eprintln!("[SYNC] pull: already up to date (server={}, local={})", server_version, local_version);
        }
    }

    // Always emit refresh so UI reflects whatever is in the vault now
    let _ = app.emit("vault://refreshed", ());
    Ok(())
}

/// Bootstrap a new device from cloud sync WITHOUT requiring a local vault.
/// Flow: fetch payload → try salts → decrypt (AEAD provides auth) → create local vault.
#[tauri::command]
pub async fn vault_restore_from_sync(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    master_password: String,
    user_id: String,
) -> CmdResult<crate::vault::VaultMeta> {
    use crate::crypto::{decode_salt, derive_master_key, derive_subkeys};

    // 1. Fetch raw payload (no local vault needed)
    let fetch_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.fetch_payload_owned(user_id.clone())
    };
    let payload = fetch_fut.await.map_err(|e| map_err(anyhow::anyhow!("Server error: {}", e)))?;

    // 2. Determine salt candidates to try.
    //    - Modern payloads: server returns the actual kdf_salt → try it first
    //    - Legacy payloads (server didn't store kdf_salt): try zero-byte salt as fallback
    //    We skip HMAC verification entirely — XChaCha20-Poly1305 decryption below
    //    provides strong authentication (wrong password/salt = MAC verification failure).
    let mut salt_candidates: Vec<[u8; 32]> = Vec::new();

    if !payload.kdf_salt.is_empty() {
        match decode_salt(&payload.kdf_salt) {
            Ok(s) => { salt_candidates.push(s); }
            Err(e) => {
                eprintln!("[RESTORE] could not decode server kdf_salt: {e}");
            }
        }
    }
    // Always add zero-byte fallback (for legacy blobs / future-proof)
    salt_candidates.push([0u8; 32]);

    // 3. Try each salt — decrypt until one works (AEAD provides authentication)
    let mut vault_json: Option<String> = None;
    let mut used_kdf_salt = String::new();

    for salt_bytes in &salt_candidates {
        let master_key = match derive_master_key(&master_password, salt_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let keys = match derive_subkeys(&master_key) {
            Ok(k) => k,
            Err(_) => continue,
        };
        match crate::crypto::decrypt_string(&keys.sync_key, &payload.encrypted_vault) {
            Ok(json) => {
                vault_json = Some(json);
                // Record which salt worked
                if salt_bytes == &[0u8; 32] && !payload.kdf_salt.is_empty() {
                    used_kdf_salt = payload.kdf_salt.clone();
                } else if salt_bytes == &[0u8; 32] {
                    used_kdf_salt = String::new();
                } else {
                    used_kdf_salt = payload.kdf_salt.clone();
                }
                break;
            }
            Err(_) => continue,
        }
    }

    let vault_json = vault_json.ok_or_else(|| map_err(anyhow::anyhow!(
        "Wrong master password. Use the EXACT same password you set up on your original device."
    )))?;

    // 4. Bootstrap local vault
    let meta = {
        let vault = state.vault.lock().map_err(map_err)?;
        let mut meta = vault.create(&master_password).map_err(map_err)?;
        // Overwrite with the server's salt so future syncs use consistent keys
        if !used_kdf_salt.is_empty() {
            vault.overwrite_salt(&used_kdf_salt, &master_password).map_err(map_err)?;
            meta.salt = used_kdf_salt;
        }
        vault.import_json(&vault_json).map_err(map_err)?;
        meta
    };

    let _ = app.emit("vault://refreshed", ());
    Ok(meta)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OS SECURITY COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn security_check_device() -> CmdResult<crate::os_security::SecurityPostureResult> {
    Ok(crate::os_security::check_device_integrity())
}

#[tauri::command]
pub fn security_biometric_info() -> CmdResult<serde_json::Value> {
    Ok(crate::os_security::get_biometric_info())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTO-LOCK COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn set_auto_lock_timeout(seconds: u64, state: State<'_, AppState>) -> CmdResult<()> {
    *state.auto_lock_timeout_secs.lock().map_err(map_err)? = seconds;
    Ok(())
}

#[tauri::command]
pub fn check_auto_lock(state: State<'_, AppState>) -> CmdResult<bool> {
    let timeout = *state.auto_lock_timeout_secs.lock().map_err(map_err)?;
    if timeout == 0 {
        return Ok(false);
    }
    let last = *state.last_activity.lock().map_err(map_err)?;
    let now = chrono::Utc::now().timestamp();
    let should_lock = (now - last) > timeout as i64;
    if should_lock {
        let vault = state.vault.lock().map_err(map_err)?;
        vault.lock();
    }
    Ok(should_lock)
}

#[tauri::command]
pub fn record_activity(state: State<'_, AppState>) -> CmdResult<()> {
    state.touch();
    Ok(())
}
