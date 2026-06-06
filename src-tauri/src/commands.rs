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
    // Extract vault data + salt (sync, no await needed)
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
    }; // vault lock released here

    eprintln!("[SYNC] vault exported v{}, kdf_salt present={}, building push future...", local_version, !kdf_salt.is_empty());

    let push_fut = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        engine.push_owned(vault_json, local_version, sync_key, hmac_key, kdf_salt)
    };

    match push_fut.await {
        Ok(s) => {
            eprintln!("[SYNC] push ok: {:?}", s);
            let _ = app.emit("vault://changed", ());
            Ok(())
        }
        Err(e) => { eprintln!("[SYNC] push FAILED: {}", e); Err(map_err(e)) }
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

    let imported = {
        let vault = state.vault.lock().map_err(map_err)?;
        if server_version > vault.version() {
            vault.import_json(&vault_json).map_err(map_err)?;
            true
        } else {
            false
        }
    };

    if imported {
        let _ = app.emit("vault://refreshed", ());
    }
    Ok(())
}

/// Bootstrap a new device from cloud sync WITHOUT requiring a local vault.
/// Flow: fetch payload → read kdf_salt → derive keys from password+salt → decrypt → create local vault.
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

    if payload.kdf_salt.is_empty() {
        return Err(map_err(anyhow::anyhow!(
            "Server vault was created with an older version that doesn't include the KDF salt. \n\nPlease open CryptoNote on your original device, go to Settings → Sync → push once to upgrade the sync format, then try again."
        )));
    }

    // 2. Derive sync keys using the password + salt from the server payload
    let salt_bytes = decode_salt(&payload.kdf_salt)
        .map_err(|e| map_err(anyhow::anyhow!("Invalid KDF salt in server payload: {}", e)))?;
    let master_key = derive_master_key(&master_password, &salt_bytes)
        .map_err(map_err)?;
    let keys = derive_subkeys(&master_key).map_err(map_err)?;

    // 3. Verify HMAC
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
    let expected = BASE64_STD
        .decode(&payload.hmac)
        .map_err(|_| map_err(anyhow::anyhow!("Invalid HMAC in server payload")))?;
    if !crate::crypto::verify_hmac(&keys.hmac_key, hmac_input.as_bytes(), &expected) {
        return Err(map_err(anyhow::anyhow!(
            "Wrong master password or the data was tampered with."
        )));
    }

    // 4. Decrypt vault JSON
    let vault_json = crate::crypto::decrypt_string(&keys.sync_key, &payload.encrypted_vault)
        .map_err(|_| map_err(anyhow::anyhow!("Decryption failed – wrong master password?")))? ;

    // 5. Bootstrap local vault: create with same password (generates new salt!) then import
    //    We must write the original salt into the DB so future syncs use consistent keys.
    let meta = {
        let vault = state.vault.lock().map_err(map_err)?;
        // Create vault (generates new DB with schema)
        let mut meta = vault.create(&master_password).map_err(map_err)?;
        // Overwrite the auto-generated salt with the server's salt so keys stay consistent
        vault.overwrite_salt(&payload.kdf_salt, &master_password).map_err(map_err)?;
        meta.salt = payload.kdf_salt.clone();
        // Import all entries from server
        vault.import_json(&vault_json).map_err(map_err)?;
        meta
    };

    // 6. Emit refresh event
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
