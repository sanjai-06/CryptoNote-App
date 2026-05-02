// src-tauri/src/commands.rs
// All #[tauri::command] functions, separated from lib.rs to avoid
// E0255 macro name conflicts (Tauri 2 generates __cmd__xxx names)

use tauri::State;
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
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let server_url = "https://localhost:3443".to_string();
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
) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    let (sync_key, hmac_key) = vault.get_sync_keys().map_err(map_err)?;
    
    let vault_json = vault.export_json().map_err(map_err)?;
    let local_version = vault.version();
    drop(vault);

    let engine = state.sync_engine.lock().map_err(map_err)?;
    engine.push(vault_json, local_version, &sync_key, &hmac_key).await.map_err(map_err)?;
    
    Ok(())
}

#[tauri::command]
pub async fn sync_pull(
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    let (sync_key, hmac_key) = vault.get_sync_keys().map_err(map_err)?;
    drop(vault);
    
    let engine = state.sync_engine.lock().map_err(map_err)?;
    let (vault_json, server_version) = engine.pull(&sync_key, &hmac_key).await.map_err(map_err)?;
    drop(engine);
    
    let mut vault = state.vault.lock().map_err(map_err)?;
    // If the server version is newer, overwrite the local vault
    if server_version > vault.version() {
        vault.import_json(&vault_json).map_err(map_err)?;
    }
    
    Ok(())
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
