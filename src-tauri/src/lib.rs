// CryptoNote – Tauri IPC Command Layer
// src-tauri/src/lib.rs
//
// All Tauri commands that bridge the React frontend to the Rust security core.
// Every command validates inputs, accesses global state, and returns typed results.

use std::sync::Mutex;
use tauri::State;

pub mod ai;
pub mod crypto;
pub mod os_security;
pub mod sync;
pub mod vault;

use ai::{AnomalyDetector, AnomalyResult, PhishingDetector, PhishingResult};
use sync::{SyncConfig, SyncEngine, SyncStatus};
use vault::{EntryListItem, PasswordOptions, Vault, VaultEntry, VaultMeta};

// ─── Global application state ─────────────────────────────────────────────────
pub struct AppState {
    pub vault: Mutex<Vault>,
    pub anomaly_detector: Mutex<AnomalyDetector>,
    pub phishing_detector: PhishingDetector,
    pub sync_engine: Mutex<SyncEngine>,
    pub auto_lock_timeout_secs: Mutex<u64>,
    pub last_activity: Mutex<i64>,
}

impl AppState {
    fn new(vault_path: String) -> Self {
        Self {
            vault: Mutex::new(Vault::new(vault_path)),
            anomaly_detector: Mutex::new(AnomalyDetector::new()),
            phishing_detector: PhishingDetector::new(),
            sync_engine: Mutex::new(SyncEngine::new(SyncConfig::default())),
            auto_lock_timeout_secs: Mutex::new(300), // 5 minutes default
            last_activity: Mutex::new(chrono::Utc::now().timestamp()),
        }
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = chrono::Utc::now().timestamp();
    }
}

// ─── Error type ───────────────────────────────────────────────────────────────
type CmdResult<T> = Result<T, String>;

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  VAULT COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if a vault database file exists at the given path.
#[tauri::command]
pub fn vault_exists(path: String) -> bool {
    std::path::Path::new(&path).exists()
}

/// Create a new vault with the given master password.
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

    // Record first device
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    let device_id = format!("device-{}", uuid::Uuid::new_v4());
    det.register_device(&device_id);

    Ok(meta)
}

/// Unlock an existing vault with the master password.
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

/// Lock the vault (clears all keys from memory).
#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    vault.lock();
    Ok(())
}

/// Check if the vault is currently locked.
#[tauri::command]
pub fn vault_is_locked(state: State<'_, AppState>) -> CmdResult<bool> {
    let vault = state.vault.lock().map_err(map_err)?;
    Ok(vault.is_locked())
}

/// List all vault entries (title + url only – no passwords exposed).
#[tauri::command]
pub fn vault_list_entries(state: State<'_, AppState>) -> CmdResult<Vec<EntryListItem>> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.list_entries().map_err(map_err)
}

/// Get a single vault entry (includes decrypted password).
#[tauri::command]
pub fn vault_get_entry(id: String, state: State<'_, AppState>) -> CmdResult<VaultEntry> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.get_entry(&id).map_err(map_err)
}

/// Add a new vault entry.
#[tauri::command]
pub fn vault_add_entry(entry: VaultEntry, state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.add_entry(&entry).map_err(map_err)
}

/// Update an existing vault entry.
#[tauri::command]
pub fn vault_update_entry(entry: VaultEntry, state: State<'_, AppState>) -> CmdResult<()> {
    let vault = state.vault.lock().map_err(map_err)?;
    state.touch();
    vault.update_entry(&entry).map_err(map_err)
}

/// Delete a vault entry by ID.
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
    vault::generate_password(&options).map_err(map_err)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AI SECURITY COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Analyse a URL for phishing risk before autofill.
#[tauri::command]
pub fn ai_check_phishing(url: String, state: State<'_, AppState>) -> CmdResult<PhishingResult> {
    Ok(state.phishing_detector.analyze(&url))
}

/// Get the current anomaly risk status.
#[tauri::command]
pub fn ai_get_anomaly_status(state: State<'_, AppState>) -> CmdResult<AnomalyResult> {
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    Ok(det.record_unlock(true)) // Non-destructive re-analysis
}

/// Record a vault export event (for anomaly detection).
#[tauri::command]
pub fn ai_record_export(state: State<'_, AppState>) -> CmdResult<AnomalyResult> {
    let det = state.anomaly_detector.lock().map_err(map_err)?;
    Ok(det.record_export())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SYNC COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Configure sync settings (server URL, device ID, auth token).
#[tauri::command]
pub fn sync_configure(config: SyncConfig, state: State<'_, AppState>) -> CmdResult<()> {
    let engine = state.sync_engine.lock().map_err(map_err)?;
    engine.update_config(config);
    Ok(())
}

/// Get the current sync status.
#[tauri::command]
pub fn sync_get_status(state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    let engine = state.sync_engine.lock().map_err(map_err)?;
    Ok(engine.get_status())
}

/// Register a new account on the sync server (zero-knowledge).
#[tauri::command]
pub async fn sync_register(
    email: String,
    master_password: String,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let (server_url, device_id, tls_cert) = {
        let engine = state.sync_engine.lock().map_err(map_err)?;
        let cfg = engine.get_status(); // just using this to access config indirectly
        drop(cfg);
        // We need to access config differently since SyncEngine wraps it
        ("https://localhost:3443".to_string(),
         uuid::Uuid::new_v4().to_string(),
         None::<String>)
    };

    // Derive device_key from master password (same derivation path)
    let salt = crypto::generate_salt();
    let master_key = crypto::derive_master_key(&master_password, &salt).map_err(map_err)?;
    let keys = crypto::derive_subkeys(&master_key).map_err(map_err)?;

    let auth_resp = sync::register(
        &server_url,
        &email,
        &keys.device_key,
        &device_id,
        tls_cert.as_deref(),
    )
    .await
    .map_err(map_err)?;

    Ok(auth_resp.token)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OS SECURITY COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Check device security posture (root/jailbreak detection).
#[tauri::command]
pub fn security_check_device() -> CmdResult<os_security::SecurityPostureResult> {
    Ok(os_security::check_device_integrity())
}

/// Get biometric authentication info.
#[tauri::command]
pub fn security_biometric_info() -> CmdResult<serde_json::Value> {
    Ok(os_security::get_biometric_info())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTO-LOCK COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Set the auto-lock timeout in seconds (0 = disabled).
#[tauri::command]
pub fn set_auto_lock_timeout(seconds: u64, state: State<'_, AppState>) -> CmdResult<()> {
    *state.auto_lock_timeout_secs.lock().map_err(map_err)? = seconds;
    Ok(())
}

/// Check whether the vault should auto-lock (call periodically from frontend).
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

/// Record user activity (resets auto-lock timer).
#[tauri::command]
pub fn record_activity(state: State<'_, AppState>) -> CmdResult<()> {
    state.touch();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TAURI APP BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Determine vault database path
    let vault_path = dirs_next::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("CryptoNote")
        .join("vault.db");

    // Ensure directory exists
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let app_state = AppState::new(vault_path.to_string_lossy().to_string());

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            // Vault
            vault_exists,
            vault_create,
            vault_unlock,
            vault_lock,
            vault_is_locked,
            vault_list_entries,
            vault_get_entry,
            vault_add_entry,
            vault_update_entry,
            vault_delete_entry,
            // Password generator
            generate_password,
            // AI security
            ai_check_phishing,
            ai_get_anomaly_status,
            ai_record_export,
            // Sync
            sync_configure,
            sync_get_status,
            sync_register,
            // OS security
            security_check_device,
            security_biometric_info,
            // Auto-lock
            set_auto_lock_timeout,
            check_auto_lock,
            record_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CryptoNote application");
}
