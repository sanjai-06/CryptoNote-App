// src-tauri/src/lib.rs
// CryptoNote – Tauri IPC bridge: registers commands and app state

use std::sync::Mutex;
use tauri::State;

pub mod ai;
pub mod commands;
pub mod crypto;
pub mod os_security;
pub mod sync;
pub mod vault;

// Glob import brings both the fn AND the __cmd__xxx macro into scope,
// which is required for tauri::generate_handler! to work.
#[allow(unused_imports)]
use commands::*;

use sync::{SyncConfig, SyncEngine};

// ─── Global application state ─────────────────────────────────────────────────
pub struct AppState {
    pub vault:                  Mutex<vault::Vault>,
    pub anomaly_detector:       Mutex<ai::AnomalyDetector>,
    pub phishing_detector:      ai::PhishingDetector,
    pub sync_engine:            Mutex<SyncEngine>,
    pub auto_lock_timeout_secs: Mutex<u64>,
    pub last_activity:          Mutex<i64>,
}

impl AppState {
    pub fn new(vault_path: String) -> Self {
        Self {
            vault:                  Mutex::new(vault::Vault::new(vault_path)),
            anomaly_detector:       Mutex::new(ai::AnomalyDetector::new()),
            phishing_detector:      ai::PhishingDetector::new(),
            sync_engine:            Mutex::new(SyncEngine::new(SyncConfig::default())),
            auto_lock_timeout_secs: Mutex::new(300),
            last_activity:          Mutex::new(chrono::Utc::now().timestamp()),
        }
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap() = chrono::Utc::now().timestamp();
    }
}

// ─── Error helper ─────────────────────────────────────────────────────────────
pub type CmdResult<T> = Result<T, String>;

pub fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ─── App entry point ──────────────────────────────────────────────────────────
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vault_path = dirs_next::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("CryptoNote")
        .join("vault.db");

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
