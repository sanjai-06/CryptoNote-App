// src-tauri/src/lib.rs
// CryptoNote – Tauri IPC bridge: registers commands and app state

use std::sync::Mutex;

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

#[cfg(desktop)]
pub mod native_messaging_server;

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

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default();

    // Desktop-only plugins
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ));
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .setup(|app| {
            #[cfg(desktop)]
            {
                // 1. Auto-install Native Messaging Host JSON
                native_messaging_server::auto_install_nmh();
                
                // 2. Start Native Messaging TCP server
                native_messaging_server::start_server(app.handle().clone());
                
                // 3. System Tray Setup
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                use tauri::{Manager, Emitter};

                let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
                let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&lock_i, &quit_i])?;

                let _tray = TrayIconBuilder::new()
                    .icon(app.default_window_icon().unwrap().clone())
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "lock" => {
                            let state = app.state::<AppState>();
                            let vault = state.vault.lock().unwrap();
                            vault.lock();
                            let _ = app.emit("vault-locked", ());
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.unminimize();
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .build(app)?;
            }

            Ok(())
        })
        .on_window_event(|_window, _event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = _event {
                // Intercept close event and hide window instead
                let _ = _window.hide();
                api.prevent_close();
            }
        })
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
            sync_push,
            sync_pull,
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
