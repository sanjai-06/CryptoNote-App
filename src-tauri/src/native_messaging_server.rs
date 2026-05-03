// src-tauri/src/native_messaging_server.rs
use crate::AppState;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tauri::{AppHandle, Manager};

pub fn start_server(app: AppHandle) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => return,
        };

        let port = listener.local_addr().unwrap().port();
        let token = uuid::Uuid::new_v4().to_string();

        let nmh_file = dirs_next::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("CryptoNote")
            .join("nmh.json");

        if let Ok(config_json) = serde_json::to_string(&serde_json::json!({
            "port": port,
            "token": token,
        })) {
            let _ = std::fs::write(&nmh_file, config_json);
        }

        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let app_handle = app.clone();
                let token_clone = token.clone();
                std::thread::spawn(move || {
                    handle_connection(stream, token_clone, app_handle);
                });
            }
        }
    });
}

fn handle_connection(mut stream: TcpStream, expected_token: String, app: AppHandle) {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() { return; }
    let token_len = u32::from_le_bytes(len_buf) as usize;
    if token_len > 1024 { return; }
    
    let mut token_buf = vec![0u8; token_len];
    if stream.read_exact(&mut token_buf).is_err() { return; }
    let received_token = String::from_utf8_lossy(&token_buf);
    
    if received_token != expected_token { return; }

    if stream.read_exact(&mut len_buf).is_err() { return; }
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    if msg_len > 10 * 1024 * 1024 { return; }
    
    let mut msg_buf = vec![0u8; msg_len];
    if stream.read_exact(&mut msg_buf).is_err() { return; }
    
    let msg_str = String::from_utf8_lossy(&msg_buf);
    if let Ok(json) = serde_json::from_str::<Value>(&msg_str) {
        let response = process_message(json, &app);
        let resp_str = serde_json::to_string(&response).unwrap();
        let _ = stream.write_all(&(resp_str.len() as u32).to_le_bytes());
        let _ = stream.write_all(resp_str.as_bytes());
    }
}

fn process_message(msg: Value, app: &AppHandle) -> Value {
    let state = app.state::<AppState>();
    
    let action = msg["action"].as_str().unwrap_or("");
    
    match action {
        "ping" => {
            let unlocked = !state.vault.lock().unwrap().is_locked();
            serde_json::json!({ "status": "ok", "unlocked": unlocked })
        }
        "get_logins" => {
            let vault = state.vault.lock().unwrap();
            if vault.is_locked() {
                return serde_json::json!({ "error": "Vault is locked" });
            }
            
            let url = msg["url"].as_str().unwrap_or("").to_lowercase();
            let mut matches = Vec::new();
            
            if let Ok(entries) = vault.list_entries() {
                for item in entries {
                    if let Some(ref item_url) = item.url {
                        if item_url.to_lowercase().contains(&url) || url.contains(&item_url.to_lowercase()) {
                            // Fetch full entry for password
                            if let Ok(full_entry) = vault.get_entry(&item.id) {
                                matches.push(serde_json::json!({
                                    "username": full_entry.username,
                                    "password": full_entry.password,
                                }));
                            }
                        }
                    }
                }
            }
            
            serde_json::json!({ "logins": matches })
        }
        "save_login" => {
            let vault = state.vault.lock().unwrap();
            if vault.is_locked() {
                return serde_json::json!({ "error": "Vault is locked" });
            }
            
            let url = msg["url"].as_str().unwrap_or("").to_string();
            let username = msg["username"].as_str().unwrap_or("").to_string();
            let password = msg["password"].as_str().unwrap_or("").to_string();
            
            // Note: Since this is native messaging, we don't have a direct way to pop up a webview 
            // dialog on the browser side easily, and the Tauri dialog plugin blocks the thread.
            // For MVP auto-save, we can just save it or send a notification.
            
            let new_entry = crate::vault::VaultEntry {
                id: uuid::Uuid::new_v4().to_string(),
                title: url.clone(),
                username,
                password,
                url: Some(url),
                notes: Some("Auto-saved from browser".to_string()),
                totp_secret: None,
                tags: vec!["autofill".to_string()],
                created_at: chrono::Utc::now().timestamp(),
                updated_at: chrono::Utc::now().timestamp(),
                version: 1,
            };
            
            if vault.add_entry(&new_entry).is_ok() {
                // Return success
                serde_json::json!({ "status": "saved" })
            } else {
                serde_json::json!({ "error": "Failed to save to vault" })
            }
        }
        _ => serde_json::json!({ "error": "Unknown action" })
    }
}
