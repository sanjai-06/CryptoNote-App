// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Check if launched by browser as native messaging host
    if args.iter().any(|a| a == "--native-messaging" || a.starts_with("chrome-extension://")) {
        run_native_messaging_host();
        return;
    }

    cryptonote_lib::run();
}

fn run_native_messaging_host() {
    // Determine where the NMH port config is stored
    let nmh_file = dirs_next::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("CryptoNote")
        .join("nmh.json");

    let config = match std::fs::read_to_string(&nmh_file) {
        Ok(c) => c,
        Err(_) => {
            // Main app isn't running
            send_native_message(&serde_json::json!({ "error": "CryptoNote app is not running" }));
            return;
        }
    };

    #[derive(serde::Deserialize)]
    struct NmhConfig {
        port: u16,
        token: String,
    }

    let config: NmhConfig = match serde_json::from_str(&config) {
        Ok(c) => c,
        Err(_) => {
            send_native_message(&serde_json::json!({ "error": "Invalid NMH config" }));
            return;
        }
    };

    // Read message from browser
    loop {
        let msg = match read_native_message() {
            Ok(Some(m)) => m,
            Ok(None) => break, // EOF
            Err(e) => {
                // Ignore silent errors
                break;
            }
        };

        // Forward to the running Tauri app via TCP
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", config.port)) {
            // Write token
            let token_bytes = config.token.as_bytes();
            let _ = stream.write_all(&(token_bytes.len() as u32).to_le_bytes());
            let _ = stream.write_all(token_bytes);
            
            // Write message length
            let _ = stream.write_all(&(msg.len() as u32).to_le_bytes());
            // Write message
            let _ = stream.write_all(&msg);
            let _ = stream.flush();

            // Read response length
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_ok() {
                let resp_len = u32::from_le_bytes(len_buf) as usize;
                // Cap to reasonable size (10MB)
                if resp_len < 10 * 1024 * 1024 {
                    let mut resp_buf = vec![0u8; resp_len];
                    if stream.read_exact(&mut resp_buf).is_ok() {
                        // Send back to browser
                        if let Ok(resp_str) = String::from_utf8(resp_buf) {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_str) {
                                send_native_message(&json);
                            }
                        }
                    }
                }
            }
        } else {
            send_native_message(&serde_json::json!({ "error": "CryptoNote app is not running" }));
        }
    }
}

fn read_native_message() -> io::Result<Option<Vec<u8>>> {
    let mut stdin = io::stdin();
    let mut len_buf = [0u8; 4];
    let bytes_read = stdin.read(&mut len_buf)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if bytes_read < 4 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Failed to read length"));
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
    }
    let mut msg_buf = vec![0u8; len];
    stdin.read_exact(&mut msg_buf)?;
    Ok(Some(msg_buf))
}

fn send_native_message(msg: &serde_json::Value) {
    let msg_str = serde_json::to_string(msg).unwrap();
    let len = msg_str.len() as u32;
    let mut stdout = io::stdout();
    let _ = stdout.write_all(&len.to_le_bytes());
    let _ = stdout.write_all(msg_str.as_bytes());
    let _ = stdout.flush();
}
