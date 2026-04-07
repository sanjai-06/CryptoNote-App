// src-tauri/src/main.rs
// Prevents additional console window on Windows in release mode
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    cryptonote_lib::run();
}
