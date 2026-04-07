// CryptoNote – Vault Module
// src-tauri/src/vault/mod.rs
//
// Local encrypted vault backed by SQLite.
// Each entry is individually encrypted with XChaCha20-Poly1305.
// The vault key never leaves RAM; it is zeroized on lock.

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    self, decrypt_string, encode_salt, encrypt_string, DerivedKeys, SecureKey,
};

// ─── Vault entry ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,       // plaintext – only exists in memory after decrypt
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: i64,
}

/// Serialised form stored in the database (all sensitive fields encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultEntryEncrypted {
    id: String,
    title_enc: String,          // JSON-serialised EncryptedData
    username_enc: String,
    password_enc: String,
    url_enc: Option<String>,
    notes_enc: Option<String>,
    totp_enc: Option<String>,
    tags_enc: String,
    created_at: i64,
    updated_at: i64,
    version: i64,
}

// ─── Vault metadata ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub vault_id: String,
    pub salt: String,           // base64-encoded Argon2 salt
    pub created_at: i64,
    pub version: i64,
    pub sync_version: i64,
}

// ─── In-memory vault state ────────────────────────────────────────────────────
#[derive(ZeroizeOnDrop)]
struct VaultState {
    keys: DerivedKeys,
}

pub struct Vault {
    db_path: String,
    state: Arc<Mutex<Option<VaultState>>>,
}

impl Vault {
    pub fn new(db_path: String) -> Self {
        Self {
            db_path,
            state: Arc::new(Mutex::new(None)),
        }
    }

    fn open_db(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| anyhow!("Failed to open vault DB: {}", e))?;
        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| anyhow!("PRAGMA error: {}", e))?;
        Ok(conn)
    }

    /// Create a new vault from a master password.
    pub fn create(&self, master_password: &str) -> Result<VaultMeta> {
        let salt = crypto::generate_salt();
        let master_key = crypto::derive_master_key(master_password, &salt)?;
        let keys = crypto::derive_subkeys(&master_key)?;

        let conn = self.open_db()?;
        self.init_schema(&conn)?;

        let meta = VaultMeta {
            vault_id: Uuid::new_v4().to_string(),
            salt: encode_salt(&salt),
            created_at: chrono::Utc::now().timestamp(),
            version: 1,
            sync_version: 0,
        };

        let meta_json = serde_json::to_string(&meta)?;
        // Store meta as an encrypted blob so it's not plaintext on disk
        let enc_meta = encrypt_string(&keys.vault_key, &meta_json)?;
        let enc_meta_json = serde_json::to_string(&enc_meta)?;

        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('salt', ?1), ('meta_enc', ?2), ('vault_id', ?3)",
            params![encode_salt(&salt), enc_meta_json, meta.vault_id],
        )
        .map_err(|e| anyhow!("Failed to store meta: {}", e))?;

        // Store keys in memory
        let mut state = self.state.lock().unwrap();
        *state = Some(VaultState { keys });

        Ok(meta)
    }

    /// Unlock an existing vault with the master password.
    pub fn unlock(&self, master_password: &str) -> Result<VaultMeta> {
        let conn = self.open_db()?;

        // Load salt
        let salt_b64: String = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'salt'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| anyhow!("Vault not initialised – no salt found"))?;

        let salt = crypto::decode_salt(&salt_b64)?;
        let master_key = crypto::derive_master_key(master_password, &salt)?;
        let keys = crypto::derive_subkeys(&master_key)?;

        // Verify by decrypting meta
        let meta_enc_json: String = conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'meta_enc'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| anyhow!("Vault meta not found"))?;

        let enc_data: crate::crypto::EncryptedData =
            serde_json::from_str(&meta_enc_json)
                .map_err(|_| anyhow!("Corrupted vault meta"))?;

        let meta_json = decrypt_string(&keys.vault_key, &enc_data)
            .map_err(|_| anyhow!("Invalid master password"))?;

        let meta: VaultMeta =
            serde_json::from_str(&meta_json).map_err(|_| anyhow!("Corrupted metadata"))?;

        // Store keys in memory
        let mut state = self.state.lock().unwrap();
        *state = Some(VaultState { keys });

        Ok(meta)
    }

    /// Lock the vault – zeroise keys from memory.
    pub fn lock(&self) {
        let mut state = self.state.lock().unwrap();
        *state = None; // ZeroizeOnDrop handles wiping
    }

    pub fn is_locked(&self) -> bool {
        self.state.lock().unwrap().is_none()
    }

    /// Add a new vault entry. Encrypts every sensitive field individually.
    pub fn add_entry(&self, entry: &VaultEntry) -> Result<()> {
        let state = self.state.lock().unwrap();
        let state = state.as_ref().ok_or_else(|| anyhow!("Vault is locked"))?;
        let key = &state.keys.vault_key;

        let enc = self.encrypt_entry(entry, key)?;
        let conn = self.open_db()?;
        self.insert_encrypted_entry(&conn, &enc)
    }

    /// Get a single decrypted entry by ID.
    pub fn get_entry(&self, id: &str) -> Result<VaultEntry> {
        let state = self.state.lock().unwrap();
        let state = state.as_ref().ok_or_else(|| anyhow!("Vault is locked"))?;
        let key = &state.keys.vault_key;

        let conn = self.open_db()?;
        let enc = self.load_encrypted_entry(&conn, id)?;
        self.decrypt_entry(&enc, key)
    }

    /// List all entries (metadata only – title and url decrypted, password NOT).
    pub fn list_entries(&self) -> Result<Vec<EntryListItem>> {
        let state = self.state.lock().unwrap();
        let state = state.as_ref().ok_or_else(|| anyhow!("Vault is locked"))?;
        let key = &state.keys.vault_key;

        let conn = self.open_db()?;
        let mut stmt = conn
            .prepare("SELECT id, title_enc, url_enc, updated_at, version FROM vault_entries")
            .map_err(|e| anyhow!("List query error: {}", e))?;

        let items = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| anyhow!("Query map error: {}", e))?
            .filter_map(|r| r.ok())
            .filter_map(|(id, title_enc, url_enc, updated_at, version)| {
                let title_data: crate::crypto::EncryptedData =
                    serde_json::from_str(&title_enc).ok()?;
                let title = decrypt_string(key, &title_data).ok()?;
                let url = url_enc.and_then(|u| {
                    let url_data: crate::crypto::EncryptedData =
                        serde_json::from_str(&u).ok()?;
                    decrypt_string(key, &url_data).ok()
                });
                Some(EntryListItem {
                    id,
                    title,
                    url,
                    updated_at,
                    version,
                })
            })
            .collect();

        Ok(items)
    }

    /// Update an existing vault entry.
    pub fn update_entry(&self, entry: &VaultEntry) -> Result<()> {
        let state = self.state.lock().unwrap();
        let state = state.as_ref().ok_or_else(|| anyhow!("Vault is locked"))?;
        let key = &state.keys.vault_key;

        let mut updated = entry.clone();
        updated.updated_at = chrono::Utc::now().timestamp();
        updated.version += 1;

        let enc = self.encrypt_entry(&updated, key)?;
        let conn = self.open_db()?;

        conn.execute(
            "UPDATE vault_entries SET title_enc=?1, username_enc=?2, password_enc=?3,
             url_enc=?4, notes_enc=?5, totp_enc=?6, tags_enc=?7,
             updated_at=?8, version=?9 WHERE id=?10",
            params![
                enc.title_enc,
                enc.username_enc,
                enc.password_enc,
                enc.url_enc,
                enc.notes_enc,
                enc.totp_enc,
                enc.tags_enc,
                enc.updated_at,
                enc.version,
                enc.id,
            ],
        )
        .map_err(|e| anyhow!("Update entry error: {}", e))?;

        Ok(())
    }

    /// Delete a vault entry by ID.
    pub fn delete_entry(&self, id: &str) -> Result<()> {
        if self.is_locked() {
            return Err(anyhow!("Vault is locked"));
        }
        let conn = self.open_db()?;
        conn.execute("DELETE FROM vault_entries WHERE id = ?1", params![id])
            .map_err(|e| anyhow!("Delete error: {}", e))?;
        Ok(())
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_entries (
                id           TEXT PRIMARY KEY,
                title_enc    TEXT NOT NULL,
                username_enc TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                url_enc      TEXT,
                notes_enc    TEXT,
                totp_enc     TEXT,
                tags_enc     TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                updated_at   INTEGER NOT NULL,
                version      INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_entries_updated ON vault_entries(updated_at);",
        )
        .map_err(|e| anyhow!("Schema init error: {}", e))
    }

    fn encrypt_entry(
        &self,
        entry: &VaultEntry,
        key: &SecureKey,
    ) -> Result<VaultEntryEncrypted> {
        let enc_field = |s: &str| -> Result<String> {
            let enc = encrypt_string(key, s)?;
            Ok(serde_json::to_string(&enc)?)
        };
        let enc_opt_field = |s: Option<&str>| -> Result<Option<String>> {
            match s {
                Some(v) => Ok(Some(enc_field(v)?)),
                None => Ok(None),
            }
        };

        let tags_json = serde_json::to_string(&entry.tags)?;

        Ok(VaultEntryEncrypted {
            id: entry.id.clone(),
            title_enc: enc_field(&entry.title)?,
            username_enc: enc_field(&entry.username)?,
            password_enc: enc_field(&entry.password)?,
            url_enc: enc_opt_field(entry.url.as_deref())?,
            notes_enc: enc_opt_field(entry.notes.as_deref())?,
            totp_enc: enc_opt_field(entry.totp_secret.as_deref())?,
            tags_enc: enc_field(&tags_json)?,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            version: entry.version,
        })
    }

    fn decrypt_entry(
        &self,
        enc: &VaultEntryEncrypted,
        key: &SecureKey,
    ) -> Result<VaultEntry> {
        let dec_field = |s: &str| -> Result<String> {
            let data: crate::crypto::EncryptedData = serde_json::from_str(s)?;
            decrypt_string(key, &data)
        };
        let dec_opt_field = |s: Option<&String>| -> Result<Option<String>> {
            match s {
                Some(v) => Ok(Some(dec_field(v)?)),
                None => Ok(None),
            }
        };

        let tags_json = dec_field(&enc.tags_enc)?;
        let tags: Vec<String> = serde_json::from_str(&tags_json)?;

        Ok(VaultEntry {
            id: enc.id.clone(),
            title: dec_field(&enc.title_enc)?,
            username: dec_field(&enc.username_enc)?,
            password: dec_field(&enc.password_enc)?,
            url: dec_opt_field(enc.url_enc.as_ref())?,
            notes: dec_opt_field(enc.notes_enc.as_ref())?,
            totp_secret: dec_opt_field(enc.totp_enc.as_ref())?,
            tags,
            created_at: enc.created_at,
            updated_at: enc.updated_at,
            version: enc.version,
        })
    }

    fn insert_encrypted_entry(&self, conn: &Connection, enc: &VaultEntryEncrypted) -> Result<()> {
        conn.execute(
            "INSERT INTO vault_entries
             (id, title_enc, username_enc, password_enc, url_enc, notes_enc, totp_enc,
              tags_enc, created_at, updated_at, version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                enc.id,
                enc.title_enc,
                enc.username_enc,
                enc.password_enc,
                enc.url_enc,
                enc.notes_enc,
                enc.totp_enc,
                enc.tags_enc,
                enc.created_at,
                enc.updated_at,
                enc.version,
            ],
        )
        .map_err(|e| anyhow!("Insert entry error: {}", e))?;
        Ok(())
    }

    fn load_encrypted_entry(&self, conn: &Connection, id: &str) -> Result<VaultEntryEncrypted> {
        conn.query_row(
            "SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc,
             totp_enc, tags_enc, created_at, updated_at, version
             FROM vault_entries WHERE id = ?1",
            params![id],
            |row| {
                Ok(VaultEntryEncrypted {
                    id: row.get(0)?,
                    title_enc: row.get(1)?,
                    username_enc: row.get(2)?,
                    password_enc: row.get(3)?,
                    url_enc: row.get(4)?,
                    notes_enc: row.get(5)?,
                    totp_enc: row.get(6)?,
                    tags_enc: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                    version: row.get(10)?,
                })
            },
        )
        .map_err(|_| anyhow!("Entry not found: {}", id))
    }
}

// ─── List item (safe to expose – no passwords) ────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryListItem {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub updated_at: i64,
    pub version: i64,
}

// ─── Password generator ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

pub fn generate_password(opts: &PasswordOptions) -> Result<String> {
    use rand::seq::SliceRandom;

    let mut charset = Vec::new();
    if opts.uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if opts.lowercase {
        charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if opts.digits {
        charset.extend_from_slice(b"0123456789");
    }
    if opts.symbols {
        charset.extend_from_slice(b"!@#$%^&*()-_=+[]{}|;:,.<>?");
    }
    if charset.is_empty() {
        return Err(anyhow!("At least one character class must be selected"));
    }
    if opts.length < 8 || opts.length > 512 {
        return Err(anyhow!("Password length must be between 8 and 512"));
    }

    let mut rng = rand::rngs::OsRng;
    let password: String = (0..opts.length)
        .map(|_| *charset.choose(&mut rng).unwrap() as char)
        .collect();
    Ok(password)
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_entry() -> VaultEntry {
        VaultEntry {
            id: Uuid::new_v4().to_string(),
            title: "GitHub".to_string(),
            username: "alice@example.com".to_string(),
            password: "correct-horse-battery-staple".to_string(),
            url: Some("https://github.com".to_string()),
            notes: Some("Work account".to_string()),
            totp_secret: None,
            tags: vec!["dev".to_string(), "work".to_string()],
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
            version: 1,
        }
    }

    #[test]
    fn test_vault_create_unlock() {
        let tmp = std::env::temp_dir().join(format!("cn_test_{}.db", Uuid::new_v4()));
        let vault = Vault::new(tmp.to_str().unwrap().to_string());

        vault.create("my-master-password").unwrap();
        assert!(!vault.is_locked());

        vault.lock();
        assert!(vault.is_locked());

        vault.unlock("my-master-password").unwrap();
        assert!(!vault.is_locked());

        // Wrong password should fail
        vault.lock();
        assert!(vault.unlock("wrong-password").is_err());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_vault_entry_crud() {
        let tmp = std::env::temp_dir().join(format!("cn_test_{}.db", Uuid::new_v4()));
        let vault = Vault::new(tmp.to_str().unwrap().to_string());
        vault.create("pw").unwrap();

        let entry = test_entry();
        let id = entry.id.clone();

        vault.add_entry(&entry).unwrap();

        let fetched = vault.get_entry(&id).unwrap();
        assert_eq!(fetched.title, entry.title);
        assert_eq!(fetched.password, entry.password);
        assert_eq!(fetched.tags, entry.tags);

        let list = vault.list_entries().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, entry.title);

        let mut updated = fetched.clone();
        updated.password = "new-password".to_string();
        vault.update_entry(&updated).unwrap();

        let re_fetched = vault.get_entry(&id).unwrap();
        assert_eq!(re_fetched.password, "new-password");

        vault.delete_entry(&id).unwrap();
        assert!(vault.list_entries().unwrap().is_empty());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_password_generator() {
        let opts = PasswordOptions {
            length: 32,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.len(), 32);
        // Two generated passwords should be different
        let pw2 = generate_password(&opts).unwrap();
        assert_ne!(pw, pw2);
    }
}
