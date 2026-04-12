# CryptoNote – Offline-First Zero-Knowledge Password Manager

> **Maximum security. Zero trust. Works anywhere.**

CryptoNote is a cross-platform password manager built with **Tauri 2.0**, **React**, **Rust**, and **Node.js + MongoDB**. It uses a zero-knowledge architecture — your master password and vault contents never leave your device unencrypted.

---

## 🔐 Security Architecture

| Layer | Technology |
|-------|-----------|
| Key Derivation | Argon2id (64 MiB, 3 passes, 4 threads) |
| Subkey Derivation | HKDF-SHA256 (vault, hmac, sync, device keys) |
| Encryption | XChaCha20-Poly1305 (authenticated) |
| Storage | SQLite with per-entry encryption |
| Memory | Zeroize on vault lock |
| Sync Auth | SHA-256(device_key) — server never sees master password |
| Sync Transport | TLS 1.3 + certificate pinning |
| Replay Protection | Monotonic sequence + HMAC-SHA256 |

## 🧱 Project Structure

```
CryptoNote-App/
├── src-ui/            # React + TypeScript frontend (Vite)
│   └── src/
│       ├── pages/     # Unlock, Setup, Vault, Settings, ItemDetail
│       ├── components/ # PasswordGenerator, SecurityAlert, SyncStatus
│       ├── hooks/     # Tauri IPC wrappers
│       ├── store/     # Zustand global state
│       └── types/     # TypeScript types
├── src-tauri/         # Rust security core (Tauri 2.0)
│   └── src/
│       ├── crypto/    # Argon2id, HKDF, XChaCha20-Poly1305
│       ├── vault/     # SQLite vault, per-entry encryption, zeroize
│       ├── ai/        # Anomaly detection, phishing detection
│       ├── os_security/ # Keychain integration (platform stubs)
│       ├── sync/      # Encrypted sync engine, TLS pinning
│       └── lib.rs     # Tauri command registration
└── server/            # Node.js + Express encrypted sync backend
    └── src/
        ├── models/    # User (ZK), VaultBlob
        ├── routes/    # auth, vault, device
        └── middleware/ # rateLimiter, replayProtection
```

## 🚀 Development Setup

### Prerequisites
- Rust ≥ 1.77 + `cargo`
- Node.js ≥ 20 + `npm`
- MongoDB ≥ 6
- (Linux) `libssl-dev`, `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`

### Run the Tauri app
```bash
npm install
npm run tauri:dev
```

### Run the sync server
```bash
cd server
cp .env.example .env   # Edit JWT_SECRET!
npm install
npm run dev
```

### Run Rust tests
```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

### Run server tests
```bash
cd server
npm test
```

## 🌐 Platforms

| Platform | Status |
|----------|--------|
| 🐧 Linux | ✅ Ready |
| 🪟 Windows | ✅ Ready |
| 🍎 macOS | ✅ Ready |
| 📱 Android | ⚙️ SDK required (NDK) |
| 📱 iOS | ⚙️ SDK required (Xcode) |

## ⚠️ Security Notes

- **Master password**: Never stored, never transmitted. Forget it → vault is unrecoverable (by design).
- **Server**: Stores only encrypted blobs. Cannot read your data.
- **OS Keychain**: Native keychain integrations are stubbed with `TODO` — implement with platform SDKs before production.
- **TLS cert**: Set real cert paths in `server/.env` before production deployment.
- **JWT_SECRET**: Must be replaced with a 256-bit random key.# DevOps Pipeline Active
