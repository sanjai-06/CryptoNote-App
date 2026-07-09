/**
 * CryptoNote Sync Server
 * This is the file Render actually runs (start command: node server-minimal.js)
 * Contains: vault push/pull with kdf_salt, force-push, patch-salt endpoint
 */

require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const mongoose = require('mongoose');

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabled — API-only server

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (origin.startsWith('tauri://') || origin.startsWith('https://tauri.')) return callback(null, true);
        if (process.env.NODE_ENV === 'production') return callback(null, true);
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
}));

app.use(express.json({ limit: '10mb' }));

// ── VaultBlob schema (includes kdf_salt for cross-device restore) ─────────────
const VaultBlobSchema = new mongoose.Schema({
    user_id:         { type: String, required: true, index: true },
    device_id:       String,
    version:         { type: Number, required: true },
    timestamp:       Number,
    encrypted_vault: Object,
    hmac:            String,
    sequence:        Number,
    size_bytes:      Number,
    kdf_salt:        { type: String, default: '' }, // plaintext Argon2 salt for cross-device restore
});
const VaultBlob = mongoose.models.VaultBlob || mongoose.model('VaultBlob', VaultBlobSchema);

// ── Root status page ──────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>CryptoNote Sync Server</title>
<style>*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px 48px;max-width:480px;width:100%;text-align:center}
.dot{display:inline-block;width:10px;height:10px;background:#3fb950;border-radius:50%;margin-right:8px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
h1{font-size:1.6rem;font-weight:700;margin:20px 0 8px}
.sub{color:#8b949e;font-size:.9rem;margin-bottom:28px}
.badge{display:inline-flex;align-items:center;background:#1f2937;border:1px solid #374151;border-radius:20px;padding:6px 16px;font-size:.85rem;color:#3fb950;font-weight:600}
.info{margin-top:28px;text-align:left;background:#0d1117;border-radius:8px;padding:16px;font-size:.8rem;color:#8b949e;line-height:1.8}
.info strong{color:#c9d1d9}</style></head>
<body><div class="card">
<svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
<h1>CryptoNote</h1><p class="sub">Zero-knowledge encrypted sync server</p>
<div class="badge"><span class="dot"></span>Server is online</div>
<div class="info"><strong>What is this?</strong><br>
Backend sync server for the CryptoNote password manager.<br><br>
<strong>Is my data safe?</strong><br>
Yes — only encrypted blobs are stored. Your master password never leaves your device.<br><br>
<strong>API health:</strong> <a href="/health" style="color:#58a6ff">/health</a></div>
</div></body></html>`);
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'cryptonote-sync', timestamp: Date.now() });
});

// ── Push vault ────────────────────────────────────────────────────────────────
app.post('/api/vault/push', async (req, res) => {
    try {
        const { user_id, device_id, version, timestamp, encrypted_vault, hmac, sequence, kdf_salt, force } = req.body;
        if (!user_id || !encrypted_vault) return res.status(400).json({ error: 'Missing required fields' });

        const sizeBytes = JSON.stringify(encrypted_vault).length;
        const existing  = await VaultBlob.findOne({ user_id }).sort({ version: -1 });

        // Conflict check — skip when force=true
        if (!force && existing && existing.version > version) {
            return res.status(200).json({
                status: 'conflict',
                server_version: existing.version,
                message: 'Server has a newer version. Use force push or pull first.',
            });
        }

        // Force push: bump version beyond server's
        const effectiveVersion = (force && existing) ? existing.version + 1 : version;

        await VaultBlob.findOneAndUpdate(
            { user_id },
            { user_id, device_id, version: effectiveVersion, timestamp, encrypted_vault,
              hmac, sequence, size_bytes: sizeBytes, kdf_salt: kdf_salt || '' },
            { upsert: true, new: true }
        );

        console.log(`[PUSH] user=${user_id} version=${effectiveVersion} kdf_salt=${kdf_salt ? 'present' : 'empty'} force=${!!force}`);
        res.status(200).json({ status: 'synced', server_version: effectiveVersion });
    } catch (err) {
        console.error('[PUSH] error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ── Pull vault ────────────────────────────────────────────────────────────────
app.get('/api/vault/pull/:user_id', async (req, res) => {
    try {
        const blob = await VaultBlob.findOne({ user_id: req.params.user_id }).sort({ version: -1 });
        if (!blob) return res.status(404).json({ status: 'not_found' });
        console.log(`[PULL] user=${req.params.user_id} version=${blob.version} kdf_salt=${blob.kdf_salt ? 'present' : 'empty'}`);
        res.json({ status: 'ok', server_version: blob.version, payload: blob });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Patch kdf_salt on old blobs (called by client after first sync) ───────────
app.post('/api/vault/patch-salt', async (req, res) => {
    try {
        const { user_id, kdf_salt } = req.body;
        if (!user_id || !kdf_salt) return res.status(400).json({ error: 'Missing user_id or kdf_salt' });

        const result = await VaultBlob.findOneAndUpdate(
            { user_id },
            { $set: { kdf_salt } },
            { new: true, sort: { version: -1 } }
        );
        if (!result) return res.status(404).json({ error: 'No vault found for this user' });
        console.log(`[PATCH-SALT] user=${user_id} kdf_salt updated`);
        res.json({ status: 'ok', server_version: result.version });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Auth stubs (app handles auth internally via vault password) ───────────────
app.post('/api/auth/register', (req, res) => res.json({ status: 'ok', message: 'Vault auth is handled client-side' }));
app.post('/api/auth/login',    (req, res) => res.json({ status: 'ok', message: 'Vault auth is handled client-side' }));
app.post('/api/auth/logout',   (req, res) => res.json({ status: 'ok' }));

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Route not found', code: 'NOT_FOUND' }));

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
    if (process.env.MONGO_URI) {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('[DB] MongoDB connected');
    } else {
        console.warn('[DB] No MONGO_URI — running without database');
    }
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`[SERVER] CryptoNote sync server on port ${PORT}`));
}

start().catch(err => { console.error('[FATAL]', err); process.exit(1); });
