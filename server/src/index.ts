// server/src/index.ts
// CryptoNote – Express sync server (zero-knowledge encrypted backend)

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { authRouter } from './routes/auth';
import { vaultRouter } from './routes/vault';
import { deviceRouter } from './routes/device';
import { replayProtection } from './middleware/replayProtection';
import { rateLimiter } from './middleware/rateLimiter';

dotenv.config();

const app = express();
const PORT = process.env.PORT ?? 3443;
const MONGO_URI = process.env.MONGO_URI ?? 'mongodb://localhost:27017/cryptonote';

// ── Security headers ────────────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'none'"],
            styleSrc: ["'unsafe-inline'"],   // needed for root status page
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// ── CORS – whitelist only Tauri app origins ─────────────────────────────────
app.use(cors({
    origin: (origin, callback) => {
        const allowed = ['tauri://localhost', 'https://tauri.localhost', 'http://localhost:1420'];
        if (!origin || allowed.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Origin not allowed'));
        }
    },
    credentials: true,
}));

app.use(express.json({ limit: '10mb' }));

// ── Global rate limiter (100 req/15min per IP) ───────────────────────────────
app.use(rateLimiter);

// ── Replay attack protection (applies to all state-mutating routes) ──────────
app.use('/api/vault', replayProtection);
app.use('/api/auth', replayProtection);

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth', authRouter);
app.use('/api/vault', vaultRouter);
app.use('/api/device', deviceRouter);

// ── Root status page (browser-visible) ───────────────────────────────────────
app.get('/', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CryptoNote Sync Server</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px 48px; max-width: 480px; width: 100%; text-align: center; }
  .dot { display: inline-block; width: 10px; height: 10px; background: #3fb950; border-radius: 50%; margin-right: 8px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  h1 { font-size: 1.6rem; font-weight: 700; margin: 20px 0 8px; letter-spacing: -0.5px; }
  .sub { color: #8b949e; font-size: 0.9rem; margin-bottom: 28px; }
  .badge { display: inline-flex; align-items: center; background: #1f2937; border: 1px solid #374151;
           border-radius: 20px; padding: 6px 16px; font-size: 0.85rem; color: #3fb950; font-weight: 600; }
  .info { margin-top: 28px; text-align: left; background: #0d1117; border-radius: 8px; padding: 16px; font-size: 0.8rem; color: #8b949e; line-height: 1.8; }
  .info strong { color: #c9d1d9; }
</style>
</head>
<body>
<div class="card">
  <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
  <h1>CryptoNote</h1>
  <p class="sub">Zero-knowledge encrypted sync server</p>
  <div class="badge"><span class="dot"></span>Server is online</div>
  <div class="info">
    <strong>What is this?</strong><br>
    This is the backend sync server for the CryptoNote password manager app.<br><br>
    <strong>Is my data safe?</strong><br>
    Yes — the server stores only encrypted blobs. Your master password and vault contents never leave your device unencrypted.<br><br>
    <strong>API health:</strong> <a href="/health" style="color:#58a6ff">/health</a>
  </div>
</div>
</body>
</html>`);
});

// ── Health check (JSON) ───────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'cryptonote-sync', timestamp: Date.now() }));

// ── 404 handler ──────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Route not found', code: 'NOT_FOUND' }));

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ── MongoDB connection ────────────────────────────────────────────────────────
async function start() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log('[DB] Connected to MongoDB');

        // In production, use `https.createServer({ key, cert }, app)`
        // with a real TLS cert and private key loaded from env
        app.listen(PORT, () => {
            console.log(`[SERVER] CryptoNote sync server running on port ${PORT}`);
            console.log('[SERVER] IMPORTANT: Enable TLS in production with a real certificate');
        });
    } catch (err) {
        console.error('[FATAL] Failed to connect to MongoDB:', err);
        process.exit(1);
    }
}

start();

export default app;
