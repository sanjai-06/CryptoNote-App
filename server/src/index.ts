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

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: Date.now() }));

// ── 404 handler ──────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

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
