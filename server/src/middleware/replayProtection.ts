// server/src/middleware/replayProtection.ts
// Prevents replay attacks using per-request nonces and timestamps

import { Request, Response, NextFunction } from 'express';

const NONCE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CLOCK_SKEW_MS = 60 * 1000;    // 1 minute max clock skew

// In-memory nonce store (use Redis in production for multi-instance setups)
const usedNonces = new Map<string, number>();

// Periodically clean up expired nonces
setInterval(() => {
    const cutoff = Date.now() - NONCE_WINDOW_MS;
    for (const [nonce, ts] of usedNonces.entries()) {
        if (ts < cutoff) usedNonces.delete(nonce);
    }
}, 60_000);

export function replayProtection(req: Request, res: Response, next: NextFunction): void {
    // Only protect state-mutating methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        next();
        return;
    }

    const body = req.body as Record<string, unknown>;
    const timestamp = body?.timestamp as number | undefined;
    const sequence = body?.sequence as number | undefined;

    if (!timestamp) {
        next(); // Allow requests without timestamp (e.g. auth/register)
        return;
    }

    const now = Date.now();
    const tsDiff = Math.abs(now - timestamp * 1000); // timestamp is unix secs

    // Reject requests with stale timestamps
    if (tsDiff > NONCE_WINDOW_MS) {
        res.status(408).json({ error: 'Request timestamp expired – replay detected' });
        return;
    }

    // Reject requests with excessive clock skew
    if (tsDiff > MAX_CLOCK_SKEW_MS && timestamp * 1000 > now) {
        res.status(400).json({ error: 'Request timestamp is in the future' });
        return;
    }

    // Build nonce from user_id + sequence + timestamp
    const userId = body?.user_id as string | undefined;
    if (userId && sequence !== undefined) {
        const nonce = `${userId}:${sequence}:${timestamp}`;
        if (usedNonces.has(nonce)) {
            res.status(409).json({ error: 'Replay attack detected – nonce already used' });
            return;
        }
        usedNonces.set(nonce, Date.now());
    }

    next();
}
