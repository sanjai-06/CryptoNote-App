// server/src/routes/vault.ts
// Upload / download encrypted vault blobs
// The server is completely zero-knowledge: it stores and returns opaque encrypted data

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { VaultBlob } from '../models/VaultBlob';
import { User } from '../models/User';
import { requireAuth } from './auth';

export const vaultRouter = Router();

const EncryptedDataSchema = z.object({
    nonce: z.string().min(1),
    ciphertext: z.string().min(1),
    algorithm: z.string().min(1),
});

const PushSchema = z.object({
    user_id: z.string().min(1),
    device_id: z.string().min(1),
    version: z.number().int().positive(),
    timestamp: z.number().int(),
    encrypted_vault: EncryptedDataSchema,
    hmac: z.string().min(1),
    sequence: z.number().int().nonnegative(),
    kdf_salt: z.string().default(''),
    force: z.boolean().optional().default(false), // bypass version conflict
});

// ── Push (upload) encrypted vault ────────────────────────────────────────────
vaultRouter.post('/push', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const parsed = PushSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: 'Invalid vault payload', details: parsed.error.errors });
        return;
    }

    const { user_id, device_id, version, timestamp, encrypted_vault, hmac, sequence, kdf_salt, force } = parsed.data;
    const authedUser = (req as any).user as { userId: string };

    if (authedUser.userId !== user_id) {
        res.status(403).json({ error: 'Forbidden: user_id mismatch' });
        return;
    }

    const sizeBytes = JSON.stringify(encrypted_vault).length;
    if (sizeBytes > 10 * 1024 * 1024) {
        res.status(413).json({ error: 'Vault payload too large' });
        return;
    }

    const existing = await VaultBlob.findOne({ user_id }).sort({ version: -1 });

    // Conflict check: skip entirely when force=true
    if (!force && existing && existing.version > version) {
        res.status(200).json({
            status: 'conflict',
            server_version: existing.version,
            message: 'Server has a newer version. Use force push or pull first.',
        });
        return;
    }

    // Force push: use serverVersion + 1 so it's always the latest
    const effectiveVersion = force && existing
        ? existing.version + 1
        : version;

    await VaultBlob.findOneAndUpdate(
        { user_id, version: effectiveVersion },
        { user_id, device_id, version: effectiveVersion, timestamp, encrypted_vault, hmac, sequence,
          kdf_salt: kdf_salt ?? '', size_bytes: sizeBytes },
        { upsert: true, new: true }
    );

    res.status(200).json({ status: 'synced', server_version: effectiveVersion });
});

// ── Patch kdf_salt on existing blob (called automatically by client after server upgrade) ──
vaultRouter.post('/patch-salt', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { user_id, kdf_salt } = req.body;
    const authedUser = (req as any).user as { userId: string };
    if (authedUser.userId !== user_id || !kdf_salt) {
        res.status(400).json({ error: 'Bad request' });
        return;
    }
    // Update the latest blob for this user if it has no kdf_salt
    const result = await VaultBlob.findOneAndUpdate(
        { user_id, $or: [{ kdf_salt: '' }, { kdf_salt: { $exists: false } }] },
        { $set: { kdf_salt } },
        { sort: { version: -1 }, new: true }
    );
    if (!result) {
        res.json({ status: 'already_set' });
    } else {
        res.json({ status: 'updated', version: result.version });
    }
});


// ── Pull (download) encrypted vault ──────────────────────────────────────────
vaultRouter.get('/pull/:user_id', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { user_id } = req.params;
    const authedUser = (req as any).user as { userId: string };

    if (authedUser.userId !== user_id) {
        res.status(403).json({ error: 'Forbidden: user_id mismatch' });
        return;
    }

    const blob = await VaultBlob.findOne({ user_id }).sort({ version: -1 });
    if (!blob) {
        res.status(404).json({ status: 'not_found', message: 'No vault on server for this user' });
        return;
    }

    res.json({
        status: 'ok',
        server_version: blob.version,
        payload: {
            user_id: blob.user_id,
            device_id: blob.device_id,
            version: blob.version,
            timestamp: blob.timestamp,
            encrypted_vault: blob.encrypted_vault,
            hmac: blob.hmac,
            sequence: blob.sequence,
            kdf_salt: blob.kdf_salt ?? '',
        },
    });
});

// ── Version history ───────────────────────────────────────────────────────────
vaultRouter.get('/history/:user_id', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { user_id } = req.params;
    const authedUser = (req as any).user as { userId: string };

    if (authedUser.userId !== user_id) {
        res.status(403).json({ error: 'Forbidden' });
        return;
    }

    const history = await VaultBlob.find({ user_id })
        .sort({ version: -1 })
        .limit(10)
        .select('version device_id timestamp size_bytes created_at');

    res.json({ history });
});
