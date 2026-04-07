// server/src/routes/device.ts
// Device management: list, approve, and revoke devices

import { Router, Request, Response } from 'express';
import { User } from '../models/User';
import { VaultBlob } from '../models/VaultBlob';
import { requireAuth } from './auth';

export const deviceRouter = Router();

// ── List devices ──────────────────────────────────────────────────────────────
deviceRouter.get('/list', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { userId } = (req as any).user;
    const user = await User.findById(userId);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    res.json({ device_ids: user.device_ids });
});

// ── Revoke a device ───────────────────────────────────────────────────────────
deviceRouter.delete('/revoke/:device_id', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { userId } = (req as any).user;
    const { device_id } = req.params;

    const user = await User.findById(userId);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }

    user.device_ids = user.device_ids.filter((id) => id !== device_id);
    await user.save();

    // Also remove any vault blobs from the revoked device
    await VaultBlob.deleteMany({ user_id: userId, device_id });

    res.json({ success: true, message: `Device ${device_id} revoked` });
});

// ── Delete account (GDPR) ─────────────────────────────────────────────────────
deviceRouter.delete('/account', requireAuth, async (req: Request, res: Response): Promise<void> => {
    const { userId } = (req as any).user;

    await VaultBlob.deleteMany({ user_id: userId });
    await User.findByIdAndDelete(userId);

    res.json({ success: true, message: 'Account and all encrypted vault data deleted' });
});
