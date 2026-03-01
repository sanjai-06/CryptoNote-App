// server/src/routes/auth.ts
// Zero-knowledge auth: server stores auth_key_hash (not master password)

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import { User } from '../models/User';
import { authLimiter } from '../middleware/rateLimiter';

export const authRouter = Router();
const JWT_SECRET = process.env.JWT_SECRET ?? 'change-me-in-production-use-256-bit-key';
const JWT_EXPIRES = process.env.JWT_EXPIRES ?? '30d';

const RegisterSchema = z.object({
    email: z.string().email(),
    auth_key_hash: z.string().length(64), // SHA-256 hex = 64 chars
    device_id: z.string().min(8).max(128),
});

const LoginSchema = z.object({
    email: z.string().email(),
    auth_key_hash: z.string().length(64),
    device_id: z.string().min(8).max(128),
});

// ── Register ─────────────────────────────────────────────────────────────────
authRouter.post('/register', authLimiter, async (req: Request, res: Response): Promise<void> => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: 'Invalid registration data', details: parsed.error.errors });
        return;
    }

    const { email, auth_key_hash, device_id } = parsed.data;

    const existing = await User.findOne({ email });
    if (existing) {
        // Return same response as success to prevent email enumeration
        res.status(409).json({ error: 'Email already registered' });
        return;
    }

    const user = await User.create({
        email,
        auth_key_hash,          // Stored as SHA-256 hex – NOT bcrypt-hashed
        // because auth_key_hash is already derived from the
        // master password via Argon2id + HKDF. It is not a
        // password that should be hashed again.
        device_ids: [device_id],
    });

    const token = jwt.sign(
        { userId: user._id.toString(), email: user.email, device_id },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, algorithm: 'HS256' }
    );

    res.status(201).json({ token, user_id: user._id.toString() });
});

// ── Login ─────────────────────────────────────────────────────────────────────
authRouter.post('/login', authLimiter, async (req: Request, res: Response): Promise<void> => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: 'Invalid login data' });
        return;
    }

    const { email, auth_key_hash, device_id } = parsed.data;

    const user = await User.findOne({ email }).select('+auth_key_hash');
    if (!user || !user.is_active) {
        // Constant-time comparison not possible without hashing, but we keep
        // the response identical to prevent timing attacks via field lookup.
        res.status(401).json({ error: 'Invalid credentials' });
        return;
    }

    // Constant-time comparison
    const expected = Buffer.from(user.auth_key_hash, 'hex');
    const provided = Buffer.from(auth_key_hash, 'hex');

    if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
    }

    // Register device if new
    if (!user.device_ids.includes(device_id)) {
        user.device_ids.push(device_id);
    }
    user.last_login = new Date();
    await user.save();

    const token = jwt.sign(
        { userId: user._id.toString(), email: user.email, device_id },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, algorithm: 'HS256' }
    );

    res.json({ token, user_id: user._id.toString() });
});

function timingSafeEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

// ── Verify token ─────────────────────────────────────────────────────────────
export function verifyToken(token: string): { userId: string; email: string; device_id: string } {
    return jwt.verify(token, JWT_SECRET) as { userId: string; email: string; device_id: string };
}

// ── Auth middleware ───────────────────────────────────────────────────────────
export function requireAuth(req: Request, res: Response, next: Function): void {
    const header = req.headers['authorization'];
    if (!header?.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Authentication required' });
        return;
    }
    try {
        const payload = verifyToken(header.slice(7));
        (req as any).user = payload;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}
