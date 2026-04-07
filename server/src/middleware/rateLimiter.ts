// server/src/middleware/rateLimiter.ts
// Tiered rate limiting for auth and API endpoints

import rateLimit from 'express-rate-limit';

// Strict limiter for auth endpoints (prevents brute force)
export const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,                   // 10 attempts per 15min per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts. Try again in 15 minutes.' },
    skipSuccessfulRequests: true,
});

// General API limiter
export const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Slow down.' },
});
