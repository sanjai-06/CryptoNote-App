// server/src/tests/auth.test.ts
// Integration tests for auth routes

import request from 'supertest';
import mongoose from 'mongoose';
import app from '../index';

const TEST_DB = 'mongodb://localhost:27017/cryptonote_test';

beforeAll(async () => {
    await mongoose.connect(TEST_DB);
});

afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
});

const validAuth = {
    email: `test_${Date.now()}@example.com`,
    // SHA-256 hex of "test-device-key" (64 chars)
    auth_key_hash: 'a'.repeat(64),
    device_id: 'test-device-001',
};

describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
        const res = await request(app).post('/api/auth/register').send(validAuth);
        expect(res.status).toBe(201);
        expect(res.body).toHaveProperty('token');
        expect(res.body).toHaveProperty('user_id');
    });

    it('should reject duplicate email', async () => {
        const res = await request(app).post('/api/auth/register').send(validAuth);
        expect(res.status).toBe(409);
    });

    it('should reject invalid auth_key_hash length', async () => {
        const res = await request(app).post('/api/auth/register').send({
            ...validAuth,
            email: 'other@example.com',
            auth_key_hash: 'short',
        });
        expect(res.status).toBe(400);
    });
});

describe('POST /api/auth/login', () => {
    it('should login with correct auth_key_hash', async () => {
        const res = await request(app).post('/api/auth/login').send(validAuth);
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('token');
    });

    it('should reject wrong auth_key_hash', async () => {
        const res = await request(app).post('/api/auth/login').send({
            ...validAuth,
            auth_key_hash: 'b'.repeat(64),
        });
        expect(res.status).toBe(401);
    });
});
