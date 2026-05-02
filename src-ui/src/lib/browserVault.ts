// src-ui/src/lib/browserVault.ts
// Browser-native vault implementation using REST API + XChaCha20-Poly1305 crypto.
// Mirrors all Tauri IPC commands so useVault.ts can call the same interface.

import { v4 as uuidv4 } from 'uuid';
import { API_BASE } from './env';
import {
    generateSalt, encodeSalt, decodeSalt,
    deriveMasterKey, deriveSubkeys,
    encryptString, decryptString, encodeHex, computeHmac,
    type DerivedKeys, type EncryptedData,
} from './browserCrypto';
import type { VaultEntry, EntryListItem, VaultMeta, PasswordOptions, SyncStatus } from '../types/vault';

// ── In-memory session state ───────────────────────────────────────────────────
interface VaultSession {
    keys: DerivedKeys;
    meta: VaultMeta;
    entries: VaultEntry[];
    userId: string;
    token: string;
    deviceId: string;
    version: number;
    sequence: number;
    lastActivity: number;
    autoLockSecs: number;
}

let session: VaultSession | null = null;

// ── Auth token storage ────────────────────────────────────────────────────────
const TOKEN_KEY = 'cn_token';
const USER_KEY = 'cn_user_id';
const DEVICE_KEY = 'cn_device_id';

function saveAuth(token: string, userId: string, deviceId: string) {
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(USER_KEY, userId);
    sessionStorage.setItem(DEVICE_KEY, deviceId);
}

function getStoredAuth() {
    return {
        token: sessionStorage.getItem(TOKEN_KEY) ?? '',
        userId: sessionStorage.getItem(USER_KEY) ?? '',
        deviceId: sessionStorage.getItem(DEVICE_KEY) ?? (uuidv4()),
    };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
async function apiFetch(path: string, opts: RequestInit = {}, token?: string): Promise<any> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(opts.headers as Record<string, string> ?? {}),
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
    return data;
}

// ── Vault serialization ───────────────────────────────────────────────────────
function serializeVault(entries: VaultEntry[], meta: VaultMeta): string {
    return JSON.stringify({ entries, meta });
}

function deserializeVault(json: string): { entries: VaultEntry[]; meta: VaultMeta } {
    return JSON.parse(json);
}

// ── Push encrypted vault to server ───────────────────────────────────────────
async function pushVault(sess: VaultSession): Promise<void> {
    const plain = serializeVault(sess.entries, sess.meta);
    const encrypted_vault = encryptString(sess.keys.syncKey, plain);

    sess.sequence += 1;
    const timestamp = Date.now();
    const version = sess.version + 1;

    const hmacInput = `${sess.userId}:${sess.deviceId}:${version}:${timestamp}:${sess.sequence}:${encrypted_vault.ciphertext}`;
    const hmacBytes = computeHmac(sess.keys.hmacKey, new TextEncoder().encode(hmacInput));
    const hmac = btoa(String.fromCharCode(...hmacBytes));

    const payload = {
        user_id: sess.userId,
        device_id: sess.deviceId,
        version,
        timestamp,
        encrypted_vault,
        hmac,
        sequence: sess.sequence,
    };

    const resp = await apiFetch('/api/vault/push', {
        method: 'POST',
        body: JSON.stringify(payload),
    }, sess.token);

    if (resp.status === 'synced') sess.version = version;
}

// ── Pull encrypted vault from server ─────────────────────────────────────────
async function pullVault(keys: DerivedKeys, userId: string, token: string): Promise<{ entries: VaultEntry[]; meta: VaultMeta; version: number }> {
    const resp = await apiFetch(`/api/vault/pull/${userId}`, {}, token);
    const { payload } = resp;

    // Verify HMAC
    const hmacInput = `${payload.user_id}:${payload.device_id}:${payload.version}:${payload.timestamp}:${payload.sequence}:${payload.encrypted_vault.ciphertext}`;
    const expected = computeHmac(keys.hmacKey, new TextEncoder().encode(hmacInput));
    const got = Uint8Array.from(atob(payload.hmac), c => c.charCodeAt(0));
    if (expected.length !== got.length || !expected.every((b, i) => b === got[i])) {
        throw new Error('Vault HMAC verification failed – possible tampering');
    }

    const plain = decryptString(keys.syncKey, payload.encrypted_vault);
    const { entries, meta } = deserializeVault(plain);
    return { entries, meta, version: payload.version };
}

// ── Register/Login helpers ────────────────────────────────────────────────────
async function ensureRegisteredOrLogin(
    email: string,
    keys: DerivedKeys,
    deviceId: string,
): Promise<{ token: string; userId: string }> {
    const authKeyHash = encodeHex(computeHmac(keys.deviceKey, new TextEncoder().encode('auth')));

    // Try login first
    try {
        const resp = await apiFetch('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, auth_key_hash: authKeyHash, device_id: deviceId }),
        });
        return { token: resp.token, userId: resp.user_id };
    } catch {
        // Register if not found
        const resp = await apiFetch('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, auth_key_hash: authKeyHash, device_id: deviceId }),
        });
        return { token: resp.token, userId: resp.user_id };
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public Vault API (mirrors Tauri commands)
// ─────────────────────────────────────────────────────────────────────────────

export async function browserVaultExists(): Promise<boolean> {
    // In web mode: check if server has a vault for the stored user
    const { token, userId } = getStoredAuth();
    if (!token || !userId) return false;
    try {
        await apiFetch(`/api/vault/pull/${userId}`, {}, token);
        return true;
    } catch {
        return false;
    }
}

export async function browserVaultCreate(masterPassword: string): Promise<VaultMeta> {
    if (masterPassword.length < 12) throw new Error('Master password must be at least 12 characters');

    const salt = generateSalt();
    const masterKey = await deriveMasterKey(masterPassword, salt);
    const keys = deriveSubkeys(masterKey);

    const { deviceId } = getStoredAuth();
    const effectiveDeviceId = deviceId || uuidv4();

    // Use a placeholder email derived from device (user can set real email in settings)
    const placeholderEmail = `user-${effectiveDeviceId.slice(0, 8)}@cryptonote.local`;

    const { token, userId } = await ensureRegisteredOrLogin(placeholderEmail, keys, effectiveDeviceId);
    saveAuth(token, userId, effectiveDeviceId);

    const meta: VaultMeta = {
        vault_id: uuidv4(),
        salt: encodeSalt(salt),
        created_at: Math.floor(Date.now() / 1000),
        version: 1,
        sync_version: 0,
    };

    session = {
        keys,
        meta,
        entries: [],
        userId,
        token,
        deviceId: effectiveDeviceId,
        version: 0,
        sequence: 0,
        lastActivity: Date.now(),
        autoLockSecs: 300,
    };

    // Push initial (empty) vault
    await pushVault(session);

    // Store salt in localStorage for future unlock
    localStorage.setItem(`cn_salt_${userId}`, encodeSalt(salt));

    return meta;
}

export async function browserVaultUnlock(masterPassword: string): Promise<VaultMeta> {
    const { token, userId, deviceId } = getStoredAuth();

    // Need salt — try localStorage first, else pull unauthenticated to get it
    let saltB64 = localStorage.getItem(`cn_salt_${userId}`);

    if (!saltB64 || !token || !userId) {
        throw new Error('No vault found. Please create a new vault first.');
    }

    const salt = decodeSalt(saltB64);
    const masterKey = await deriveMasterKey(masterPassword, salt);
    const keys = deriveSubkeys(masterKey);

    // Try to pull vault to verify password (decryption will fail if wrong key)
    let entries: VaultEntry[] = [];
    let meta: VaultMeta;
    let version = 0;

    try {
        const pulled = await pullVault(keys, userId, token);
        entries = pulled.entries;
        meta = pulled.meta;
        version = pulled.version;
    } catch (e: any) {
        if (e.message?.includes('HMAC') || e.message?.includes('decrypt')) {
            throw new Error('Invalid master password');
        }
        // Network error — unlock offline with empty vault
        meta = {
            vault_id: userId,
            salt: saltB64,
            created_at: Math.floor(Date.now() / 1000),
            version: 1,
            sync_version: 0,
        };
    }

    session = {
        keys,
        meta: meta!,
        entries,
        userId,
        token,
        deviceId,
        version,
        sequence: 0,
        lastActivity: Date.now(),
        autoLockSecs: 300,
    };

    return meta!;
}

export function browserVaultLock(): void {
    session = null;
}

export function browserVaultIsLocked(): boolean {
    return session === null;
}

export function browserVaultListEntries(): EntryListItem[] {
    if (!session) throw new Error('Vault is locked');
    session.lastActivity = Date.now();
    return session.entries.map(e => ({
        id: e.id,
        title: e.title,
        url: e.url ?? undefined,
        tags: e.tags ?? [],
        updated_at: e.updated_at,
        version: e.version,
    }));
}

export function browserVaultGetEntry(id: string): VaultEntry {
    if (!session) throw new Error('Vault is locked');
    session.lastActivity = Date.now();
    const entry = session.entries.find(e => e.id === id);
    if (!entry) throw new Error(`Entry not found: ${id}`);
    return entry;
}

export async function browserVaultAddEntry(entry: VaultEntry): Promise<void> {
    if (!session) throw new Error('Vault is locked');
    session.lastActivity = Date.now();
    session.entries.push(entry);
    await pushVault(session);
}

export async function browserVaultUpdateEntry(entry: VaultEntry): Promise<void> {
    if (!session) throw new Error('Vault is locked');
    session.lastActivity = Date.now();
    const idx = session.entries.findIndex(e => e.id === entry.id);
    if (idx < 0) throw new Error('Entry not found');
    session.entries[idx] = { ...entry, updated_at: Math.floor(Date.now() / 1000), version: entry.version + 1 };
    await pushVault(session);
}

export async function browserVaultDeleteEntry(id: string): Promise<void> {
    if (!session) throw new Error('Vault is locked');
    session.lastActivity = Date.now();
    session.entries = session.entries.filter(e => e.id !== id);
    await pushVault(session);
}

// ── Password generator ────────────────────────────────────────────────────────
export function browserGeneratePassword(opts: PasswordOptions): string {
    let charset = '';
    if (opts.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (opts.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (opts.digits) charset += '0123456789';
    if (opts.symbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';
    if (!charset) throw new Error('Select at least one character type');
    const arr = new Uint32Array(opts.length);
    crypto.getRandomValues(arr);
    return Array.from(arr, v => charset[v % charset.length]).join('');
}

// ── AI phishing check (heuristic in browser) ──────────────────────────────────
import type { PhishingResult } from '../types/vault';

export function browserCheckPhishing(url: string): PhishingResult {
    const reasons: string[] = [];
    let risk: PhishingResult['risk'] = 'Safe';
    let domain = '';
    try {
        const u = new URL(url);
        domain = u.hostname.toLowerCase();
        const brands = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'facebook', 'instagram', 'netflix'];
        for (const b of brands) {
            if (domain.includes(b) && !domain.endsWith(`.${b}.com`) && domain !== `${b}.com`) {
                reasons.push(`Possible ${b} impersonation`);
                risk = 'HighRisk';
            }
        }
        if (domain.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            reasons.push('IP address used instead of domain');
            if (risk === 'Safe') risk = 'Suspicious';
        }
        if ((domain.match(/-/g) ?? []).length > 3) {
            reasons.push('Excessive hyphens in domain');
            if (risk === 'Safe') risk = 'Suspicious';
        }
        if (u.protocol === 'http:') {
            reasons.push('Insecure HTTP connection');
            if (risk === 'Safe') risk = 'Suspicious';
        }
    } catch {
        reasons.push('Invalid URL');
        risk = 'Suspicious';
    }
    const risk_score = risk === 'Safe' ? 0 : risk === 'Suspicious' ? 40 : risk === 'HighRisk' ? 80 : 100;
    return { domain, risk, risk_score, reasons, allow_autofill: risk === 'Safe' };
}

// ── Auto-lock ─────────────────────────────────────────────────────────────────
export function browserCheckAutoLock(): boolean {
    if (!session || session.autoLockSecs === 0) return false;
    const idle = (Date.now() - session.lastActivity) / 1000;
    if (idle > session.autoLockSecs) {
        session = null;
        return true;
    }
    return false;
}

export function browserRecordActivity(): void {
    if (session) session.lastActivity = Date.now();
}

export function browserSetAutoLockTimeout(seconds: number): void {
    if (session) session.autoLockSecs = seconds;
}

// ── Sync status ───────────────────────────────────────────────────────────────
export function browserGetSyncStatus(): SyncStatus {
    if (!session) return 'Idle' as any;
    return { Synced: { at: Math.floor(Date.now() / 1000) } } as any;
}

export function browserConfigureSync(_config: any): void {
    // In web mode, sync is always-on via the REST API — no extra config needed
}

// ── Security check ────────────────────────────────────────────────────────────
export function browserSecurityCheck() {
    const findings: string[] = [];
    if (!window.isSecureContext) findings.push('Page is not served over HTTPS');
    if (navigator.webdriver) findings.push('Automated browser detected');
    return { is_compromised: findings.length > 0, findings };
}
