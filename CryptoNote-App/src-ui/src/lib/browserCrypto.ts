// src-ui/src/lib/browserCrypto.ts
// Browser-side crypto matching the Rust implementation:
//   Argon2id (hash-wasm) + HKDF-SHA256 (@noble/hashes) + XChaCha20-Poly1305 (@noble/ciphers)

import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';

// ── Constants matching Rust ──────────────────────────────────────────────────
const SALT_LEN = 32;
const SUBKEY_LEN = 32;
const NONCE_LEN = 24; // XChaCha20 nonce

// ── Types ────────────────────────────────────────────────────────────────────
export interface EncryptedData {
    nonce: string;       // base64
    ciphertext: string;  // base64
    algorithm: string;
}

export interface DerivedKeys {
    vaultKey: Uint8Array;
    hmacKey: Uint8Array;
    syncKey: Uint8Array;
    deviceKey: Uint8Array;
}

// ── Utilities ────────────────────────────────────────────────────────────────
const b64encode = (buf: Uint8Array): string => btoa(String.fromCharCode(...buf));
const b64decode = (s: string): Uint8Array => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export function generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(SALT_LEN));
}

export function encodeSalt(salt: Uint8Array): string {
    return b64encode(salt);
}

export function decodeSalt(s: string): Uint8Array {
    return b64decode(s);
}

// ── Argon2id KDF (matches Rust: 64MiB, 3 iterations, 4 threads) ─────────────
export async function deriveMasterKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const result = await argon2id({
        password,
        salt,
        parallelism: 4,
        iterations: 3,
        memorySize: 65536, // 64 MiB
        hashLength: 32,
        outputType: 'binary',
    });
    return result as Uint8Array;
}

// ── HKDF-SHA256 subkey derivation (matches Rust labels) ─────────────────────
export function deriveSubkeys(masterKey: Uint8Array): DerivedKeys {
    const expand = (info: string) => hkdf(sha256, masterKey, undefined, new TextEncoder().encode(info), SUBKEY_LEN);
    return {
        vaultKey:  expand('cryptonote-vault-key-v1'),
        hmacKey:   expand('cryptonote-hmac-key-v1'),
        syncKey:   expand('cryptonote-sync-key-v1'),
        deviceKey: expand('cryptonote-device-key-v1'),
    };
}

// ── XChaCha20-Poly1305 ────────────────────────────────────────────────────────
export function encrypt(key: Uint8Array, plaintext: Uint8Array): EncryptedData {
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const cipher = xchacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);
    return {
        nonce: b64encode(nonce),
        ciphertext: b64encode(ciphertext),
        algorithm: 'XChaCha20-Poly1305',
    };
}

export function decrypt(key: Uint8Array, data: EncryptedData): Uint8Array {
    const nonce = b64decode(data.nonce);
    const ciphertext = b64decode(data.ciphertext);
    const cipher = xchacha20poly1305(key, nonce);
    return cipher.decrypt(ciphertext);
}

export function encryptString(key: Uint8Array, plaintext: string): EncryptedData {
    return encrypt(key, new TextEncoder().encode(plaintext));
}

export function decryptString(key: Uint8Array, data: EncryptedData): string {
    return new TextDecoder().decode(decrypt(key, data));
}

// ── HMAC-SHA256 (for sync payload integrity) ─────────────────────────────────

export function computeHmac(key: Uint8Array, data: Uint8Array): Uint8Array {
    return hmac(sha256, key, data);
}

export function encodeHex(buf: Uint8Array): string {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}
