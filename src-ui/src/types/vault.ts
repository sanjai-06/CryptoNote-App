// src-ui/src/types/vault.ts
// TypeScript type definitions mirroring Rust structs

export interface VaultEntry {
    id: string;
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
    totp_secret?: string;
    tags: string[];
    created_at: number;
    updated_at: number;
    version: number;
}

export interface EntryListItem {
    id: string;
    title: string;
    url?: string;
    updated_at: number;
    version: number;
}

export interface VaultMeta {
    vault_id: string;
    salt: string;
    created_at: number;
    version: number;
    sync_version: number;
}

export interface PasswordOptions {
    length: number;
    uppercase: boolean;
    lowercase: boolean;
    digits: boolean;
    symbols: boolean;
}

export type SyncStatus =
    | { Idle: null }
    | { Syncing: null }
    | { Synced: { at: number } }
    | { Conflict: { server_version: number; local_version: number } }
    | { Offline: null }
    | { Error: string };

export interface SyncConfig {
    server_url: string;
    device_id: string;
    user_id?: string;
    auth_token?: string;
    tls_cert_pem?: string;
}

export type PhishingRisk = 'Safe' | 'Suspicious' | 'HighRisk' | 'Blocked';

export interface PhishingResult {
    domain: string;
    risk: PhishingRisk;
    risk_score: number;
    reasons: string[];
    allow_autofill: boolean;
}

export type AnomalyType =
    | 'RapidFailedAttempts'
    | 'UnusualUnlockTime'
    | 'SuspiciousExportBehavior'
    | 'NewDeviceUnlock'
    | 'HighRiskScore';

export interface AnomalyResult {
    anomalies: AnomalyType[];
    risk_score: number;
    should_lock: boolean;
    should_alert: boolean;
    message: string;
}

export interface SecurityPostureResult {
    is_compromised: boolean;
    findings: string[];
}
