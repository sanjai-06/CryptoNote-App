// src-ui/src/hooks/useVault.ts
// Type-safe wrappers around Tauri IPC commands

import { invoke } from '@tauri-apps/api/core';
import type {
    AnomalyResult,
    EntryListItem,
    PasswordOptions,
    PhishingResult,
    SyncConfig,
    SyncStatus,
    VaultEntry,
    VaultMeta,
} from '../types/vault';

// ─── Vault ─────────────────────────────────────────────────────────────────  //

export const vaultExists = (path: string): Promise<boolean> =>
    invoke('vault_exists', { path });

export const vaultCreate = (masterPassword: string): Promise<VaultMeta> =>
    invoke('vault_create', { masterPassword });

export const vaultUnlock = (masterPassword: string): Promise<VaultMeta> =>
    invoke('vault_unlock', { masterPassword });

export const vaultLock = (): Promise<void> =>
    invoke('vault_lock');

export const vaultIsLocked = (): Promise<boolean> =>
    invoke('vault_is_locked');

export const vaultListEntries = (): Promise<EntryListItem[]> =>
    invoke('vault_list_entries');

export const vaultGetEntry = (id: string): Promise<VaultEntry> =>
    invoke('vault_get_entry', { id });

export const vaultAddEntry = (entry: VaultEntry): Promise<void> =>
    invoke('vault_add_entry', { entry });

export const vaultUpdateEntry = (entry: VaultEntry): Promise<void> =>
    invoke('vault_update_entry', { entry });

export const vaultDeleteEntry = (id: string): Promise<void> =>
    invoke('vault_delete_entry', { id });

// ─── Password generator ────────────────────────────────────────────────────── //

export const generatePassword = (options: PasswordOptions): Promise<string> =>
    invoke('generate_password', { options });

// ─── AI security ──────────────────────────────────────────────────────────── //

export const aiCheckPhishing = (url: string): Promise<PhishingResult> =>
    invoke('ai_check_phishing', { url });

export const aiGetAnomalyStatus = (): Promise<AnomalyResult> =>
    invoke('ai_get_anomaly_status');

export const aiRecordExport = (): Promise<AnomalyResult> =>
    invoke('ai_record_export');

// ─── Sync ──────────────────────────────────────────────────────────────────── //

export const syncConfigure = (config: SyncConfig): Promise<void> =>
    invoke('sync_configure', { config });

export const syncGetStatus = (): Promise<SyncStatus> =>
    invoke('sync_get_status');

export const syncRegister = (email: string, masterPassword: string): Promise<string> =>
    invoke('sync_register', { email, masterPassword });

// ─── Auto-lock ─────────────────────────────────────────────────────────────── //

export const setAutoLockTimeout = (seconds: number): Promise<void> =>
    invoke('set_auto_lock_timeout', { seconds });

export const checkAutoLock = (): Promise<boolean> =>
    invoke('check_auto_lock');

export const recordActivity = (): Promise<void> =>
    invoke('record_activity');

// ─── OS security ──────────────────────────────────────────────────────────── //

export const securityCheckDevice = (): Promise<{ is_compromised: boolean; findings: string[] }> =>
    invoke('security_check_device');
