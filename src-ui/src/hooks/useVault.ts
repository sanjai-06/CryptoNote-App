// src-ui/src/hooks/useVault.ts
// Unified vault API — automatically switches between:
//   • Tauri IPC (invoke) when running inside the desktop app
//   • Browser REST API + WebCrypto when running in a regular browser (AWS/web)

import { isTauri } from '../lib/env';
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

import * as browser from '../lib/browserVault';

// Lazy-load Tauri invoke only when inside the desktop app
async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
}

// ─── Vault ────────────────────────────────────────────────────────────────── //

export const vaultExists = (path: string): Promise<boolean> =>
    isTauri()
        ? tauriInvoke('vault_exists', { path })
        : browser.browserVaultExists();

export const vaultCreate = async (masterPassword: string): Promise<VaultMeta> => {
    if (isTauri()) {
        const meta = await tauriInvoke<VaultMeta>('vault_create', { masterPassword });
        await tauriInvoke('sync_push').catch(console.error);
        return meta;
    } else {
        return browser.browserVaultCreate(masterPassword);
    }
};

export const vaultUnlock = async (masterPassword: string): Promise<VaultMeta> => {
    if (isTauri()) {
        const meta = await tauriInvoke<VaultMeta>('vault_unlock', { masterPassword });
        await tauriInvoke('sync_pull').catch(console.error);
        return meta;
    } else {
        return browser.browserVaultUnlock(masterPassword);
    }
};

export const vaultLock = (): Promise<void> =>
    isTauri()
        ? tauriInvoke('vault_lock')
        : Promise.resolve(browser.browserVaultLock());

export const vaultIsLocked = (): Promise<boolean> =>
    isTauri()
        ? tauriInvoke('vault_is_locked')
        : Promise.resolve(browser.browserVaultIsLocked());

export const vaultListEntries = (): Promise<EntryListItem[]> =>
    isTauri()
        ? tauriInvoke('vault_list_entries')
        : Promise.resolve(browser.browserVaultListEntries());

export const vaultGetEntry = (id: string): Promise<VaultEntry> =>
    isTauri()
        ? tauriInvoke('vault_get_entry', { id })
        : Promise.resolve(browser.browserVaultGetEntry(id));

export const vaultAddEntry = async (entry: VaultEntry): Promise<void> => {
    if (isTauri()) {
        await tauriInvoke('vault_add_entry', { entry });
        await tauriInvoke('sync_push').catch(console.error);
    } else {
        await browser.browserVaultAddEntry(entry);
    }
};

export const vaultUpdateEntry = async (entry: VaultEntry): Promise<void> => {
    if (isTauri()) {
        await tauriInvoke('vault_update_entry', { entry });
        await tauriInvoke('sync_push').catch(console.error);
    } else {
        await browser.browserVaultUpdateEntry(entry);
    }
};

export const vaultDeleteEntry = async (id: string): Promise<void> => {
    if (isTauri()) {
        await tauriInvoke('vault_delete_entry', { id });
        await tauriInvoke('sync_push').catch(console.error);
    } else {
        await browser.browserVaultDeleteEntry(id);
    }
};

// ─── Password generator ────────────────────────────────────────────────────── //

export const generatePassword = (options: PasswordOptions): Promise<string> =>
    isTauri()
        ? tauriInvoke('generate_password', { options })
        : Promise.resolve(browser.browserGeneratePassword(options));

// ─── AI security ──────────────────────────────────────────────────────────── //

export const aiCheckPhishing = (url: string): Promise<PhishingResult> =>
    isTauri()
        ? tauriInvoke('ai_check_phishing', { url })
        : Promise.resolve(browser.browserCheckPhishing(url));

export const aiGetAnomalyStatus = (): Promise<AnomalyResult> =>
    isTauri()
        ? tauriInvoke('ai_get_anomaly_status')
        : Promise.resolve({ should_alert: false, should_lock: false, message: '', risk_score: 0 } as AnomalyResult);

export const aiRecordExport = (): Promise<AnomalyResult> =>
    isTauri()
        ? tauriInvoke('ai_record_export')
        : Promise.resolve({ should_alert: false, should_lock: false, message: '', risk_score: 0 } as AnomalyResult);

// ─── Sync ──────────────────────────────────────────────────────────────────── //

export const syncConfigure = (config: SyncConfig): Promise<void> =>
    isTauri()
        ? tauriInvoke('sync_configure', { config })
        : Promise.resolve(browser.browserConfigureSync(config));

export const syncGetStatus = (): Promise<SyncStatus> =>
    isTauri()
        ? tauriInvoke('sync_get_status')
        : Promise.resolve(browser.browserGetSyncStatus());

export const syncRegister = (email: string, masterPassword: string): Promise<string> =>
    isTauri()
        ? tauriInvoke('sync_register', { email, masterPassword })
        : Promise.resolve('');

export const syncPush = (): Promise<void> =>
    isTauri()
        ? tauriInvoke('sync_push')
        : Promise.resolve(); // browser vault auto-pushes on mutation

export const syncPull = (): Promise<void> =>
    isTauri()
        ? tauriInvoke('sync_pull')
        : Promise.resolve(); // browser vault pulls on unlock

// ─── Auto-lock ─────────────────────────────────────────────────────────────── //

export const setAutoLockTimeout = (seconds: number): Promise<void> =>
    isTauri()
        ? tauriInvoke('set_auto_lock_timeout', { seconds })
        : Promise.resolve(browser.browserSetAutoLockTimeout(seconds));

export const checkAutoLock = (): Promise<boolean> =>
    isTauri()
        ? tauriInvoke('check_auto_lock')
        : Promise.resolve(browser.browserCheckAutoLock());

export const recordActivity = (): Promise<void> =>
    isTauri()
        ? tauriInvoke('record_activity')
        : Promise.resolve(browser.browserRecordActivity());

// ─── OS security ──────────────────────────────────────────────────────────── //

export const securityCheckDevice = (): Promise<{ is_compromised: boolean; findings: string[] }> =>
    isTauri()
        ? tauriInvoke('security_check_device')
        : Promise.resolve(browser.browserSecurityCheck());
