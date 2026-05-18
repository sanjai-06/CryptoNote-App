// src-ui/src/store/vaultStore.ts
// Global state management using Zustand

import { create } from 'zustand';
import type { AnomalyResult, EntryListItem, SyncStatus, VaultMeta } from '../types/vault';

// ── localStorage helpers ───────────────────────────────────────────────────────
const LS_SYNC_KEY      = 'cryptonote_sync_config';
const LS_AUTOLOCK_KEY  = 'cryptonote_autolock_secs';
const LS_THEME_KEY     = 'cryptonote_theme';
const LS_BIOMETRIC_KEY = 'cryptonote_biometric_enabled';
const LS_BIO_PW_KEY    = 'cryptonote_bio_pw';

type AppTheme = 'light' | 'dark' | 'system';

function loadTheme(): AppTheme {
    try {
        const t = localStorage.getItem(LS_THEME_KEY);
        if (t === 'light' || t === 'dark' || t === 'system') return t;
    } catch {}
    return 'system';
}

function saveTheme(theme: AppTheme) {
    try { localStorage.setItem(LS_THEME_KEY, theme); } catch {}
}

function loadSyncConfig() {
    try {
        const raw = localStorage.getItem(LS_SYNC_KEY);
        if (raw) return JSON.parse(raw) as { serverUrl: string; email: string; enabled: boolean };
    } catch {}
    return { serverUrl: 'https://sanjai-06-cryptonote-app.onrender.com', email: '', enabled: false };
}

function saveSyncConfig(serverUrl: string, email: string, enabled: boolean) {
    try { localStorage.setItem(LS_SYNC_KEY, JSON.stringify({ serverUrl, email, enabled })); } catch {}
}

function loadAutoLock(): number {
    try {
        const v = localStorage.getItem(LS_AUTOLOCK_KEY);
        if (v !== null) return parseInt(v, 10);
    } catch {}
    return 300; // default 5 minutes
}

function saveAutoLock(secs: number) {
    try { localStorage.setItem(LS_AUTOLOCK_KEY, String(secs)); } catch {}
}

const savedSync     = loadSyncConfig();
const savedAutoLock = loadAutoLock();
const savedTheme    = loadTheme();
const savedBiometric = (() => {
    try { return localStorage.getItem(LS_BIOMETRIC_KEY) === 'true'; } catch { return false; }
})();

// ── Store interface ───────────────────────────────────────────────────────────
interface VaultStore {
    // Auth state
    isLocked: boolean;
    meta: VaultMeta | null;
    setLocked: (locked: boolean) => void;
    setMeta: (meta: VaultMeta | null) => void;

    // Entry list
    entries: EntryListItem[];
    setEntries: (entries: EntryListItem[]) => void;

    // Sync status
    syncStatus: SyncStatus;
    setSyncStatus: (status: SyncStatus) => void;

    // Security alerts
    anomaly: AnomalyResult | null;
    setAnomaly: (result: AnomalyResult | null) => void;
    dismissAnomaly: () => void;

    // UI state
    searchQuery: string;
    setSearchQuery: (q: string) => void;
    selectedEntryId: string | null;
    setSelectedEntryId: (id: string | null) => void;

    // Settings — persisted
    theme: AppTheme;
    setTheme: (theme: AppTheme) => void;
    autoLockTimeout: number;
    setAutoLockTimeout: (secs: number) => void;
    syncEnabled: boolean;
    setSyncEnabled: (enabled: boolean) => void;

    // Persisted sync config (survives navigation & restarts)
    syncServerUrl: string;
    syncEmail: string;
    setSyncConfig: (serverUrl: string, email: string, enabled: boolean) => void;

    // Biometric unlock
    biometricEnabled: boolean;
    setBiometricEnabled: (enabled: boolean) => void;
    storeBiometricPassword: (pw: string) => void;
    getBiometricPassword: () => string | null;
    clearBiometricPassword: () => void;

    // Reset
    reset: () => void;
}

const initialState = {
    isLocked:       true,
    meta:           null,
    entries:        [],
    syncStatus:     { Idle: null } as SyncStatus,
    anomaly:        null,
    searchQuery:    '',
    selectedEntryId: null,
    theme:          savedTheme,              // ← loaded from localStorage
    autoLockTimeout: savedAutoLock,          // ← loaded from localStorage
    syncEnabled:    savedSync.enabled,
    syncServerUrl:  savedSync.serverUrl,
    syncEmail:      savedSync.email,
    biometricEnabled: savedBiometric,
};

export const useVaultStore = create<VaultStore>((set) => ({
    ...initialState,

    setLocked:          (locked)      => set({ isLocked: locked }),
    setMeta:            (meta)        => set({ meta }),
    setEntries:         (entries)     => set({ entries }),
    setSyncStatus:      (syncStatus)  => set({ syncStatus }),
    setAnomaly:         (anomaly)     => set({ anomaly }),
    dismissAnomaly:     ()            => set({ anomaly: null }),
    setSearchQuery:     (searchQuery) => set({ searchQuery }),
    setSelectedEntryId: (selectedEntryId) => set({ selectedEntryId }),

    setTheme: (theme) => {
        saveTheme(theme);
        set({ theme });
    },

    // Persist auto-lock to localStorage on every change
    setAutoLockTimeout: (autoLockTimeout) => {
        saveAutoLock(autoLockTimeout);
        set({ autoLockTimeout });
    },

    setSyncEnabled: (syncEnabled) => set({ syncEnabled }),

    setSyncConfig: (syncServerUrl, syncEmail, syncEnabled) => {
        saveSyncConfig(syncServerUrl, syncEmail, syncEnabled);
        set({ syncServerUrl, syncEmail, syncEnabled });
    },

    setBiometricEnabled: (biometricEnabled) => {
        try { localStorage.setItem(LS_BIOMETRIC_KEY, String(biometricEnabled)); } catch {}
        if (!biometricEnabled) {
            try { localStorage.removeItem(LS_BIO_PW_KEY); } catch {}
        }
        set({ biometricEnabled });
    },
    storeBiometricPassword: (pw) => {
        try { localStorage.setItem(LS_BIO_PW_KEY, btoa(pw)); } catch {}
    },
    getBiometricPassword: () => {
        try {
            const v = localStorage.getItem(LS_BIO_PW_KEY);
            return v ? atob(v) : null;
        } catch { return null; }
    },
    clearBiometricPassword: () => {
        try { localStorage.removeItem(LS_BIO_PW_KEY); } catch {}
    },

    reset: () => set(initialState),
}));
