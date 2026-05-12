// src-ui/src/store/vaultStore.ts
// Global state management using Zustand

import { create } from 'zustand';
import type { AnomalyResult, EntryListItem, SyncStatus, VaultMeta } from '../types/vault';

// ── Sync config localStorage persistence ─────────────────────────────────────
const LS_SYNC_KEY = 'cryptonote_sync_config';

function loadSyncConfig() {
    try {
        const raw = localStorage.getItem(LS_SYNC_KEY);
        if (raw) return JSON.parse(raw) as { serverUrl: string; email: string; enabled: boolean };
    } catch {}
    return { serverUrl: 'https://sanjai-06-cryptonote-app.onrender.com', email: '', enabled: false };
}

function saveSyncConfig(serverUrl: string, email: string, enabled: boolean) {
    try {
        localStorage.setItem(LS_SYNC_KEY, JSON.stringify({ serverUrl, email, enabled }));
    } catch {}
}

const savedSync = loadSyncConfig();

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

    // Settings
    autoLockTimeout: number;
    setAutoLockTimeout: (secs: number) => void;
    syncEnabled: boolean;
    setSyncEnabled: (enabled: boolean) => void;

    // Persisted sync config (survives navigation & restarts)
    syncServerUrl: string;
    syncEmail: string;
    setSyncConfig: (serverUrl: string, email: string, enabled: boolean) => void;

    // Reset
    reset: () => void;
}

const initialState = {
    isLocked: true,
    meta: null,
    entries: [],
    syncStatus: { Idle: null } as SyncStatus,
    anomaly: null,
    searchQuery: '',
    selectedEntryId: null,
    autoLockTimeout: 300,
    syncEnabled: savedSync.enabled,
    syncServerUrl: savedSync.serverUrl,
    syncEmail: savedSync.email,
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
    setAutoLockTimeout: (autoLockTimeout) => set({ autoLockTimeout }),
    setSyncEnabled:     (syncEnabled) => set({ syncEnabled }),

    setSyncConfig: (syncServerUrl, syncEmail, syncEnabled) => {
        saveSyncConfig(syncServerUrl, syncEmail, syncEnabled);
        set({ syncServerUrl, syncEmail, syncEnabled });
    },

    reset: () => set(initialState),
}));
