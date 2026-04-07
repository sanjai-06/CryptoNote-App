// src-ui/src/store/vaultStore.ts
// Global state management using Zustand

import { create } from 'zustand';
import type { AnomalyResult, EntryListItem, SyncStatus, VaultMeta } from '../types/vault';

interface VaultStore {
    // Auth state
    isLocked: boolean;
    meta: VaultMeta | null;
    setLocked: (locked: boolean) => void;
    setMeta: (meta: VaultMeta | null) => void;

    // Entry list
    entries: EntryListItem[];
    setEntries: (entries: EntryListItem[]) => void;

    // Sync
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
    autoLockTimeout: number; // seconds
    setAutoLockTimeout: (secs: number) => void;
    syncEnabled: boolean;
    setSyncEnabled: (enabled: boolean) => void;

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
    syncEnabled: false,
};

export const useVaultStore = create<VaultStore>((set) => ({
    ...initialState,

    setLocked: (locked) => set({ isLocked: locked }),
    setMeta: (meta) => set({ meta }),
    setEntries: (entries) => set({ entries }),
    setSyncStatus: (syncStatus) => set({ syncStatus }),
    setAnomaly: (anomaly) => set({ anomaly }),
    dismissAnomaly: () => set({ anomaly: null }),
    setSearchQuery: (searchQuery) => set({ searchQuery }),
    setSelectedEntryId: (selectedEntryId) => set({ selectedEntryId }),
    setAutoLockTimeout: (autoLockTimeout) => set({ autoLockTimeout }),
    setSyncEnabled: (syncEnabled) => set({ syncEnabled }),
    reset: () => set(initialState),
}));
