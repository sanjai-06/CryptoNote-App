// src-ui/src/components/SyncStatus.tsx
// Compact sync status pill shown in the sidebar

import { useEffect, useRef, useState } from 'react';
import { syncGetStatus } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import type { SyncStatus } from '../types/vault';

function getSyncLabel(status: SyncStatus | string, syncingSeconds = 0): { label: string; dotClass: string } {
    const isSyncing = status === 'Syncing' || (status && typeof status === 'object' && 'Syncing' in status);
    if (isSyncing) {
        if (syncingSeconds >= 5) return { label: 'Waking server…', dotClass: 'syncing' };
        return { label: 'Syncing…', dotClass: 'syncing' };
    }

    if (typeof status === 'string') {
        if (status === 'Idle')    return { label: 'Sync Idle',  dotClass: '' };
        if (status === 'Synced')  return { label: 'Synced ✓',   dotClass: 'synced' };
        if (status === 'Offline') return { label: 'Offline',    dotClass: 'offline' };
        if (status === 'Error')   return { label: 'Sync Error', dotClass: 'error' };
        return { label: status, dotClass: '' };
    }

    if (status && typeof status === 'object') {
        if ('Idle'     in status) return { label: 'Sync Idle',  dotClass: '' };
        if ('Synced'   in status) return { label: 'Synced ✓',   dotClass: 'synced' };
        if ('Offline'  in status) return { label: 'Offline',    dotClass: 'offline' };
        if ('Conflict' in status) return { label: 'Conflict',   dotClass: 'error' };
        if ('Error'    in status) return { label: 'Sync Error', dotClass: 'error' };
    }

    return { label: 'Sync Idle', dotClass: '' };
}

export function SyncStatus() {
    const { syncStatus, setSyncStatus, syncEmail, syncServerUrl } = useVaultStore();
    const [syncingSeconds, setSyncingSeconds] = useState(0);
    const { label, dotClass } = getSyncLabel(syncStatus, syncingSeconds);
    const syncingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

    const isSyncConfigured = !!(syncEmail && syncServerUrl);
    const isSyncing = label === 'Syncing…' || label === 'Waking server…';

    // Count seconds while syncing so we can show "Waking server..." hint
    useEffect(() => {
        if (isSyncing) {
            setSyncingSeconds(0);
            syncingTimerRef.current = setInterval(() => setSyncingSeconds(s => s + 1), 1000);
        } else {
            if (syncingTimerRef.current) clearInterval(syncingTimerRef.current);
            setSyncingSeconds(0);
        }
        return () => { if (syncingTimerRef.current) clearInterval(syncingTimerRef.current); };
    }, [isSyncing]);

    // Poll Rust engine status every 5s if sync is configured
    useEffect(() => {
        if (!isSyncConfigured) return;

        const poll = async () => {
            try {
                const status = await syncGetStatus();
                setSyncStatus(status);
            } catch { /* ignore */ }
        };

        poll();
        const interval = setInterval(poll, 5_000);
        return () => clearInterval(interval);
    }, [isSyncConfigured, setSyncStatus]);

    if (!isSyncConfigured) return null;

    return (
        <div className='sync-pill' title={`Server: ${syncServerUrl} | User: ${syncEmail}`}>
            <div className={`sync-dot ${dotClass}`} />
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{label}</span>
        </div>
    );
}
