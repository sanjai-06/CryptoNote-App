// src-ui/src/components/SyncStatus.tsx
// Compact sync status pill shown in the sidebar

import { useEffect } from 'react';
import { syncGetStatus, syncPush } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import type { SyncStatus } from '../types/vault';

function getSyncLabel(status: SyncStatus | string): { label: string; dotClass: string } {
    // Handle string variants (Serde unit enum variants like "Idle", "Syncing", "Offline")
    if (typeof status === 'string') {
        if (status === 'Idle')    return { label: 'Sync Idle',  dotClass: '' };
        if (status === 'Syncing') return { label: 'Syncing…',   dotClass: 'syncing' };
        if (status === 'Synced')  return { label: 'Synced ✓',   dotClass: 'synced' };
        if (status === 'Offline') return { label: 'Offline',    dotClass: 'offline' };
        if (status === 'Error')   return { label: 'Sync Error', dotClass: 'error' };
        return { label: status, dotClass: '' };
    }

    // Handle object variants
    if (status && typeof status === 'object') {
        if ('Idle'     in status) return { label: 'Sync Idle',  dotClass: '' };
        if ('Syncing'  in status) return { label: 'Syncing…',   dotClass: 'syncing' };
        if ('Synced'   in status) return { label: 'Synced ✓',   dotClass: 'synced' };
        if ('Offline'  in status) return { label: 'Offline',    dotClass: 'offline' };
        if ('Conflict' in status) return { label: 'Conflict',   dotClass: 'error' };
        if ('Error'    in status) return { label: 'Sync Error', dotClass: 'error' };
    }
    
    return { label: 'Sync Idle', dotClass: '' };
}

export function SyncStatus() {
    const { syncStatus, setSyncStatus, syncEmail, syncServerUrl } = useVaultStore();
    const { label, dotClass } = getSyncLabel(syncStatus);

    // Poll status every 5s if sync is configured (email + server URL present)
    const isSyncConfigured = !!(syncEmail && syncServerUrl);

    useEffect(() => {
        if (!isSyncConfigured) return;

        const poll = async () => {
            try {
                const status = await syncGetStatus();
                setSyncStatus(status);
            } catch { /* ignore */ }
        };

        poll();
        const interval = setInterval(poll, 5_000); // poll every 5s
        return () => clearInterval(interval);
    }, [isSyncConfigured, setSyncStatus]);

    // Don't render the pill if sync is not configured at all
    if (!isSyncConfigured) return null;

    return (
        <div className='sync-pill' title={`Server: ${syncServerUrl} | User: ${syncEmail}`}>
            <div className={`sync-dot ${dotClass}`} />
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{label}</span>
        </div>
    );
}
