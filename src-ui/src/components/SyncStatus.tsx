// src-ui/src/components/SyncStatus.tsx
// Compact sync status pill shown in the sidebar

import { useEffect } from 'react';
import { syncGetStatus } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import type { SyncStatus } from '../types/vault';

function getSyncLabel(status: SyncStatus): { label: string; dotClass: string } {
    if ('Idle' in status) return { label: 'Sync Idle', dotClass: '' };
    if ('Syncing' in status) return { label: 'Syncing…', dotClass: 'syncing' };
    if ('Synced' in status) return { label: 'Synced', dotClass: 'synced' };
    if ('Offline' in status) return { label: 'Offline', dotClass: 'offline' };
    if ('Conflict' in status) return { label: 'Conflict', dotClass: 'error' };
    if ('Error' in status) return { label: 'Sync Error', dotClass: 'error' };
    return { label: 'Unknown', dotClass: '' };
}

export function SyncStatus() {
    const { syncStatus, setSyncStatus, syncEnabled } = useVaultStore();
    const { label, dotClass } = getSyncLabel(syncStatus);

    useEffect(() => {
        if (!syncEnabled) return;

        const poll = async () => {
            try {
                const status = await syncGetStatus();
                setSyncStatus(status);
            } catch { /* ignore */ }
        };

        poll();
        const interval = setInterval(poll, 15_000);
        return () => clearInterval(interval);
    }, [syncEnabled, setSyncStatus]);

    return (
        <div className='sync-pill' title={JSON.stringify(syncStatus)}>
            <div className={`sync-dot ${dotClass}`} />
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{label}</span>
        </div>
    );
}
