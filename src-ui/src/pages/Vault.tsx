// src-ui/src/pages/Vault.tsx
// Main vault view: sidebar nav + entry list + detail panel

import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Plus, Search, Lock, Settings, Shield, Globe,
    CreditCard, Wifi, FileText, Key
} from 'lucide-react';
import { SyncStatus } from '../components/SyncStatus';
import { ItemDetail } from './ItemDetail';
import { vaultListEntries, vaultLock } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import type { EntryListItem } from '../types/vault';

function getCategoryIcon(url?: string): string {
    if (!url) return '🔑';
    if (url.includes('bank') || url.includes('finance') || url.includes('pay')) return '🏦';
    if (url.includes('google') || url.includes('gmail')) return '🎨';
    if (url.includes('github') || url.includes('gitlab')) return '⚙️';
    if (url.includes('facebook') || url.includes('twitter') || url.includes('instagram')) return '💬';
    if (url.includes('amazon') || url.includes('shop')) return '🛒';
    if (url.includes('apple') || url.includes('icloud')) return '🍎';
    return '🔐';
}

export function VaultPage() {
    const navigate = useNavigate();
    const {
        entries, setEntries, searchQuery, setSearchQuery,
        selectedEntryId, setSelectedEntryId, setLocked, isLocked
    } = useVaultStore();

    const [isLoading, setIsLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);

    useEffect(() => {
        loadEntries();
    }, []);

    async function loadEntries() {
        setIsLoading(true);
        try {
            const list = await vaultListEntries();
            setEntries(list);
        } catch {
            // Vault may have been locked externally
        } finally {
            setIsLoading(false);
        }
    }

    async function handleLock() {
        await vaultLock();
        setLocked(true);
        navigate('/unlock');
    }

    const filtered = useMemo(() => {
        const q = searchQuery.toLowerCase();
        return entries.filter(
            (e) =>
                e.title.toLowerCase().includes(q) ||
                e.url?.toLowerCase().includes(q)
        );
    }, [entries, searchQuery]);

    const navItems = [
        { label: 'All Items', icon: <Key size={16} />, path: '/vault' },
        { label: 'Settings', icon: <Settings size={16} />, path: '/settings' },
    ];

    return (
        <div className='app-shell'>
            {/* Sidebar */}
            <aside className='sidebar'>
                <div className='sidebar-logo'>
                    <div className='logo-icon'>🔐</div>
                    <div>
                        <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>CryptoNote</div>
                        <div className='text-xs text-muted'>{entries.length} items</div>
                    </div>
                </div>

                {navItems.map((item) => (
                    <div
                        key={item.path}
                        className={`sidebar-nav-item ${item.path === '/vault' ? 'active' : ''}`}
                        onClick={() => navigate(item.path)}
                    >
                        {item.icon}
                        {item.label}
                    </div>
                ))}

                <div style={{ flex: 1 }} />

                <div style={{ padding: '0 12px 16px' }}>
                    <SyncStatus />
                    <button
                        className='btn btn-secondary w-full'
                        style={{ marginTop: 10, gap: 8 }}
                        onClick={handleLock}
                    >
                        <Lock size={14} /> Lock Vault
                    </button>
                </div>
            </aside>

            {/* Main content */}
            <div className='main-content'>
                {/* Top bar */}
                <div className='topbar'>
                    <div className='search-bar'>
                        <Search size={15} className='search-icon' />
                        <input
                            type='text'
                            placeholder='Search passwords…'
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                            className='btn btn-primary'
                            style={{ gap: 6, padding: '8px 14px' }}
                            onClick={() => setShowAddModal(true)}
                        >
                            <Plus size={15} /> New Item
                        </button>
                    </div>
                </div>

                {/* Vault layout: list + detail */}
                <div className='vault-layout'>
                    {/* Entry list */}
                    <div className='entry-list'>
                        {isLoading ? (
                            Array.from({ length: 6 }).map((_, i) => (
                                <div key={i} style={{ padding: '12px 14px', display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <div className='skeleton' style={{ width: 36, height: 36, borderRadius: 8, flexShrink: 0 }} />
                                    <div style={{ flex: 1 }}>
                                        <div className='skeleton' style={{ height: 13, width: '65%', marginBottom: 6 }} />
                                        <div className='skeleton' style={{ height: 11, width: '45%' }} />
                                    </div>
                                </div>
                            ))
                        ) : filtered.length === 0 ? (
                            <div className='empty-state' style={{ paddingTop: 60 }}>
                                <div className='empty-state-icon'>🔍</div>
                                <p style={{ fontWeight: 600 }}>
                                    {searchQuery ? 'No results found' : 'Your vault is empty'}
                                </p>
                                <p className='text-sm text-muted'>
                                    {searchQuery ? 'Try a different search' : 'Click "+ New Item" to add your first password'}
                                </p>
                            </div>
                        ) : (
                            filtered.map((entry) => (
                                <EntryRow
                                    key={entry.id}
                                    entry={entry}
                                    selected={selectedEntryId === entry.id}
                                    onClick={() => setSelectedEntryId(entry.id)}
                                />
                            ))
                        )}
                    </div>

                    {/* Detail panel */}
                    {selectedEntryId ? (
                        <ItemDetail
                            key={selectedEntryId}
                            entryId={selectedEntryId}
                            onClose={() => setSelectedEntryId(null)}
                            onSaved={loadEntries}
                        />
                    ) : showAddModal ? (
                        <ItemDetail
                            entryId={null}
                            onClose={() => setShowAddModal(false)}
                            onSaved={() => { setShowAddModal(false); loadEntries(); }}
                        />
                    ) : (
                        <div className='empty-state' style={{ flex: 1 }}>
                            <div className='empty-state-icon'>🔐</div>
                            <p style={{ fontWeight: 600 }}>Select an item to view details</p>
                            <p className='text-sm text-muted'>Or click "+ New Item" to add a password</p>
                            <button className='btn btn-primary' style={{ marginTop: 8 }} onClick={() => setShowAddModal(true)}>
                                <Plus size={15} /> New Item
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function EntryRow({ entry, selected, onClick }: {
    entry: EntryListItem;
    selected: boolean;
    onClick: () => void;
}) {
    const icon = getCategoryIcon(entry.url);
    const formatted = entry.url?.replace(/^https?:\/\//, '').split('/')[0] ?? '';

    return (
        <div className={`entry-item ${selected ? 'selected' : ''}`} onClick={onClick}>
            <div className='entry-favicon'>{icon}</div>
            <div className='entry-info'>
                <div className='entry-title'>{entry.title}</div>
                {formatted && <div className='entry-url'>{formatted}</div>}
            </div>
        </div>
    );
}
