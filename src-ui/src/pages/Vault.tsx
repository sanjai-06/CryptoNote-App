// src-ui/src/pages/Vault.tsx
// Main vault view – fully responsive: mobile-first, desktop-enhanced

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Search, Lock, Settings, Key, ShieldCheck, ChevronRight, X } from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { SyncStatus } from '../components/SyncStatus';
import { ItemDetail } from './ItemDetail';
import { vaultListEntries, vaultLock, syncPull } from '../hooks/useVault';
import { syncConfigure } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';
import { PasswordHealthDashboard } from '../components/PasswordHealth';
import type { EntryListItem } from '../types/vault';

// ── Icon helpers ──────────────────────────────────────────────────────────────
function getCategoryIcon(url?: string): string {
    if (!url) return '🔑';
    if (url.includes('bank') || url.includes('finance') || url.includes('pay')) return '🏦';
    if (url.includes('google') || url.includes('gmail')) return '🎨';
    if (url.includes('github') || url.includes('gitlab')) return '⚙️';
    if (url.includes('facebook') || url.includes('twitter') || url.includes('instagram') || url.includes('linkedin')) return '💬';
    if (url.includes('amazon') || url.includes('shop') || url.includes('ebay')) return '🛒';
    if (url.includes('apple') || url.includes('icloud')) return '🍎';
    if (url.includes('netflix') || url.includes('spotify') || url.includes('youtube')) return '🎵';
    if (url.includes('mail') || url.includes('email') || url.includes('outlook')) return '📧';
    return '🔐';
}

function getCategoryColor(url?: string): string {
    if (!url) return 'linear-gradient(135deg, #6366f1, #8b5cf6)';
    if (url.includes('bank') || url.includes('finance') || url.includes('pay')) return 'linear-gradient(135deg, #f59e0b, #d97706)';
    if (url.includes('google') || url.includes('gmail')) return 'linear-gradient(135deg, #3b82f6, #2563eb)';
    if (url.includes('github')) return 'linear-gradient(135deg, #374151, #111827)';
    if (url.includes('facebook') || url.includes('twitter') || url.includes('instagram')) return 'linear-gradient(135deg, #8b5cf6, #6d28d9)';
    if (url.includes('amazon')) return 'linear-gradient(135deg, #f97316, #ea580c)';
    if (url.includes('netflix')) return 'linear-gradient(135deg, #ef4444, #dc2626)';
    return 'linear-gradient(135deg, var(--accent-1), var(--accent-2))';
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function VaultPage() {
    const navigate = useNavigate();
    const {
        entries, setEntries, searchQuery, setSearchQuery,
        selectedEntryId, setSelectedEntryId, setLocked,
        syncServerUrl, syncEmail, setSyncStatus,
    } = useVaultStore();

    const [isLoading, setIsLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);
    const [showHealth, setShowHealth] = useState(false);
    const [searchFocused, setSearchFocused] = useState(false);
    const [activeTab, setActiveTab] = useState<'vault' | 'health' | 'settings'>('vault');

    const loadEntries = useCallback(async () => {
        setIsLoading(true);
        try {
            const list = await vaultListEntries();
            setEntries(list);
        } catch {
            // Vault locked externally
        } finally {
            setIsLoading(false);
        }
    }, [setEntries]);

    useEffect(() => {
        loadEntries();
        if (syncEmail && syncServerUrl) {
            syncConfigure({
                server_url: syncServerUrl,
                device_id: `device-${syncEmail.replace(/[^a-z0-9]/gi, '')}`,
                user_id: syncEmail,
            }).catch(() => {});
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Auto-sync polling + Tauri event listeners
    useEffect(() => {
        if (!syncEmail || !syncServerUrl) return;
        const doPull = async () => { try { await syncPull(); } catch { } };
        const interval = setInterval(doPull, 30_000);
        let u1: (() => void) | null = null;
        let u2: (() => void) | null = null;
        if (isTauri()) {
            import('@tauri-apps/api/event').then(({ listen }) => {
                listen<void>('vault://refreshed', () => { loadEntries(); setSyncStatus('Synced' as any); }).then(f => { u1 = f; });
                listen<void>('vault://changed', () => { loadEntries(); }).then(f => { u2 = f; });
            });
        }
        return () => { clearInterval(interval); u1?.(); u2?.(); };
    }, [syncEmail, syncServerUrl, loadEntries, setSyncStatus]);

    async function handleLock() {
        await vaultLock();
        setLocked(true);
        navigate('/unlock');
    }

    const filtered = useMemo(() => {
        const q = searchQuery.toLowerCase();
        return entries.filter(e =>
            e.title.toLowerCase().includes(q) ||
            e.url?.toLowerCase().includes(q) ||
            e.tags?.some(t => t.toLowerCase().includes(q))
        );
    }, [entries, searchQuery]);

    const isDetailOpen = !!(selectedEntryId || showAddModal);

    // Navigate via bottom tab
    function handleTab(tab: 'vault' | 'health' | 'settings') {
        setActiveTab(tab);
        if (tab === 'health') { setShowHealth(true); return; }
        if (tab === 'settings') { navigate('/settings'); return; }
    }

    return (
        <div className='app-shell'>
            {/* ── DESKTOP SIDEBAR (hidden on mobile) ── */}
            <aside className='sidebar'>
                <div className='sidebar-logo'>
                    <img src={logoImg} alt='' style={{ width: 32, height: 32, borderRadius: 8 }} />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>CryptoNote</div>
                        <div className='text-xs text-muted'>{entries.length} items</div>
                    </div>
                </div>

                {[
                    { label: 'All Items', icon: <Key size={16} />, tab: 'vault' as const },
                    { label: 'Password Health', icon: <ShieldCheck size={16} />, tab: 'health' as const },
                    { label: 'Settings', icon: <Settings size={16} />, tab: 'settings' as const },
                ].map((item) => (
                    <div
                        key={item.tab}
                        className={`sidebar-nav-item ${activeTab === item.tab ? 'active' : ''}`}
                        onClick={() => handleTab(item.tab)}
                    >
                        {item.icon}
                        {item.label}
                    </div>
                ))}

                <div style={{ flex: 1 }} />
                <div style={{ padding: '0 12px 16px' }}>
                    <SyncStatus />
                    <button className='btn btn-secondary w-full' style={{ marginTop: 10, gap: 8 }} onClick={handleLock}>
                        <Lock size={14} /> Lock Vault
                    </button>
                </div>
            </aside>

            {/* ── MAIN CONTENT ── */}
            <div className='main-content'>

                {/* Mobile header */}
                <div className='mobile-header'>
                    <div className='mobile-header-inner'>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <img src={logoImg} alt='' style={{ width: 28, height: 28, borderRadius: 6 }} />
                            <div>
                                <div style={{ fontWeight: 700, fontSize: '0.9rem', lineHeight: 1.2 }}>CryptoNote</div>
                                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', lineHeight: 1 }}>{entries.length} items</div>
                            </div>
                        </div>
                        <div style={{ display: 'flex', gap: 6 }}>
                            <SyncStatus />
                            <button className='icon-btn' onClick={handleLock} title='Lock Vault'>
                                <Lock size={17} />
                            </button>
                        </div>
                    </div>

                    {/* Inline search (mobile) */}
                    <div className='mobile-search'>
                        <Search size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                        <input
                            type='text'
                            placeholder='Search…'
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                            onFocus={() => setSearchFocused(true)}
                            onBlur={() => setSearchFocused(false)}
                            style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: '0.875rem' }}
                        />
                        {searchQuery && (
                            <button onClick={() => setSearchQuery('')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0, display: 'flex' }}>
                                <X size={14} />
                            </button>
                        )}
                    </div>
                </div>

                {/* Desktop top bar */}
                <div className='topbar desktop-only'>
                    <div className='search-bar'>
                        <Search size={15} className='search-icon' />
                        <input
                            type='text'
                            placeholder='Search passwords…'
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                        />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button className='btn btn-ghost' style={{ gap: 6, padding: '8px 12px' }} onClick={() => setShowHealth(true)}>
                            <ShieldCheck size={15} /> Health
                        </button>
                        <button className='btn btn-primary' style={{ gap: 6, padding: '8px 14px' }} onClick={() => setShowAddModal(true)}>
                            <Plus size={15} /> New Item
                        </button>
                    </div>
                </div>

                {/* Vault layout */}
                <div className={`vault-layout${isDetailOpen ? ' detail-open' : ''}`}>

                    {/* Entry list */}
                    <div className='entry-list'>
                        {isLoading ? (
                            Array.from({ length: 6 }).map((_, i) => (
                                <div key={i} className='entry-skeleton'>
                                    <div className='skeleton' style={{ width: 44, height: 44, borderRadius: 12, flexShrink: 0 }} />
                                    <div style={{ flex: 1 }}>
                                        <div className='skeleton' style={{ height: 13, width: '60%', marginBottom: 7 }} />
                                        <div className='skeleton' style={{ height: 11, width: '40%' }} />
                                    </div>
                                </div>
                            ))
                        ) : filtered.length === 0 ? (
                            <div className='empty-state' style={{ paddingTop: 60 }}>
                                <div className='empty-state-icon'>{searchQuery ? '🔍' : '🔐'}</div>
                                <p style={{ fontWeight: 600 }}>
                                    {searchQuery ? 'No results' : 'Vault is empty'}
                                </p>
                                <p className='text-sm text-muted'>
                                    {searchQuery ? 'Try a different search term' : 'Tap + to add your first password'}
                                </p>
                            </div>
                        ) : (
                            filtered.map((entry) => (
                                <EntryCard
                                    key={entry.id}
                                    entry={entry}
                                    selected={selectedEntryId === entry.id}
                                    onClick={() => setSelectedEntryId(entry.id)}
                                />
                            ))
                        )}
                    </div>

                    {/* Detail / Add panel */}
                    {isDetailOpen ? (
                        <>
                            {/* Mobile back nav strip */}
                            <div className='mobile-back-btn'>
                                <button
                                    onClick={() => { setSelectedEntryId(null); setShowAddModal(false); }}
                                >
                                    <ChevronRight size={16} style={{ transform: 'rotate(180deg)' }} />
                                    All Items
                                </button>
                            </div>
                            <ItemDetail
                                key={selectedEntryId ?? 'new'}
                                entryId={selectedEntryId ?? null}
                                onClose={() => { setSelectedEntryId(null); setShowAddModal(false); }}
                                onSaved={() => { setShowAddModal(false); loadEntries(); }}
                            />
                        </>
                    ) : (
                        <div className='empty-state desktop-only' style={{ flex: 1 }}>
                            <img src={logoImg} alt='' style={{ width: 48, height: 48, opacity: 0.4, marginBottom: 16 }} />
                            <p style={{ fontWeight: 600 }}>Select an item</p>
                            <p className='text-sm text-muted'>Or add a new password</p>
                            <button className='btn btn-primary' style={{ marginTop: 12 }} onClick={() => setShowAddModal(true)}>
                                <Plus size={15} /> New Item
                            </button>
                        </div>
                    )}
                </div>

                {/* Mobile FAB */}
                <button
                    className='mobile-fab'
                    onClick={() => setShowAddModal(true)}
                    aria-label='Add new entry'
                >
                    <Plus size={24} />
                </button>
            </div>

            {/* ── MOBILE BOTTOM NAV ── */}
            <nav className='mobile-bottom-nav'>
                {[
                    { tab: 'vault' as const, icon: <Key size={20} />, label: 'Vault' },
                    { tab: 'health' as const, icon: <ShieldCheck size={20} />, label: 'Health' },
                    { tab: 'settings' as const, icon: <Settings size={20} />, label: 'Settings' },
                ].map(item => (
                    <button
                        key={item.tab}
                        className={`bottom-nav-item${activeTab === item.tab ? ' active' : ''}`}
                        onClick={() => handleTab(item.tab)}
                    >
                        {item.icon}
                        <span>{item.label}</span>
                    </button>
                ))}
            </nav>

            {showHealth && (
                <PasswordHealthDashboard
                    onClose={() => { setShowHealth(false); setActiveTab('vault'); }}
                    onSelectEntry={(id) => setSelectedEntryId(id)}
                />
            )}
        </div>
    );
}

// ── Entry card (mobile-optimized) ─────────────────────────────────────────────
function EntryCard({ entry, selected, onClick }: {
    entry: EntryListItem;
    selected: boolean;
    onClick: () => void;
}) {
    const icon = getCategoryIcon(entry.url);
    const color = getCategoryColor(entry.url);
    const domain = entry.url?.replace(/^https?:\/\//, '').split('/')[0] ?? '';
    const initials = entry.title.slice(0, 2).toUpperCase();

    return (
        <div className={`entry-item mobile-entry-card${selected ? ' selected' : ''}`} onClick={onClick}>
            <div className='entry-favicon' style={{ background: color }}>
                {icon}
            </div>
            <div className='entry-info'>
                <div className='entry-title'>{entry.title}</div>
                {domain && <div className='entry-url'>{domain}</div>}
                {entry.tags && entry.tags.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, marginTop: 3, flexWrap: 'wrap' }}>
                        {entry.tags.slice(0, 2).map(t => (
                            <span key={t} className='mobile-tag'>{t}</span>
                        ))}
                    </div>
                )}
            </div>
            <ChevronRight size={16} className='entry-chevron' />
        </div>
    );
}
