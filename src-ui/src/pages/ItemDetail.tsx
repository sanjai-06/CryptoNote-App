// src-ui/src/pages/ItemDetail.tsx
// View and edit a vault entry, with phishing check on autofill

import { useEffect, useState } from 'react';
import {
    Eye, EyeOff, Copy, X, Save, Trash2,
    ExternalLink, RefreshCw, AlertTriangle, Check, Shield
} from 'lucide-react';
import { PasswordGenerator } from '../components/PasswordGenerator';
import {
    vaultGetEntry, vaultAddEntry, vaultUpdateEntry, vaultDeleteEntry, aiCheckPhishing
} from '../hooks/useVault';
import type { VaultEntry, PhishingRisk } from '../types/vault';
import { v4 as uuidv4 } from 'uuid';

interface Props {
    entryId: string | null;  // null = new entry
    onClose: () => void;
    onSaved: () => void;
}

const emptyEntry = (): VaultEntry => ({
    id: uuidv4(),
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    totp_secret: '',
    tags: [],
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
    version: 1,
});

const riskColors: Record<PhishingRisk, string> = {
    Safe: 'var(--color-success)',
    Suspicious: 'var(--color-warning)',
    HighRisk: 'var(--color-danger)',
    Blocked: '#b91c1c',
};

export function ItemDetail({ entryId, onClose, onSaved }: Props) {
    const isNew = entryId === null;
    const [entry, setEntry] = useState<VaultEntry>(emptyEntry());
    const [isEditing, setIsEditing] = useState(isNew);
    const [showPw, setShowPw] = useState(false);
    const [showGen, setShowGen] = useState(false);
    const [isLoading, setIsLoading] = useState(!isNew);
    const [isSaving, setIsSaving] = useState(false);
    const [copied, setCopied] = useState<string | null>(null);
    const [phishing, setPhishing] = useState<{ risk: PhishingRisk; reasons: string[] } | null>(null);
    const [error, setError] = useState('');

    useEffect(() => {
        if (entryId) {
            vaultGetEntry(entryId).then((e) => {
                setEntry(e);
                setIsLoading(false);
            }).catch(() => setIsLoading(false));
        }
    }, [entryId]);

    async function checkPhishing(url: string) {
        if (!url) return;
        try {
            const result = await aiCheckPhishing(url);
            if (result.risk !== 'Safe') {
                setPhishing({ risk: result.risk, reasons: result.reasons });
            } else {
                setPhishing(null);
            }
        } catch { /* offline AI check failed gracefully */ }
    }

    function copyField(value: string, field: string) {
        navigator.clipboard.writeText(value);
        setCopied(field);
        setTimeout(() => setCopied(null), 1800);
    }

    async function handleSave() {
        if (!entry.title.trim()) { setError('Title is required'); return; }
        if (!entry.password.trim()) { setError('Password is required'); return; }
        setIsSaving(true);
        setError('');
        try {
            if (isNew) {
                await vaultAddEntry({ ...entry, updated_at: Math.floor(Date.now() / 1000) });
            } else {
                await vaultUpdateEntry({ ...entry, updated_at: Math.floor(Date.now() / 1000) });
            }
            onSaved();
            if (!isNew) setIsEditing(false);
        } catch (err: any) {
            setError(err?.toString() ?? 'Failed to save');
        } finally {
            setIsSaving(false);
        }
    }

    async function handleDelete() {
        if (!confirm('Delete this entry? This cannot be undone.')) return;
        await vaultDeleteEntry(entry.id);
        onSaved();
        onClose();
    }

    function set(key: keyof VaultEntry, value: any) {
        setEntry((prev) => ({ ...prev, [key]: value }));
    }

    if (isLoading) {
        return (
            <div className='entry-detail' style={{ flex: 1 }}>
                {[300, 200, 180, 200].map((w, i) => (
                    <div key={i} className='skeleton' style={{ height: 48, width: `${w}px`, maxWidth: '100%', borderRadius: 12 }} />
                ))}
            </div>
        );
    }

    return (
        <div className='entry-detail' style={{ flex: 1, position: 'relative' }}>
            {/* Header */}
            <div className='detail-header'>
                <div className='detail-favicon' style={{ fontSize: 26 }}>
                    {entry.url ? '🌐' : '🔑'}
                </div>
                {isEditing ? (
                    <input
                        className='form-input'
                        style={{ fontSize: '1.1rem', fontWeight: 700, flex: 1 }}
                        placeholder='Entry title…'
                        value={entry.title}
                        onChange={(e) => set('title', e.target.value)}
                        autoFocus={isNew}
                    />
                ) : (
                    <div style={{ flex: 1 }}>
                        <h2 style={{ fontSize: '1.25rem' }}>{entry.title}</h2>
                        {entry.url && (
                            <a
                                href={entry.url}
                                target='_blank'
                                rel='noreferrer'
                                style={{ color: 'var(--color-info)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: 4, textDecoration: 'none', marginTop: 2 }}
                            >
                                {entry.url.replace(/^https?:\/\//, '')} <ExternalLink size={11} />
                            </a>
                        )}
                    </div>
                )}
                <div style={{ display: 'flex', gap: 6 }}>
                    {!isNew && !isEditing && (
                        <button className='btn btn-secondary btn-icon' title='Edit' onClick={() => setIsEditing(true)}>
                            ✏️
                        </button>
                    )}
                    {!isNew && (
                        <button className='btn btn-ghost btn-icon' title='Delete' onClick={handleDelete}>
                            <Trash2 size={15} color='var(--color-danger)' />
                        </button>
                    )}
                    <button className='btn btn-ghost btn-icon' onClick={onClose}>
                        <X size={16} />
                    </button>
                </div>
            </div>

            {/* Phishing warning */}
            {phishing && (
                <div style={{
                    background: phishing.risk === 'Blocked' ? 'rgba(185,28,28,0.15)' : 'rgba(239,68,68,0.1)',
                    border: `1px solid ${riskColors[phishing.risk]}`,
                    borderRadius: 'var(--radius-md)',
                    padding: '12px 16px',
                    display: 'flex', flexDirection: 'column', gap: 6,
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: riskColors[phishing.risk], fontWeight: 700 }}>
                        <AlertTriangle size={16} />
                        {phishing.risk === 'Blocked' ? '⛔ Autofill Blocked – High Phishing Risk' : `⚠️ ${phishing.risk} Phishing Risk Detected`}
                    </div>
                    {phishing.reasons.map((r) => (
                        <div key={r} style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: 24 }}>• {r}</div>
                    ))}
                </div>
            )}

            {/* URL field */}
            {isEditing ? (
                <>
                    <div className='form-group'>
                        <label className='form-label'>Website URL</label>
                        <input
                            className='form-input'
                            placeholder='https://example.com'
                            value={entry.url ?? ''}
                            onChange={(e) => { set('url', e.target.value); checkPhishing(e.target.value); }}
                        />
                    </div>
                    <div className='form-group'>
                        <label className='form-label'>Username / Email</label>
                        <input
                            className='form-input'
                            placeholder='username@email.com'
                            value={entry.username}
                            onChange={(e) => set('username', e.target.value)}
                        />
                    </div>
                    <div className='form-group'>
                        <label className='form-label'>Password</label>
                        <div style={{ display: 'flex', gap: 8 }}>
                            <div style={{ position: 'relative', flex: 1 }}>
                                <input
                                    className='form-input font-mono'
                                    type={showPw ? 'text' : 'password'}
                                    placeholder='Password…'
                                    value={entry.password}
                                    onChange={(e) => set('password', e.target.value)}
                                    style={{ paddingRight: 40 }}
                                />
                                <button type='button' className='btn btn-ghost btn-icon'
                                    style={{ position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)' }}
                                    onClick={() => setShowPw(!showPw)}>
                                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                                </button>
                            </div>
                            <button className='btn btn-secondary btn-icon' title='Generate password'
                                onClick={() => setShowGen(!showGen)}>
                                <RefreshCw size={15} />
                            </button>
                        </div>
                        {showGen && (
                            <div style={{ marginTop: 8 }}>
                                <PasswordGenerator onSelect={(pw) => { set('password', pw); setShowGen(false); }} />
                            </div>
                        )}
                    </div>
                    <div className='form-group'>
                        <label className='form-label'>Notes</label>
                        <textarea
                            className='form-input'
                            rows={3}
                            placeholder='Optional notes…'
                            value={entry.notes ?? ''}
                            onChange={(e) => set('notes', e.target.value)}
                            style={{ resize: 'vertical', fontFamily: 'inherit' }}
                        />
                    </div>
                </>
            ) : (
                <>
                    <FieldRow label='Username' value={entry.username} onCopy={() => copyField(entry.username, 'username')} copied={copied === 'username'} />
                    <FieldRow
                        label='Password'
                        value={entry.password}
                        masked
                        onCopy={() => copyField(entry.password, 'password')}
                        copied={copied === 'password'}
                    />
                    {entry.url && <FieldRow label='URL' value={entry.url} onCopy={() => copyField(entry.url!, 'url')} copied={copied === 'url'} />}
                    {entry.notes && <FieldRow label='Notes' value={entry.notes} onCopy={() => copyField(entry.notes!, 'notes')} copied={copied === 'notes'} />}
                    <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                        <span className='badge badge-info'><Shield size={9} /> Zero-Knowledge Encrypted</span>
                    </div>
                </>
            )}

            {error && (
                <div style={{
                    padding: '10px 14px', background: 'rgba(239,68,68,0.1)',
                    borderRadius: 'var(--radius-md)', border: '1px solid var(--border-danger)',
                    color: 'var(--color-danger)', fontSize: '0.8125rem'
                }}>{error}</div>
            )}

            {isEditing && (
                <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                    <button className='btn btn-primary' style={{ flex: 1 }} onClick={handleSave} disabled={isSaving}>
                        <Save size={15} /> {isSaving ? 'Saving…' : 'Save Entry'}
                    </button>
                    {!isNew && (
                        <button className='btn btn-secondary' onClick={() => { setIsEditing(false); setError(''); }}>
                            Cancel
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}

function FieldRow({ label, value, masked = false, onCopy, copied }: {
    label: string; value: string; masked?: boolean; onCopy: () => void; copied: boolean;
}) {
    const [reveal, setReveal] = useState(false);

    return (
        <div className='detail-field'>
            <div style={{ flex: 1, minWidth: 0 }}>
                <div className='detail-field-label'>{label}</div>
                <div className={`detail-field-value ${masked && !reveal ? 'masked' : ''} select-text`}>
                    {masked && !reveal ? '••••••••••••' : value}
                </div>
            </div>
            <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                {masked && (
                    <button className='btn btn-ghost btn-icon' onClick={() => setReveal(!reveal)}>
                        {reveal ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                )}
                <button className='btn btn-ghost btn-icon' onClick={onCopy} title='Copy to clipboard'>
                    {copied ? <Check size={14} color='var(--color-success)' /> : <Copy size={14} />}
                </button>
            </div>
        </div>
    );
}
