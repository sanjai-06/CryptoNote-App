// src-ui/src/pages/Settings.tsx
// Auto-lock, sync, security, and device management settings

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, Clock, Cloud, Smartphone, Lock,
    Key, AlertTriangle, ChevronLeft, RefreshCw
} from 'lucide-react';
import { SyncStatus } from '../components/SyncStatus';
import { PasswordGenerator } from '../components/PasswordGenerator';
import {
    setAutoLockTimeout, syncConfigure, securityCheckDevice, vaultLock
} from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';

const lockOptions = [
    { label: '1 minute', value: 60 },
    { label: '5 minutes', value: 300 },
    { label: '15 minutes', value: 900 },
    { label: '1 hour', value: 3600 },
    { label: 'Never', value: 0 },
];

export function SettingsPage() {
    const navigate = useNavigate();
    const { autoLockTimeout, setAutoLockTimeout: storeSetTimeout,
        syncEnabled, setSyncEnabled, setLocked } = useVaultStore();

    const [serverUrl, setServerUrl] = useState('https://localhost:3443');
    const [email, setEmail] = useState('');
    const [isSavingSync, setIsSavingSync] = useState(false);
    const [securityStatus, setSecurityStatus] = useState<{ is_compromised: boolean; findings: string[] } | null>(null);
    const [checkingDevice, setCheckingDevice] = useState(false);
    const [showPwGen, setShowPwGen] = useState(false);
    const [savedMsg, setSavedMsg] = useState('');

    useEffect(() => {
        runDeviceCheck();
    }, []);

    async function runDeviceCheck() {
        setCheckingDevice(true);
        try {
            const result = await securityCheckDevice();
            setSecurityStatus(result);
        } catch { /* desktop – not applicable */ }
        setCheckingDevice(false);
    }

    async function handleLockTimeout(val: number) {
        storeSetTimeout(val);
        await setAutoLockTimeout(val);
        flash('Auto-lock timeout saved ✓');
    }

    async function handleSaveSync() {
        setIsSavingSync(true);
        try {
            await syncConfigure({
                server_url: serverUrl,
                device_id: `device-${Math.random().toString(36).slice(2)}`,
                user_id: email || undefined,
            });
            setSyncEnabled(true);
            flash('Sync settings saved ✓');
        } catch { /* ignore */ }
        setIsSavingSync(false);
    }

    function flash(msg: string) {
        setSavedMsg(msg);
        setTimeout(() => setSavedMsg(''), 2500);
    }

    async function handleLockNow() {
        await vaultLock();
        setLocked(true);
        navigate('/unlock');
    }

    return (
        <div className='app-shell'>
            {/* Sidebar */}
            <aside className='sidebar'>
                <div className='sidebar-logo'>
                    <div className='logo-icon'>🔐</div>
                    <div>
                        <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>CryptoNote</div>
                        <div className='text-xs text-muted'>Settings</div>
                    </div>
                </div>
                <div className='sidebar-nav-item' onClick={() => navigate('/vault')}>
                    <ChevronLeft size={16} /> Back to Vault
                </div>
                <div style={{ flex: 1 }} />
                <div style={{ padding: '0 12px 16px' }}>
                    <SyncStatus />
                    <button className='btn btn-secondary w-full' style={{ marginTop: 10 }} onClick={handleLockNow}>
                        <Lock size={14} /> Lock Vault
                    </button>
                </div>
            </aside>

            {/* Main */}
            <div className='main-content' style={{ overflowY: 'auto' }}>
                <div className='page-header'>
                    <div>
                        <h2>Settings</h2>
                        <p className='text-sm text-muted' style={{ marginTop: 4 }}>Security, sync, and preferences</p>
                    </div>
                    {savedMsg && (
                        <span className='badge badge-success' style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
                            {savedMsg}
                        </span>
                    )}
                </div>

                <div style={{ padding: '24px 32px', maxWidth: 640 }}>

                    {/* ── Security status ────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><ShieldCheck size={13} style={{ display: 'inline', marginRight: 6 }} />Device Security</div>

                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Device integrity check</div>
                                <div className='settings-row-desc'>Detects root / jailbreak</div>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                {securityStatus === null ? (
                                    <span className='text-xs text-muted'>{checkingDevice ? 'Checking…' : 'N/A'}</span>
                                ) : securityStatus.is_compromised ? (
                                    <span className='badge badge-danger'><AlertTriangle size={10} /> Compromised</span>
                                ) : (
                                    <span className='badge badge-success'><ShieldCheck size={10} /> Secure</span>
                                )}
                                <button className='btn btn-ghost btn-icon' onClick={runDeviceCheck}>
                                    <RefreshCw size={13} className={checkingDevice ? 'spin' : ''} />
                                </button>
                            </div>
                        </div>

                        {securityStatus?.is_compromised && (
                            <div style={{
                                margin: '0 16px 16px',
                                padding: '12px',
                                background: 'rgba(239,68,68,0.08)',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid var(--border-danger)',
                                fontSize: '0.8rem',
                                color: 'var(--color-danger)'
                            }}>
                                ⚠️ Running on a compromised device significantly reduces security guarantees.
                                {securityStatus.findings.map((f) => <div key={f} style={{ paddingLeft: 12, marginTop: 4 }}>• {f}</div>)}
                            </div>
                        )}

                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Zero-Knowledge Architecture</div>
                                <div className='settings-row-desc'>Server never sees your plaintext data</div>
                            </div>
                            <span className='badge badge-success'>Active</span>
                        </div>

                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Encryption</div>
                                <div className='settings-row-desc'>XChaCha20-Poly1305 + Argon2id</div>
                            </div>
                            <span className='badge badge-info'>Enabled</span>
                        </div>
                    </div>

                    {/* ── Auto-lock ──────────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Clock size={13} style={{ display: 'inline', marginRight: 6 }} />Auto-Lock</div>
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Lock after inactivity</div>
                                <div className='settings-row-desc'>Vault automatically locks when idle</div>
                            </div>
                            <select
                                value={autoLockTimeout}
                                onChange={(e) => handleLockTimeout(Number(e.target.value))}
                                style={{
                                    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                                    borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
                                    padding: '6px 10px', fontSize: '0.875rem', cursor: 'pointer',
                                    outline: 'none',
                                }}
                            >
                                {lockOptions.map((o) => (
                                    <option key={o.value} value={o.value}>{o.label}</option>
                                ))}
                            </select>
                        </div>
                    </div>

                    {/* ── Sync ───────────────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Cloud size={13} style={{ display: 'inline', marginRight: 6 }} />Encrypted Cloud Sync</div>

                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Enable sync</div>
                                <div className='settings-row-desc'>Encrypted vault sync to your server</div>
                            </div>
                            <label className='toggle'>
                                <input type='checkbox' checked={syncEnabled} onChange={(e) => setSyncEnabled(e.target.checked)} />
                                <span className='toggle-slider' />
                            </label>
                        </div>

                        {syncEnabled && (
                            <div style={{ padding: '0 20px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                                <div className='form-group'>
                                    <label className='form-label'>Server URL</label>
                                    <input
                                        className='form-input'
                                        value={serverUrl}
                                        onChange={(e) => setServerUrl(e.target.value)}
                                        placeholder='https://your-server.com'
                                    />
                                </div>
                                <div className='form-group'>
                                    <label className='form-label'>Account Email</label>
                                    <input
                                        className='form-input'
                                        type='email'
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        placeholder='you@example.com'
                                    />
                                </div>
                                <div style={{
                                    background: 'rgba(0,229,160,0.06)',
                                    border: '1px solid var(--border-accent)',
                                    borderRadius: 'var(--radius-md)',
                                    padding: '10px 14px',
                                    fontSize: '0.8rem',
                                    color: 'var(--text-secondary)'
                                }}>
                                    🔒 Your vault is encrypted before leaving this device. The server stores only an encrypted blob — it cannot read your data.
                                </div>
                                <button className='btn btn-primary' onClick={handleSaveSync} disabled={isSavingSync}>
                                    <Cloud size={14} /> {isSavingSync ? 'Saving…' : 'Save Sync Settings'}
                                </button>
                            </div>
                        )}
                    </div>

                    {/* ── Biometrics ──────────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Smartphone size={13} style={{ display: 'inline', marginRight: 6 }} />Biometric Unlock</div>
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Face ID / Touch ID / Fingerprint</div>
                                <div className='settings-row-desc'>Available on Android & iOS via Tauri plugin</div>
                            </div>
                            <span className='badge badge-info'>Mobile Only</span>
                        </div>
                    </div>

                    {/* ── Password Generator ───────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Key size={13} style={{ display: 'inline', marginRight: 6 }} />Password Generator</div>
                        <div className='settings-row' onClick={() => setShowPwGen(!showPwGen)} style={{ cursor: 'pointer' }}>
                            <div>
                                <div className='settings-row-label'>Generate secure password</div>
                                <div className='settings-row-desc'>Create a new random password</div>
                            </div>
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{showPwGen ? '▲ Hide' : '▼ Show'}</span>
                        </div>
                        {showPwGen && (
                            <div style={{ padding: '0 16px 16px' }}>
                                <PasswordGenerator />
                            </div>
                        )}
                    </div>

                    {/* ── Data Management ────────────────────────────────── */}
                    <DataManagementSection onFlash={flash} />

                    {/* ── About ───────────────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'>About</div>
                        <div className='settings-row'>
                            <div className='settings-row-label'>CryptoNote</div>
                            <span className='text-sm text-muted'>v0.1.0</span>
                        </div>
                        <div className='settings-row'>
                            <div className='settings-row-label'>Encryption</div>
                            <span className='text-sm text-muted font-mono'>XChaCha20-Poly1305</span>
                        </div>
                        <div className='settings-row'>
                            <div className='settings-row-label'>Key Derivation</div>
                            <span className='text-sm text-muted font-mono'>Argon2id</span>
                        </div>
                        <div className='settings-row'>
                            <div className='settings-row-label'>Subkey Derivation</div>
                            <span className='text-sm text-muted font-mono'>HKDF-SHA256</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

function DataManagementSection({ onFlash }: { onFlash: (msg: string) => void }) {
    const [isExporting, setIsExporting] = useState(false);
    const [isImporting, setIsImporting] = useState(false);

    async function handleExport() {
        setIsExporting(true);
        try {
            const { exportVaultJson } = await import('../lib/importExport');
            await exportVaultJson();
            onFlash('Export successful ✓');
        } catch (e: any) {
            onFlash(`Export failed: ${e?.message ?? 'Unknown error'}`);
        }
        setIsExporting(false);
    }

    async function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
        const file = e.target.files?.[0];
        if (!file) return;

        setIsImporting(true);
        try {
            const { importVaultJson } = await import('../lib/importExport');
            const result = await importVaultJson(file);
            onFlash(`Imported: ${result.success} added, ${result.skipped} skipped.`);
        } catch (err: any) {
            onFlash(`Import failed: ${err?.message ?? 'Unknown error'}`);
        }
        setIsImporting(false);
        e.target.value = ''; // reset
    }

    return (
        <div className='settings-section'>
            <div className='settings-section-title'>Data Management</div>
            <div className='settings-row'>
                <div>
                    <div className='settings-row-label'>Export Vault</div>
                    <div className='settings-row-desc'>Download your unencrypted vault as JSON</div>
                </div>
                <button className='btn btn-secondary' onClick={handleExport} disabled={isExporting}>
                    {isExporting ? 'Exporting…' : 'Export JSON'}
                </button>
            </div>
            <div className='settings-row'>
                <div>
                    <div className='settings-row-label'>Import Vault</div>
                    <div className='settings-row-desc'>Merge entries from a JSON backup</div>
                </div>
                <div>
                    <input
                        type='file'
                        accept='.json'
                        style={{ display: 'none' }}
                        id='import-file'
                        onChange={handleImport}
                        disabled={isImporting}
                    />
                    <label htmlFor='import-file' className='btn btn-secondary' style={{ display: 'inline-block', cursor: 'pointer', opacity: isImporting ? 0.5 : 1 }}>
                        {isImporting ? 'Importing…' : 'Import JSON'}
                    </label>
                </div>
            </div>
        </div>
    );
}
