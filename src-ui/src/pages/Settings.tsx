// src-ui/src/pages/Settings.tsx
// Auto-lock, sync, security, and device management settings

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, Clock, Cloud, Smartphone, Lock,
    Key, AlertTriangle, ChevronLeft, RefreshCw, Palette, Fingerprint
} from 'lucide-react';
import logoImg from '../assets/logo-120.png';
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

const themeOptions = [
    { label: 'System Default', value: 'system' },
    { label: 'Dark Mode', value: 'dark' },
    { label: 'Light Mode', value: 'light' },
];

export function SettingsPage() {
    const navigate = useNavigate();
    const { autoLockTimeout, setAutoLockTimeout: storeSetTimeout,
        syncEnabled, setSyncEnabled, setLocked,
        syncServerUrl, syncEmail, setSyncConfig,
        theme, setTheme,
        biometricEnabled, setBiometricEnabled } = useVaultStore();

    const [serverUrl, setServerUrl] = useState(syncServerUrl);
    const [email, setEmail] = useState(syncEmail);
    const [isSavingSync, setIsSavingSync] = useState(false);
    const [securityStatus, setSecurityStatus] = useState<{ is_compromised: boolean; findings: string[] } | null>(null);
    const [checkingDevice, setCheckingDevice] = useState(false);
    const [showPwGen, setShowPwGen] = useState(false);
    const [savedMsg, setSavedMsg] = useState('');
    const [syncError, setSyncError] = useState('');

    // Re-apply saved sync config to Tauri engine on mount
    useEffect(() => {
        runDeviceCheck();
        if (syncEmail && syncServerUrl) {
            syncConfigure({
                server_url: syncServerUrl,
                device_id: `device-${syncEmail.replace(/[^a-z0-9]/gi, '')}`,
                user_id: syncEmail,
            }).catch(() => {});
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
        setSyncError('');
        if (!email.trim()) {
            setSyncError('Please enter your Account Email before saving.');
            return;
        }
        if (!serverUrl.trim()) {
            setSyncError('Server URL is required.');
            return;
        }
        const deviceId = `device-${email.trim().replace(/[^a-z0-9]/gi, '')}`;
        setIsSavingSync(true);
        try {
            await syncConfigure({
                server_url: serverUrl.trim(),
                device_id: deviceId,
                user_id: email.trim(),
            });
            // Persist to localStorage via store
            setSyncConfig(serverUrl.trim(), email.trim(), true);
            setSyncError('');
            flash('Sync settings saved ✓');
        } catch (err: any) {
            setSyncError(err?.message || 'Failed to save sync settings. Is the app running?');
        }
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
                    <img src={logoImg} alt="" className='logo-icon' style={{ width: 32, height: 32, borderRadius: 8 }} />
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

            {/* Fixed toast notification – visible regardless of scroll */}
            {savedMsg && (
                <div style={{
                    position: 'fixed',
                    bottom: 24,
                    right: 24,
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-accent)',
                    borderRadius: 'var(--radius-md)',
                    padding: '10px 18px',
                    color: 'var(--accent-1)',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
                    zIndex: 9999,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                }}>
                    ✓ {savedMsg}
                </div>
            )}

            {/* Main */}
            <div className='main-content' style={{ overflowY: 'auto' }}>
                <div className='page-header'>
                    <div>
                        <h2>Settings</h2>
                        <p className='text-sm text-muted' style={{ marginTop: 4 }}>Security, sync, and preferences</p>
                    </div>
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

                    {/* ── Appearance ───────────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Palette size={13} style={{ display: 'inline', marginRight: 6 }} />Appearance</div>
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Theme</div>
                                <div className='settings-row-desc'>Customize the look and feel of the app</div>
                            </div>
                            <select
                                className='form-select'
                                value={theme}
                                onChange={(e) => setTheme(e.target.value as 'system' | 'light' | 'dark')}
                                style={{ width: 'auto', minWidth: '140px' }}
                            >
                                {themeOptions.map((o) => (
                                    <option key={o.value} value={o.value}>{o.label}</option>
                                ))}
                            </select>
                        </div>
                    </div>

                    {/* ── Biometric Unlock ─────────────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Fingerprint size={13} style={{ display: 'inline', marginRight: 6 }} />Biometric Unlock</div>
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Unlock with Biometrics</div>
                                <div className='settings-row-desc'>Use fingerprint or Face ID to unlock your vault</div>
                            </div>
                            <label className='toggle'>
                                <input type='checkbox' checked={biometricEnabled} onChange={(e) => setBiometricEnabled(e.target.checked)} />
                                <span className='toggle-slider' />
                            </label>
                        </div>
                        {biometricEnabled && (
                            <div style={{
                                padding: '10px 14px', marginTop: 4,
                                background: 'rgba(0,229,160,0.08)',
                                borderRadius: 'var(--radius-md)',
                                border: '1px solid rgba(0,229,160,0.2)',
                                fontSize: '0.8rem', color: 'var(--text-secondary)',
                            }}>
                                <Fingerprint size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                                After your next master password unlock, biometric unlock will be available.
                                Your password is stored securely on this device.
                            </div>
                        )}
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
                                className='form-select'
                                value={autoLockTimeout}
                                onChange={(e) => handleLockTimeout(Number(e.target.value))}
                                style={{ width: 'auto', minWidth: '140px' }}
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
                                {syncError && (
                                    <div style={{
                                        background: 'rgba(239,68,68,0.08)',
                                        border: '1px solid var(--border-danger)',
                                        borderRadius: 'var(--radius-md)',
                                        padding: '8px 12px',
                                        fontSize: '0.8rem',
                                        color: 'var(--color-danger)',
                                    }}>
                                        ⚠️ {syncError}
                                    </div>
                                )}
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

    async function handleExport(format: 'json' | 'csv') {
        setIsExporting(true);
        try {
            const { exportVault } = await import('../lib/importExport');
            await exportVault(format);
            onFlash(`Export successful ✓`);
        } catch (e: any) {
            console.error('Export error:', e);
            const msg = typeof e === 'string' ? e : e?.message ?? 'Unknown error';
            onFlash(`Export failed: ${msg}`);
        }
        setIsExporting(false);
    }

    async function handleImport() {
        setIsImporting(true);
        try {
            const { importVaultJson } = await import('../lib/importExport');
            const result = await importVaultJson();
            if (result) {
                onFlash(`Imported: ${result.success} added, ${result.skipped} skipped.`);
            }
        } catch (err: any) {
            console.error('Import error:', err);
            const msg = typeof err === 'string' ? err : err?.message ?? 'Unknown error';
            onFlash(`Import failed: ${msg}`);
        }
        setIsImporting(false);
    }

    return (
        <div className='settings-section'>
            <div className='settings-section-title'>Data Management</div>
            <div className='settings-row'>
                <div>
                    <div className='settings-row-label'>Export Vault</div>
                    <div className='settings-row-desc'>Download your unencrypted vault</div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <button className='btn btn-secondary' onClick={() => handleExport('json')} disabled={isExporting}>
                        JSON
                    </button>
                    <button className='btn btn-secondary' onClick={() => handleExport('csv')} disabled={isExporting}>
                        CSV
                    </button>
                </div>
            </div>
            <div className='settings-row'>
                <div>
                    <div className='settings-row-label'>Import Vault</div>
                    <div className='settings-row-desc'>Merge entries from a JSON backup</div>
                </div>
                <button className='btn btn-secondary' onClick={handleImport} disabled={isImporting}>
                    {isImporting ? 'Importing…' : 'Import JSON / CSV'}
                </button>
            </div>
        </div>
    );
}
