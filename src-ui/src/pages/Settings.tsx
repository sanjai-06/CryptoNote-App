// src-ui/src/pages/Settings.tsx
// Auto-lock, sync, security, and device management settings

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, Clock, Cloud, Smartphone, Lock,
    Key, AlertTriangle, ChevronLeft, RefreshCw, Palette,
    Fingerprint, Eye, EyeOff, Download, CheckCircle2
} from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { SyncStatus } from '../components/SyncStatus';
import { PasswordGenerator } from '../components/PasswordGenerator';
import {
    vaultLock, syncConfigure, securityCheckDevice,
    setAutoLockTimeout, syncPull, syncPush,
} from '../hooks/useVault';
import { isTauri } from '@tauri-apps/api/core';
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
        biometricEnabled, setBiometricEnabled,
        storeBiometricPassword, getBiometricPassword,
    } = useVaultStore();

    const [serverUrl, setServerUrl] = useState(syncServerUrl);
    const [email, setEmail] = useState(syncEmail);
    const [isSavingSync, setIsSavingSync] = useState(false);
    const [securityStatus, setSecurityStatus] = useState<{ is_compromised: boolean; findings: string[] } | null>(null);
    const [checkingDevice, setCheckingDevice] = useState(false);
    const [showPwGen, setShowPwGen] = useState(false);
    const [savedMsg, setSavedMsg] = useState('');
    const [syncError, setSyncError] = useState('');

    const [syncPullState, setSyncPullState] = useState<'idle'|'pulling'|'ok'|'error'>('idle');
    const [syncPushState, setSyncPushState] = useState<'idle'|'pushing'|'ok'|'error'>('idle');
    const [syncActionMsg, setSyncActionMsg] = useState('');
    const [showBioEnroll, setShowBioEnroll]   = useState(false);
    const [bioEnrollPw, setBioEnrollPw]       = useState('');
    const [showBioEnrollPw, setShowBioEnrollPw] = useState(false);
    const [bioEnrollError, setBioEnrollError] = useState('');
    const [bioEnrolling, setBioEnrolling]     = useState(false);
    const bioEnrollRef = useRef<HTMLInputElement>(null);
    const isEnrolled = getBiometricPassword() !== null;
    const enrolledAt = (() => { try { return localStorage.getItem('cryptonote_bio_enrolled_at'); } catch { return null; } })();

    // Biometric sensor status
    type BioSensorStatus = 'checking' | 'available' | 'notEnrolled' | 'unavailable' | 'notAvailable' | 'unknown';
    const [bioSensorStatus, setBioSensorStatus] = useState<BioSensorStatus>('checking');

    // Re-apply saved sync config to Tauri engine on mount
    useEffect(() => {
        runDeviceCheck();
        checkBioSensor();
        if (syncEmail && syncServerUrl) {
            syncConfigure({
                server_url: syncServerUrl,
                device_id: `device-${syncEmail.replace(/[^a-z0-9]/gi, '')}`,
                user_id: syncEmail,
            }).catch(() => {});
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    async function checkBioSensor() {
        setBioSensorStatus('checking');
        try {
            const { checkStatus } = await import('@tauri-apps/plugin-biometric');
            const status = await checkStatus();
            if (status.isAvailable) {
                setBioSensorStatus('available');
            } else {
                const code = status.errorCode ?? '';
                if (code === 'biometryNotEnrolled')  setBioSensorStatus('notEnrolled');
                else if (code === 'biometryLockout')  setBioSensorStatus('unavailable');
                else                                  setBioSensorStatus('notAvailable');
            }
        } catch {
            // Plugin not available on this platform (desktop) — that's fine
            setBioSensorStatus('unknown');
        }
    }

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

    async function handleSyncNow() {
        setSyncPushState('pushing');
        setSyncActionMsg('');
        try {
            await syncPush();
            setSyncPushState('ok');
            setSyncActionMsg('Vault pushed to cloud ✓');
            setTimeout(() => { setSyncPushState('idle'); setSyncActionMsg(''); }, 3000);
        } catch (err: any) {
            setSyncPushState('error');
            setSyncActionMsg(err?.message ?? 'Push failed. Check your sync settings.');
        }
    }

    async function handleForcePull() {
        setSyncPullState('pulling');
        setSyncActionMsg('');
        try {
            await syncPull();
            setSyncPullState('ok');
            setSyncActionMsg('Vault pulled from cloud ✓ — your passwords are now synced.');
            setTimeout(() => { setSyncPullState('idle'); setSyncActionMsg(''); }, 5000);
        } catch (err: any) {
            setSyncPullState('error');
            const msg = err?.message ?? '';
            if (msg.includes('No vault data')) {
                setSyncActionMsg('No data on server for this account. Make sure sync is enabled on your other device and the email matches.');
            } else if (msg.includes('HMAC') || msg.includes('decrypt')) {
                setSyncActionMsg('Decryption failed — the master password on this device does not match the one used to push the vault.');
            } else {
                setSyncActionMsg(msg || 'Pull failed. Is the server awake? Try again in 30 seconds.');
            }
        }
    }

    async function handleLockNow() {
        await vaultLock();
        setLocked(true);
        navigate('/unlock');
    }

    // Verify password against vault, then store it for biometric unlock
    async function doEnroll() {
        if (!bioEnrollPw) return;
        setBioEnrolling(true);
        setBioEnrollError('');
        try {
            // Import vaultUnlock inline to verify password (vault is already unlocked,
            // but we call it to confirm the password is correct before trusting it)
            const { vaultUnlock: verify } = await import('../hooks/useVault');
            await verify(bioEnrollPw);
            storeBiometricPassword(bioEnrollPw);
            try { localStorage.setItem('cryptonote_bio_enrolled_at', String(Date.now())); } catch {}
            setShowBioEnroll(false);
            flash('Biometric unlock enrolled ✓');
        } catch {
            setBioEnrollError('Password is incorrect. Please try again.');
        } finally {
            setBioEnrolling(false);
        }
    }

    return (
        <div className='app-shell'>
            {/* Sidebar */}
            <aside className='sidebar'>
                <div className='sidebar-logo'>
                    <img src={logoImg} alt="" style={{ width: 32, height: 32, borderRadius: 8 }} />
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

                {/* Mobile top bar (hidden on desktop via CSS) */}
                <div className='mobile-header'>
                    <div className='mobile-header-inner'>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <button
                                className='icon-btn'
                                onClick={() => navigate('/vault')}
                                aria-label='Back to Vault'
                            >
                                <ChevronLeft size={20} />
                            </button>
                            <div>
                                <div style={{ fontWeight: 700, fontSize: '0.9rem', lineHeight: 1.2 }}>Settings</div>
                                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', lineHeight: 1 }}>Security, sync &amp; preferences</div>
                            </div>
                        </div>
                        <button className='icon-btn' onClick={handleLockNow} title='Lock Vault'>
                            <Lock size={17} />
                        </button>
                    </div>
                </div>

                {/* Desktop page header */}
                <div className='page-header desktop-only'>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <button
                            className='btn btn-ghost btn-icon'
                            onClick={() => navigate('/vault')}
                            title='Back to Vault'
                            style={{ width: 36, height: 36, borderRadius: 10, border: '1px solid var(--border)', flexShrink: 0 }}
                        >
                            <ChevronLeft size={18} />
                        </button>
                        <div>
                            <h2>Settings</h2>
                            <p className='text-sm text-muted' style={{ marginTop: 4 }}>Security, sync, and preferences</p>
                        </div>
                    </div>
                </div>

                <div style={{ padding: 'clamp(16px, 4vw, 32px) clamp(16px, 5vw, 32px)', maxWidth: 640 }}>

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

                        {/* Sensor status row */}
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Sensor Status</div>
                                <div className='settings-row-desc'>
                                    {bioSensorStatus === 'available' && 'Fingerprint / Face ID sensor detected and enrolled'}
                                    {bioSensorStatus === 'notEnrolled' && 'Sensor detected but no fingerprints registered in system settings'}
                                    {bioSensorStatus === 'unavailable' && 'Sensor temporarily unavailable (too many attempts or locked)'}
                                    {bioSensorStatus === 'notAvailable' && 'No biometric hardware found on this device'}
                                    {bioSensorStatus === 'checking' && 'Detecting sensor…'}
                                    {bioSensorStatus === 'unknown' && 'Could not determine sensor status'}
                                </div>
                                {bioSensorStatus === 'notEnrolled' && (
                                    <div style={{ fontSize: '0.75rem', color: 'var(--color-warning)', marginTop: 4 }}>
                                        → Go to Settings → Security → Fingerprint and add a fingerprint.
                                    </div>
                                )}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                                <span className={`badge ${
                                    bioSensorStatus === 'available' ? 'badge-success'
                                    : bioSensorStatus === 'notEnrolled' ? 'badge-warning'
                                    : bioSensorStatus === 'checking' ? 'badge-info'
                                    : 'badge-danger'
                                }`}>
                                    {bioSensorStatus === 'available' ? 'Ready'
                                        : bioSensorStatus === 'notEnrolled' ? 'Not Enrolled'
                                        : bioSensorStatus === 'unavailable' ? 'Locked'
                                        : bioSensorStatus === 'notAvailable' ? 'No Hardware'
                                        : bioSensorStatus === 'checking' ? 'Checking…'
                                        : 'Unknown'}
                                </span>
                                <button className='icon-btn' title='Re-check sensor' onClick={checkBioSensor} style={{ width: 32, height: 32, borderRadius: 8 }}>
                                    <RefreshCw size={13} />
                                </button>
                            </div>
                        </div>

                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Unlock with Biometrics</div>
                                <div className='settings-row-desc'>Use fingerprint or Face ID to unlock your vault</div>
                            </div>
                            <label className='toggle'>
                                <input type='checkbox' checked={biometricEnabled} onChange={(e) => {
                                    if (e.target.checked) {
                                        setBiometricEnabled(true);
                                        setShowBioEnroll(true);
                                        setBioEnrollPw('');
                                        setBioEnrollError('');
                                        setTimeout(() => bioEnrollRef.current?.focus(), 120);
                                    } else {
                                        setBiometricEnabled(false);
                                        try { localStorage.removeItem('cryptonote_bio_enrolled_at'); } catch {}
                                        flash('Biometric unlock disabled');
                                    }
                                }} />
                                <span className='toggle-slider' />
                            </label>
                        </div>

                        {/* Enrollment status */}
                        {biometricEnabled && isEnrolled && !showBioEnroll && (
                            <div style={{ padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.82rem', color: 'var(--color-success)' }}>
                                    <Fingerprint size={14} />
                                    <span>
                                        Active{enrolledAt ? ` · enrolled ${new Date(Number(enrolledAt)).toLocaleDateString()}` : ''}
                                    </span>
                                </div>
                                <button className='btn btn-secondary' style={{ fontSize: '0.78rem', padding: '6px 12px', minHeight: 0 }}
                                    onClick={() => { setShowBioEnroll(true); setBioEnrollPw(''); setBioEnrollError(''); setTimeout(() => bioEnrollRef.current?.focus(), 120); }}>
                                    Re-enroll
                                </button>
                            </div>
                        )}

                        {biometricEnabled && !isEnrolled && !showBioEnroll && (
                            <div style={{ padding: '10px 20px 14px', fontSize: '0.8rem', color: 'var(--color-warning)', display: 'flex', alignItems: 'center', gap: 6 }}>
                                <AlertTriangle size={13} />
                                Enrollment incomplete — enter your master password to activate.
                            </div>
                        )}

                        {/* Enrollment form */}
                        {showBioEnroll && (
                            <div style={{ margin: '0 16px 16px', padding: 16, background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-accent)' }}>
                                <p style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 4 }}>Confirm Master Password</p>
                                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 12 }}>
                                    Your password will be securely stored on this device and used for biometric unlock.
                                </p>
                                <div style={{ display: 'flex', alignItems: 'stretch', marginBottom: 10 }}>
                                    <input
                                        ref={bioEnrollRef}
                                        type={showBioEnrollPw ? 'text' : 'password'}
                                        className={`form-input font-mono ${bioEnrollError ? 'error' : ''}`}
                                        placeholder='Master password…'
                                        value={bioEnrollPw}
                                        onChange={(e) => { setBioEnrollPw(e.target.value); setBioEnrollError(''); }}
                                        style={{ flex: 1, borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', borderRight: 'none' }}
                                        onKeyDown={async (e) => { if (e.key === 'Enter' && bioEnrollPw) { e.preventDefault(); await doEnroll(); } }}
                                    />
                                    <button type='button' tabIndex={-1}
                                        onClick={() => setShowBioEnrollPw(v => !v)}
                                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 44, flexShrink: 0, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderLeft: 'none', borderRadius: '0 var(--radius-md) var(--radius-md) 0', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                        {showBioEnrollPw ? <EyeOff size={15} /> : <Eye size={15} />}
                                    </button>
                                </div>
                                {bioEnrollError && (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--color-danger)', fontSize: '0.8rem', marginBottom: 10 }}>
                                        <AlertTriangle size={13} />{bioEnrollError}
                                    </div>
                                )}
                                <div style={{ display: 'flex', gap: 8 }}>
                                    <button className='btn btn-primary' style={{ flex: 1 }}
                                        disabled={!bioEnrollPw || bioEnrolling}
                                        onClick={doEnroll}>
                                        {bioEnrolling
                                            ? <><div style={{ width: 14, height: 14, border: '2px solid #080c10', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />Verifying…</>
                                            : <><Fingerprint size={14} />Enroll Biometrics</>}
                                    </button>
                                    <button className='btn btn-secondary' onClick={() => {
                                        setShowBioEnroll(false);
                                        if (!isEnrolled) setBiometricEnabled(false);
                                    }}>Cancel</button>
                                </div>
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

                    {/* ── Encrypted Cloud Sync ─────────────────────────── */}
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

                                {/* ── Sync action buttons (only when settings are saved) ── */}
                                {syncServerUrl && syncEmail && (
                                    <>
                                        <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />
                                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>Sync Actions</div>

                                        {/* Sync Now (push) */}
                                        <button className='btn btn-secondary'
                                            disabled={syncPushState === 'pushing'}
                                            onClick={handleSyncNow}
                                            style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                            <RefreshCw size={14} className={syncPushState === 'pushing' ? 'spin' : ''} />
                                            {syncPushState === 'pushing' ? 'Pushing…' : 'Sync Now (Push to Cloud)'}
                                        </button>

                                        {/* Force Pull */}
                                        <div style={{
                                            background: 'rgba(255,140,0,0.07)',
                                            border: '1px solid rgba(255,140,0,0.25)',
                                            borderRadius: 'var(--radius-md)',
                                            padding: '12px 14px',
                                        }}>
                                            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-warning)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                                                <AlertTriangle size={13} /> Pull from Cloud
                                            </div>
                                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.5 }}>
                                                Downloads the latest vault from the server and merges it into this device.
                                                Use this if you just set up sync on a new device and your passwords aren't showing.
                                            </div>
                                            <button className='btn btn-secondary'
                                                style={{ width: '100%', borderColor: 'rgba(255,140,0,0.3)' }}
                                                disabled={syncPullState === 'pulling'}
                                                onClick={handleForcePull}>
                                                <Download size={14} className={syncPullState === 'pulling' ? 'spin' : ''} />
                                                {syncPullState === 'pulling' ? 'Pulling from server… (may take 30s)' : 'Pull from Cloud'}
                                            </button>
                                        </div>

                                        {/* Status message */}
                                        {syncActionMsg && (
                                            <div style={{
                                                padding: '10px 14px',
                                                borderRadius: 'var(--radius-md)',
                                                fontSize: '0.8rem',
                                                display: 'flex',
                                                alignItems: 'flex-start',
                                                gap: 8,
                                                background: (syncPullState === 'error' || syncPushState === 'error')
                                                    ? 'rgba(239,68,68,0.08)' : 'rgba(0,229,160,0.08)',
                                                border: `1px solid ${
                                                    (syncPullState === 'error' || syncPushState === 'error')
                                                    ? 'var(--border-danger)' : 'var(--border-accent)'}`,
                                                color: (syncPullState === 'error' || syncPushState === 'error')
                                                    ? 'var(--color-danger)' : 'var(--color-success)',
                                            }}>
                                                {(syncPullState === 'error' || syncPushState === 'error')
                                                    ? <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                                                    : <CheckCircle2 size={13} style={{ flexShrink: 0, marginTop: 1 }} />}
                                                {syncActionMsg}
                                            </div>
                                        )}
                                    </>
                                )}

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
