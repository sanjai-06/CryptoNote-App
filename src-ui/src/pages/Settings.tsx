// src-ui/src/pages/Settings.tsx
// Auto-lock, sync, security, and device management settings

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    ShieldCheck, Clock, Cloud, Smartphone, Lock,
    Key, AlertTriangle, ChevronLeft, RefreshCw, Palette,
    Fingerprint, Eye, EyeOff, Download, CheckCircle2, Wifi
} from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { SyncStatus } from '../components/SyncStatus';
import { PasswordGenerator } from '../components/PasswordGenerator';
import {
    vaultLock, syncConfigure, securityCheckDevice,
    setAutoLockTimeout, syncPull, syncPush, syncForcePush, syncPatchSalt, vaultRestoreFromSync,
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
    const [syncStatus, setSyncStatus] = useState<'idle'|'syncing'|'synced'|'error'>('idle');
    const [syncMsg, setSyncMsg] = useState('');
    const [needsRestore, setNeedsRestore] = useState(false);
    const [hasLocalVault, setHasLocalVault] = useState(false);
    const [securityStatus, setSecurityStatus] = useState<{ is_compromised: boolean; findings: string[] } | null>(null);
    const [checkingDevice, setCheckingDevice] = useState(false);
    const [showPwGen, setShowPwGen] = useState(false);
    const [savedMsg, setSavedMsg] = useState('');
    const [syncError, setSyncError] = useState('');

    const [restorePw, setRestorePw]   = useState('');
    const [showRestorePw, setShowRestorePw] = useState(false);
    const [restoreError, setRestoreError]   = useState('');
    const [showBioEnroll, setShowBioEnroll]   = useState(false);
    const [bioEnrollPw, setBioEnrollPw]       = useState('');
    const [showBioEnrollPw, setShowBioEnrollPw] = useState(false);
    const [bioEnrollError, setBioEnrollError] = useState('');
    const [bioEnrolling, setBioEnrolling]     = useState(false);
    const bioEnrollRef = useRef<HTMLInputElement>(null);
    // isEnrolled is async — loaded from Tauri file on mount (localStorage is wiped on Android restart)
    const [isEnrolled, setIsEnrolled] = useState(() => getBiometricPassword() !== null);
    const enrolledAt = (() => { try { return localStorage.getItem('cryptonote_bio_enrolled_at'); } catch { return null; } })();

    // Biometric sensor status
    type BioSensorStatus = 'checking' | 'available' | 'notEnrolled' | 'unavailable' | 'notAvailable' | 'unknown';
    const [bioSensorStatus, setBioSensorStatus] = useState<BioSensorStatus>('checking');

    // Re-apply saved sync config to Tauri engine on mount
    useEffect(() => {
        // Load biometric credential from Tauri file into localStorage
        // so isEnrolled is correct immediately on Android (localStorage wiped on restart)
        (async () => {
            try {
                if ((window as any).__TAURI_INTERNALS__) {
                    const { invoke } = await import('@tauri-apps/api/core');
                    const encoded = await invoke<string>('biometric_load_credential');
                    if (encoded && encoded.length > 0) {
                        localStorage.setItem('cryptonote_bio_pw', encoded);
                        setIsEnrolled(true);
                    }
                }
            } catch {}
        })();

        runDeviceCheck();
        checkBioSensor();
        import('../hooks/useVault').then(({ vaultIsInitialized }) => {
            vaultIsInitialized().then(ok => setHasLocalVault(ok)).catch(() => {});
        });
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
            console.log('[biometric] checkStatus:', JSON.stringify(status));
            if (status.isAvailable) {
                setBioSensorStatus('available');
            } else {
                const code = status.errorCode ?? '';
                // Use exact error codes from plugin API
                if (code === 'biometryNotEnrolled') {
                    setBioSensorStatus('notEnrolled');
                } else if (code === 'biometryLockout') {
                    setBioSensorStatus('unavailable');
                } else if (code === 'biometryNotAvailable') {
                    // Sensor exists but OS says not available — could be a permissions issue
                    // (missing USE_BIOMETRIC in manifest). Show as notAvailable with hint.
                    setBioSensorStatus('notAvailable');
                } else if (code === 'passcodeNotSet') {
                    // Device has no screen lock set — biometric requires it
                    setBioSensorStatus('notEnrolled');
                } else {
                    // Unknown code — could be a plugin error
                    setBioSensorStatus('unknown');
                    console.warn('[biometric] unexpected errorCode:', code, 'error:', status.error);
                }
            }
        } catch (e: any) {
            // Plugin not available on this platform (desktop) — that's fine
            console.warn('[biometric] checkStatus threw:', e?.message ?? e);
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

    function flash(msg: string) {
        setSavedMsg(msg);
        setTimeout(() => setSavedMsg(''), 2500);
    }

        async function handleRestoreFromCloud() {
        if (!restorePw.trim()) return;
        const userId = email.trim() || syncEmail;
        if (!userId) { setRestoreError('Enter your Account Email first.'); return; }
        setSyncStatus('syncing');
        setRestoreError('');
        try {
            await vaultRestoreFromSync(restorePw.trim(), userId);
            setSyncStatus('synced');
            setSyncMsg('Vault restored ✓');
            setNeedsRestore(false);
            setRestorePw('');
            setTimeout(() => navigate('/vault'), 1200);
        } catch (err: any) {
            setSyncStatus('error');
            const msg = typeof err === 'string' ? err : (err?.message ?? err?.toString() ?? 'unknown');
            console.error('[restore] failed:', msg);
            if (msg.includes('No vault data') || msg.includes('not_found')) {
                setRestoreError('No vault found on server. Enable sync on your primary device (Linux) first.');
            } else if (msg.includes('Wrong master password') || msg.includes('HMAC') || msg.includes('tamper') || msg.includes('decrypt') || msg.includes('Decryption')) {
                setRestoreError(
                    '❌ Decryption failed. Two possible causes:\n' +
                    '1. Wrong password — make sure you enter the EXACT password from your Linux app.\n' +
                    '2. Missing server metadata — toggle sync OFF then ON on your Linux device, then try again here.'
                );
            } else {
                setRestoreError(msg || 'Restore failed.');
            }
        }
    }
    async function handleLockNow() {
        await vaultLock();
        setLocked(true);
        navigate('/unlock');
    }

    // Enroll biometric: verify password → trigger biometric hardware → store credential
    async function doEnroll() {
        if (!bioEnrollPw) return;
        setBioEnrolling(true);
        setBioEnrollError('');
        try {
            // Step 1: verify the master password is correct
            const { vaultUnlock: verify } = await import('../hooks/useVault');
            await verify(bioEnrollPw);

            // Step 2: trigger the actual biometric hardware prompt
            // This confirms the user's fingerprint/face is enrolled in the OS
            if ((window as any).__TAURI_INTERNALS__) {
                try {
                    const { authenticate } = await import('@tauri-apps/plugin-biometric');
                    await authenticate('Enroll biometric for CryptoNote', {
                        title: 'Confirm Fingerprint',
                        subtitle: 'Touch the sensor to enable biometric unlock',
                        cancelTitle: 'Cancel',
                        allowDeviceCredential: false,
                    });
                } catch (bioErr: any) {
                    const code = bioErr?.errorCode ?? '';
                    const msg  = typeof bioErr === 'string' ? bioErr : (bioErr?.message ?? '');
                    const cancelled = ['userCancel', 'appCancel', 'systemCancel'].includes(code)
                        || msg.toLowerCase().includes('cancel');
                    if (cancelled) {
                        setBioEnrollError('Biometric prompt cancelled. Try again.');
                        return;
                    }
                    if (code === 'biometryNotEnrolled' || msg.toLowerCase().includes('not enrolled')) {
                        setBioEnrollError('No fingerprint registered on this device. Go to Phone Settings → Security → Fingerprint first.');
                        return;
                    }
                    // Other sensor error — proceed anyway (some emulators/devices report errors)
                    console.warn('[biometric] enroll prompt error (non-fatal):', msg);
                }
            }

            // Step 3: store credential and enable biometric
            setBiometricEnabled(true);
            storeBiometricPassword(bioEnrollPw);
            try { localStorage.setItem('cryptonote_bio_enrolled_at', String(Date.now())); } catch {}
            setIsEnrolled(true);
            setShowBioEnroll(false);
            flash('Biometric unlock enrolled ✓');
        } catch (err: any) {
            const msg = typeof err === 'string' ? err : (err?.message ?? '');
            if (msg.includes('Wrong') || msg.includes('Invalid') || msg.includes('incorrect')) {
                setBioEnrollError('Incorrect master password. Please try again.');
            } else {
                setBioEnrollError(msg || 'Enrollment failed.');
            }
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
                                    {bioSensorStatus === 'available' && 'Fingerprint / Face ID sensor detected and enrolled ✓'}
                                    {bioSensorStatus === 'notEnrolled' && 'Sensor detected but no fingerprints registered in system settings'}
                                    {bioSensorStatus === 'unavailable' && 'Sensor temporarily unavailable (too many failed attempts — wait 30s)'}
                                    {bioSensorStatus === 'notAvailable' && 'Biometric not available — make sure you have fingerprints enrolled in Phone Settings → Security → Fingerprint, then tap ↻'}
                                    {bioSensorStatus === 'checking' && 'Detecting sensor…'}
                                    {bioSensorStatus === 'unknown' && 'Running on desktop or biometric plugin not loaded on this device'}
                                </div>
                                {bioSensorStatus === 'notEnrolled' && (
                                    <div style={{ fontSize: '0.75rem', color: 'var(--color-warning)', marginTop: 4 }}>
                                        → Phone Settings → Security → Fingerprint → add a fingerprint, then tap ↻ above.
                                    </div>
                                )}
                                {bioSensorStatus === 'notAvailable' && (
                                    <div style={{ fontSize: '0.75rem', color: 'var(--color-warning)', marginTop: 4 }}>
                                        If you have a fingerprint sensor, try: 1) Update to the latest APK  2) Enroll fingerprint in Phone Settings  3) Tap ↻ to re-check.
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
                                        // Don't enable yet — only enable after successful enrollment in doEnroll()
                                        setShowBioEnroll(true);
                                        setBioEnrollPw('');
                                        setBioEnrollError('');
                                        setTimeout(() => bioEnrollRef.current?.focus(), 120);
                                    } else {
                                        setBiometricEnabled(false);
                                        setIsEnrolled(false);
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
                    {/* ── Encrypted Cloud Sync ─────────────────────────── */}
                    <div className='settings-section'>
                        <div className='settings-section-title'><Cloud size={13} style={{ display: 'inline', marginRight: 6 }} />Encrypted Cloud Sync</div>

                        {/* Server URL — always visible when sync section shown */}
                        <div style={{ padding: '0 20px 4px', display: 'flex', flexDirection: 'column', gap: 10 }}>
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
                        </div>

                        {/* Toggle row */}
                        <div className='settings-row'>
                            <div>
                                <div className='settings-row-label'>Enable Sync</div>
                                <div className='settings-row-desc'>
                                    {syncStatus === 'syncing' ? 'Syncing…' :
                                     syncStatus === 'synced'  ? 'Vault synced ✓' :
                                     syncStatus === 'error'   ? 'Sync error' :
                                     'Pull from cloud and push your changes'}
                                </div>
                            </div>
                            <label className='toggle'>
                                <input type='checkbox' checked={syncEnabled}
                                    onChange={async (e) => {
                                        const enabled = e.target.checked;
                                        setSyncEnabled(enabled);
                                        if (!enabled) { setSyncStatus('idle'); setSyncMsg(''); return; }

                                        // Validate inputs
                                        const url = serverUrl.trim();
                                        const mail = email.trim();
                                        if (!url || !mail) {
                                            setSyncStatus('error');
                                            setSyncMsg('Enter Server URL and Account Email first.');
                                            return;
                                        }

                                        // Configure → push → pull automatically
                                        setSyncStatus('syncing');
                                        setSyncMsg('');
                                        const deviceId = `device-${mail.replace(/[^a-z0-9]/gi, '')}`;
                                        try {
                                            await syncConfigure({ server_url: url, device_id: deviceId, user_id: mail });
                                            setSyncConfig(url, mail, true);
                                            // Patch kdf_salt on any old server blob (non-fatal)
                                            syncPatchSalt().catch(() => {});
                                        } catch (err: any) {
                                            setSyncStatus('error');
                                            setSyncMsg('Config failed: ' + (typeof err === 'string' ? err : err?.message ?? 'unknown'));
                                            return;
                                        }

                                        // Pull first to get server data
                                        let pullOk = await syncPull().then(() => true).catch(async (pullErr: any) => {
                                            const msg = typeof pullErr === 'string' ? pullErr : (pullErr?.message ?? '');

                                            // Server has no vault yet → this is the first device, push ours
                                            if (msg.toLowerCase().includes('no vault') || msg.toLowerCase().includes('not_found') || msg.toLowerCase().includes('no vault data')) {
                                                setSyncStatus('syncing');
                                                setSyncMsg('Uploading vault to server…');
                                                try { await syncForcePush(); } catch { /* non-fatal */ }
                                                return true;
                                            }

                                            // HMAC / key mismatch — server has a different device's vault.
                                            // Always show restore form. User can also choose to override
                                            // with their local vault using the 'Use This Device' button.
                                            setSyncStatus('error');
                                            setSyncMsg('Vault on server belongs to a different device.');
                                            setNeedsRestore(true);
                                            return false;
                                        });
                                        if (pullOk) {
                                            // Push after successful pull to refresh kdf_salt on server
                                            syncForcePush().catch(() => {});
                                            setSyncStatus('synced');
                                            setSyncMsg('');
                                        }
                                    }}
                                />
                                <span className='toggle-slider' />
                            </label>
                        </div>

                        {/* Status message */}
                        {syncMsg && (
                            <div style={{
                                margin: '0 20px 12px',
                                padding: '8px 12px',
                                borderRadius: 'var(--radius-md)',
                                fontSize: '0.78rem',
                                display: 'flex', alignItems: 'flex-start', gap: 6,
                                background: syncStatus === 'error' ? 'rgba(239,68,68,0.08)' : 'rgba(0,229,160,0.08)',
                                border: `1px solid ${syncStatus === 'error' ? 'var(--border-danger)' : 'var(--border-accent)'}`,
                                color: syncStatus === 'error' ? 'var(--color-danger)' : 'var(--color-success)',
                            }}>
                                {syncStatus === 'error'
                                    ? <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
                                    : <CheckCircle2 size={12} style={{ flexShrink: 0, marginTop: 1 }} />}
                                {syncMsg}
                            </div>
                        )}

                        {/* Restore panel — one-time setup when adding this device to sync */}
                        {needsRestore && syncEnabled && (
                            <div style={{ margin: '0 20px 16px', padding: '14px', background: 'rgba(99,102,241,0.07)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: 'var(--radius-md)' }}>

                                {/* Header */}
                                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#a5b4fc', marginBottom: 4 }}>
                                    🔗 Connect This Device to Sync
                                </div>
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.6 }}>
                                    This is a <strong style={{ color: 'var(--text-secondary)' }}>one-time setup</strong> step.
                                    Enter your <strong style={{ color: 'var(--text-secondary)' }}>master password</strong> to download the shared vault from the cloud.
                                    After this, all your devices sync automatically as equals — no "primary device" needed.
                                </div>

                                {/* Password input + Sync button */}
                                <div style={{ display: 'flex', gap: 8 }}>
                                    <div style={{ flex: 1, display: 'flex', alignItems: 'stretch' }}>
                                        <input
                                            autoFocus
                                            type={showRestorePw ? 'text' : 'password'}
                                            autoCapitalize='none'
                                            autoCorrect='off'
                                            autoComplete='off'
                                            spellCheck={false}
                                            className='form-input font-mono'
                                            placeholder='Your master password…'
                                            value={restorePw}
                                            onChange={(e) => { setRestorePw(e.target.value); setRestoreError(''); }}
                                            style={{ flex: 1, borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', borderRight: 'none' }}
                                            onKeyDown={async (e) => { if (e.key === 'Enter' && restorePw) { e.preventDefault(); await handleRestoreFromCloud(); } }}
                                        />
                                        <button type='button' tabIndex={-1} onClick={() => setShowRestorePw(v => !v)}
                                            style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 38, flexShrink: 0, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderLeft: 'none', borderRadius: '0 var(--radius-md) var(--radius-md) 0', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                            {showRestorePw ? <EyeOff size={13} /> : <Eye size={13} />}
                                        </button>
                                    </div>
                                    <button className='btn btn-primary'
                                        disabled={!restorePw || syncStatus === 'syncing'}
                                        onClick={handleRestoreFromCloud}
                                        style={{ whiteSpace: 'nowrap' }}>
                                        {syncStatus === 'syncing' ? 'Syncing…' : '🔗 Sync Now'}
                                    </button>
                                </div>
                                {restoreError && (
                                    <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--color-danger)', display: 'flex', alignItems: 'flex-start', gap: 5, whiteSpace: 'pre-line' }}>
                                        <AlertTriangle size={11} style={{ flexShrink: 0, marginTop: 1 }} />{restoreError}
                                    </div>
                                )}

                                {/* Override option */}
                                <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid rgba(99,102,241,0.2)' }}>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                                        ⚠️ If <strong style={{ color: 'var(--text-secondary)' }}>this device</strong> has the latest vault and you want it to be the cloud copy:
                                    </div>
                                    <button className='btn'
                                        disabled={syncStatus === 'syncing'}
                                        style={{ width: '100%', fontSize: '0.78rem', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#fca5a5' }}
                                        onClick={async () => {
                                            if (!window.confirm('This uploads THIS device\'s vault to the cloud, replacing what\'s there. Your other devices will need to re-sync. Continue?')) return;
                                            setSyncStatus('syncing');
                                            setSyncMsg('Uploading this device\'s vault…');
                                            try {
                                                await syncForcePush();
                                                setNeedsRestore(false);
                                                setSyncStatus('synced');
                                                setSyncMsg('Vault uploaded ✓ — other devices can now sync');
                                            } catch (e: any) {
                                                setSyncStatus('error');
                                                setSyncMsg(e?.message ?? 'Upload failed');
                                            }
                                        }}>
                                        {syncStatus === 'syncing' ? 'Uploading…' : '⬆ Upload This Device\'s Vault to Cloud'}
                                    </button>
                                </div>
                            </div>
                        )}

                        <div style={{ padding: '0 20px 16px' }}>
                            <div style={{ background: 'rgba(0,229,160,0.06)', border: '1px solid var(--border-accent)', borderRadius: 'var(--radius-md)', padding: '8px 12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                🔒 Vault is encrypted on-device. The server stores only an encrypted blob.
                            </div>
                        </div>
                    </div>
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
