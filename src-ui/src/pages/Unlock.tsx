// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with biometric support

import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, Eye, EyeOff, AlertTriangle, Fingerprint, KeyRound, Cloud, CheckCircle2, ShieldCheck } from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { vaultUnlock, vaultIsInitialized, syncConfigure } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
}

type BioState = 'idle' | 'scanning' | 'success' | 'error';

export function UnlockPage() {
    const navigate = useNavigate();
    const {
        setLocked, setMeta,
        biometricEnabled, storeBiometricPassword, getBiometricPassword,
        syncServerUrl, syncEmail, setSyncConfig,
    } = useVaultStore();

    const [password, setPassword]         = useState('');
    const [showPw, setShowPw]             = useState(false);
    const [isLoading, setIsLoading]       = useState(false);
    const [error, setError]               = useState('');
    const [failCount, setFailCount]       = useState(0);
    const [showPwScreen, setShowPwScreen] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    // Biometric animation state
    const [bioState, setBioState]         = useState<BioState>('idle');
    const bioTimerRef                     = useRef<ReturnType<typeof setTimeout> | null>(null);

    // No-vault + sync restore state
    const [noVault, setNoVault]           = useState(false);
    const [showSyncPanel, setShowSyncPanel] = useState(false);
    const [restoreUrl, setRestoreUrl]     = useState(syncServerUrl || 'https://sanjai-06-cryptonote-app.onrender.com');
    const [restoreEmail, setRestoreEmail] = useState(syncEmail || '');
    const [restorePassword, setRestorePassword] = useState('');
    const [showRestorePw, setShowRestorePw] = useState(false);
    const [isSavingSync, setIsSavingSync] = useState(false);
    const [syncPanelError, setSyncPanelError] = useState('');

    const storedPw     = getBiometricPassword();
    const hasBiometric = biometricEnabled && storedPw !== null;

    useEffect(() => {
        vaultIsInitialized().then((ok) => {
            if (!ok) setNoVault(true);
        }).catch(() => {});
    }, []);

    const [bioReady, setBioReady] = useState(false); // true once we've loaded from Tauri

    useEffect(() => () => { if (bioTimerRef.current) clearTimeout(bioTimerRef.current); }, []);

    // On Android, localStorage is wiped on restart — load credential from Tauri file first
    useEffect(() => {
        async function loadCredentialFromTauri() {
            try {
                if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
                    const { invoke } = await import('@tauri-apps/api/core');
                    const encoded = await invoke<string>('biometric_load_credential');
                    if (encoded && encoded.length > 0) {
                        // Populate localStorage so getBiometricPassword() works synchronously
                        localStorage.setItem('cryptonote_bio_pw', encoded);
                        console.log('[BIO] credential restored from Tauri file into localStorage');
                    }
                }
            } catch (e) {
                console.warn('[BIO] load_credential failed:', e);
            } finally {
                setBioReady(true);
            }
        }
        loadCredentialFromTauri();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // ── Core unlock ───────────────────────────────────────────────────────────
    const doUnlock = useCallback(async (pw: string) => {
        const meta = await vaultUnlock(pw);
        setMeta(meta);
        setLocked(false);
        if (biometricEnabled) storeBiometricPassword(pw);
        navigate('/vault');
    }, [biometricEnabled, navigate, setLocked, setMeta, storeBiometricPassword]);

    const handleBiometricUnlock = useCallback(async () => {
        if (bioState === 'scanning' || bioState === 'success') return;
        setBioState('scanning');
        setError('');
        try {
            if (isTauri()) {
                const { authenticate } = await import('@tauri-apps/plugin-biometric');
                try {
                    await authenticate('Unlock CryptoNote', {
                        allowDeviceCredential: true,
                        title: 'CryptoNote',
                        subtitle: 'Use fingerprint to unlock',
                        cancelTitle: 'Use Password',
                    });
                    // authenticate() resolved → biometric passed
                } catch (authErr: any) {
                    // Normalise the error — plugin can throw a string, an Error, or an object
                    const msg = typeof authErr === 'string'
                        ? authErr
                        : authErr?.message ?? authErr?.toString() ?? 'unknown';
                    const code = authErr?.errorCode ?? '';
                    console.warn('[biometric] error — code:', code, 'msg:', msg);

                    // User deliberately tapped "Use Password" / cancelled → switch to pw screen
                    const isCancel = ['userCancel', 'appCancel', 'systemCancel', 'userFallback'].includes(code)
                        || msg.toLowerCase().includes('cancel')
                        || msg.toLowerCase().includes('user cancel');
                    if (isCancel) {
                        setBioState('idle');
                        setShowPwScreen(true);
                        return;
                    }

                    // Sensor not enrolled / not available → surface a clear message
                    if (code === 'biometryNotEnrolled' || msg.toLowerCase().includes('not enrolled')) {
                        throw new Error('No fingerprint enrolled. Add one in Phone Settings → Security → Fingerprint.');
                    }

                    // Any other error: show the raw message so we can diagnose
                    throw new Error(msg || `Biometric error (${code || 'unknown'})`);
                }
            }

            // Biometric passed (or not Tauri) — unlock with stored password
            const pw = getBiometricPassword();
            if (!pw) throw new Error('Biometric credential lost — please use your master password.');
            setBioState('success');
            await doUnlock(pw);
        } catch (err: any) {
            setBioState('error');
            setError(err?.message ?? err?.toString() ?? 'Authentication failed.');
            bioTimerRef.current = setTimeout(() => setBioState('idle'), 2800);
        }
    }, [bioState, doUnlock, getBiometricPassword]);

    // Auto-trigger biometric on mount — but only after credential loaded from Tauri
    useEffect(() => {
        if (!bioReady) return; // Wait for Tauri credential load
        const storedPwNow = getBiometricPassword();
        const hasBio = biometricEnabled && storedPwNow !== null;
        if (hasBio && !noVault) {
            const t = setTimeout(() => handleBiometricUnlock(), 400);
            return () => clearTimeout(t);
        } else if (!hasBio && !noVault) {
            const t = setTimeout(() => inputRef.current?.focus(), 300);
            return () => clearTimeout(t);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bioReady, noVault]);

    async function handleUnlock(e: React.FormEvent) {
        e.preventDefault();
        if (!password) return;
        setIsLoading(true);
        setError('');
        try {
            await doUnlock(password);
        } catch (err: any) {
            setFailCount((c) => c + 1);
            setError(failCount >= 4
                ? '⚠️ Multiple failed attempts. Check your password carefully.'
                : err?.toString() ?? 'Invalid master password');
            setPassword('');
            inputRef.current?.focus();
        } finally {
            setIsLoading(false);
        }
    }

    async function handleSyncRestore() {
        if (!restoreEmail.trim() || !restoreUrl.trim() || !restorePassword.trim()) {
            setSyncPanelError('Enter server URL, account email, and master password.');
            return;
        }
        setIsSavingSync(true);
        setSyncPanelError('');
        try {
            await syncConfigure({
                server_url: restoreUrl.trim(),
                device_id: `device-${restoreEmail.trim().replace(/[^a-z0-9]/gi, '')}`,
                user_id: restoreEmail.trim(),
            });
            const meta = await tauriInvoke<{ vault_id: string; salt: string; created_at: number; version: number; sync_version: number }>(
                'vault_restore_from_sync',
                { masterPassword: restorePassword.trim(), userId: restoreEmail.trim() }
            );
            setSyncConfig(restoreUrl.trim(), restoreEmail.trim(), true);
            setMeta(meta);
            setLocked(false);
            if (biometricEnabled) storeBiometricPassword(restorePassword.trim());
            navigate('/vault');
        } catch (e: any) {
            setSyncPanelError(e?.toString() ?? 'Restore failed. Check your credentials.');
        } finally {
            setIsSavingSync(false);
        }
    }

    // ── Biometric-first screen ────────────────────────────────────────────────
    // Re-evaluate hasBiometric AFTER credential load from Tauri
    const hasBioNow = biometricEnabled && getBiometricPassword() !== null;
    if (hasBioNow && !showPwScreen && !noVault) {
        return (
            <div className='auth-layout'>
                <div className='auth-card bio-card' style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 52, paddingBottom: 48 }}>

                    {/* Logo */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 44 }}>
                        <div style={{ width: 80, height: 80, borderRadius: 20, marginBottom: 16, filter: 'drop-shadow(0 0 28px rgba(0,229,160,0.45))' }}>
                            <img src={logoImg} alt='CryptoNote' style={{ width: 80, height: 80, borderRadius: 18 }} />
                        </div>
                        <h1 className='gradient-text' style={{ fontSize: '1.75rem', marginBottom: 4 }}>CryptoNote</h1>
                        <p className='text-muted text-sm'>Your vault is locked</p>
                    </div>

                    {/* Animated fingerprint button */}
                    <BioButton state={bioState} onClick={handleBiometricUnlock} />

                    {/* Status label */}
                    <p style={{
                        marginTop: 18, fontSize: '0.85rem', textAlign: 'center',
                        color: bioState === 'error' ? 'var(--color-danger)'
                            : bioState === 'success' ? 'var(--accent-1)'
                            : bioState === 'scanning' ? 'var(--accent-2)'
                            : 'var(--text-muted)',
                        transition: 'color 0.3s ease',
                        minHeight: 22,
                    }}>
                        {bioState === 'scanning' ? 'Hold still…'
                            : bioState === 'success' ? '✓ Authenticated!'
                            : bioState === 'error' ? 'Try again'
                            : 'Tap to unlock'}
                    </p>

                    {error && bioState !== 'scanning' && (
                        <div className='bio-error' style={{ marginTop: 14, maxWidth: '100%' }}>
                            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Security info badge */}
                    <div style={{
                        marginTop: 28,
                        display: 'flex', alignItems: 'center', gap: 6,
                        padding: '6px 14px', borderRadius: 99,
                        background: 'rgba(0,229,160,0.06)', border: '1px solid rgba(0,229,160,0.14)',
                        fontSize: '0.71rem', color: 'var(--text-muted)',
                    }}>
                        <ShieldCheck size={11} style={{ color: 'var(--accent-1)' }} />
                        Protected · XChaCha20-Poly1305
                    </div>

                    <button className='btn btn-ghost w-full'
                        style={{ marginTop: 24, gap: 8, color: 'var(--text-muted)', fontSize: '0.82rem' }}
                        onClick={() => { setShowPwScreen(true); setError(''); setBioState('idle'); setTimeout(() => inputRef.current?.focus(), 120); }}>
                        <KeyRound size={14} />
                        Use master password instead
                    </button>
                </div>
            </div>
        );
    }

    // ── Password screen ───────────────────────────────────────────────────────
    return (
        <div className='auth-layout'>
            <div className='auth-card'>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 30 }}>
                    <div style={{ width: 72, height: 72, borderRadius: 18, marginBottom: 14, filter: 'drop-shadow(0 0 20px rgba(0,229,160,0.4))' }}>
                        <img src={logoImg} alt='CryptoNote' style={{ width: 72, height: 72, borderRadius: 14 }} />
                    </div>
                    <h1 className='gradient-text' style={{ fontSize: '1.6rem', marginBottom: 4 }}>CryptoNote</h1>
                    <p className='text-muted text-sm'>Enter your master password</p>
                </div>

                {noVault && (
                    <div style={{ padding: '10px 14px', marginBottom: 16, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 'var(--radius-md)', fontSize: '0.8rem', color: 'var(--color-warning)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                        <Cloud size={14} style={{ flexShrink: 0, marginTop: 1 }} />
                        No vault found. Restore from cloud sync below, or create a new vault.
                    </div>
                )}

                <form onSubmit={handleUnlock}>
                    <div className='form-group'>
                        <label className='form-label' htmlFor='master-pw'>Master Password</label>
                        <div style={{ display: 'flex', alignItems: 'stretch' }}>
                            <input id='master-pw' ref={inputRef}
                                type={showPw ? 'text' : 'password'}
                                className={`form-input font-mono ${error && !error.startsWith('✓') ? 'error' : ''}`}
                                placeholder='Enter master password…' value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                autoComplete='current-password' disabled={isLoading}
                                style={{ flex: 1, borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', borderRight: 'none' }} />
                            <button type='button' onClick={() => setShowPw(!showPw)} tabIndex={-1}
                                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 44, flexShrink: 0, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderLeft: 'none', borderRadius: '0 var(--radius-md) var(--radius-md) 0', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 10, padding: '10px 14px', background: error.startsWith('✓') ? 'rgba(0,229,160,0.08)' : 'rgba(239,68,68,0.1)', borderRadius: 'var(--radius-md)', border: `1px solid ${error.startsWith('✓') ? 'rgba(0,229,160,0.25)' : 'var(--border-danger)'}`, color: error.startsWith('✓') ? 'var(--accent-1)' : 'var(--color-danger)', fontSize: '0.8125rem' }}>
                            {error.startsWith('✓') ? <CheckCircle2 size={14} style={{ marginTop: 2, flexShrink: 0 }} /> : <AlertTriangle size={14} style={{ marginTop: 2, flexShrink: 0 }} />}
                            {error}
                        </div>
                    )}

                    <button type='submit' className='btn btn-primary w-full' style={{ marginTop: 18 }} disabled={!password || isLoading}>
                        {isLoading
                            ? <><div style={{ width: 16, height: 16, border: '2px solid #080c10', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />Unlocking…</>
                            : <><Lock size={15} />Unlock Vault</>}
                    </button>
                </form>

                {hasBiometric && (
                    <>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '16px 0', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                            <span>or</span>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                        </div>
                        <button className='btn btn-secondary w-full'
                            style={{ gap: 10, background: 'rgba(0,229,160,0.07)', border: '1px solid rgba(0,229,160,0.2)' }}
                            onClick={() => { setShowPwScreen(false); }}>
                            <Fingerprint size={18} style={{ color: 'var(--accent-1)' }} />
                            Use Biometrics
                        </button>
                    </>
                )}

                <div className='divider' style={{ margin: '20px 0' }} />

                {showSyncPanel ? (
                    <div style={{ padding: 16, background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)' }}>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Cloud size={14} /> Restore from Cloud Sync
                        </p>
                        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 12 }}>
                            Enter your sync details and master password. Your vault will be downloaded and decrypted.
                        </p>
                        <div className='form-group'>
                            <label className='form-label'>Server URL</label>
                            <input className='form-input' value={restoreUrl} onChange={(e) => setRestoreUrl(e.target.value)} placeholder='https://your-server.onrender.com' />
                        </div>
                        <div className='form-group' style={{ marginTop: 8 }}>
                            <label className='form-label'>Account Email</label>
                            <input className='form-input' type='email' value={restoreEmail} onChange={(e) => setRestoreEmail(e.target.value)} placeholder='your@email.com' />
                        </div>
                        <div className='form-group' style={{ marginTop: 8 }}>
                            <label className='form-label'>Master Password</label>
                            <div style={{ display: 'flex', alignItems: 'stretch' }}>
                                <input className='form-input font-mono' type={showRestorePw ? 'text' : 'password'} value={restorePassword} onChange={(e) => setRestorePassword(e.target.value)} placeholder='Your master password…' style={{ flex: 1, borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', borderRight: 'none' }} />
                                <button type='button' tabIndex={-1} onClick={() => setShowRestorePw(v => !v)} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 44, flexShrink: 0, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderLeft: 'none', borderRadius: '0 var(--radius-md) var(--radius-md) 0', cursor: 'pointer', color: 'var(--text-muted)' }}>
                                    {showRestorePw ? <EyeOff size={16} /> : <Eye size={16} />}
                                </button>
                            </div>
                        </div>
                        {syncPanelError && (
                            <div style={{ color: 'var(--color-danger)', fontSize: '0.8rem', marginTop: 8, display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                                <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 2 }} />{syncPanelError}
                            </div>
                        )}
                        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                            <button className='btn btn-primary' style={{ flex: 1 }} disabled={isSavingSync || !restoreEmail || !restoreUrl || !restorePassword} onClick={handleSyncRestore}>
                                {isSavingSync ? 'Restoring…' : <><Cloud size={14} /> Restore Vault</>}
                            </button>
                            <button className='btn btn-secondary' onClick={() => setShowSyncPanel(false)}>Cancel</button>
                        </div>
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        <button className='btn btn-secondary w-full' style={{ gap: 8 }} onClick={() => setShowSyncPanel(true)} disabled={isLoading}>
                            <Cloud size={15} /> Restore from Cloud Sync
                        </button>
                        <button className='btn btn-secondary w-full' onClick={() => navigate('/setup')} disabled={isLoading}>
                            Create New Vault
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}

// ── Animated fingerprint button ───────────────────────────────────────────────
function BioButton({ state, onClick }: { state: BioState; onClick: () => void }) {
    return (
        <button
            className='bio-pulse-btn'
            onClick={onClick}
            disabled={state === 'scanning' || state === 'success'}
            aria-label='Unlock with biometrics'
            style={{
                boxShadow: state === 'scanning'
                    ? '0 0 0 8px rgba(0,180,216,0.14), 0 0 0 20px rgba(0,180,216,0.06)'
                    : state === 'success'
                    ? '0 0 0 14px rgba(0,229,160,0.2), 0 0 48px rgba(0,229,160,0.4)'
                    : state === 'error'
                    ? '0 0 0 8px rgba(239,68,68,0.1), 0 0 24px rgba(239,68,68,0.15)'
                    : undefined,
                background: state === 'scanning'
                    ? 'radial-gradient(circle, rgba(0,180,216,0.18) 0%, transparent 70%)'
                    : state === 'success'
                    ? 'radial-gradient(circle, rgba(0,229,160,0.22) 0%, transparent 70%)'
                    : state === 'error'
                    ? 'radial-gradient(circle, rgba(239,68,68,0.12) 0%, transparent 70%)'
                    : undefined,
                animation: state === 'idle' ? 'bio-ring-pulse 2.5s ease-in-out infinite' : 'none',
                transition: 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
            }}
        >
            {state === 'scanning' ? (
                <div style={{ position: 'relative', width: 52, height: 52, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div className='bio-spinner' />
                    <Fingerprint size={26} style={{ position: 'absolute', color: 'var(--accent-2)', opacity: 0.6 }} />
                </div>
            ) : state === 'success' ? (
                <CheckCircle2 size={52} style={{ color: 'var(--accent-1)' }} />
            ) : state === 'error' ? (
                <AlertTriangle size={48} style={{ color: 'var(--color-danger)' }} />
            ) : (
                <Fingerprint size={52} />
            )}
        </button>
    );
}
