// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with biometric support

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, Eye, EyeOff, AlertTriangle, Fingerprint, KeyRound, Cloud, RefreshCw } from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { vaultUnlock, vaultIsInitialized, syncConfigure, syncPull } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';


export function UnlockPage() {
    const navigate = useNavigate();
    const {
        setLocked, setMeta,
        biometricEnabled, storeBiometricPassword, getBiometricPassword,
        syncServerUrl, syncEmail,
    } = useVaultStore();

    const [password, setPassword]         = useState('');
    const [showPw, setShowPw]             = useState(false);
    const [isLoading, setIsLoading]       = useState(false);
    const [isBioLoading, setIsBioLoading] = useState(false);
    const [error, setError]               = useState('');
    const [failCount, setFailCount]       = useState(0);
    const [showPassword, setShowPassword] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    // Cloud sync restore state (shown when no local vault exists)
    const [noVault, setNoVault]           = useState(false);
    const [showSyncRestore, setShowSyncRestore] = useState(false);
    const [restoreUrl, setRestoreUrl]     = useState(syncServerUrl || 'https://sanjai-06-cryptonote-app.onrender.com');
    const [restoreEmail, setRestoreEmail] = useState(syncEmail || '');
    const [isPulling, setIsPulling]       = useState(false);
    const [pullError, setPullError]       = useState('');
    const [pullDone, setPullDone]         = useState(false);

    const storedPw     = getBiometricPassword();
    const hasBiometric = biometricEnabled && storedPw !== null;

    // Check if local vault exists; if not, offer cloud restore
    useEffect(() => {
        vaultIsInitialized().then((exists) => {
            if (!exists) setNoVault(true);
        }).catch(() => {});
    }, []);

    // Auto-trigger biometric on load if enrolled and vault exists
    useEffect(() => {
        if (hasBiometric && !noVault) {
            setTimeout(() => handleBiometricUnlock(), 600);
        } else if (!hasBiometric) {
            inputRef.current?.focus();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [noVault]);

    async function handleSyncRestore() {
        if (!restoreEmail.trim() || !restoreUrl.trim()) {
            setPullError('Please enter server URL and account email.');
            return;
        }
        setIsPulling(true);
        setPullError('');
        try {
            await syncConfigure({
                server_url: restoreUrl.trim(),
                device_id: `device-${restoreEmail.trim().replace(/[^a-z0-9]/gi, '')}`,
                user_id: restoreEmail.trim(),
            });
            await syncPull();
            setPullDone(true);
            setNoVault(false);
            setShowSyncRestore(false);
            setError('Vault restored from cloud! Enter your master password to unlock.');
        } catch (e: any) {
            setPullError(e?.toString() ?? 'Failed to restore from sync. Check your server URL and account email.');
        } finally {
            setIsPulling(false);
        }
    }


    async function doUnlock(pw: string) {
        const meta = await vaultUnlock(pw);
        setMeta(meta);
        setLocked(false);
        if (biometricEnabled) storeBiometricPassword(pw);
        setTimeout(() => navigate('/vault'), 0);
    }

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
                ? '⚠️ Multiple failed attempts detected.'
                : err?.toString() ?? 'Invalid master password');
            setPassword('');
            inputRef.current?.focus();
        } finally {
            setIsLoading(false);
        }
    }

    async function handleBiometricUnlock() {
        if (isBioLoading) return;
        setIsBioLoading(true);
        setError('');
        try {
            if (isTauri()) {
                try {
                    const { authenticate } = await import('@tauri-apps/plugin-biometric');
                    await authenticate('Unlock your CryptoNote vault', {
                        allowDeviceCredential: true,
                    });
                } catch (bioErr: any) {
                    const msg = bioErr?.toString() ?? '';
                    // Only suppress "not available" errors (desktop dev mode)
                    if (!msg.includes('not available') && !msg.includes('not supported')) {
                        throw new Error('Biometric authentication failed. Try your master password.');
                    }
                }
            }

            const pw = getBiometricPassword();
            if (!pw) throw new Error('Biometric credential lost. Please use master password.');
            await doUnlock(pw);
        } catch (err: any) {
            setError(err?.message ?? err?.toString() ?? 'Authentication failed');
        } finally {
            setIsBioLoading(false);
        }
    }

    // ── Biometric-first layout ────────────────────────────────────────────────
    if (hasBiometric && !showPassword) {
        return (
            <div className='auth-layout'>
                <div className='auth-card bio-card'>
                    {/* Logo */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 40 }}>
                        <div style={{
                            width: 88, height: 88, borderRadius: 22,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            marginBottom: 20,
                            filter: 'drop-shadow(0 0 28px rgba(0,229,160,0.45))',
                        }}>
                            <img src={logoImg} alt='CryptoNote' style={{ width: 88, height: 88, borderRadius: 18 }} />
                        </div>
                        <h1 className='gradient-text' style={{ fontSize: '1.75rem' }}>CryptoNote</h1>
                        <p className='text-muted text-sm' style={{ marginTop: 8 }}>Touch the sensor to unlock</p>
                    </div>

                    {/* Big fingerprint button */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
                        <button
                            className='bio-pulse-btn'
                            onClick={handleBiometricUnlock}
                            disabled={isBioLoading}
                            aria-label='Unlock with biometrics'
                        >
                            {isBioLoading
                                ? <div className='bio-spinner' />
                                : <Fingerprint size={52} />
                            }
                        </button>

                        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                            {isBioLoading ? 'Waiting for biometric…' : 'Tap to authenticate'}
                        </p>

                        {error && (
                            <div className='bio-error'>
                                <AlertTriangle size={14} />
                                {error}
                            </div>
                        )}
                    </div>

                    {/* Fallback to password */}
                    <button
                        className='btn btn-ghost w-full'
                        style={{ marginTop: 36, gap: 8, color: 'var(--text-muted)', fontSize: '0.85rem' }}
                        onClick={() => { setShowPassword(true); setTimeout(() => inputRef.current?.focus(), 100); }}
                    >
                        <KeyRound size={15} />
                        Use master password instead
                    </button>
                </div>
            </div>
        );
    }

    // ── Password-first layout ─────────────────────────────────────────────────
    return (
        <div className='auth-layout'>
            <div className='auth-card'>
                {/* Logo */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 36 }}>
                    <div style={{
                        width: 80, height: 80, borderRadius: 20,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        marginBottom: 16,
                        filter: 'drop-shadow(0 0 24px rgba(0,229,160,0.4))',
                    }}>
                        <img src={logoImg} alt='CryptoNote' style={{ width: 80, height: 80, borderRadius: 16 }} />
                    </div>
                    <h1 className='gradient-text' style={{ fontSize: '1.75rem' }}>CryptoNote</h1>
                    <p className='text-muted text-sm' style={{ marginTop: 6 }}>Enter your master password</p>
                </div>

                <form onSubmit={handleUnlock}>
                    <div className='form-group'>
                        <label className='form-label' htmlFor='master-pw'>Master Password</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                id='master-pw'
                                ref={inputRef}
                                type={showPw ? 'text' : 'password'}
                                className={`form-input font-mono ${error ? 'error' : ''}`}
                                placeholder='Enter master password…'
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                autoComplete='current-password'
                                disabled={isLoading || isBioLoading}
                                style={{ paddingRight: 44 }}
                            />
                            <button
                                type='button'
                                className='btn btn-ghost btn-icon'
                                style={{ position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)' }}
                                onClick={() => setShowPw(!showPw)}
                                tabIndex={-1}
                            >
                                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <div style={{
                            display: 'flex', alignItems: 'flex-start', gap: 8,
                            marginTop: 12, padding: '10px 14px',
                            background: 'rgba(239,68,68,0.1)', borderRadius: 'var(--radius-md)',
                            border: '1px solid var(--border-danger)', color: 'var(--color-danger)',
                            fontSize: '0.8125rem',
                        }}>
                            <AlertTriangle size={15} style={{ marginTop: 1, flexShrink: 0 }} />
                            {error}
                        </div>
                    )}

                    <button
                        type='submit'
                        className='btn btn-primary w-full'
                        style={{ marginTop: 24 }}
                        disabled={!password || isLoading}
                    >
                        {isLoading
                            ? <><div className='spin' style={{ width: 16, height: 16, border: '2px solid #080c10', borderTopColor: 'transparent', borderRadius: '50%' }} />Unlocking…</>
                            : <><Lock size={16} />Unlock Vault</>
                        }
                    </button>
                </form>

                {/* Biometric shortcut if enrolled */}
                {hasBiometric && (
                    <>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '20px 0', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                            <span>or</span>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                        </div>
                        <button
                            className='btn btn-secondary w-full'
                            style={{ gap: 10, background: 'rgba(0,229,160,0.08)', border: '1px solid rgba(0,229,160,0.25)' }}
                            onClick={handleBiometricUnlock}
                            disabled={isBioLoading}
                        >
                            {isBioLoading
                                ? <><div className='spin' style={{ width: 16, height: 16, border: '2px solid var(--accent-1)', borderTopColor: 'transparent', borderRadius: '50%' }} />Authenticating…</>
                                : <><Fingerprint size={18} style={{ color: 'var(--accent-1)' }} />Use Biometrics</>
                            }
                        </button>
                    </>
                )}

                <div className='divider' style={{ margin: '24px 0' }} />

                {/* No vault banner + cloud restore */}
                {noVault && (
                    <div style={{
                        padding: '12px 14px', marginBottom: 12,
                        background: 'rgba(255,170,0,0.08)',
                        border: '1px solid rgba(255,170,0,0.3)',
                        borderRadius: 'var(--radius-md)',
                        fontSize: '0.8rem', color: 'var(--color-warning)',
                        display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                        <Cloud size={14} />
                        No vault found on this device. Restore from cloud sync or create a new vault.
                    </div>
                )}

                {showSyncRestore && (
                    <div style={{
                        padding: 16, marginBottom: 12,
                        background: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-lg)',
                    }}>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 12 }}>
                            <Cloud size={14} style={{ display: 'inline', marginRight: 6 }} />
                            Restore from Cloud Sync
                        </p>
                        <div className='form-group'>
                            <label className='form-label'>Sync Server URL</label>
                            <input className='form-input' value={restoreUrl}
                                onChange={(e) => setRestoreUrl(e.target.value)}
                                placeholder='https://your-server.onrender.com' />
                        </div>
                        <div className='form-group' style={{ marginTop: 8 }}>
                            <label className='form-label'>Account Email</label>
                            <input className='form-input' type='email' value={restoreEmail}
                                onChange={(e) => setRestoreEmail(e.target.value)}
                                placeholder='your@email.com' />
                        </div>
                        {pullError && (
                            <div style={{ color: 'var(--color-danger)', fontSize: '0.8rem', marginTop: 8 }}>
                                <AlertTriangle size={13} style={{ display: 'inline', marginRight: 4 }} />
                                {pullError}
                            </div>
                        )}
                        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                            <button className='btn btn-primary' style={{ flex: 1 }}
                                disabled={isPulling || !restoreEmail || !restoreUrl}
                                onClick={handleSyncRestore}>
                                {isPulling
                                    ? <><RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} />Restoring…</>
                                    : <><Cloud size={14} />Restore Vault</>
                                }
                            </button>
                            <button className='btn btn-secondary' onClick={() => setShowSyncRestore(false)}>
                                Cancel
                            </button>
                        </div>
                    </div>
                )}

                <div style={{ textAlign: 'center' }}>
                    {!showSyncRestore && (
                        <button
                            className='btn btn-secondary w-full'
                            style={{ marginBottom: 8, gap: 8 }}
                            onClick={() => setShowSyncRestore(true)}
                            disabled={isLoading}
                        >
                            <Cloud size={15} />
                            Restore from Cloud Sync
                        </button>
                    )}
                    <p className='text-sm text-muted' style={{ marginBottom: 10, marginTop: 4 }}>
                        No account? Create a fresh vault.
                    </p>
                    <button className='btn btn-secondary w-full' onClick={() => navigate('/setup')} disabled={isLoading}>
                        Create New Vault
                    </button>
                </div>
            </div>
        </div>
    );
}
