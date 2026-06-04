// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with biometric support

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, Eye, EyeOff, AlertTriangle, Fingerprint, KeyRound, Cloud, CheckCircle2 } from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { vaultUnlock, vaultIsInitialized, syncConfigure } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';

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
    const [isBioLoading, setIsBioLoading] = useState(false);
    const [error, setError]               = useState('');
    const [failCount, setFailCount]       = useState(0);
    const [showPassword, setShowPassword] = useState(false); // switch from bio view to pw view
    const inputRef = useRef<HTMLInputElement>(null);

    // No-vault + sync restore state
    const [noVault, setNoVault]           = useState(false);
    const [showSyncPanel, setShowSyncPanel] = useState(false);
    const [restoreUrl, setRestoreUrl]     = useState(syncServerUrl || 'https://sanjai-06-cryptonote-app.onrender.com');
    const [restoreEmail, setRestoreEmail] = useState(syncEmail || '');
    const [isSavingSync, setIsSavingSync] = useState(false);
    const [syncSaved, setSyncSaved]       = useState(false);
    const [syncPanelError, setSyncPanelError] = useState('');

    const storedPw     = getBiometricPassword();
    const hasBiometric = biometricEnabled && storedPw !== null;

    // Detect missing vault on mount
    useEffect(() => {
        vaultIsInitialized().then((ok) => {
            if (!ok) setNoVault(true);
        }).catch(() => {});
    }, []);

    // Auto-trigger biometric (only when vault exists)
    useEffect(() => {
        if (hasBiometric && !noVault) {
            setTimeout(() => handleBiometricUnlock(), 600);
        } else if (!hasBiometric && !noVault) {
            inputRef.current?.focus();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [noVault]);

    // ── Save sync credentials so unlock can pull automatically ────────────────
    async function handleSaveSyncCredentials() {
        if (!restoreEmail.trim() || !restoreUrl.trim()) {
            setSyncPanelError('Enter both server URL and account email.');
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
            setSyncConfig(restoreUrl.trim(), restoreEmail.trim(), true);
            setSyncSaved(true);
            setShowSyncPanel(false);
            setError('✓ Sync configured! Now enter your master password — your vault will be restored automatically.');
        } catch (e: any) {
            setSyncPanelError(e?.toString() ?? 'Failed to configure sync.');
        } finally {
            setIsSavingSync(false);
        }
    }

    // ── Core unlock ───────────────────────────────────────────────────────────
    async function doUnlock(pw: string) {
        const meta = await vaultUnlock(pw); // vaultUnlock calls sync_pull internally
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
                    await authenticate('Unlock your CryptoNote vault', { allowDeviceCredential: true });
                } catch (bioErr: any) {
                    const msg = bioErr?.toString() ?? '';
                    if (!msg.includes('not available') && !msg.includes('not supported')) {
                        throw new Error('Biometric failed. Try your master password.');
                    }
                }
            }
            const pw = getBiometricPassword();
            if (!pw) throw new Error('Biometric credential lost. Use master password.');
            await doUnlock(pw);
        } catch (err: any) {
            setError(err?.message ?? err?.toString() ?? 'Authentication failed');
        } finally {
            setIsBioLoading(false);
        }
    }

    // ── Biometric-first screen ────────────────────────────────────────────────
    if (hasBiometric && !showPassword && !noVault) {
        return (
            <div className='auth-layout'>
                <div className='auth-card bio-card'>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 40 }}>
                        <div style={{ width: 88, height: 88, borderRadius: 22, marginBottom: 20, filter: 'drop-shadow(0 0 28px rgba(0,229,160,0.45))' }}>
                            <img src={logoImg} alt='CryptoNote' style={{ width: 88, height: 88, borderRadius: 18 }} />
                        </div>
                        <h1 className='gradient-text' style={{ fontSize: '1.75rem' }}>CryptoNote</h1>
                        <p className='text-muted text-sm' style={{ marginTop: 8 }}>Touch the sensor to unlock</p>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20 }}>
                        <button className='bio-pulse-btn' onClick={handleBiometricUnlock} disabled={isBioLoading} aria-label='Unlock with biometrics'>
                            {isBioLoading ? <div className='bio-spinner' /> : <Fingerprint size={52} />}
                        </button>
                        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                            {isBioLoading ? 'Waiting for biometric…' : 'Tap to authenticate'}
                        </p>
                        {error && <div className='bio-error'><AlertTriangle size={14} />{error}</div>}
                    </div>

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

    // ── Password screen ───────────────────────────────────────────────────────
    return (
        <div className='auth-layout'>
            <div className='auth-card'>
                {/* Logo */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 36 }}>
                    <div style={{ width: 80, height: 80, borderRadius: 20, marginBottom: 16, filter: 'drop-shadow(0 0 24px rgba(0,229,160,0.4))' }}>
                        <img src={logoImg} alt='CryptoNote' style={{ width: 80, height: 80, borderRadius: 16 }} />
                    </div>
                    <h1 className='gradient-text' style={{ fontSize: '1.75rem' }}>CryptoNote</h1>
                    <p className='text-muted text-sm' style={{ marginTop: 6 }}>Enter your master password</p>
                </div>

                {/* No-vault banner */}
                {noVault && !syncSaved && (
                    <div style={{
                        padding: '10px 14px', marginBottom: 16,
                        background: 'rgba(255,170,0,0.08)',
                        border: '1px solid rgba(255,170,0,0.3)',
                        borderRadius: 'var(--radius-md)',
                        fontSize: '0.8rem', color: 'var(--color-warning)',
                        display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                        <Cloud size={14} style={{ flexShrink: 0 }} />
                        No vault on this device. Configure sync below to restore, or create a new vault.
                    </div>
                )}

                <form onSubmit={handleUnlock}>
                    <div className='form-group'>
                        <label className='form-label' htmlFor='master-pw'>Master Password</label>
                        {/* Flex row so eye button never clips on mobile */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
                            <input
                                id='master-pw'
                                ref={inputRef}
                                type={showPw ? 'text' : 'password'}
                                className={`form-input font-mono ${error && !error.startsWith('✓') ? 'error' : ''}`}
                                placeholder='Enter master password…'
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                autoComplete='current-password'
                                disabled={isLoading || isBioLoading}
                                style={{ flex: 1, borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', borderRight: 'none' }}
                            />
                            <button
                                type='button'
                                onClick={() => setShowPw(!showPw)}
                                tabIndex={-1}
                                style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    width: 44, height: 44, flexShrink: 0,
                                    background: 'var(--bg-input)',
                                    border: '1px solid var(--border)',
                                    borderLeft: 'none',
                                    borderRadius: '0 var(--radius-md) var(--radius-md) 0',
                                    cursor: 'pointer',
                                    color: 'var(--text-muted)',
                                }}
                            >
                                {showPw ? <EyeOff size={17} /> : <Eye size={17} />}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <div style={{
                            display: 'flex', alignItems: 'flex-start', gap: 8,
                            marginTop: 10, padding: '10px 14px',
                            background: error.startsWith('✓') ? 'rgba(0,229,160,0.08)' : 'rgba(239,68,68,0.1)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${error.startsWith('✓') ? 'rgba(0,229,160,0.25)' : 'var(--border-danger)'}`,
                            color: error.startsWith('✓') ? 'var(--accent-1)' : 'var(--color-danger)',
                            fontSize: '0.8125rem',
                        }}>
                            {error.startsWith('✓')
                                ? <CheckCircle2 size={15} style={{ marginTop: 1, flexShrink: 0 }} />
                                : <AlertTriangle size={15} style={{ marginTop: 1, flexShrink: 0 }} />
                            }
                            {error}
                        </div>
                    )}

                    <button
                        type='submit'
                        className='btn btn-primary w-full'
                        style={{ marginTop: 20 }}
                        disabled={!password || isLoading}
                    >
                        {isLoading
                            ? <><div className='spin' style={{ width: 16, height: 16, border: '2px solid #080c10', borderTopColor: 'transparent', borderRadius: '50%' }} />Unlocking…</>
                            : <><Lock size={16} />Unlock Vault</>
                        }
                    </button>
                </form>

                {/* Biometric shortcut */}
                {hasBiometric && (
                    <>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '16px 0', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
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

                <div className='divider' style={{ margin: '20px 0' }} />

                {/* Sync restore panel (collapsed by default) */}
                {showSyncPanel ? (
                    <div style={{
                        padding: 16, marginBottom: 12,
                        background: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-lg)',
                    }}>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Cloud size={14} /> Configure Cloud Sync
                        </p>
                        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 12 }}>
                            Enter your sync details. After saving, unlock with your master password — your vault will be downloaded automatically.
                        </p>
                        <div className='form-group'>
                            <label className='form-label'>Server URL</label>
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
                        {syncPanelError && (
                            <p style={{ color: 'var(--color-danger)', fontSize: '0.8rem', marginTop: 8 }}>
                                <AlertTriangle size={13} style={{ display: 'inline', marginRight: 4 }} />
                                {syncPanelError}
                            </p>
                        )}
                        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                            <button className='btn btn-primary' style={{ flex: 1 }}
                                disabled={isSavingSync || !restoreEmail || !restoreUrl}
                                onClick={handleSaveSyncCredentials}>
                                {isSavingSync
                                    ? 'Saving…'
                                    : <><Cloud size={14} /> Save & Unlock</>
                                }
                            </button>
                            <button className='btn btn-secondary' onClick={() => setShowSyncPanel(false)}>Cancel</button>
                        </div>
                    </div>
                ) : (
                    <div style={{ textAlign: 'center' }}>
                        <button
                            className='btn btn-secondary w-full'
                            style={{ marginBottom: 10, gap: 8 }}
                            onClick={() => setShowSyncPanel(true)}
                            disabled={isLoading}
                        >
                            <Cloud size={15} />
                            {syncSaved ? '✓ Sync Configured — Change Settings' : 'Restore from Cloud Sync'}
                        </button>
                        <p className='text-sm text-muted' style={{ marginBottom: 8 }}>New here? Create a fresh vault.</p>
                        <button className='btn btn-secondary w-full' onClick={() => navigate('/setup')} disabled={isLoading}>
                            Create New Vault
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
