// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with biometric support

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, Eye, EyeOff, AlertTriangle, Fingerprint, KeyRound } from 'lucide-react';
import logoImg from '../assets/logo-120.png';
import { vaultUnlock } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';

export function UnlockPage() {
    const navigate = useNavigate();
    const {
        setLocked, setMeta,
        biometricEnabled, storeBiometricPassword, getBiometricPassword,
    } = useVaultStore();

    const [password, setPassword]         = useState('');
    const [showPw, setShowPw]             = useState(false);
    const [isLoading, setIsLoading]       = useState(false);
    const [isBioLoading, setIsBioLoading] = useState(false);
    const [error, setError]               = useState('');
    const [failCount, setFailCount]       = useState(0);
    const [showPassword, setShowPassword] = useState(false); // show pw form when bio available
    const inputRef = useRef<HTMLInputElement>(null);

    const storedPw    = getBiometricPassword();
    const hasBiometric = biometricEnabled && storedPw !== null;

    // Auto-trigger biometric on load if enrolled
    useEffect(() => {
        if (hasBiometric) {
            // Small delay so the UI renders first
            setTimeout(() => handleBiometricUnlock(), 600);
        } else {
            inputRef.current?.focus();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

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

                <div style={{ textAlign: 'center' }}>
                    <p className='text-sm text-muted' style={{ marginBottom: 10 }}>First time? Set up a new vault.</p>
                    <button className='btn btn-secondary w-full' onClick={() => navigate('/setup')} disabled={isLoading}>
                        Create New Vault
                    </button>
                </div>
            </div>
        </div>
    );
}
