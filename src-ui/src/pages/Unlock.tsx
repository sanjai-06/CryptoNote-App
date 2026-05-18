// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with biometric support

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Lock, Eye, EyeOff, AlertTriangle, Fingerprint } from 'lucide-react';
import { vaultUnlock, vaultCreate, vaultExists } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';
import { isTauri } from '../lib/env';

export function UnlockPage() {
    const navigate = useNavigate();
    const { setLocked, setMeta, biometricEnabled, storeBiometricPassword, getBiometricPassword } = useVaultStore();
    const [password, setPassword] = useState('');
    const [showPw, setShowPw] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [isBioLoading, setIsBioLoading] = useState(false);
    const [error, setError] = useState('');
    const [failCount, setFailCount] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);

    const hasBiometric = biometricEnabled && getBiometricPassword() !== null;

    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    async function doUnlock(pw: string) {
        const meta = await vaultUnlock(pw);
        setMeta(meta);
        setLocked(false);

        // Store password for future biometric unlocks
        if (biometricEnabled) {
            storeBiometricPassword(pw);
        }

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
                ? '⚠️ Multiple failed attempts detected. Vault will be locked after one more failure.'
                : err?.toString() ?? 'Invalid master password');
            setPassword('');
            inputRef.current?.focus();
        } finally {
            setIsLoading(false);
        }
    }

    async function handleBiometricUnlock() {
        setIsBioLoading(true);
        setError('');
        try {
            // Attempt biometric authentication via Tauri plugin
            if (isTauri()) {
                try {
                    const { authenticate } = await import('@tauri-apps/plugin-biometric');
                    await authenticate('Unlock CryptoNote vault', {
                        allowDeviceCredential: true,
                    });
                } catch (bioErr: any) {
                    // If biometric plugin is not available (e.g., Linux desktop),
                    // fall through and use the stored password directly
                    const errStr = bioErr?.toString() ?? '';
                    if (errStr.includes('not available') || errStr.includes('not supported') || errStr.includes('plugin')) {
                        // Platform doesn't support biometrics — skip auth challenge
                    } else {
                        throw bioErr; // Real auth failure
                    }
                }
            }

            const storedPw = getBiometricPassword();
            if (!storedPw) {
                setError('Biometric password not found. Please unlock with your master password first.');
                return;
            }

            await doUnlock(storedPw);
        } catch (err: any) {
            setError(err?.toString() ?? 'Biometric authentication failed');
        } finally {
            setIsBioLoading(false);
        }
    }

    return (
        <div className='auth-layout'>
            <div className='auth-card'>
                {/* Logo */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 36 }}>
                    <div style={{
                        width: 64, height: 64, borderRadius: 18,
                        background: 'linear-gradient(135deg, var(--accent-1), var(--accent-2))',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        marginBottom: 16, boxShadow: '0 0 32px rgba(0,229,160,0.3)'
                    }}>
                        <ShieldCheck size={32} color='#080c10' strokeWidth={2.5} />
                    </div>
                    <h1 className='gradient-text' style={{ fontSize: '1.75rem' }}>CryptoNote</h1>
                    <p className='text-muted text-sm' style={{ marginTop: 6 }}>Enter your master password to unlock</p>
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
                            fontSize: '0.8125rem'
                        }}>
                            <AlertTriangle size={15} style={{ marginTop: 1, flexShrink: 0 }} />
                            {error}
                        </div>
                    )}

                    <button
                        type='submit'
                        className='btn btn-primary w-full'
                        style={{ marginTop: 24 }}
                        disabled={!password || isLoading || isBioLoading}
                    >
                        {isLoading ? (
                            <>
                                <div className='spin' style={{ width: 16, height: 16, border: '2px solid #080c10', borderTopColor: 'transparent', borderRadius: '50%' }} />
                                Unlocking…
                            </>
                        ) : (
                            <>
                                <Lock size={16} />
                                Unlock Vault
                            </>
                        )}
                    </button>
                </form>

                {/* Biometric unlock button */}
                {hasBiometric && (
                    <>
                        <div style={{
                            display: 'flex', alignItems: 'center', gap: 12,
                            margin: '20px 0', color: 'var(--text-muted)', fontSize: '0.75rem',
                        }}>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                            <span>or</span>
                            <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                        </div>
                        <button
                            className='btn btn-secondary w-full'
                            style={{
                                gap: 10, padding: '12px 16px',
                                background: 'rgba(0,229,160,0.08)',
                                border: '1px solid rgba(0,229,160,0.25)',
                            }}
                            onClick={handleBiometricUnlock}
                            disabled={isLoading || isBioLoading}
                        >
                            {isBioLoading ? (
                                <>
                                    <div className='spin' style={{ width: 16, height: 16, border: '2px solid var(--accent-1)', borderTopColor: 'transparent', borderRadius: '50%' }} />
                                    Authenticating…
                                </>
                            ) : (
                                <>
                                    <Fingerprint size={18} style={{ color: 'var(--accent-1)' }} />
                                    Unlock with Biometrics
                                </>
                            )}
                        </button>
                    </>
                )}

                <div className='divider' style={{ margin: '24px 0' }} />

                <div style={{ textAlign: 'center' }}>
                    <p className='text-sm text-muted' style={{ marginBottom: 10 }}>First time? Set up a new vault.</p>
                    <button
                        className='btn btn-secondary w-full'
                        onClick={() => navigate('/setup')}
                        disabled={isLoading}
                    >
                        Create New Vault
                    </button>
                </div>
            </div>
        </div>
    );
}

