// src-ui/src/pages/Unlock.tsx
// Master password unlock screen with strength indicator

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Lock, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { vaultUnlock, vaultCreate, vaultExists } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';

export function UnlockPage() {
    const navigate = useNavigate();
    const { setLocked, setMeta } = useVaultStore();
    const [password, setPassword] = useState('');
    const [showPw, setShowPw] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [failCount, setFailCount] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    async function handleUnlock(e: React.FormEvent) {
        e.preventDefault();
        if (!password) return;
        setIsLoading(true);
        setError('');
        try {
            const meta = await vaultUnlock(password);
            setMeta(meta);
            setLocked(false);
            navigate('/vault');
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
                                disabled={isLoading}
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
                        disabled={!password || isLoading}
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
