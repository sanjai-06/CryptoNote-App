// src-ui/src/pages/Setup.tsx
// First-run vault creation wizard

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Eye, EyeOff, CheckCircle2, XCircle } from 'lucide-react';
import { vaultCreate } from '../hooks/useVault';
import { useVaultStore } from '../store/vaultStore';

function calcStrength(pw: string): { score: number; label: string; color: string } {
    let score = 0;
    if (pw.length >= 12) score++;
    if (pw.length >= 20) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length >= 32) score++;

    if (score <= 2) return { score, label: 'Weak', color: 'var(--color-danger)' };
    if (score <= 3) return { score, label: 'Fair', color: 'var(--color-warning)' };
    if (score <= 4) return { score, label: 'Good', color: 'var(--color-info)' };
    return { score, label: 'Strong', color: 'var(--color-success)' };
}

const requirements = [
    { test: (pw: string) => pw.length >= 12, label: 'At least 12 characters' },
    { test: (pw: string) => /[A-Z]/.test(pw), label: 'Uppercase letter' },
    { test: (pw: string) => /[0-9]/.test(pw), label: 'Number' },
    { test: (pw: string) => /[^A-Za-z0-9]/.test(pw), label: 'Special character' },
];

export function SetupPage() {
    const navigate = useNavigate();
    const { setMeta, setLocked } = useVaultStore();
    const [step, setStep] = useState<1 | 2>(1);
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [showPw, setShowPw] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const strength = calcStrength(password);
    const allMet = requirements.every((r) => r.test(password));
    const matches = password === confirm && confirm.length > 0;

    async function handleCreate() {
        if (!allMet) { setError('Password does not meet requirements'); return; }
        if (!matches) { setError('Passwords do not match'); return; }
        setIsLoading(true);
        setError('');
        try {
            const meta = await vaultCreate(password);
            setMeta(meta);
            setLocked(false);
            navigate('/vault');
        } catch (err: any) {
            setError(err?.toString() ?? 'Failed to create vault');
        } finally {
            setIsLoading(false);
        }
    }

    return (
        <div className='auth-layout'>
            <div className='auth-card' style={{ width: 480 }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 32 }}>
                    <div style={{
                        width: 64, height: 64, borderRadius: 18,
                        background: 'linear-gradient(135deg, var(--accent-1), var(--accent-2))',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        marginBottom: 16, boxShadow: '0 0 32px rgba(0,229,160,0.3)'
                    }}>
                        <ShieldCheck size={32} color='#080c10' strokeWidth={2.5} />
                    </div>
                    <h2 className='gradient-text'>Create Your Vault</h2>
                    <p className='text-muted text-sm' style={{ marginTop: 6 }}>
                        Your master password encrypts everything. It is never stored or transmitted.
                    </p>
                </div>

                {/* Warning banner */}
                <div style={{
                    background: 'rgba(245,158,11,0.08)',
                    border: '1px solid rgba(245,158,11,0.3)',
                    borderRadius: 'var(--radius-md)',
                    padding: '12px 16px',
                    marginBottom: 24,
                    fontSize: '0.8125rem',
                    color: 'var(--color-warning)'
                }}>
                    ⚠️ <strong>If you forget your master password, your vault cannot be recovered.</strong> There is no reset mechanism by design.
                </div>

                <div className='form-group'>
                    <label className='form-label' htmlFor='new-pw'>Master Password</label>
                    <div style={{ position: 'relative' }}>
                        <input
                            id='new-pw'
                            type={showPw ? 'text' : 'password'}
                            className='form-input font-mono'
                            placeholder='Choose a strong master password…'
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            style={{ paddingRight: 44 }}
                        />
                        <button type='button' className='btn btn-ghost btn-icon'
                            style={{ position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)' }}
                            onClick={() => setShowPw(!showPw)} tabIndex={-1}>
                            {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                    </div>
                </div>

                {/* Strength bar */}
                {password && (
                    <div style={{ marginTop: 10 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                            <span className='text-xs text-muted'>Strength</span>
                            <span className='text-xs' style={{ color: strength.color, fontWeight: 600 }}>{strength.label}</span>
                        </div>
                        <div className='strength-bar'>
                            <div className='strength-fill' style={{
                                width: `${(strength.score / 6) * 100}%`,
                                background: strength.color
                            }} />
                        </div>
                    </div>
                )}

                {/* Requirements */}
                {password && (
                    <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {requirements.map((req) => {
                            const ok = req.test(password);
                            return (
                                <div key={req.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8rem' }}>
                                    {ok
                                        ? <CheckCircle2 size={14} color='var(--color-success)' />
                                        : <XCircle size={14} color='var(--color-danger)' />}
                                    <span style={{ color: ok ? 'var(--text-secondary)' : 'var(--text-muted)' }}>{req.label}</span>
                                </div>
                            );
                        })}
                    </div>
                )}

                <div className='form-group mt-4'>
                    <label className='form-label' htmlFor='confirm-pw'>Confirm Password</label>
                    <input
                        id='confirm-pw'
                        type='password'
                        className={`form-input font-mono ${confirm && !matches ? 'error' : ''}`}
                        placeholder='Re-enter your master password…'
                        value={confirm}
                        onChange={(e) => setConfirm(e.target.value)}
                    />
                    {confirm && !matches && (
                        <p className='text-xs text-danger' style={{ marginTop: 4 }}>Passwords do not match</p>
                    )}
                </div>

                {error && (
                    <div style={{
                        marginTop: 12, padding: '10px 14px',
                        background: 'rgba(239,68,68,0.1)', borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--border-danger)', color: 'var(--color-danger)',
                        fontSize: '0.8125rem'
                    }}>{error}</div>
                )}

                <button
                    className='btn btn-primary w-full'
                    style={{ marginTop: 24 }}
                    onClick={handleCreate}
                    disabled={!allMet || !matches || isLoading}
                >
                    {isLoading ? 'Creating Vault…' : '🔐 Create Encrypted Vault'}
                </button>

                <button className='btn btn-ghost w-full' style={{ marginTop: 12 }} onClick={() => navigate('/unlock')}>
                    ← Back to Unlock
                </button>
            </div>
        </div>
    );
}
