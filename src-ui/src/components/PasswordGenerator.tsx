// src-ui/src/components/PasswordGenerator.tsx
// Inline password generator with strength display

import { useState, useCallback } from 'react';
import { RefreshCw, Copy, Check } from 'lucide-react';
import { generatePassword } from '../hooks/useVault';
import type { PasswordOptions } from '../types/vault';

interface Props {
    onSelect?: (password: string) => void;
}

function calcStrength(pw: string): { pct: number; color: string; label: string } {
    let score = 0;
    if (pw.length >= 12) score++;
    if (pw.length >= 20) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length >= 32) score++;
    const pct = Math.round((score / 6) * 100);
    if (score <= 2) return { pct, color: 'var(--color-danger)', label: 'Weak' };
    if (score <= 3) return { pct, color: 'var(--color-warning)', label: 'Fair' };
    if (score <= 4) return { pct, color: 'var(--color-info)', label: 'Good' };
    return { pct, color: 'var(--color-success)', label: 'Strong' };
}

const defaultOpts: PasswordOptions = {
    length: 24,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
};

export function PasswordGenerator({ onSelect }: Props) {
    const [opts, setOpts] = useState<PasswordOptions>(defaultOpts);
    const [password, setPassword] = useState('');
    const [copied, setCopied] = useState(false);
    const [isGen, setIsGen] = useState(false);

    const strength = calcStrength(password);

    const generate = useCallback(async () => {
        setIsGen(true);
        try {
            const pw = await generatePassword(opts);
            setPassword(pw);
            setCopied(false);
        } catch { /* ignore */ }
        setIsGen(false);
    }, [opts]);

    function copy() {
        if (!password) return;
        navigator.clipboard.writeText(password);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
    }

    function toggle(field: keyof PasswordOptions) {
        setOpts((o) => ({ ...o, [field]: !o[field] }));
    }

    return (
        <div className='gen-panel'>
            {/* Generated password */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'stretch' }}>
                <div className='gen-result' style={{ flex: 1 }}>
                    {password || <span style={{ color: 'var(--text-muted)', fontFamily: 'inherit' }}>Click Generate 🎲</span>}
                </div>
                {password && (
                    <>
                        <button className='btn btn-ghost btn-icon' onClick={copy} title='Copy'>
                            {copied ? <Check size={15} color='var(--color-success)' /> : <Copy size={15} />}
                        </button>
                        {onSelect && (
                            <button className='btn btn-primary' onClick={() => onSelect(password)} title='Use this password'>
                                Use
                            </button>
                        )}
                    </>
                )}
            </div>

            {/* Strength bar */}
            {password && (
                <div style={{ marginBottom: 14 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span className='text-xs text-muted'>Strength</span>
                        <span className='text-xs' style={{ color: strength.color, fontWeight: 600 }}>{strength.label} ({strength.pct}%)</span>
                    </div>
                    <div className='strength-bar'>
                        <div className='strength-fill' style={{ width: `${strength.pct}%`, background: strength.color }} />
                    </div>
                </div>
            )}

            {/* Length slider */}
            <div style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <label className='form-label' style={{ margin: 0 }}>Length</label>
                    <span className='font-mono' style={{ fontSize: '0.875rem', color: 'var(--accent-1)', fontWeight: 700 }}>{opts.length}</span>
                </div>
                <input
                    type='range'
                    min={8}
                    max={128}
                    value={opts.length}
                    onChange={(e) => setOpts((o) => ({ ...o, length: +e.target.value }))}
                    style={{ width: '100%', accentColor: 'var(--accent-1)', cursor: 'pointer' }}
                />
            </div>

            {/* Character options */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                {[
                    { key: 'uppercase', label: 'Uppercase (A–Z)' },
                    { key: 'lowercase', label: 'Lowercase (a–z)' },
                    { key: 'digits', label: 'Numbers (0–9)' },
                    { key: 'symbols', label: 'Symbols (!@#…)' },
                ].map(({ key, label }) => (
                    <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.8125rem' }}>
                        <input
                            type='checkbox'
                            checked={opts[key as keyof PasswordOptions] as boolean}
                            onChange={() => toggle(key as keyof PasswordOptions)}
                            style={{ accentColor: 'var(--accent-1)', width: 15, height: 15, cursor: 'pointer' }}
                        />
                        {label}
                    </label>
                ))}
            </div>

            <button className='btn btn-primary w-full' onClick={generate} disabled={isGen}>
                <RefreshCw size={14} className={isGen ? 'spin' : ''} />
                {isGen ? 'Generating…' : 'Generate Password'}
            </button>
        </div>
    );
}
