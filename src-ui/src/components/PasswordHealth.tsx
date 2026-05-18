// src-ui/src/components/PasswordHealth.tsx
// Password Health Dashboard — shows weak, reused, and breached passwords

import { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Copy, RefreshCw, X, ExternalLink } from 'lucide-react';
import { vaultListEntries, vaultGetEntry } from '../hooks/useVault';
import { analyzeVaultHealth, type PasswordHealthResult, type HealthSummary } from '../lib/passwordHealth';
import type { VaultEntry } from '../types/vault';

interface Props {
    onClose: () => void;
    onSelectEntry: (id: string) => void;
}

const strengthColors: Record<string, string> = {
    critical: '#ef4444',
    weak: '#f97316',
    fair: '#eab308',
    strong: '#22c55e',
    excellent: '#059669',
};

const strengthLabels: Record<string, string> = {
    critical: 'Critical',
    weak: 'Weak',
    fair: 'Fair',
    strong: 'Strong',
    excellent: 'Excellent',
};

function ScoreRing({ score, size = 120 }: { score: number; size?: number }) {
    const stroke = 8;
    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    let color = '#ef4444';
    if (score >= 80) color = '#059669';
    else if (score >= 60) color = '#22c55e';
    else if (score >= 40) color = '#eab308';
    else if (score >= 20) color = '#f97316';

    return (
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
            <circle
                cx={size / 2} cy={size / 2} r={radius}
                fill="none"
                stroke="var(--border)"
                strokeWidth={stroke}
            />
            <circle
                cx={size / 2} cy={size / 2} r={radius}
                fill="none"
                stroke={color}
                strokeWidth={stroke}
                strokeDasharray={circumference}
                strokeDashoffset={offset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease' }}
            />
            <text
                x="50%" y="50%"
                textAnchor="middle"
                dominantBaseline="central"
                fill="var(--text-primary)"
                fontSize={size * 0.28}
                fontWeight={700}
                style={{ transform: 'rotate(90deg)', transformOrigin: 'center' }}
            >
                {score}
            </text>
        </svg>
    );
}

function StrengthBar({ score }: { score: number }) {
    let color = '#ef4444';
    if (score >= 80) color = '#059669';
    else if (score >= 60) color = '#22c55e';
    else if (score >= 40) color = '#eab308';
    else if (score >= 20) color = '#f97316';

    return (
        <div style={{
            width: 60, height: 4, borderRadius: 2,
            background: 'var(--border)', overflow: 'hidden'
        }}>
            <div style={{
                width: `${score}%`, height: '100%',
                background: color, borderRadius: 2,
                transition: 'width 0.5s ease',
            }} />
        </div>
    );
}

export function PasswordHealthDashboard({ onClose, onSelectEntry }: Props) {
    const [isLoading, setIsLoading] = useState(true);
    const [progress, setProgress] = useState({ current: 0, total: 0 });
    const [results, setResults] = useState<PasswordHealthResult[]>([]);
    const [summary, setSummary] = useState<HealthSummary | null>(null);
    const [filter, setFilter] = useState<'all' | 'critical' | 'weak' | 'reused' | 'breached'>('all');

    const runAnalysis = useCallback(async () => {
        setIsLoading(true);
        setResults([]);
        setSummary(null);

        try {
            const list = await vaultListEntries();
            const entries: VaultEntry[] = [];

            for (const item of list) {
                try {
                    const entry = await vaultGetEntry(item.id);
                    entries.push(entry);
                } catch { /* skip locked entries */ }
            }

            const { results: healthResults, summary: healthSummary } = await analyzeVaultHealth(
                entries,
                (current, total) => setProgress({ current, total })
            );

            setResults(healthResults);
            setSummary(healthSummary);
        } catch (e) {
            console.error('Health analysis failed:', e);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => { runAnalysis(); }, [runAnalysis]);

    const filtered = results.filter(r => {
        if (filter === 'all') return true;
        if (filter === 'critical') return r.strength === 'critical';
        if (filter === 'weak') return r.strength === 'weak' || r.strength === 'critical';
        if (filter === 'reused') return r.isReused;
        if (filter === 'breached') return r.isBreached;
        return true;
    });

    return (
        <div style={{
            position: 'fixed', inset: 0,
            background: 'rgba(0,0,0,0.6)',
            backdropFilter: 'blur(8px)',
            zIndex: 1000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
            <div style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-xl)',
                width: '90%', maxWidth: 800, maxHeight: '85vh',
                display: 'flex', flexDirection: 'column',
                boxShadow: 'var(--shadow-lg)',
                overflow: 'hidden',
            }}>
                {/* Header */}
                <div style={{
                    padding: '20px 24px',
                    borderBottom: '1px solid var(--border)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{
                            width: 36, height: 36, borderRadius: 10,
                            background: 'linear-gradient(135deg, var(--accent-1), var(--accent-2))',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                            <ShieldCheck size={18} color="#080c10" />
                        </div>
                        <div>
                            <h3 style={{ margin: 0 }}>Password Health</h3>
                            <p className="text-xs text-muted" style={{ margin: 0 }}>
                                Analyze strength, reuse, and breach exposure
                            </p>
                        </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <button className="btn btn-ghost btn-icon" onClick={runAnalysis} disabled={isLoading}>
                            <RefreshCw size={14} className={isLoading ? 'spin' : ''} />
                        </button>
                        <button className="btn btn-ghost btn-icon" onClick={onClose}>
                            <X size={16} />
                        </button>
                    </div>
                </div>

                {/* Body */}
                <div style={{ overflowY: 'auto', flex: 1, padding: '20px 24px' }}>
                    {isLoading ? (
                        <div style={{
                            textAlign: 'center', padding: '60px 0',
                            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
                        }}>
                            <RefreshCw size={32} className="spin" style={{ color: 'var(--accent-1)' }} />
                            <div>
                                <p style={{ margin: 0, fontWeight: 600 }}>Analyzing passwords…</p>
                                <p className="text-sm text-muted" style={{ margin: '4px 0 0' }}>
                                    Checking {progress.current} of {progress.total} entries
                                </p>
                            </div>
                        </div>
                    ) : summary && (
                        <>
                            {/* Summary cards */}
                            <div style={{
                                display: 'flex', gap: 20, marginBottom: 24,
                                flexWrap: 'wrap', justifyContent: 'center',
                            }}>
                                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                                    <ScoreRing score={summary.overallScore} />
                                    <span className="text-sm text-muted" style={{ marginTop: 8 }}>Overall Score</span>
                                </div>

                                <div style={{
                                    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 20px',
                                    alignContent: 'center',
                                }}>
                                    {[
                                        { label: 'Critical', count: summary.critical, color: '#ef4444', f: 'critical' as const },
                                        { label: 'Weak', count: summary.weak, color: '#f97316', f: 'weak' as const },
                                        { label: 'Reused', count: summary.reused, color: '#a855f7', f: 'reused' as const },
                                        { label: 'Breached', count: summary.breached, color: '#dc2626', f: 'breached' as const },
                                    ].map(item => (
                                        <button
                                            key={item.label}
                                            onClick={() => setFilter(item.f)}
                                            style={{
                                                background: filter === item.f ? 'var(--bg-hover)' : 'var(--bg-elevated)',
                                                border: filter === item.f
                                                    ? `1px solid ${item.color}40`
                                                    : '1px solid var(--border)',
                                                borderRadius: 'var(--radius-md)',
                                                padding: '10px 16px',
                                                display: 'flex', alignItems: 'center', gap: 10,
                                                cursor: 'pointer',
                                                minWidth: 140,
                                            }}
                                        >
                                            <span style={{
                                                width: 28, height: 28, borderRadius: 8,
                                                background: `${item.color}18`,
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                fontSize: '0.85rem', fontWeight: 700,
                                                color: item.color,
                                            }}>
                                                {item.count}
                                            </span>
                                            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                                {item.label}
                                            </span>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Filter tabs */}
                            <div style={{
                                display: 'flex', gap: 4, marginBottom: 16,
                                borderBottom: '1px solid var(--border)', paddingBottom: 8,
                            }}>
                                {(['all', 'critical', 'weak', 'reused', 'breached'] as const).map(f => (
                                    <button
                                        key={f}
                                        className="btn btn-ghost"
                                        onClick={() => setFilter(f)}
                                        style={{
                                            fontSize: '0.75rem',
                                            padding: '4px 12px',
                                            borderBottom: filter === f ? '2px solid var(--accent-1)' : '2px solid transparent',
                                            borderRadius: 0,
                                            color: filter === f ? 'var(--text-primary)' : 'var(--text-secondary)',
                                        }}
                                    >
                                        {f === 'all' ? `All (${results.length})` : `${f.charAt(0).toUpperCase() + f.slice(1)} (${
                                            f === 'critical' ? summary.critical :
                                            f === 'weak' ? summary.weak + summary.critical :
                                            f === 'reused' ? summary.reused :
                                            summary.breached
                                        })`}
                                    </button>
                                ))}
                            </div>

                            {/* Results list */}
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                {filtered.length === 0 ? (
                                    <div style={{
                                        textAlign: 'center', padding: '40px 0',
                                        color: 'var(--text-muted)',
                                    }}>
                                        <ShieldCheck size={32} style={{ marginBottom: 8, color: 'var(--color-success)' }} />
                                        <p>No issues found in this category!</p>
                                    </div>
                                ) : filtered.map(r => (
                                    <button
                                        key={r.id}
                                        onClick={() => { onSelectEntry(r.id); onClose(); }}
                                        style={{
                                            background: 'var(--bg-elevated)',
                                            border: r.isBreached
                                                ? '1px solid rgba(239,68,68,0.3)'
                                                : '1px solid var(--border)',
                                            borderRadius: 'var(--radius-md)',
                                            padding: '12px 16px',
                                            display: 'flex', alignItems: 'center', gap: 12,
                                            cursor: 'pointer',
                                            textAlign: 'left',
                                            width: '100%',
                                            transition: 'var(--transition)',
                                        }}
                                        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
                                        onMouseLeave={e => (e.currentTarget.style.background = 'var(--bg-elevated)')}
                                    >
                                        {/* Strength indicator */}
                                        <div style={{
                                            width: 8, height: 8, borderRadius: '50%',
                                            background: strengthColors[r.strength],
                                            flexShrink: 0,
                                        }} />

                                        {/* Title & URL */}
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{
                                                fontWeight: 500, fontSize: '0.875rem',
                                                color: 'var(--text-primary)',
                                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                            }}>
                                                {r.title}
                                            </div>
                                            {r.url && (
                                                <div className="text-xs text-muted" style={{
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                }}>
                                                    {r.url}
                                                </div>
                                            )}
                                        </div>

                                        {/* Badges */}
                                        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                                            {r.isBreached && (
                                                <span style={{
                                                    background: 'rgba(239,68,68,0.15)',
                                                    color: '#ef4444',
                                                    padding: '2px 8px',
                                                    borderRadius: 4,
                                                    fontSize: '0.65rem',
                                                    fontWeight: 600,
                                                }}>
                                                    BREACHED
                                                </span>
                                            )}
                                            {r.isReused && (
                                                <span style={{
                                                    background: 'rgba(168,85,247,0.15)',
                                                    color: '#a855f7',
                                                    padding: '2px 8px',
                                                    borderRadius: 4,
                                                    fontSize: '0.65rem',
                                                    fontWeight: 600,
                                                }}>
                                                    REUSED
                                                </span>
                                            )}
                                        </div>

                                        {/* Strength */}
                                        <div style={{
                                            display: 'flex', flexDirection: 'column',
                                            alignItems: 'flex-end', gap: 4, flexShrink: 0,
                                        }}>
                                            <span style={{
                                                fontSize: '0.65rem', fontWeight: 600,
                                                color: strengthColors[r.strength],
                                            }}>
                                                {strengthLabels[r.strength]}
                                            </span>
                                            <StrengthBar score={r.strengthScore} />
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}
