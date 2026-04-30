// src-ui/src/components/SecurityAlert.tsx
// Full-screen modal triggered by AI anomaly detection

import { ShieldAlert, Lock, X } from 'lucide-react';
import type { AnomalyResult } from '../types/vault';

const anomalyLabels: Record<string, string> = {
    RapidFailedAttempts: '🔴 Rapid failed unlock attempts',
    UnusualUnlockTime: '🌙 Unusual unlock time detected',
    SuspiciousExportBehavior: '📤 Suspicious export activity',
    NewDeviceUnlock: '📱 New device accessing vault',
    HighRiskScore: '⚠️ High overall risk score',
};

interface Props {
    result: AnomalyResult;
    onDismiss: () => void;
    onLock: () => void;
}

export function SecurityAlert({ result, onDismiss, onLock }: Props) {
    const isCritical = result.should_lock;

    return (
        <div className='alert-overlay'>
            <div className='alert-modal'>
                {/* Icon */}
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
                    <div style={{
                        width: 64, height: 64, borderRadius: '50%',
                        background: isCritical ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.12)',
                        border: `2px solid ${isCritical ? 'var(--color-danger)' : 'var(--color-warning)'}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <ShieldAlert size={30} color={isCritical ? 'var(--color-danger)' : 'var(--color-warning)'} />
                    </div>
                </div>

                <h3 style={{ textAlign: 'center', marginBottom: 8, color: isCritical ? 'var(--color-danger)' : 'var(--color-warning)' }}>
                    {isCritical ? 'Security Threat Detected' : 'Security Alert'}
                </h3>

                <p style={{ textAlign: 'center', fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: 20 }}>
                    {result.message}
                </p>

                {/* Anomalies list */}
                {result.anomalies.length > 0 && (
                    <div style={{
                        background: 'var(--bg-base)', borderRadius: 'var(--radius-md)',
                        padding: '12px 16px', marginBottom: 20,
                        display: 'flex', flexDirection: 'column', gap: 8
                    }}>
                        {result.anomalies.map((a) => (
                            <div key={a} style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                                {anomalyLabels[a] ?? a}
                            </div>
                        ))}
                    </div>
                )}

                {/* Risk score */}
                <div style={{ marginBottom: 20 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        <span>Risk Score</span>
                        <span style={{ fontWeight: 700, color: isCritical ? 'var(--color-danger)' : 'var(--color-warning)' }}>
                            {Math.round(result.risk_score * 100)}%
                        </span>
                    </div>
                    <div className='strength-bar'>
                        <div className='strength-fill' style={{
                            width: `${result.risk_score * 100}%`,
                            background: isCritical ? 'var(--color-danger)' : 'var(--color-warning)',
                        }} />
                    </div>
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <button className='btn btn-danger w-full' onClick={onLock}>
                        <Lock size={15} /> Lock Vault Now
                    </button>
                    {!isCritical && (
                        <button className='btn btn-ghost w-full' onClick={onDismiss}>
                            <X size={15} /> Dismiss (I understand the risk)
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
