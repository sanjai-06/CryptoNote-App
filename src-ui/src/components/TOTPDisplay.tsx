import { useEffect, useState } from 'react';
import * as OTPAuth from 'otpauth';
import { Copy, Check } from 'lucide-react';

interface Props {
    secret: string;
}

export function TOTPDisplay({ secret }: Props) {
    const [code, setCode] = useState('');
    const [progress, setProgress] = useState(100);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        let totp: OTPAuth.TOTP | null = null;
        try {
            // Remove spaces from secret just in case
            const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
            totp = new OTPAuth.TOTP({
                algorithm: 'SHA1',
                digits: 6,
                period: 30,
                secret: OTPAuth.Secret.fromBase32(cleanSecret),
            });
        } catch (e) {
            console.error('Invalid TOTP secret', e);
            setCode('INVALID');
            return;
        }

        const update = () => {
            if (!totp) return;
            const token = totp.generate();
            setCode(token);
            
            // Calculate remaining seconds
            const seconds = Math.floor(Date.now() / 1000);
            const remaining = 30 - (seconds % 30);
            setProgress((remaining / 30) * 100);
        };

        update();
        const interval = setInterval(update, 1000);
        return () => clearInterval(interval);
    }, [secret]);

    function copyCode() {
        if (code === 'INVALID') return;
        navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
    }

    if (code === 'INVALID') {
        return <div className="text-danger text-xs mt-1">Invalid TOTP Secret</div>;
    }

    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-md)', padding: '8px 12px', marginTop: 6
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {/* Circular progress */}
                <div style={{ position: 'relative', width: 20, height: 20, flexShrink: 0 }}>
                    <svg width="20" height="20" viewBox="0 0 24 24" style={{ transform: 'rotate(-90deg)' }}>
                        <circle cx="12" cy="12" r="10" fill="none" stroke="var(--border-color)" strokeWidth="3" />
                        <circle
                            cx="12" cy="12" r="10" fill="none"
                            stroke={progress < 15 ? 'var(--color-danger)' : 'var(--accent-1)'}
                            strokeWidth="3"
                            strokeDasharray="62.83" // 2 * PI * r
                            strokeDashoffset={62.83 - (progress / 100) * 62.83}
                            style={{ transition: 'stroke-dashoffset 1s linear, stroke 0.3s ease' }}
                        />
                    </svg>
                </div>
                <div style={{ fontSize: '1.5rem', fontWeight: 600, letterSpacing: '2px', fontFamily: 'monospace' }}>
                    {code.slice(0, 3)} {code.slice(3)}
                </div>
            </div>
            <button className="btn btn-ghost btn-icon" onClick={copyCode} title="Copy code">
                {copied ? <Check size={16} color="var(--color-success)" /> : <Copy size={16} />}
            </button>
        </div>
    );
}
