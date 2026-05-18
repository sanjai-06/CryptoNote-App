// src-ui/src/lib/passwordHealth.ts
// Password strength scoring, reuse detection, and breach checking via HIBP k-anonymity API

import type { VaultEntry } from '../types/vault';

// ─── Types ──────────────────────────────────────────────────────────────────

export type StrengthLevel = 'critical' | 'weak' | 'fair' | 'strong' | 'excellent';

export interface PasswordHealthResult {
    id: string;
    title: string;
    url?: string;
    strength: StrengthLevel;
    strengthScore: number;      // 0-100
    issues: string[];
    isReused: boolean;
    reusedWith: string[];       // titles of other entries sharing this password
    isBreached: boolean;
    breachCount: number;        // number of times seen in breaches
}

export interface HealthSummary {
    total: number;
    critical: number;
    weak: number;
    fair: number;
    strong: number;
    excellent: number;
    reused: number;
    breached: number;
    overallScore: number;       // 0-100
}

// ─── Password Strength ─────────────────────────────────────────────────────

const COMMON_PASSWORDS = new Set([
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', 'login', 'princess', 'letmein', 'welcome', 'shadow', 'admin',
    'passw0rd', 'password1', '123456789', '1234567890', 'iloveyou', 'sunshine',
    'trustno1', 'batman', 'football', 'baseball', 'soccer', 'charlie',
]);

export function scorePassword(password: string): { score: number; level: StrengthLevel; issues: string[] } {
    if (!password) return { score: 0, level: 'critical', issues: ['Empty password'] };

    const issues: string[] = [];
    let score = 0;

    // Length scoring (max 30 pts)
    if (password.length >= 16) score += 30;
    else if (password.length >= 12) score += 22;
    else if (password.length >= 8) score += 14;
    else if (password.length >= 6) score += 6;
    else issues.push('Too short (less than 6 characters)');

    // Character diversity (max 30 pts)
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);
    const charTypes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

    score += charTypes * 7.5;
    if (charTypes < 3) issues.push('Low character variety');
    if (!hasUpper) issues.push('No uppercase letters');
    if (!hasDigit && !hasSymbol) issues.push('No numbers or symbols');

    // Entropy estimation (max 25 pts)
    const charsetSize =
        (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSymbol ? 33 : 0);
    const entropy = password.length * Math.log2(Math.max(charsetSize, 1));
    if (entropy >= 80) score += 25;
    else if (entropy >= 60) score += 18;
    else if (entropy >= 40) score += 12;
    else if (entropy >= 28) score += 6;
    else issues.push('Low entropy');

    // Pattern penalties (max -15 pts)
    if (/^(.)\1+$/.test(password)) {
        score -= 15;
        issues.push('Repeated single character');
    }
    if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde|def)/i.test(password)) {
        score -= 10;
        issues.push('Sequential pattern detected');
    }
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
        score -= 15;
        issues.push('Commonly used password');
    }

    // Uniqueness bonus (max 15 pts)
    const uniqueChars = new Set(password).size;
    const uniqueRatio = uniqueChars / password.length;
    score += Math.round(uniqueRatio * 15);

    score = Math.max(0, Math.min(100, Math.round(score)));

    let level: StrengthLevel;
    if (score >= 85) level = 'excellent';
    else if (score >= 65) level = 'strong';
    else if (score >= 45) level = 'fair';
    else if (score >= 25) level = 'weak';
    else level = 'critical';

    return { score, level, issues };
}

// ─── Reuse Detection ────────────────────────────────────────────────────────

function detectReuse(entries: VaultEntry[]): Map<string, string[]> {
    const passwordMap = new Map<string, string[]>();

    for (const entry of entries) {
        if (!entry.password) continue;
        const existing = passwordMap.get(entry.password) || [];
        existing.push(entry.title);
        passwordMap.set(entry.password, existing);
    }

    return passwordMap;
}

// ─── HIBP Breach Check (k-anonymity) ────────────────────────────────────────

async function sha1(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

export async function checkBreach(password: string): Promise<number> {
    try {
        const hash = await sha1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' },
        });

        if (!response.ok) return 0;

        const text = await response.text();
        const lines = text.split('\n');

        for (const line of lines) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix.trim() === suffix) {
                return parseInt(count.trim(), 10);
            }
        }
        return 0;
    } catch {
        return 0; // Network error — fail open (don't block the UI)
    }
}

// ─── Full Health Analysis ───────────────────────────────────────────────────

export async function analyzeVaultHealth(
    entries: VaultEntry[],
    onProgress?: (current: number, total: number) => void
): Promise<{ results: PasswordHealthResult[]; summary: HealthSummary }> {
    const reuseMap = detectReuse(entries);
    const results: PasswordHealthResult[] = [];

    for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        onProgress?.(i + 1, entries.length);

        const { score, level, issues } = scorePassword(entry.password);

        // Reuse
        const reusedEntries = reuseMap.get(entry.password) || [];
        const isReused = reusedEntries.length > 1;
        const reusedWith = reusedEntries.filter(t => t !== entry.title);

        // Breach check
        const breachCount = await checkBreach(entry.password);
        const isBreached = breachCount > 0;
        if (isBreached) issues.unshift(`Found in ${breachCount.toLocaleString()} data breaches`);
        if (isReused) issues.unshift(`Reused with: ${reusedWith.join(', ')}`);

        results.push({
            id: entry.id,
            title: entry.title,
            url: entry.url,
            strength: level,
            strengthScore: score,
            issues,
            isReused,
            reusedWith,
            isBreached,
            breachCount,
        });
    }

    // Summary
    const summary: HealthSummary = {
        total: results.length,
        critical: results.filter(r => r.strength === 'critical').length,
        weak: results.filter(r => r.strength === 'weak').length,
        fair: results.filter(r => r.strength === 'fair').length,
        strong: results.filter(r => r.strength === 'strong').length,
        excellent: results.filter(r => r.strength === 'excellent').length,
        reused: results.filter(r => r.isReused).length,
        breached: results.filter(r => r.isBreached).length,
        overallScore: results.length > 0
            ? Math.round(results.reduce((sum, r) => sum + r.strengthScore, 0) / results.length)
            : 100,
    };

    return { results, summary };
}
