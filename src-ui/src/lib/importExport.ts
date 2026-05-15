import { vaultListEntries, vaultGetEntry, vaultAddEntry, aiRecordExport, vaultUpdateEntry } from '../hooks/useVault';
import { v4 as uuidv4 } from 'uuid';
import type { VaultEntry } from '../types/vault';

import { isTauri } from './env';

export async function exportVault(format: 'json' | 'csv'): Promise<void> {
    // 1. Record the export for anomaly detection
    await aiRecordExport().catch(() => {});

    // 2. Fetch all decrypted entries
    const list = await vaultListEntries();
    const entries: VaultEntry[] = [];
    
    for (const item of list) {
        try {
            const entry = await vaultGetEntry(item.id);
            entries.push(entry);
        } catch (e) {
            console.error(`Failed to export entry ${item.id}`, e);
        }
    }

    let payload = '';
    let defaultFilename = '';
    let mimeType = '';
    let ext = '';
    let filterName = '';

    if (format === 'csv') {
        const csvData = entries.map(e => ({
            name: e.title,
            url: e.url,
            username: e.username,
            password: e.password,
            note: e.notes,
            totp: e.totp_secret
        }));
        payload = Papa.unparse(csvData);
        ext = 'csv';
        filterName = 'CSV';
        mimeType = 'text/csv';
    } else {
        payload = JSON.stringify({
            source: 'CryptoNote',
            version: 1,
            exported_at: Math.floor(Date.now() / 1000),
            entries
        }, null, 2);
        ext = 'json';
        filterName = 'JSON';
        mimeType = 'application/json';
    }

    defaultFilename = `cryptonote_export_${new Date().toISOString().split('T')[0]}.${ext}`;

    if (isTauri()) {
        const { save } = await import('@tauri-apps/plugin-dialog');
        const { writeTextFile } = await import('@tauri-apps/plugin-fs');
        
        const path = await save({
            filters: [{ name: filterName, extensions: [ext] }],
            defaultPath: defaultFilename
        });
        
        if (path) {
            await writeTextFile(path, payload);
        }
    } else {
        // Fallback for browser environment
        const blob = new Blob([payload], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = defaultFilename;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }
}

import Papa from 'papaparse';

export async function importVaultJson(): Promise<{ success: number; skipped: number; errors: number } | null> {
    let content = '';
    let isCsv = false;

    if (isTauri()) {
        const { open } = await import('@tauri-apps/plugin-dialog');
        const { readTextFile } = await import('@tauri-apps/plugin-fs');
        
        const selected = await open({
            multiple: false,
            filters: [{ name: 'Vault Data', extensions: ['json', 'csv'] }]
        });
        
        if (!selected) return null;
        
        // Handle path format depending on return type
        const path = typeof selected === 'string' ? selected : (selected as any).path;
        if (!path) return null;

        if (path.toLowerCase().endsWith('.csv')) {
            isCsv = true;
        }

        content = await readTextFile(path);
    } else {
        // Fallback for browser environment using a temporary input element
        content = await new Promise<string>((resolve, reject) => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.json,.csv';
            input.onchange = (e) => {
                const file = (e.target as HTMLInputElement).files?.[0];
                if (!file) return reject(new Error('No file selected'));
                if (file.name.toLowerCase().endsWith('.csv')) {
                    isCsv = true;
                }
                const reader = new FileReader();
                reader.onload = (e) => resolve((e.target?.result as string) || '');
                reader.onerror = () => reject(new Error('Failed to read file'));
                reader.readAsText(file);
            };
            input.click();
        });
    }

    let parsedEntries: any[] = [];

    if (isCsv) {
        const result = Papa.parse(content, {
            header: true,
            skipEmptyLines: true,
            transformHeader: (header) => header.trim().toLowerCase().replace(/^\uFEFF/, ''),
        });
        if (result.errors.length && !result.data.length) {
            throw new Error(`Failed to parse CSV: ${result.errors[0].message}`);
        }
        
        // Map common CSV columns (Chrome, Bitwarden, etc.) to VaultEntry
        parsedEntries = result.data.map((row: any) => ({
            title: row.name || row.title || 'Imported Entry',
            username: row.username || row.login_username || '',
            password: row.password || row.login_password || '',
            url: row.url || row.login_uri || '',
            notes: row.note || row.notes || '',
            totp_secret: row.totp || row.login_totp || '',
            tags: ['Imported']
        }));
    } else {
        const data = JSON.parse(content);
        if (!Array.isArray(data.entries)) {
            throw new Error('Invalid export format: missing entries array');
        }
        parsedEntries = data.entries;
    }

    let success = 0;
    let skipped = 0;
    let errors = 0;

    const existingItems = await vaultListEntries();
    const existingTitles = new Set(existingItems.map(i => i.title.toLowerCase()));

    for (const item of parsedEntries) {
        // Skip completely empty rows
        if (!item.title && !item.username && !item.password && !item.url) {
            skipped++;
            continue;
        }

        // Generate a unique title if empty to prevent duplicate skipping
        let finalTitle = item.title;
        if (finalTitle === 'Imported Entry') {
            finalTitle = `${finalTitle} - ${Math.random().toString(36).substring(7)}`;
        }

        if (existingTitles.has(finalTitle.toLowerCase())) {
            skipped++;
            continue;
        }

        const entry: VaultEntry = {
            id: uuidv4(),
            title: finalTitle,
            username: item.username || '',
            password: item.password || '',
            url: item.url || '',
            notes: item.notes || '',
            totp_secret: item.totp_secret || '',
            tags: Array.isArray(item.tags) ? item.tags : ['Imported'],
            created_at: Math.floor(Date.now() / 1000),
            updated_at: Math.floor(Date.now() / 1000),
            version: 1,
        };

        try {
            await vaultAddEntry(entry);
            success++;
            existingTitles.add(finalTitle.toLowerCase());
        } catch (err) {
            console.error('Failed to import entry', err);
            errors++;
        }
    }

    return { success, skipped, errors };
}
