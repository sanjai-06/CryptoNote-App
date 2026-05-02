import { vaultListEntries, vaultGetEntry, vaultAddEntry, aiRecordExport, vaultUpdateEntry } from '../hooks/useVault';
import { v4 as uuidv4 } from 'uuid';
import type { VaultEntry } from '../types/vault';

export async function exportVaultJson(): Promise<void> {
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

    // 3. Create JSON payload
    const payload = JSON.stringify({
        source: 'CryptoNote',
        version: 1,
        exported_at: Math.floor(Date.now() / 1000),
        entries
    }, null, 2);

    // 4. Trigger download
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `cryptonote_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    
    // Cleanup
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

export async function importVaultJson(file: File): Promise<{ success: number; skipped: number; errors: number }> {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const content = e.target?.result as string;
                const data = JSON.parse(content);
                
                if (!Array.isArray(data.entries)) {
                    throw new Error('Invalid export format: missing entries array');
                }

                // Try to import each entry
                let success = 0;
                let skipped = 0;
                let errors = 0;

                const existingItems = await vaultListEntries();
                const existingTitles = new Set(existingItems.map(i => i.title.toLowerCase()));

                for (const item of data.entries as any[]) {
                    if (!item.title || !item.password) {
                        skipped++;
                        continue;
                    }

                    // Check for exact duplicates (basic check)
                    if (existingTitles.has(item.title.toLowerCase())) {
                        skipped++;
                        continue;
                    }

                    const entry: VaultEntry = {
                        id: uuidv4(), // generate new ID to avoid collisions
                        title: item.title,
                        username: item.username || '',
                        password: item.password,
                        url: item.url,
                        notes: item.notes,
                        totp_secret: item.totp_secret,
                        tags: Array.isArray(item.tags) ? item.tags : [],
                        created_at: Math.floor(Date.now() / 1000),
                        updated_at: Math.floor(Date.now() / 1000),
                        version: 1,
                    };

                    try {
                        await vaultAddEntry(entry);
                        success++;
                    } catch (err) {
                        console.error('Failed to import entry', err);
                        errors++;
                    }
                }

                resolve({ success, skipped, errors });
            } catch (err) {
                reject(err);
            }
        };
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsText(file);
    });
}
