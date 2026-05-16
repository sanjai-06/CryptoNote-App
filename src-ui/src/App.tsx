// src-ui/src/App.tsx
// Root component: handles routing and auto-lock polling

import { useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import { SecurityAlert } from './components/SecurityAlert';
import { UnlockPage } from './pages/Unlock';
import { SetupPage } from './pages/Setup';
import { VaultPage } from './pages/Vault';
import { SettingsPage } from './pages/Settings';
import { useVaultStore } from './store/vaultStore';
import { checkAutoLock, recordActivity, setAutoLockTimeout } from './hooks/useVault';

import { listen } from '@tauri-apps/api/event';

function AutoLockWatcher() {
    const { isLocked, setLocked, autoLockTimeout } = useVaultStore();
    const navigate = useNavigate();

    useEffect(() => {
        // Sync saved timeout setting to Rust backend on load
        setAutoLockTimeout(autoLockTimeout).catch(() => {});
        
        // Listen for "vault-locked" events from Rust (e.g. from System Tray)
        const unlistenPromise = listen('vault-locked', () => {
            setLocked(true);
            navigate('/unlock');
        });

        if (isLocked) return () => {
            unlistenPromise.then(f => f());
        };

        // Poll for auto-lock every 30 seconds
        const interval = setInterval(async () => {
            try {
                const shouldLock = await checkAutoLock();
                if (shouldLock) {
                    setLocked(true);
                    navigate('/unlock');
                }
            } catch {
                // Ignore errors
            }
        }, 30_000);

        // Record activity on any user interaction
        const onActivity = () => recordActivity().catch(() => { });
        const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
        events.forEach((ev) => window.addEventListener(ev, onActivity, { passive: true }));

        return () => {
            clearInterval(interval);
            events.forEach((ev) => window.removeEventListener(ev, onActivity));
            unlistenPromise.then(f => f());
        };
    }, [isLocked, setLocked, navigate, autoLockTimeout]);

    return null;
}

function ThemeWatcher() {
    const { theme } = useVaultStore();

    useEffect(() => {
        function applyTheme() {
            let activeTheme = theme;
            if (activeTheme === 'system') {
                activeTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
            }
            if (activeTheme === 'light') {
                document.documentElement.setAttribute('data-theme', 'light');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        }

        applyTheme();

        if (theme === 'system') {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
            mediaQuery.addEventListener('change', applyTheme);
            return () => mediaQuery.removeEventListener('change', applyTheme);
        }
    }, [theme]);

    return null;
}

function AppRoutes() {
    const { isLocked, anomaly, dismissAnomaly, setLocked } = useVaultStore();

    return (
        <>
            <AutoLockWatcher />
            {anomaly?.should_alert && (
                <SecurityAlert
                    result={anomaly}
                    onDismiss={dismissAnomaly}
                    onLock={() => {
                        setLocked(true);
                        dismissAnomaly();
                    }}
                />
            )}
            <Routes>
                <Route path='/setup' element={<SetupPage />} />
                <Route path='/unlock' element={<UnlockPage />} />
                <Route
                    path='/vault'
                    element={isLocked ? <Navigate to='/unlock' replace /> : <VaultPage />}
                />
                <Route
                    path='/settings'
                    element={isLocked ? <Navigate to='/unlock' replace /> : <SettingsPage />}
                />
                <Route path='*' element={<Navigate to='/unlock' replace />} />
            </Routes>
        </>
    );
}

export default function App() {
    return (
        <BrowserRouter>
            <ThemeWatcher />
            <AutoLockWatcher />
            <AppRoutes />
        </BrowserRouter>
    );
}
