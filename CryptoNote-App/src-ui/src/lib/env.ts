// src-ui/src/lib/env.ts
// Detect whether we're running inside Tauri or in a plain browser

export const isTauri = (): boolean => {
    return typeof window !== 'undefined' &&
        typeof (window as any).__TAURI_INTERNALS__ !== 'undefined';
};

// Base URL for the REST API when running in browser mode
// Reads from Vite env var, falls back to same origin (useful on AWS)
export const API_BASE = (() => {
    const env = (import.meta as any).env?.VITE_API_URL;
    if (env) return env.replace(/\/$/, '');
    // Same origin – the backend is behind the same load balancer
    return '';
})();
