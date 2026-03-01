// CryptoNote – Local AI Security Engine
// src-tauri/src/ai/mod.rs
//
// Runs 100% OFFLINE. Never sends data to a server.
// Does NOT analyze vault contents.
//
// Implements:
//   1. AnomalyDetector – behavioral heuristics for unlock events
//   2. PhishingDetector – domain-level phishing analysis for autofill

use anyhow::Result;
use chrono::{Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

// ─── Anomaly Detection ────────────────────────────────────────────────────────

/// An unlock event recorded for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockEvent {
    pub timestamp: i64,
    pub success: bool,
    pub hour_of_day: u32,
    pub day_of_week: u32,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    RapidFailedAttempts,
    UnusualUnlockTime,
    SuspiciousExportBehavior,
    NewDeviceUnlock,
    MultipleDeviceAccess,
    HighRiskScore,
}

/// Result of anomaly analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub anomalies: Vec<AnomalyType>,
    pub risk_score: f32,    // 0.0 = clean, 1.0 = max risk
    pub should_lock: bool,
    pub should_alert: bool,
    pub message: String,
}

/// Window of recent events for behavioral analysis.
const EVENT_WINDOW: usize = 50;
/// Number of failed attempts in 5 minutes to trigger alert
const RAPID_FAIL_THRESHOLD: usize = 5;
const RAPID_FAIL_WINDOW_SECS: i64 = 300;

pub struct AnomalyDetector {
    events: Mutex<VecDeque<UnlockEvent>>,
    known_device_ids: Mutex<Vec<String>>,
    export_timestamps: Mutex<Vec<i64>>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(EVENT_WINDOW)),
            known_device_ids: Mutex::new(Vec::new()),
            export_timestamps: Mutex::new(Vec::new()),
        }
    }

    /// Record an unlock attempt (success or failure) and analyse for anomalies.
    pub fn record_unlock(&self, success: bool) -> AnomalyResult {
        let now = Utc::now();
        let event = UnlockEvent {
            timestamp: now.timestamp(),
            success,
            hour_of_day: now.hour(),
            day_of_week: now.weekday().number_from_monday(),
        };

        let mut events = self.events.lock().unwrap();
        events.push_back(event.clone());
        if events.len() > EVENT_WINDOW {
            events.pop_front();
        }

        self.analyze_events(&events)
    }

    /// Record an export event.
    pub fn record_export(&self) -> AnomalyResult {
        let now = Utc::now().timestamp();
        let mut exports = self.export_timestamps.lock().unwrap();
        exports.push(now);
        // Keep only last 24h
        exports.retain(|&t| now - t < 86400);

        let events = self.events.lock().unwrap();
        let mut result = self.analyze_events(&events);

        // Check for suspicious export frequency (>3 exports in 1 hour)
        let recent_exports = exports.iter().filter(|&&t| now - t < 3600).count();
        if recent_exports >= 3 {
            result.anomalies.push(AnomalyType::SuspiciousExportBehavior);
            result.risk_score = (result.risk_score + 0.5).min(1.0);
            result.should_alert = true;
            result.message = format!(
                "Suspicious: {} vault exports in the last hour. Verify this is intentional.",
                recent_exports
            );
        }
        result
    }

    /// Register a new device – flags if it's unknown.
    pub fn register_device(&self, device_id: &str) -> AnomalyResult {
        let mut known = self.known_device_ids.lock().unwrap();
        let is_new = !known.contains(&device_id.to_string());
        if is_new {
            known.push(device_id.to_string());
        }

        let events = self.events.lock().unwrap();
        let mut result = self.analyze_events(&events);

        if is_new {
            result.anomalies.push(AnomalyType::NewDeviceUnlock);
            result.risk_score = (result.risk_score + 0.4).min(1.0);
            result.should_alert = true;
            result.message = format!(
                "New device registered: {}. If you did not add this device, revoke access immediately.",
                device_id
            );
        }
        result
    }

    fn analyze_events(&self, events: &VecDeque<UnlockEvent>) -> AnomalyResult {
        let mut anomalies = Vec::new();
        let mut risk_score: f32 = 0.0;
        let now = Utc::now().timestamp();

        // ── 1. Rapid failed attempts ──────────────────────────────────────
        let recent_failures = events
            .iter()
            .filter(|e| !e.success && now - e.timestamp < RAPID_FAIL_WINDOW_SECS)
            .count();

        if recent_failures >= RAPID_FAIL_THRESHOLD {
            anomalies.push(AnomalyType::RapidFailedAttempts);
            risk_score += 0.6;
        }

        // ── 2. Unusual unlock hour (before 5am or after midnight) ─────────
        if let Some(last) = events.iter().filter(|e| e.success).last() {
            if last.hour_of_day >= 0 && last.hour_of_day < 5 {
                anomalies.push(AnomalyType::UnusualUnlockTime);
                risk_score += 0.3;
            }
        }

        // ── 3. High failure rate (>60% of recent events are failures) ─────
        let recent_events: Vec<_> = events
            .iter()
            .filter(|e| now - e.timestamp < 600)
            .collect();
        if recent_events.len() >= 5 {
            let fail_rate = recent_events.iter().filter(|e| !e.success).count() as f32
                / recent_events.len() as f32;
            if fail_rate > 0.6 {
                risk_score += 0.3;
            }
        }

        risk_score = risk_score.min(1.0);

        let should_lock = risk_score >= 0.8;
        let should_alert = risk_score >= 0.5;

        let message = if should_lock {
            "HIGH RISK: Vault auto-locked due to suspicious activity. Re-authentication required."
                .to_string()
        } else if should_alert {
            format!(
                "Security alert: {} anomalies detected (risk score: {:.0}%).",
                anomalies.len(),
                risk_score * 100.0
            )
        } else {
            String::new()
        };

        AnomalyResult {
            anomalies,
            risk_score,
            should_lock,
            should_alert,
            message,
        }
    }
}

// ─── Phishing Detection ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PhishingRisk {
    Safe,
    Suspicious,
    HighRisk,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingResult {
    pub domain: String,
    pub risk: PhishingRisk,
    pub risk_score: f32,
    pub reasons: Vec<String>,
    pub allow_autofill: bool,
}

/// Known legitimate TLDs that phishers commonly mimic.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz",
    ".click", ".link", ".live", ".online", ".site", ".work", ".loan",
];

/// High-value target keywords that phishers commonly use.
const HIGH_VALUE_BRANDS: &[&str] = &[
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "bank", "chase", "wellsfargo",
    "citibank", "barclays", "hsbc", "coinbase", "binance", "kraken",
    "blockchain", "metamask", "ledger", "trezor",
];

/// Homograph lookalike character pairs (Unicode → ASCII).
const HOMOGRAPH_PAIRS: &[(&str, &str)] = &[
    ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"), ("с", "c"),
    ("у", "y"), ("х", "x"), ("ԁ", "d"), ("ｇ", "g"), ("ｏ", "o"),
];

pub struct PhishingDetector;

impl PhishingDetector {
    pub fn new() -> Self {
        Self
    }

    /// Analyse a URL or domain before allowing autofill. Runs 100% offline.
    pub fn analyze(&self, url: &str) -> PhishingResult {
        let domain = Self::extract_domain(url);
        let mut reasons = Vec::new();
        let mut risk_score: f32 = 0.0;

        // ── 1. Suspicious TLD ─────────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS {
            if domain.ends_with(tld) {
                reasons.push(format!("Suspicious TLD: {}", tld));
                risk_score += 0.4;
            }
        }

        // ── 2. IP address as domain ───────────────────────────────────────
        if Self::is_ip_address(&domain) {
            reasons.push("Domain is a raw IP address – unusual for legitimate sites".to_string());
            risk_score += 0.5;
        }

        // ── 3. Homograph / Unicode lookalike ──────────────────────────────
        if Self::contains_homograph(&domain) {
            reasons.push("Domain contains Unicode lookalike characters (homograph attack)".to_string());
            risk_score += 0.8;
        }

        // ── 4. Brand keyword in non-brand domain (subdomain trick) ────────
        let parts: Vec<&str> = domain.split('.').collect();
        let registrable = parts.iter().rev().take(2).rev().cloned().collect::<Vec<_>>().join(".");
        for brand in HIGH_VALUE_BRANDS {
            let brand_in_subdomain = domain.contains(brand)
                && !registrable.starts_with(brand);
            if brand_in_subdomain {
                reasons.push(format!(
                    "Brand keyword '{}' used in subdomain – potential spoofing",
                    brand
                ));
                risk_score += 0.6;
            }
        }

        // ── 5. Excessive subdomains (>4 labels) ───────────────────────────
        if parts.len() > 4 {
            reasons.push(format!("Excessive subdomain depth: {} labels", parts.len()));
            risk_score += 0.2;
        }

        // ── 6. Long domain (>40 chars in registrable portion) ─────────────
        if registrable.len() > 40 {
            reasons.push("Unusually long domain name".to_string());
            risk_score += 0.2;
        }

        // ── 7. Hyphen abuse (multiple hyphens in main label) ──────────────
        if let Some(main_label) = parts.iter().rev().nth(1) {
            if main_label.matches('-').count() >= 3 {
                reasons.push("Multiple hyphens in domain – common phishing pattern".to_string());
                risk_score += 0.3;
            }
        }

        risk_score = risk_score.min(1.0);

        let risk = if risk_score >= 0.8 {
            PhishingRisk::Blocked
        } else if risk_score >= 0.5 {
            PhishingRisk::HighRisk
        } else if risk_score >= 0.25 {
            PhishingRisk::Suspicious
        } else {
            PhishingRisk::Safe
        };

        let allow_autofill = matches!(risk, PhishingRisk::Safe | PhishingRisk::Suspicious);

        PhishingResult {
            domain,
            risk,
            risk_score,
            reasons,
            allow_autofill,
        }
    }

    fn extract_domain(url: &str) -> String {
        let url = url.trim();
        // Strip scheme
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        // Strip path
        without_scheme
            .split('/')
            .next()
            .unwrap_or(without_scheme)
            .to_lowercase()
    }

    fn is_ip_address(domain: &str) -> bool {
        domain
            .split('.')
            .filter(|part| part.parse::<u8>().is_ok())
            .count()
            == 4
            && domain.split('.').count() == 4
    }

    fn contains_homograph(domain: &str) -> bool {
        // Check for non-ASCII characters in domain
        if domain.is_ascii() {
            return false;
        }
        // Check for known homograph pairs
        for (unicode_char, _ascii_char) in HOMOGRAPH_PAIRS {
            if domain.contains(*unicode_char) {
                return true;
            }
        }
        // Any non-ASCII in domain is suspicious
        !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rapid_failed_attempts() {
        let detector = AnomalyDetector::new();
        // Simulate 5 rapid failures
        for _ in 0..5 {
            detector.record_unlock(false);
        }
        let result = detector.record_unlock(false);
        assert!(result.anomalies.contains(&AnomalyType::RapidFailedAttempts));
        assert!(result.risk_score >= 0.5);
    }

    #[test]
    fn test_normal_unlock_no_anomaly() {
        let detector = AnomalyDetector::new();
        let result = detector.record_unlock(true);
        assert!(result.anomalies.is_empty());
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn test_phishing_safe_domain() {
        let detector = PhishingDetector::new();
        let result = detector.analyze("https://github.com/login");
        assert_eq!(result.risk, PhishingRisk::Safe);
        assert!(result.allow_autofill);
    }

    #[test]
    fn test_phishing_suspicious_tld() {
        let detector = PhishingDetector::new();
        let result = detector.analyze("http://login.tk");
        assert!(result.risk_score > 0.0);
        assert!(!matches!(result.risk, PhishingRisk::Safe));
    }

    #[test]
    fn test_phishing_brand_subdomain() {
        let detector = PhishingDetector::new();
        let result = detector.analyze("https://paypal.secure-login.xyz/auth");
        assert!(result.risk_score >= 0.5);
    }

    #[test]
    fn test_phishing_ip_address() {
        let detector = PhishingDetector::new();
        let result = detector.analyze("http://192.168.1.100/login");
        assert!(result.reasons.iter().any(|r| r.contains("IP address")));
        assert!(result.risk_score >= 0.4);
    }

    #[test]
    fn test_suspicious_export() {
        let detector = AnomalyDetector::new();
        // 3 exports in quick succession
        detector.record_export();
        detector.record_export();
        let result = detector.record_export();
        assert!(result.anomalies.contains(&AnomalyType::SuspiciousExportBehavior));
    }

    #[test]
    fn test_new_device_detection() {
        let detector = AnomalyDetector::new();
        let result = detector.register_device("device-abc-123");
        assert!(result.anomalies.contains(&AnomalyType::NewDeviceUnlock));
        // Second time same device – not flagged
        let result2 = detector.register_device("device-abc-123");
        assert!(!result2.anomalies.contains(&AnomalyType::NewDeviceUnlock));
    }
}
