//! Scan profiles for different testing scenarios

use crate::core::capability::Capability;
use std::collections::HashSet;

#[derive(Debug)]
pub struct ScanProfile {
    pub enabled: HashSet<Capability>,
}

impl ScanProfile {
    /// Create an empty profile (no capabilities enabled)
    pub fn empty() -> Self {
        Self {
            enabled: HashSet::new(),
        }
    }

    /// Create a profile with all capabilities enabled (except exploitation)
    pub fn all() -> Self {
        use Capability::*;
        Self {
            enabled: [
                Crawl,
                Fingerprint,
                SqlInjection,
                TimeSqlInjection,
                StackedSqlInjection,
                // Note: OOB requires callback, so not enabled by default
                // SecondOrderSqli requires specific workflow
                Xss,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Create a minimal profile (crawl + fingerprint only)
    pub fn minimal() -> Self {
        use Capability::*;
        Self {
            enabled: [Crawl, Fingerprint].into_iter().collect(),
        }
    }

    /// Create a SQLi-focused profile
    pub fn sqli_all() -> Self {
        use Capability::*;
        Self {
            enabled: [
                Crawl,
                Fingerprint,
                SqlInjection,
                TimeSqlInjection,
                StackedSqlInjection,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Create an exploitation profile (includes proof mode)
    pub fn exploit() -> Self {
        let mut profile = Self::sqli_all();
        profile.enable(Capability::ProofMode);
        profile.enable(Capability::ExploitMode);
        profile
    }

    /// Enable a specific capability
    pub fn enable(&mut self, cap: Capability) {
        self.enabled.insert(cap);
    }

    /// Disable a specific capability
    pub fn disable(&mut self, cap: Capability) {
        self.enabled.remove(&cap);
    }

    /// Check if a capability is enabled
    pub fn has(&self, cap: Capability) -> bool {
        self.enabled.contains(&cap)
    }

    /// Check if any SQLi capability is enabled
    pub fn has_sqli(&self) -> bool {
        self.enabled.iter().any(|c| c.is_sqli())
    }

    /// Check if any exploitation capability is enabled
    pub fn has_exploit(&self) -> bool {
        self.enabled.iter().any(|c| c.is_exploit())
    }
}
