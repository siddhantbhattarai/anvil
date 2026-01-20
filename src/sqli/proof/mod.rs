//! SQL Injection Proof Module
//!
//! Safe exploitation for enterprise environments.
//! Extracts metadata without touching user data.

pub mod metadata;
pub mod capabilities;

use crate::sqli::DatabaseType;

/// Database metadata extracted safely
#[derive(Debug, Clone, Default)]
pub struct DatabaseMetadata {
    pub db_type: Option<DatabaseType>,
    pub version: Option<String>,
    pub current_user: Option<String>,
    pub current_database: Option<String>,
    pub hostname: Option<String>,
    pub is_dba: Option<bool>,
}

impl std::fmt::Display for DatabaseMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Database Metadata:")?;
        if let Some(v) = &self.db_type {
            writeln!(f, "  Type: {}", v)?;
        }
        if let Some(v) = &self.version {
            writeln!(f, "  Version: {}", v)?;
        }
        if let Some(v) = &self.current_user {
            writeln!(f, "  User: {}", v)?;
        }
        if let Some(v) = &self.current_database {
            writeln!(f, "  Database: {}", v)?;
        }
        if let Some(v) = &self.hostname {
            writeln!(f, "  Hostname: {}", v)?;
        }
        if let Some(v) = &self.is_dba {
            writeln!(f, "  Is DBA: {}", v)?;
        }
        Ok(())
    }
}

/// Database capabilities detected
#[derive(Debug, Clone, Default)]
pub struct DatabaseCapabilities {
    pub stacked_queries: bool,
    pub union_select: bool,
    pub file_read: bool,
    pub file_write: bool,
    pub command_exec: bool,
    pub dns_exfil: bool,
    pub outbound_http: bool,
}

impl DatabaseCapabilities {
    /// Get overall risk level
    pub fn risk_level(&self) -> RiskLevel {
        if self.command_exec {
            RiskLevel::Critical
        } else if self.file_write {
            RiskLevel::Critical
        } else if self.file_read || self.stacked_queries {
            RiskLevel::High
        } else if self.union_select || self.dns_exfil {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Generate risk assessment
    pub fn assessment(&self) -> String {
        let mut risks = Vec::new();

        if self.command_exec {
            risks.push("CRITICAL: Command execution possible - full system compromise");
        }
        if self.file_write {
            risks.push("CRITICAL: File write possible - webshell upload risk");
        }
        if self.file_read {
            risks.push("HIGH: File read possible - credential/config theft");
        }
        if self.stacked_queries {
            risks.push("HIGH: Stacked queries - INSERT/UPDATE/DELETE possible");
        }
        if self.dns_exfil {
            risks.push("MEDIUM: DNS exfiltration - data theft via DNS");
        }
        if self.outbound_http {
            risks.push("MEDIUM: Outbound HTTP - SSRF possible");
        }
        if self.union_select {
            risks.push("MEDIUM: UNION SELECT - data extraction possible");
        }

        if risks.is_empty() {
            "LOW: Basic SQL injection with limited capabilities".to_string()
        } else {
            risks.join("\n")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
        }
    }
}

