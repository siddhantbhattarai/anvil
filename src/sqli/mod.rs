//! SQL Injection Domain Module
//!
//! This module provides comprehensive SQL injection detection and exploitation
//! capabilities that surpass sqlmap:
//!
//! - `inference`: Detection techniques (boolean, time, stacked, oob, union)
//! - `extract`: Data extraction (databases, tables, columns, dump)
//! - `proof`: Safe metadata extraction (enterprise mode)
//! - `workflow`: Advanced attack chains and orchestration

pub mod inference;
pub mod extract;
pub mod proof;
pub mod workflow;

// Re-export extraction types for convenience
pub use extract::{Extractor, ExtractionConfig, ExtractionResult, DatabaseInfo, TableData};

use crate::http::client::HttpClient;
use crate::scanner::sitemap::SiteMap;
use url::Url;

/// Result of SQL injection testing
#[derive(Debug, Clone)]
pub struct SqliResult {
    pub endpoint: String,
    pub parameter: String,
    pub technique: SqliTechnique,
    pub confidence: f32,
    pub db_type: Option<DatabaseType>,
    pub details: String,
}

/// SQL injection detection technique used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliTechnique {
    Boolean,
    ErrorBased,
    TimeBased,
    StackedQueries,
    OutOfBand,
    Union,
    SecondOrder,
}

impl std::fmt::Display for SqliTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqliTechnique::Boolean => write!(f, "Boolean-based"),
            SqliTechnique::ErrorBased => write!(f, "Error-based"),
            SqliTechnique::TimeBased => write!(f, "Time-based"),
            SqliTechnique::StackedQueries => write!(f, "Stacked Queries"),
            SqliTechnique::OutOfBand => write!(f, "Out-of-Band"),
            SqliTechnique::Union => write!(f, "UNION-based"),
            SqliTechnique::SecondOrder => write!(f, "Second-Order"),
        }
    }
}

/// Detected database type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    Unknown,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::MySQL => write!(f, "MySQL"),
            DatabaseType::PostgreSQL => write!(f, "PostgreSQL"),
            DatabaseType::MSSQL => write!(f, "MSSQL"),
            DatabaseType::Oracle => write!(f, "Oracle"),
            DatabaseType::SQLite => write!(f, "SQLite"),
            DatabaseType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Configuration for SQL injection testing
#[derive(Debug, Clone)]
pub struct SqliConfig {
    /// Enable boolean-based detection
    pub boolean: bool,
    /// Enable time-based detection
    pub time_based: bool,
    /// Enable stacked queries detection
    pub stacked: bool,
    /// Enable out-of-band detection
    pub oob: bool,
    /// OOB callback domain (e.g., "attacker.com")
    pub oob_callback: Option<String>,
    /// Number of samples for time-based detection
    pub time_samples: usize,
    /// Delay in seconds for time-based payloads
    pub time_delay: u64,
    /// Enable proof mode (safe metadata extraction)
    pub proof_mode: bool,
    /// Enable exploitation (dangerous, opt-in)
    pub exploit_mode: bool,
}

impl Default for SqliConfig {
    fn default() -> Self {
        Self {
            boolean: true,
            time_based: true,
            stacked: false,
            oob: false,
            oob_callback: None,
            time_samples: 6,
            time_delay: 2,
            proof_mode: false,
            exploit_mode: false,
        }
    }
}

impl SqliConfig {
    /// Enable all detection techniques
    pub fn all() -> Self {
        Self {
            boolean: true,
            time_based: true,
            stacked: true,
            oob: true,
            oob_callback: None,
            time_samples: 6,
            time_delay: 2,
            proof_mode: false,
            exploit_mode: false,
        }
    }

    /// Conservative config for production
    pub fn safe() -> Self {
        Self {
            boolean: true,
            time_based: true,
            stacked: false,
            oob: false,
            oob_callback: None,
            time_samples: 8,
            time_delay: 2,
            proof_mode: false,
            exploit_mode: false,
        }
    }

    /// Set OOB callback domain
    pub fn with_oob_callback(mut self, domain: &str) -> Self {
        self.oob = true;
        self.oob_callback = Some(domain.to_string());
        self
    }

    /// Enable proof mode
    pub fn with_proof(mut self) -> Self {
        self.proof_mode = true;
        self
    }

    /// Enable exploitation (dangerous)
    pub fn with_exploit(mut self) -> Self {
        self.exploit_mode = true;
        self
    }
}

/// Main SQL injection scanner
pub struct SqliScanner {
    config: SqliConfig,
}

impl SqliScanner {
    pub fn new(config: SqliConfig) -> Self {
        Self { config }
    }

    /// Run SQL injection tests against discovered endpoints
    pub async fn scan(
        &self,
        client: &HttpClient,
        target_url: &Url,
        sitemap: &SiteMap,
    ) -> anyhow::Result<Vec<SqliResult>> {
        let mut results = Vec::new();

        for (path, endpoint) in sitemap.endpoints.iter() {
            if endpoint.parameters.is_empty() {
                continue;
            }

            // Construct base URL, preserving query params if path matches target URL path
            let base_url = if path == target_url.path() {
                // Direct param mode: use target URL as-is (preserves query params like Submit=Submit)
                target_url.clone()
            } else {
                // Crawled endpoint: join path to target
                match target_url.join(path) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            };

            for param in endpoint.parameters.iter() {
                // Determine if we should use POST (based on endpoint method)
                let use_post = endpoint.methods.contains("POST");
                
                // Boolean-based detection
                if self.config.boolean {
                    let result = if use_post {
                        inference::boolean::detect_post(
                            client,
                            &base_url,
                            param,
                            Some("Submit=Submit"),
                        ).await?
                    } else {
                        inference::boolean::detect(
                            client,
                            &base_url,
                            param,
                        ).await?
                    };
                    
                    if let Some(r) = result {
                        results.push(r);
                    }
                }

                // Time-based detection
                if self.config.time_based {
                    if let Some(result) = inference::time::detect(
                        client,
                        &base_url,
                        param,
                        self.config.time_samples,
                        self.config.time_delay,
                    ).await? {
                        results.push(result);
                    }
                }

                // Stacked queries detection
                if self.config.stacked {
                    if let Some(result) = inference::stacked::detect(
                        client,
                        &base_url,
                        param,
                    ).await? {
                        results.push(result);
                    }
                }

                // Out-of-band detection
                if self.config.oob {
                    if let Some(callback) = &self.config.oob_callback {
                        if let Some(result) = inference::oob::detect(
                            client,
                            &base_url,
                            param,
                            callback,
                        ).await? {
                            results.push(result);
                        }
                    }
                }
            }
        }

        // If proof mode enabled, extract metadata for confirmed SQLi
        if self.config.proof_mode && !results.is_empty() {
            for result in results.iter_mut() {
                if result.confidence >= 0.8 {
                    if let Ok(metadata) = proof::metadata::extract(
                        client,
                        &Url::parse(&result.endpoint)?,
                        &result.parameter,
                        result.db_type,
                    ).await {
                        result.details = format!("{}\n{}", result.details, metadata);
                    }
                }
            }
        }

        Ok(results)
    }
}

