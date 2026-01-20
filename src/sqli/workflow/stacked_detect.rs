//! Stacked Queries Detection Workflow
//!
//! Advanced detection and capability assessment for stacked queries.

use crate::http::client::HttpClient;
use crate::sqli::inference::stacked::{detect_capabilities, StackedCapabilities};
use crate::sqli::inference::time::{measure_baseline, measure_injected, LatencyProfile};
use crate::sqli::workflow::{WorkflowConfig, WorkflowResult};
use crate::sqli::{DatabaseType, SqliResult, SqliTechnique};
use url::Url;

/// Full stacked queries detection workflow
pub async fn run_workflow(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    config: &WorkflowConfig,
) -> anyhow::Result<WorkflowResult> {
    let mut result = WorkflowResult::new("Stacked Queries Detection");

    tracing::info!("[WORKFLOW] Starting stacked queries detection");
    result.add_step("Started stacked queries workflow");

    // Step 1: Baseline measurement
    let baseline = measure_baseline(client, base_url, 4).await?;
    result.add_step(&format!("Baseline measured: {:.0}ms mean", baseline.mean));

    // Step 2: Test each database type
    let db_types = if let Some(db) = config.db_hint {
        vec![db]
    } else {
        vec![
            DatabaseType::MySQL,
            DatabaseType::PostgreSQL,
            DatabaseType::MSSQL,
        ]
    };

    for db_type in db_types {
        if config.verbose {
            tracing::info!("[WORKFLOW] Testing {} stacked queries", db_type);
        }

        let stacked_result = test_stacked_for_db(
            client,
            base_url,
            param,
            db_type,
            &baseline,
        ).await?;

        if let Some(finding) = stacked_result {
            result.add_step(&format!("Stacked queries confirmed for {}", db_type));

            // Step 3: Detect capabilities
            if config.verbose {
                tracing::info!("[WORKFLOW] Detecting {} capabilities", db_type);
            }

            let caps = detect_capabilities(client, base_url, param, db_type).await?;
            result.add_step(&format!(
                "Capabilities detected: risk level {}",
                caps.risk_level()
            ));

            let enriched_finding = enrich_finding(finding, &caps);
            result.add_finding(enriched_finding);

            if config.stop_on_first {
                break;
            }
        }
    }

    result.complete();
    tracing::info!(
        "[WORKFLOW] Stacked queries workflow complete. Findings: {}",
        result.findings.len()
    );

    Ok(result)
}

/// Test stacked queries for a specific database type
async fn test_stacked_for_db(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
    baseline: &LatencyProfile,
) -> anyhow::Result<Option<SqliResult>> {
    let delay = 2u64;

    let payload = match db_type {
        DatabaseType::MySQL => format!("'; SELECT SLEEP({});-- ", delay),
        DatabaseType::PostgreSQL => format!("'; SELECT pg_sleep({});-- ", delay),
        DatabaseType::MSSQL => format!("'; WAITFOR DELAY '0:0:{}';-- ", delay),
        _ => return Ok(None),
    };

    let injected = measure_injected(client, base_url, param, &payload, 4).await?;

    let delta = injected.mean - baseline.mean;
    let expected_delay_ms = (delay * 1000) as f64;
    let delay_ratio = delta / expected_delay_ms;

    // If delay is close to expected (0.5x to 2x)
    if delay_ratio > 0.5 && delay_ratio < 2.0 {
        let noise = (baseline.variance + injected.variance).sqrt();
        let signal_ratio = if noise > 0.0 { delta / noise } else { 0.0 };

        if signal_ratio >= 2.0 {
            let confidence = if signal_ratio >= 3.0 {
                0.95
            } else if delay_ratio > 0.8 && delay_ratio < 1.2 {
                0.90
            } else {
                0.80
            };

            return Ok(Some(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::StackedQueries,
                confidence,
                db_type: Some(db_type),
                details: format!(
                    "Stacked queries detected. Delay: {:.0}ms (expected: {}ms). Signal ratio: {:.2}",
                    delta, expected_delay_ms, signal_ratio
                ),
            }));
        }
    }

    Ok(None)
}

/// Enrich finding with capability information
fn enrich_finding(mut finding: SqliResult, caps: &StackedCapabilities) -> SqliResult {
    let risk = caps.risk_level();
    let cap_summary = format!(
        "\nCapabilities: SELECT={} INSERT={} UPDATE={} DELETE={}\nRisk: {}",
        caps.select, caps.insert, caps.update, caps.delete, risk
    );

    finding.details.push_str(&cap_summary);

    // Increase confidence if dangerous operations possible
    if caps.is_dangerous() {
        finding.confidence = (finding.confidence + 0.05).min(1.0);
    }

    finding
}

/// Quick stacked queries check (faster, less accurate)
pub async fn quick_check(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
) -> anyhow::Result<bool> {
    let baseline = measure_baseline(client, base_url, 2).await?;

    // Try MySQL first (most common)
    let payload = "'; SELECT SLEEP(2);-- ";
    let injected = measure_injected(client, base_url, param, payload, 2).await?;

    let delta = injected.mean - baseline.mean;

    // Quick check: did we get approximately 2000ms delay?
    Ok(delta > 1500.0 && delta < 3000.0)
}

