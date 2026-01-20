//! SQL Injection Inference Module
//!
//! This module contains detection techniques for various SQL injection types.

pub mod boolean;
pub mod time;
pub mod stacked;
pub mod oob;

use crate::sqli::DatabaseType;

/// Error patterns that indicate SQL injection
pub const ERROR_PATTERNS: &[(&str, DatabaseType)] = &[
    // MySQL errors
    ("You have an error in your SQL syntax", DatabaseType::MySQL),
    ("mysql_fetch", DatabaseType::MySQL),
    ("mysql_num_rows", DatabaseType::MySQL),
    ("MySQL server version", DatabaseType::MySQL),
    ("mysqli_", DatabaseType::MySQL),
    ("Warning: mysql_", DatabaseType::MySQL),
    
    // PostgreSQL errors
    ("pg_query", DatabaseType::PostgreSQL),
    ("pg_exec", DatabaseType::PostgreSQL),
    ("PostgreSQL query failed", DatabaseType::PostgreSQL),
    ("PSQLException", DatabaseType::PostgreSQL),
    ("ERROR: syntax error at or near", DatabaseType::PostgreSQL),
    
    // MSSQL errors
    ("Microsoft SQL Server", DatabaseType::MSSQL),
    ("Unclosed quotation mark", DatabaseType::MSSQL),
    ("ODBC SQL Server Driver", DatabaseType::MSSQL),
    ("SQLServer JDBC Driver", DatabaseType::MSSQL),
    ("mssql_query", DatabaseType::MSSQL),
    ("[SQL Server]", DatabaseType::MSSQL),
    
    // Oracle errors
    ("ORA-", DatabaseType::Oracle),
    ("Oracle error", DatabaseType::Oracle),
    ("Oracle.*Driver", DatabaseType::Oracle),
    ("quoted string not properly terminated", DatabaseType::Oracle),
    
    // SQLite errors
    ("SQLite/JDBCDriver", DatabaseType::SQLite),
    ("SQLite.Exception", DatabaseType::SQLite),
    ("sqlite3.OperationalError", DatabaseType::SQLite),
    ("SQLITE_ERROR", DatabaseType::SQLite),
    
    // Generic errors
    ("SQL syntax", DatabaseType::Unknown),
    ("syntax error", DatabaseType::Unknown),
    ("Unclosed quotation", DatabaseType::Unknown),
    ("Invalid query", DatabaseType::Unknown),
];

/// Detect database type from error message
pub fn detect_db_from_error(body: &str) -> Option<DatabaseType> {
    let body_lower = body.to_lowercase();
    
    for (pattern, db_type) in ERROR_PATTERNS {
        if body_lower.contains(&pattern.to_lowercase()) {
            return Some(*db_type);
        }
    }
    
    None
}

/// Check if response contains SQL error patterns
pub fn contains_sql_error(body: &str) -> bool {
    detect_db_from_error(body).is_some()
}

/// Calculate similarity between two response bodies
pub fn body_similarity(a: &str, b: &str) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    
    let len_a = a.len() as f32;
    let len_b = b.len() as f32;
    let len_diff = (len_a - len_b).abs();
    
    // Simple length-based similarity
    let length_sim = 1.0 - (len_diff / len_a.max(len_b));
    
    // Content similarity using common prefix/suffix
    let common_prefix = a.chars()
        .zip(b.chars())
        .take_while(|(ca, cb)| ca == cb)
        .count() as f32;
    
    let prefix_sim = common_prefix / len_a.max(len_b);
    
    (length_sim * 0.5) + (prefix_sim * 0.5)
}

