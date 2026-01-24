//! Enumerations for SQL injection

/// Database Management System types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DBMS {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    Access,
    Unknown,
}

impl std::fmt::Display for DBMS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DBMS::MySQL => write!(f, "MySQL"),
            DBMS::PostgreSQL => write!(f, "PostgreSQL"),
            DBMS::MSSQL => write!(f, "Microsoft SQL Server"),
            DBMS::Oracle => write!(f, "Oracle"),
            DBMS::SQLite => write!(f, "SQLite"),
            DBMS::Access => write!(f, "Microsoft Access"),
            DBMS::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Payload injection location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadWhere {
    Original,   // Append to original value
    Negative,   // Replace with negative value
    Replace,    // Replace entirely
}

/// SQL injection technique types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Technique {
    Boolean,
    Error,
    Union,
    Stacked,
    Time,
    Inline,
}

impl std::fmt::Display for Technique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Technique::Boolean => write!(f, "Boolean-based blind"),
            Technique::Error => write!(f, "Error-based"),
            Technique::Union => write!(f, "UNION query"),
            Technique::Stacked => write!(f, "Stacked queries"),
            Technique::Time => write!(f, "Time-based blind"),
            Technique::Inline => write!(f, "Inline query"),
        }
    }
}
