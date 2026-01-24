//! Database-specific SQL queries

use super::enums::DBMS;

/// Query templates for each database type
pub struct Queries {
    pub dbms: DBMS,
}

impl Queries {
    pub fn new(dbms: DBMS) -> Self {
        Self { dbms }
    }

    /// Get current database name
    pub fn current_db(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => "DATABASE()",
            DBMS::PostgreSQL => "CURRENT_DATABASE()",
            DBMS::MSSQL => "DB_NAME()",
            DBMS::Oracle => "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
            DBMS::SQLite => "'main'",
            DBMS::Access => "'MSysObjects'",
        }
    }

    /// Get current user
    pub fn current_user(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => "CURRENT_USER()",
            DBMS::PostgreSQL => "CURRENT_USER",
            DBMS::MSSQL => "SYSTEM_USER",
            DBMS::Oracle => "USER",
            DBMS::SQLite => "'admin'",
            DBMS::Access => "'admin'",
        }
    }

    /// Get database version
    pub fn version(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => "VERSION()",
            DBMS::PostgreSQL => "VERSION()",
            DBMS::MSSQL => "@@VERSION",
            DBMS::Oracle => "SELECT BANNER FROM V$VERSION WHERE ROWNUM=1",
            DBMS::SQLite => "SQLITE_VERSION()",
            DBMS::Access => "'Microsoft Access'",
        }
    }

    /// Get all database names query - uses GROUP_CONCAT to get all in one query
    pub fn databases(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                "SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c) FROM information_schema.schemata"
            },
            DBMS::PostgreSQL => {
                "SELECT string_agg(datname,'|') FROM pg_database"
            },
            DBMS::MSSQL => {
                "SELECT STUFF((SELECT '|'+name FROM master..sysdatabases FOR XML PATH('')),1,1,'')"
            },
            DBMS::Oracle => {
                "SELECT LISTAGG(owner,'|') WITHIN GROUP (ORDER BY owner) FROM (SELECT DISTINCT owner FROM all_tables)"
            },
            DBMS::SQLite => {
                "SELECT GROUP_CONCAT(name,'|') FROM pragma_database_list"
            },
            DBMS::Access => {
                "SELECT Name FROM MSysObjects WHERE Type=1"
            },
        }
    }

    /// Get tables in a database - uses GROUP_CONCAT
    pub fn tables(&self, database: &str) -> String {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!(
                    "SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema='{}'",
                    database
                )
            },
            DBMS::PostgreSQL => {
                format!(
                    "SELECT string_agg(tablename,'|') FROM pg_tables WHERE schemaname='{}'",
                    database
                )
            },
            DBMS::MSSQL => {
                format!(
                    "SELECT STUFF((SELECT '|'+name FROM {}.sys.tables FOR XML PATH('')),1,1,'')",
                    database
                )
            },
            DBMS::Oracle => {
                format!(
                    "SELECT LISTAGG(table_name,'|') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE owner='{}'",
                    database.to_uppercase()
                )
            },
            DBMS::SQLite => {
                "SELECT GROUP_CONCAT(name,'|') FROM sqlite_master WHERE type='table'".to_string()
            },
            DBMS::Access => {
                "SELECT Name FROM MSysObjects WHERE Type=1 AND Flags=0".to_string()
            },
        }
    }

    /// Get columns in a table - uses GROUP_CONCAT
    pub fn columns(&self, database: &str, table: &str) -> String {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!(
                    "SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}'",
                    database, table
                )
            },
            DBMS::PostgreSQL => {
                format!(
                    "SELECT string_agg(column_name,'|') FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}'",
                    database, table
                )
            },
            DBMS::MSSQL => {
                format!(
                    "SELECT STUFF((SELECT '|'+name FROM {}.sys.columns WHERE object_id=OBJECT_ID('{}.{}') FOR XML PATH('')),1,1,'')",
                    database, database, table
                )
            },
            DBMS::Oracle => {
                format!(
                    "SELECT LISTAGG(column_name,'|') WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE owner='{}' AND table_name='{}'",
                    database.to_uppercase(), table.to_uppercase()
                )
            },
            DBMS::SQLite => {
                format!("SELECT GROUP_CONCAT(name,'|') FROM pragma_table_info('{}')", table)
            },
            DBMS::Access => {
                format!(
                    "SELECT * FROM {} WHERE 1=0",
                    table
                )
            },
        }
    }

    /// Get row count from table
    pub fn count(&self, database: &str, table: &str) -> String {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("SELECT COUNT(*) FROM {}.{}", database, table)
            },
            DBMS::PostgreSQL => {
                format!("SELECT COUNT(*) FROM {}.{}", database, table)
            },
            DBMS::MSSQL => {
                format!("SELECT COUNT(*) FROM {}.dbo.{}", database, table)
            },
            DBMS::Oracle => {
                format!("SELECT COUNT(*) FROM {}.{}", database, table)
            },
            DBMS::SQLite => {
                format!("SELECT COUNT(*) FROM {}", table)
            },
            DBMS::Access => {
                format!("SELECT COUNT(*) FROM {}", table)
            },
        }
    }

    /// Dump table data
    pub fn dump(&self, database: &str, table: &str, columns: &[String]) -> String {
        let cols = columns.join(",");
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                format!("SELECT {} FROM {}.{}", cols, database, table)
            },
            DBMS::PostgreSQL => {
                format!("SELECT {} FROM {}.{}", cols, database, table)
            },
            DBMS::MSSQL => {
                format!("SELECT {} FROM {}.dbo.{}", cols, database, table)
            },
            DBMS::Oracle => {
                format!("SELECT {} FROM {}.{}", cols, database, table)
            },
            DBMS::SQLite => {
                format!("SELECT {} FROM {}", cols, table)
            },
            DBMS::Access => {
                format!("SELECT {} FROM {}", cols, table)
            },
        }
    }

    /// Get database users
    pub fn users(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                "SELECT DISTINCT user FROM mysql.user"
            },
            DBMS::PostgreSQL => {
                "SELECT usename FROM pg_user"
            },
            DBMS::MSSQL => {
                "SELECT name FROM master..syslogins"
            },
            DBMS::Oracle => {
                "SELECT username FROM all_users"
            },
            DBMS::SQLite => "'admin'",
            DBMS::Access => "'admin'",
        }
    }

    /// Get password hashes
    pub fn passwords(&self) -> &'static str {
        match self.dbms {
            DBMS::MySQL | DBMS::Unknown => {
                "SELECT user,password FROM mysql.user"
            },
            DBMS::PostgreSQL => {
                "SELECT usename,passwd FROM pg_shadow"
            },
            DBMS::MSSQL => {
                "SELECT name,master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins"
            },
            DBMS::Oracle => {
                "SELECT username,password FROM sys.dba_users"
            },
            DBMS::SQLite => "SELECT 'admin','*'",
            DBMS::Access => "SELECT 'admin','*'",
        }
    }

    /// Dummy table for FROM clause (some DBs require it)
    pub fn from_dummy(&self) -> Option<&'static str> {
        match self.dbms {
            DBMS::Oracle => Some("DUAL"),
            DBMS::Access => Some("MSysAccessObjects"),
            _ => None,
        }
    }
}
