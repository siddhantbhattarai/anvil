//! Out-of-Band (OOB) Listener Infrastructure
//!
//! DNS and HTTP callback servers for OOB SQL injection detection.

use crate::sqli::inference::oob::{OobCallback, OobCallbackType};
use crate::sqli::DatabaseType;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Enhanced OOB listener with actual server implementation
pub struct OobServer {
    /// Callback domain
    pub domain: String,
    /// DNS server port
    pub dns_port: u16,
    /// HTTP server port
    pub http_port: u16,
    /// Received callbacks
    pub callbacks: Arc<Mutex<HashMap<String, OobCallback>>>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl OobServer {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            dns_port: 5353, // Non-privileged port for testing
            http_port: 8080,
            callbacks: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx: None,
        }
    }

    /// Start the OOB listener servers
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let callbacks = self.callbacks.clone();
        let domain = self.domain.clone();
        let dns_port = self.dns_port;

        // Start DNS listener
        tokio::spawn(async move {
            if let Err(e) = run_dns_listener(dns_port, &domain, callbacks).await {
                tracing::error!("[OOB] DNS listener error: {}", e);
            }
        });

        let callbacks = self.callbacks.clone();
        let http_port = self.http_port;

        // Start HTTP listener
        tokio::spawn(async move {
            if let Err(e) = run_http_listener(http_port, callbacks).await {
                tracing::error!("[OOB] HTTP listener error: {}", e);
            }
        });

        tracing::info!(
            "[OOB] Listeners started. DNS: {}, HTTP: {}",
            self.dns_port,
            self.http_port
        );

        Ok(())
    }

    /// Stop the OOB listener servers
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        tracing::info!("[OOB] Listeners stopped");
    }

    /// Check for a callback with the given token
    pub fn check_callback(&self, token: &str) -> Option<OobCallback> {
        let callbacks = self.callbacks.lock().unwrap();
        callbacks.get(token).cloned()
    }

    /// Wait for a callback with timeout
    pub async fn wait_for_callback(
        &self,
        token: &str,
        timeout_ms: u64,
    ) -> Option<OobCallback> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            if let Some(callback) = self.check_callback(token) {
                return Some(callback);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        None
    }

    /// Generate callback URL for HTTP OOB
    pub fn http_callback_url(&self, token: &str) -> String {
        format!("http://{}:{}/{}", self.domain, self.http_port, token)
    }

    /// Generate callback domain for DNS OOB
    pub fn dns_callback_domain(&self, token: &str) -> String {
        format!("{}.{}", token, self.domain)
    }
}

/// Run DNS listener (simplified implementation)
async fn run_dns_listener(
    port: u16,
    domain: &str,
    callbacks: Arc<Mutex<HashMap<String, OobCallback>>>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("[OOB-DNS] Listening on {}", addr);

    let mut buf = [0u8; 512];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;

        // Parse DNS query (simplified)
        if let Some(queried_name) = parse_dns_query(&buf[..len]) {
            tracing::debug!("[OOB-DNS] Query from {}: {}", src, queried_name);

            // Extract token from subdomain
            if let Some(token) = extract_token_from_dns(&queried_name, domain) {
                let db_type = detect_db_from_dns(&queried_name);

                let callback = OobCallback {
                    token: token.clone(),
                    db_type,
                    callback_type: OobCallbackType::Dns,
                    data: Some(queried_name.clone()),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                {
                    let mut cbs = callbacks.lock().unwrap();
                    cbs.insert(token, callback);
                }

                tracing::info!("[OOB-DNS] Callback recorded for query: {}", queried_name);
            }

            // Send minimal DNS response
            let response = build_dns_response(&buf[..len]);
            let _ = socket.send_to(&response, src).await;
        }
    }
}

/// Run HTTP listener
async fn run_http_listener(
    port: u16,
    callbacks: Arc<Mutex<HashMap<String, OobCallback>>>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("[OOB-HTTP] Listening on {}", addr);

    loop {
        let (mut socket, src) = listener.accept().await?;
        let callbacks = callbacks.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok(n) = socket.read(&mut buf).await {
                let request = String::from_utf8_lossy(&buf[..n]);

                // Parse path from HTTP request
                if let Some(path) = parse_http_path(&request) {
                    tracing::debug!("[OOB-HTTP] Request from {}: {}", src, path);

                    // Token is the first path segment
                    let token = path.trim_start_matches('/').split('/').next().unwrap_or("");

                    if !token.is_empty() {
                        let callback = OobCallback {
                            token: token.to_string(),
                            db_type: detect_db_from_path(&path),
                            callback_type: OobCallbackType::Http,
                            data: Some(path.clone()),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        };

                        {
                            let mut cbs = callbacks.lock().unwrap();
                            cbs.insert(token.to_string(), callback);
                        }

                        tracing::info!("[OOB-HTTP] Callback recorded: {}", path);
                    }
                }

                // Send HTTP response
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
    }
}

/// Parse DNS query to extract queried name (simplified)
fn parse_dns_query(data: &[u8]) -> Option<String> {
    // Skip DNS header (12 bytes)
    if data.len() < 13 {
        return None;
    }

    let mut name = String::new();
    let mut pos = 12;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }

        if !name.is_empty() {
            name.push('.');
        }

        pos += 1;
        if pos + len > data.len() {
            break;
        }

        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Extract token from DNS query
fn extract_token_from_dns(queried_name: &str, callback_domain: &str) -> Option<String> {
    // Token is the first subdomain
    if queried_name.ends_with(callback_domain) {
        let prefix = queried_name.trim_end_matches(callback_domain).trim_end_matches('.');
        let token = prefix.split('.').next()?;
        if token.starts_with("anvil") {
            return Some(token.to_string());
        }
    }
    None
}

/// Detect database type from DNS query
fn detect_db_from_dns(name: &str) -> Option<DatabaseType> {
    let name_lower = name.to_lowercase();
    if name_lower.contains(".mysql.") {
        Some(DatabaseType::MySQL)
    } else if name_lower.contains(".mssql.") {
        Some(DatabaseType::MSSQL)
    } else if name_lower.contains(".pgsql.") || name_lower.contains(".postgres.") {
        Some(DatabaseType::PostgreSQL)
    } else if name_lower.contains(".oracle.") {
        Some(DatabaseType::Oracle)
    } else {
        None
    }
}

/// Detect database type from HTTP path
fn detect_db_from_path(path: &str) -> Option<DatabaseType> {
    let path_lower = path.to_lowercase();
    if path_lower.contains("mysql") {
        Some(DatabaseType::MySQL)
    } else if path_lower.contains("mssql") {
        Some(DatabaseType::MSSQL)
    } else if path_lower.contains("postgres") {
        Some(DatabaseType::PostgreSQL)
    } else if path_lower.contains("oracle") {
        Some(DatabaseType::Oracle)
    } else {
        None
    }
}

/// Build minimal DNS response
fn build_dns_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();

    // Set response flags
    if response.len() >= 4 {
        response[2] = 0x81; // Response, recursion desired
        response[3] = 0x80; // Recursion available, no error
    }

    response
}

/// Parse HTTP request path
fn parse_http_path(request: &str) -> Option<String> {
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Integration helper for full OOB SQLi workflow
pub async fn test_oob_sqli(
    client: &crate::http::client::HttpClient,
    server: &OobServer,
    base_url: &url::Url,
    param: &str,
) -> anyhow::Result<Option<crate::sqli::SqliResult>> {
    use crate::http::request::HttpRequest;
    use crate::sqli::inference::oob::OobPayloads;
    use reqwest::Method;

    let token = OobPayloads::generate_token();

    tracing::info!("[OOB] Testing {} param={} token={}", base_url, param, token);

    // Send OOB payloads
    for (payload, db_type, oob_type) in OobPayloads::all(&server.domain, &token) {
        let mut url = base_url.clone();
        url.query_pairs_mut().append_pair(param, &payload);

        let req = HttpRequest::new(Method::GET, url);
        let _ = client.execute(req).await;
    }

    // Wait for callback
    if let Some(callback) = server.wait_for_callback(&token, 10000).await {
        return Ok(Some(crate::sqli::SqliResult {
            endpoint: base_url.to_string(),
            parameter: param.to_string(),
            technique: crate::sqli::SqliTechnique::OutOfBand,
            confidence: 0.95,
            db_type: callback.db_type,
            details: format!(
                "OOB SQLi confirmed via {:?}. Token: {}. Data: {:?}",
                callback.callback_type, callback.token, callback.data
            ),
        }));
    }

    Ok(None)
}

