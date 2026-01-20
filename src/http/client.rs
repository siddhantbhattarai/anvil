//! HTTP client with scope enforcement, rate limiting, and cookie support

use crate::core::rate_limit::RateLimiter;
use crate::core::scope::Scope;
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use anyhow::Result;
use reqwest::{header, Client, redirect::Policy};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

pub struct HttpClient {
    client: Client,
    scope: Scope,
    limiter: RateLimiter,
    default_headers: HashMap<String, String>,
    cookies: Option<String>,
}

impl HttpClient {
    pub fn new(scope: Scope, limiter: RateLimiter) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            client,
            scope,
            limiter,
            default_headers: HashMap::new(),
            cookies: None,
        })
    }

    /// Create HTTP client with cookies for authenticated scanning
    pub fn with_cookies(scope: Scope, limiter: RateLimiter, cookies: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            client,
            scope,
            limiter,
            default_headers: HashMap::new(),
            cookies: Some(cookies.to_string()),
        })
    }

    /// Create HTTP client with cookies and custom headers
    pub fn with_auth(
        scope: Scope,
        limiter: RateLimiter,
        cookies: Option<String>,
        headers: HashMap<String, String>,
    ) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            client,
            scope,
            limiter,
            default_headers: headers,
            cookies,
        })
    }

    pub async fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
        // ---- RATE LIMIT ENFORCEMENT ----
        self.limiter.wait().await;

        // ---- SCOPE CHECK ----
        if !self.scope.is_in_scope(&req.url) {
            anyhow::bail!("Blocked out-of-scope request: {}", req.url);
        }

        let start = Instant::now();

        let mut request = self
            .client
            .request(req.method, req.url.clone())
            .headers(req.headers.clone());

        // Add default headers
        for (key, value) in &self.default_headers {
            if let Ok(header_name) = header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = header::HeaderValue::from_str(value) {
                    request = request.header(header_name, header_value);
                }
            }
        }

        // Add cookies
        if let Some(ref cookies) = self.cookies {
            request = request.header(header::COOKIE, cookies);
        }

        if let Some(body) = req.body {
            request = request.body(body);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        let final_url = response.url().clone();
        if !self.scope.is_in_scope(&final_url) {
            anyhow::bail!("Blocked out-of-scope redirect to {}", final_url);
        }

        let mut headers = std::collections::HashMap::new();
        for (k, v) in response.headers().iter() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        let body_len = body_bytes.len();

        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        let body_hash = format!("{:x}", hasher.finalize());

        Ok(HttpResponse {
            status,
            headers,
            body_len,
            body_hash,
            body: body_bytes.to_vec(),
            elapsed_ms: start.elapsed().as_millis(),
        })
    }
}
