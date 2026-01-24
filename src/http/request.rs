use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// Set request body from string
    pub fn set_body(&mut self, body: String) {
        self.body = Some(body.into_bytes());
    }

    /// Set request body from bytes
    pub fn set_body_bytes(&mut self, body: Vec<u8>) {
        self.body = Some(body);
    }

    /// Set a header
    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
            if let Ok(header_value) = HeaderValue::from_str(value) {
                self.headers.insert(header_name, header_value);
            }
        }
    }

    /// Create a GET request
    pub fn get(url: Url) -> Self {
        Self::new(Method::GET, url)
    }

    /// Create a POST request with body
    pub fn post(url: Url, body: String) -> Self {
        let mut req = Self::new(Method::POST, url);
        req.set_body(body);
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        req
    }

    pub fn inject_payload(&mut self, payload: &str) {
        // Inject payload into URL
        let url_str = self.url.to_string();
        if url_str.contains("=") {
            if let Some(pos) = url_str.rfind("=") {
                let base = &url_str[..pos + 1];
                let new_url = format!("{}{}", base, payload);
                if let Ok(parsed) = Url::parse(&new_url) {
                    self.url = parsed;
                }
            }
        }
    }
}
