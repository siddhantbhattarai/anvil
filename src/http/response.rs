use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body_len: usize,
    pub body_hash: String,
    pub body: Vec<u8>,
    pub elapsed_ms: u128,
}

impl HttpResponse {
    /// Get body as UTF-8 string (lossy conversion)
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}
