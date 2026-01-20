//! Out-of-band (OOB) callback system for blind SSRF detection
//!
//! This module provides functionality for detecting blind SSRF through
//! out-of-band callbacks (DNS or HTTP).

use std::time::{SystemTime, UNIX_EPOCH};

/// OOB callback generator
#[derive(Debug, Clone)]
pub struct OobCallbackGenerator {
    /// Base callback domain (e.g., "attacker.com")
    pub callback_domain: String,
}

impl OobCallbackGenerator {
    pub fn new(callback_domain: String) -> Self {
        Self { callback_domain }
    }
    
    /// Generate a unique callback URL with identifier
    pub fn generate_callback_url(&self, identifier: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        format!("http://{}.{}", identifier, self.callback_domain)
    }
    
    /// Generate a DNS callback hostname
    pub fn generate_dns_callback(&self, identifier: &str) -> String {
        format!("{}.{}", identifier, self.callback_domain)
    }
    
    /// Generate multiple callback variants for different protocols
    pub fn generate_callback_variants(&self, identifier: &str) -> Vec<String> {
        vec![
            // HTTP variants
            format!("http://{}.{}", identifier, self.callback_domain),
            format!("https://{}.{}", identifier, self.callback_domain),
            format!("http://{}.{}/", identifier, self.callback_domain),
            format!("http://{}.{}/callback", identifier, self.callback_domain),
            
            // DNS-only (for DNS exfiltration)
            format!("{}.{}", identifier, self.callback_domain),
            
            // With path encoding
            format!("http://{}.{}/ssrf-test", identifier, self.callback_domain),
        ]
    }
    
    /// Extract identifier from callback URL
    pub fn extract_identifier(&self, callback_url: &str) -> Option<String> {
        // Extract subdomain before callback_domain
        if let Some(pos) = callback_url.find(&self.callback_domain) {
            let before = &callback_url[..pos];
            // Remove protocol and extract subdomain
            let subdomain = before
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('.');
            
            if !subdomain.is_empty() {
                return Some(subdomain.to_string());
            }
        }
        
        None
    }
}

/// OOB callback listener (mock for now - in production, this would be a real server)
#[derive(Debug, Clone)]
pub struct OobCallbackListener {
    pub callback_domain: String,
    // In production, this would track received callbacks
    // For now, we'll simulate it
}

impl OobCallbackListener {
    pub fn new(callback_domain: String) -> Self {
        Self { callback_domain }
    }
    
    /// Check if a callback was received (mock implementation)
    /// In production, this would query a real callback server
    pub async fn check_callback(&self, identifier: &str) -> bool {
        // TODO: In production, implement actual callback checking
        // This would query your callback server's API
        
        tracing::debug!("Checking for OOB callback: {}", identifier);
        
        // For now, return false (no callback received)
        // In real implementation:
        // 1. Query callback server API
        // 2. Check if DNS/HTTP request was received
        // 3. Return true if callback was received
        
        false
    }
    
    /// Wait for callback with timeout (mock implementation)
    pub async fn wait_for_callback(&self, identifier: &str, timeout_secs: u64) -> bool {
        tracing::debug!(
            "Waiting for OOB callback: {} (timeout: {}s)",
            identifier,
            timeout_secs
        );
        
        // Sleep for a short time to simulate waiting
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs.min(2))).await;
        
        // Check if callback was received
        self.check_callback(identifier).await
    }
}

/// Generate a unique identifier for tracking callbacks
pub fn generate_identifier(endpoint: &str, param: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    endpoint.hash(&mut hasher);
    param.hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut hasher);
    
    format!("ssrf-{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_callback_url() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let url = generator.generate_callback_url("test123");
        
        assert!(url.contains("test123"));
        assert!(url.contains("attacker.com"));
        assert!(url.starts_with("http://"));
    }
    
    #[test]
    fn test_extract_identifier() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let url = "http://test123.attacker.com/callback";
        
        let identifier = generator.extract_identifier(url);
        assert_eq!(identifier, Some("test123".to_string()));
    }
    
    #[test]
    fn test_generate_variants() {
        let generator = OobCallbackGenerator::new("attacker.com".to_string());
        let variants = generator.generate_callback_variants("test");
        
        assert!(!variants.is_empty());
        assert!(variants.iter().any(|v| v.contains("http://")));
        assert!(variants.iter().any(|v| v.contains("https://")));
    }
}

