//! Parameter identification for SSRF detection
//!
//! Identifies parameters that plausibly influence outbound requests

use url::Url;

/// Parameter patterns that suggest SSRF potential
const SSRF_PARAM_PATTERNS: &[&str] = &[
    // URL/Host parameters
    "url", "uri", "link", "href", "src", "source", "path", "dest", "destination",
    "redirect", "return", "next", "continue", "goto", "target", "to", "from",
    
    // Host/IP parameters
    "host", "hostname", "server", "domain", "ip", "address", "endpoint",
    
    // Webhook/Callback parameters
    "webhook", "callback", "notify", "ping", "hook", "listener",
    
    // File/Resource parameters (HIGH PRIORITY)
    "file", "filename", "filepath", "document", "doc", "resource",
    "image", "img", "picture", "photo", "avatar", "icon",
    "page", "view", "content", "data",  // Added common file inclusion params
    
    // Import/Fetch parameters
    "import", "fetch", "load", "get", "retrieve", "download",
    "include", "require", "read",
    
    // API/Remote parameters
    "api", "remote", "external", "proxy", "forward",
    
    // PDF/Document generation
    "pdf", "html", "template", "render",
    
    // Metadata/Feed parameters
    "feed", "rss", "atom", "xml", "json",
    "metadata", "meta", "info",
];

/// Value patterns that suggest URL/host input
const SSRF_VALUE_PATTERNS: &[&str] = &[
    "http://", "https://", "ftp://", "file://",
    "://", "www.", ".com", ".net", ".org",
];

/// Identifies parameters that are likely SSRF candidates
#[derive(Debug, Clone)]
pub struct SsrfParamIdentifier;

impl SsrfParamIdentifier {
    pub fn new() -> Self {
        Self
    }
    
    /// Identify SSRF candidate parameters from a URL
    pub fn identify_from_url(&self, url: &Url) -> Vec<SsrfCandidate> {
        let mut candidates = Vec::new();
        
        for (key, value) in url.query_pairs() {
            let key_lower = key.to_lowercase();
            let value_str = value.to_string();
            
            // Check if parameter name matches SSRF patterns
            let name_score = self.score_param_name(&key_lower);
            
            // Check if value looks like a URL/host
            let value_score = self.score_param_value(&value_str);
            
            let total_score = name_score + value_score;
            
            if total_score > 0.0 {
                candidates.push(SsrfCandidate {
                    param_name: key.to_string(),
                    param_value: value_str.clone(),
                    score: total_score,
                    reason: self.get_reason(&key_lower, &value_str, name_score, value_score),
                });
            }
        }
        
        // Sort by score (highest first)
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        candidates
    }
    
    /// Identify SSRF candidate parameters from POST data
    pub fn identify_from_post_data(&self, data: &str) -> Vec<SsrfCandidate> {
        let mut candidates = Vec::new();
        
        // Try to parse as form data
        for pair in data.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key_lower = key.to_lowercase();
                let value_decoded = urlencoding::decode(value).unwrap_or_default().to_string();
                
                let name_score = self.score_param_name(&key_lower);
                let value_score = self.score_param_value(&value_decoded);
                let total_score = name_score + value_score;
                
                if total_score > 0.0 {
                    candidates.push(SsrfCandidate {
                        param_name: key.to_string(),
                        param_value: value_decoded.clone(),
                        score: total_score,
                        reason: self.get_reason(&key_lower, &value_decoded, name_score, value_score),
                    });
                }
            }
        }
        
        // Sort by score
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        candidates
    }
    
    /// Score a parameter name for SSRF likelihood
    fn score_param_name(&self, name: &str) -> f32 {
        let mut score = 0.0;
        
        for pattern in SSRF_PARAM_PATTERNS {
            if name == *pattern {
                // Exact match
                score += 1.0;
            } else if name.contains(pattern) {
                // Partial match
                score += 0.5;
            }
        }
        
        score
    }
    
    /// Score a parameter value for SSRF likelihood
    fn score_param_value(&self, value: &str) -> f32 {
        let mut score = 0.0;
        
        // Check if it's a valid URL
        if Url::parse(value).is_ok() {
            score += 2.0;
        }
        
        // Check for URL-like patterns
        for pattern in SSRF_VALUE_PATTERNS {
            if value.contains(pattern) {
                score += 0.5;
            }
        }
        
        // Check if it looks like an IP address
        if value.split('.').count() == 4 {
            if value.split('.').all(|part| part.parse::<u8>().is_ok()) {
                score += 1.5;
            }
        }
        
        // Check if it looks like a hostname
        if value.contains('.') && !value.contains('/') && !value.contains('=') {
            score += 0.5;
        }
        
        score
    }
    
    /// Get human-readable reason for SSRF candidacy
    fn get_reason(&self, name: &str, value: &str, name_score: f32, value_score: f32) -> String {
        let mut reasons = Vec::new();
        
        if name_score >= 1.0 {
            reasons.push("parameter name suggests URL/host input");
        } else if name_score > 0.0 {
            reasons.push("parameter name contains URL-related keywords");
        }
        
        if Url::parse(value).is_ok() {
            reasons.push("value is a valid URL");
        } else if value_score > 0.0 {
            reasons.push("value contains URL-like patterns");
        }
        
        if reasons.is_empty() {
            "parameter may influence outbound requests".to_string()
        } else {
            reasons.join(", ")
        }
    }
}

impl Default for SsrfParamIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

/// A parameter that is a candidate for SSRF testing
#[derive(Debug, Clone)]
pub struct SsrfCandidate {
    pub param_name: String,
    pub param_value: String,
    pub score: f32,
    pub reason: String,
}

impl SsrfCandidate {
    /// Check if this is a high-priority candidate
    pub fn is_high_priority(&self) -> bool {
        self.score >= 2.0
    }
    
    /// Check if this is a medium-priority candidate
    pub fn is_medium_priority(&self) -> bool {
        self.score >= 1.0 && self.score < 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identify_url_params() {
        let identifier = SsrfParamIdentifier::new();
        let url = Url::parse("https://example.com/fetch?url=http://target.com&name=test").unwrap();
        
        let candidates = identifier.identify_from_url(&url);
        
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].param_name, "url");
        assert!(candidates[0].is_high_priority());
    }
    
    #[test]
    fn test_score_param_name() {
        let identifier = SsrfParamIdentifier::new();
        
        assert!(identifier.score_param_name("url") > 0.0);
        assert!(identifier.score_param_name("callback") > 0.0);
        assert!(identifier.score_param_name("webhook") > 0.0);
        assert_eq!(identifier.score_param_name("random"), 0.0);
    }
    
    #[test]
    fn test_score_param_value() {
        let identifier = SsrfParamIdentifier::new();
        
        assert!(identifier.score_param_value("http://example.com") > 0.0);
        assert!(identifier.score_param_value("192.168.1.1") > 0.0);
        assert!(identifier.score_param_value("example.com") > 0.0);
        assert_eq!(identifier.score_param_value("test123"), 0.0);
    }
}

