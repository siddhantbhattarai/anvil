// Main XSS Scanner Engine
// Orchestrates the multi-stage XSS detection pipeline

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::payload::injector::inject_query_param;
use crate::reporting::model::{Finding, Severity};
use crate::reporting::reporter::Reporter;
use crate::scanner::sitemap::SiteMap;
use crate::xss::context::{classify_context, XssContext};
use crate::xss::payloads::{load_payloads_for_context, load_polyglot_payloads, generate_bypass_payloads, prioritize_payloads};
use crate::xss::reflect::{discover_reflections, analyze_reflection_characteristics, ReflectionPoint};
use crate::xss::validate::validate_execution_likelihood;
use reqwest::Method;
use url::Url;

pub struct XssScanner {
    pub max_payloads_per_context: usize,
    pub test_stored: bool,
    pub test_dom: bool,
}

impl Default for XssScanner {
    fn default() -> Self {
        Self {
            max_payloads_per_context: 20, // Limit payloads to avoid excessive requests
            test_stored: true,
            test_dom: true,
        }
    }
}

impl XssScanner {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Main entry point: Scan for all XSS types
    pub async fn scan(
        &self,
        client: &HttpClient,
        base_url: &Url,
        sitemap: &SiteMap,
        reporter: &mut Reporter,
    ) -> anyhow::Result<()> {
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        tracing::info!("        ANVIL XSS SCANNER - MULTI-STAGE PIPELINE");
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        let mut total_findings = 0;
        
        for (path, endpoint) in sitemap.endpoints.iter() {
            if endpoint.parameters.is_empty() {
                continue;
            }
            
            let url = match base_url.join(path) {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            tracing::info!("\n🔍 Testing: {}", path);
            tracing::info!("   Parameters: {:?}", endpoint.parameters);
            
            // Scan this endpoint
            let params_vec: Vec<String> = endpoint.parameters.iter().cloned().collect();
            let findings = self.scan_endpoint(client, &url, &params_vec, reporter).await?;
            total_findings += findings;
        }
        
        tracing::info!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        tracing::info!("✅ XSS scan complete: {} vulnerabilities found", total_findings);
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        Ok(())
    }
    
    /// Scan a single endpoint for XSS
    async fn scan_endpoint(
        &self,
        client: &HttpClient,
        url: &Url,
        parameters: &[String],
        reporter: &mut Reporter,
    ) -> anyhow::Result<usize> {
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 1: REFLECTION DISCOVERY (Benign Markers)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        tracing::info!("   Phase 1: Discovering reflection points...");
        
        let discovery = discover_reflections(client, url, parameters).await?;
        
        if discovery.reflections.is_empty() {
            tracing::info!("   ✗ No reflections found");
            return Ok(0);
        }
        
        tracing::info!(
            "   ✓ Found {} reflection points",
            discovery.reflections.len()
        );
        
        let mut findings = 0;
        
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 2-4: For each reflection, test exploitation
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        for reflection in discovery.reflections {
            findings += self.test_reflection(client, url, &reflection, reporter).await?;
        }
        
        Ok(findings)
    }
    
    /// Test a single reflection point for XSS
    async fn test_reflection(
        &self,
        client: &HttpClient,
        url: &Url,
        reflection: &ReflectionPoint,
        reporter: &mut Reporter,
    ) -> anyhow::Result<usize> {
        tracing::info!(
            "\n   → Parameter: {} (Context: {:?}, Confidence: {:.0}%)",
            reflection.parameter,
            reflection.context.context,
            reflection.context.confidence * 100.0
        );
        
        // Analyze reflection characteristics
        let characteristics = analyze_reflection_characteristics(reflection);
        
        if characteristics.encoding_level != crate::xss::reflect::EncodingLevel::None {
            tracing::info!(
                "      ⚠ Encoding detected: {:?}",
                characteristics.encoding_level
            );
        }
        
        if characteristics.sanitization_detected {
            tracing::info!(
                "      ⚠ Sanitization patterns: {:?}",
                characteristics.sanitization_patterns
            );
        }
        
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 2: CONTEXT CLASSIFICATION
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        tracing::info!("   Phase 2: Context classification complete");
        
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 3: CONTEXT-AWARE PAYLOAD SELECTION
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        tracing::info!("   Phase 3: Loading context-aware payloads...");
        
        let mut payload_set = load_payloads_for_context(&reflection.context.context)?;
        
        // Add bypass payloads if filtering detected
        if characteristics.sanitization_detected || reflection.context.encoding_detected {
            let bypasses = generate_bypass_payloads(
                &reflection.context.context,
                reflection.context.encoding_detected,
                &characteristics.sanitization_patterns,
            );
            for bypass in bypasses {
                payload_set.add(bypass);
            }
        }
        
        // If context is unknown, use polyglots
        if reflection.context.context == XssContext::Unknown {
            let polyglots = load_polyglot_payloads()?;
            for payload in polyglots.payloads {
                payload_set.add(payload);
            }
        }
        
        // Prioritize most promising payloads
        let payloads = prioritize_payloads(payload_set, self.max_payloads_per_context);
        
        tracing::info!("      Testing {} payloads", payloads.len());
        
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // PHASE 4: EXECUTION LIKELIHOOD VALIDATION
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        tracing::info!("   Phase 4: Testing payload execution...");
        
        let mut findings = 0;
        
        for (idx, payload) in payloads.iter().enumerate() {
            if idx > 0 && idx % 5 == 0 {
                tracing::debug!("      Progress: {}/{}", idx, payloads.len());
            }
            
            // Inject payload
            let test_url = inject_query_param(url, &reflection.parameter, &payload.value)?;
            let request = HttpRequest::new(Method::GET, test_url);
            
            let response = match client.execute(request).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("      Request failed: {}", e);
                    continue;
                }
            };
            
            // Re-classify context with actual payload
            let body_str = String::from_utf8_lossy(&response.body).to_string();
            let context = classify_context(&body_str, &payload.value);
            
            // Validate execution likelihood
            let validation = validate_execution_likelihood(
                &body_str,
                &payload.value,
                &context.context,
            );
            
            // Only report if exploitable with reasonable confidence
            if validation.exploitable && validation.confidence >= 0.7 {
                findings += 1;
                
                tracing::info!(
                    "      ✅ XSS FOUND! Technique: {} | Confidence: {:.0}% | Severity: {:?}",
                    payload.technique,
                    validation.confidence * 100.0,
                    validation.severity
                );
                
                reporter.add(Finding {
                    vuln_type: "Cross-Site Scripting (XSS)".to_string(),
                    technique: format!("Reflected XSS - {}", payload.technique),
                    endpoint: url.path().to_string(),
                    parameter: Some(reflection.parameter.clone()),
                    confidence: validation.confidence,
                    severity: match validation.severity {
                        crate::xss::validate::ExecutionSeverity::Critical => Severity::Critical,
                        crate::xss::validate::ExecutionSeverity::High => Severity::High,
                        crate::xss::validate::ExecutionSeverity::Medium => Severity::Medium,
                        crate::xss::validate::ExecutionSeverity::Low => Severity::Low,
                        crate::xss::validate::ExecutionSeverity::Info => Severity::Info,
                    },
                    evidence: format!(
                        "REFLECTED XSS VULNERABILITY CONFIRMED\n\n\
                        Parameter: {}\n\
                        Context: {:?}\n\
                        Technique: {}\n\
                        Confidence: {:.1}%\n\
                        Severity: {:?}\n\n\
                        ANALYSIS:\n\
                        {}\n\n\
                        TECHNICAL DETAILS:\n\
                        {}\n\n\
                        BREAKOUT REQUIRED: {}\n\
                        CSP BYPASS NEEDED: {}",
                        reflection.parameter,
                        context.context,
                        payload.technique,
                        validation.confidence * 100.0,
                        validation.severity,
                        validation.reason,
                        validation.technical_details,
                        validation.breakout_required,
                        validation.csp_bypass_needed
                    ),
                    http_method: "GET".to_string(),
                    database: None,
                    cwe: "CWE-79".to_string(),
                    cvss_score: Some(calculate_cvss(validation.confidence, &validation.severity)),
                    description: generate_xss_description(&context.context, &payload.technique),
                    impact: generate_xss_impact(&validation.severity),
                    remediation: generate_xss_remediation(),
                    references: vec![
                        "https://owasp.org/www-community/attacks/xss/".to_string(),
                        "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
                        "https://portswigger.net/web-security/cross-site-scripting".to_string(),
                    ],
                    payload_sample: Some(payload.value.clone()),
                });
                
                // Found one, no need to test more payloads for this param
                break;
            }
        }
        
        if findings == 0 {
            tracing::info!("      ✗ No exploitable XSS found");
        }
        
        Ok(findings)
    }
}

fn calculate_cvss(confidence: f32, severity: &crate::xss::validate::ExecutionSeverity) -> f32 {
    let base = match severity {
        crate::xss::validate::ExecutionSeverity::Critical => 9.0,
        crate::xss::validate::ExecutionSeverity::High => 7.5,
        crate::xss::validate::ExecutionSeverity::Medium => 5.5,
        crate::xss::validate::ExecutionSeverity::Low => 3.5,
        crate::xss::validate::ExecutionSeverity::Info => 0.0,
    };
    (base * confidence).min(10.0)
}

fn generate_xss_description(context: &XssContext, technique: &str) -> String {
    format!(
        "Cross-Site Scripting (XSS) vulnerability detected using {} technique.\n\n\
        The application reflects user input in a {} context without proper sanitization \
        or output encoding. This allows an attacker to inject malicious JavaScript code \
        that will execute in victims' browsers.\n\n\
        ATTACK SCENARIO:\n\
        1. Attacker crafts a malicious URL with XSS payload\n\
        2. Victim clicks the link or visits the page\n\
        3. Malicious JavaScript executes in victim's browser\n\
        4. Attacker can steal cookies, session tokens, or perform actions as the victim",
        technique,
        format!("{:?}", context)
    )
}

fn generate_xss_impact(severity: &crate::xss::validate::ExecutionSeverity) -> String {
    match severity {
        crate::xss::validate::ExecutionSeverity::Critical => {
            "CRITICAL: Immediate JavaScript execution without user interaction. \
            Attacker can steal session cookies, redirect users, deface pages, \
            or perform any action as the victim.".to_string()
        }
        crate::xss::validate::ExecutionSeverity::High => {
            "HIGH: JavaScript execution requiring minimal user interaction (click, hover). \
            Attacker can steal credentials, hijack sessions, or manipulate page content.".to_string()
        }
        crate::xss::validate::ExecutionSeverity::Medium => {
            "MEDIUM: Limited execution or requires specific conditions. \
            May allow information disclosure or limited session attacks.".to_string()
        }
        _ => {
            "LOW: Reflected but unlikely to execute. May be exploitable in specific scenarios.".to_string()
        }
    }
}

fn generate_xss_remediation() -> String {
    r#"IMMEDIATE ACTIONS REQUIRED:

1. **OUTPUT ENCODING (Primary Defense)**
   Encode ALL user input based on output context:
   
   HTML Context: < > " ' & /
   JavaScript Context: \ " ' newline
   URL Context: Use URL encoding
   CSS Context: Avoid user input in CSS

2. **CONTENT SECURITY POLICY (CSP)**
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'

3. **INPUT VALIDATION**
   Whitelist allowed characters and patterns
   Reject or sanitize dangerous input

4. **HTTPONLY COOKIES**
   Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict

5. **USE FRAMEWORK PROTECTIONS**
   React/Angular/Vue auto-escape by default"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scanner_creation() {
        let scanner = XssScanner::new();
        assert!(scanner.max_payloads_per_context > 0);
    }
}
