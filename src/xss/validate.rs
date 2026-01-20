// Execution Likelihood Validation Module
// Evaluates if a reflected payload would actually execute (reduces false positives)

use crate::xss::context::{XssContext, QuoteType, would_break_context};
use scraper::{Html, Selector};

#[derive(Debug, Clone)]
pub struct XssValidationResult {
    pub exploitable: bool,
    pub confidence: f32,
    pub severity: ExecutionSeverity,
    pub reason: String,
    pub technical_details: String,
    pub breakout_required: bool,
    pub csp_bypass_needed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionSeverity {
    Critical,   // Immediate JavaScript execution
    High,       // Requires user interaction (click, hover)
    Medium,     // Requires specific conditions
    Low,        // Unlikely to execute
    Info,       // Reflected but encoded/safe
}

/// Main validation function: Determines if a payload would execute
pub fn validate_execution_likelihood(
    response_body: &str,
    payload: &str,
    context: &XssContext,
) -> XssValidationResult {
    // Step 1: Check if payload is reflected at all
    if !response_body.contains(payload) {
        return XssValidationResult {
            exploitable: false,
            confidence: 0.0,
            severity: ExecutionSeverity::Info,
            reason: "Payload not reflected in response".to_string(),
            technical_details: "The injected payload was not found in the response body".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        };
    }
    
    // Step 2: Check for encoding that prevents execution
    if is_safely_encoded(response_body, payload) {
        return XssValidationResult {
            exploitable: false,
            confidence: 0.2,
            severity: ExecutionSeverity::Info,
            reason: "Payload reflected but safely encoded".to_string(),
            technical_details: format!(
                "Special characters in the payload are HTML entity encoded, preventing execution"
            ),
            breakout_required: false,
            csp_bypass_needed: false,
        };
    }
    
    // Step 3: Check for sanitization
    if is_sanitized(response_body, payload) {
        return XssValidationResult {
            exploitable: false,
            confidence: 0.3,
            severity: ExecutionSeverity::Low,
            reason: "Payload sanitized by input filter".to_string(),
            technical_details: "Dangerous characters were stripped or modified".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        };
    }
    
    // Step 4: Context-specific validation
    validate_context_execution(response_body, payload, context)
}

fn validate_context_execution(
    response_body: &str,
    payload: &str,
    context: &XssContext,
) -> XssValidationResult {
    match context {
        XssContext::HtmlText => validate_html_text_execution(response_body, payload),
        XssContext::HtmlAttribute { tag, attr, quote_type } => {
            validate_attribute_execution(response_body, payload, tag, attr, quote_type)
        }
        XssContext::JavaScriptString { quote_type } => {
            validate_js_string_execution(response_body, payload, quote_type)
        }
        XssContext::JavaScriptCode => validate_js_code_execution(response_body, payload),
        XssContext::Url { protocol_allowed } => {
            validate_url_execution(response_body, payload, *protocol_allowed)
        }
        XssContext::HtmlComment => validate_comment_execution(response_body, payload),
        XssContext::Css => validate_css_execution(response_body, payload),
        XssContext::Json => validate_json_execution(response_body, payload),
        XssContext::Unknown => validate_unknown_execution(response_body, payload),
    }
}

fn validate_html_text_execution(response_body: &str, payload: &str) -> XssValidationResult {
    // Check if payload creates executable HTML
    if contains_script_tag(payload) {
        // Verify the script tag is not broken or commented out
        if is_script_tag_intact(response_body, payload) {
            return XssValidationResult {
                exploitable: true,
                confidence: 0.95,
                severity: ExecutionSeverity::Critical,
                reason: "Script tag injection in HTML context".to_string(),
                technical_details: "A complete <script> tag was injected and will execute immediately".to_string(),
                breakout_required: false,
                csp_bypass_needed: check_csp_present(response_body),
            };
        }
    }
    
    if contains_event_handler(payload) {
        let severity = if requires_user_interaction(payload) {
            ExecutionSeverity::High
        } else {
            ExecutionSeverity::Critical
        };
        
        return XssValidationResult {
            exploitable: true,
            confidence: 0.90,
            severity,
            reason: "Event handler injection detected".to_string(),
            technical_details: format!(
                "Payload injects an event handler that {} user interaction",
                if requires_user_interaction(payload) { "requires" } else { "does not require" }
            ),
            breakout_required: false,
            csp_bypass_needed: check_csp_present(response_body),
        };
    }
    
    if contains_svg_tag(payload) && contains_event_handler(payload) {
        return XssValidationResult {
            exploitable: true,
            confidence: 0.92,
            severity: ExecutionSeverity::Critical,
            reason: "SVG tag with onload event".to_string(),
            technical_details: "SVG onload events fire automatically without user interaction".to_string(),
            breakout_required: false,
            csp_bypass_needed: check_csp_present(response_body),
        };
    }
    
    XssValidationResult {
        exploitable: false,
        confidence: 0.4,
        severity: ExecutionSeverity::Low,
        reason: "Payload reflected but no executable context created".to_string(),
        technical_details: "Injection did not create executable HTML elements".to_string(),
        breakout_required: true,
        csp_bypass_needed: false,
    }
}

fn validate_attribute_execution(
    response_body: &str,
    payload: &str,
    tag: &str,
    attr: &str,
    quote_type: &QuoteType,
) -> XssValidationResult {
    // Check if payload breaks out of the attribute
    let breaks_out = match quote_type {
        QuoteType::Double => payload.contains('"'),
        QuoteType::Single => payload.contains('\''),
        QuoteType::None => payload.contains(|c: char| c.is_whitespace()),
        QuoteType::Backtick => payload.contains('`'),
    };
    
    if breaks_out {
        // Check if breakout leads to event handler injection
        if contains_event_handler(payload) {
            let severity = if requires_user_interaction(payload) {
                ExecutionSeverity::High
            } else {
                ExecutionSeverity::Critical
            };
            
            return XssValidationResult {
                exploitable: true,
                confidence: 0.92,
                severity,
                reason: format!("Attribute breakout in <{}> tag", tag),
                technical_details: format!(
                    "Successfully broke out of {} attribute using {} quotes and injected event handler",
                    attr, format!("{:?}", quote_type)
                ),
                breakout_required: false,
                csp_bypass_needed: check_csp_present(response_body),
            };
        }
        
        // Check if breakout leads to new tag
        if payload.contains('<') && payload.contains('>') {
            return XssValidationResult {
                exploitable: true,
                confidence: 0.88,
                severity: ExecutionSeverity::Critical,
                reason: "Attribute breakout with new tag injection".to_string(),
                technical_details: "Closed the attribute and injected a new malicious tag".to_string(),
                breakout_required: false,
                csp_bypass_needed: check_csp_present(response_body),
            };
        }
    }
    
    // Check if it's a URL attribute with javascript: protocol
    if is_url_attribute(attr) && payload.starts_with("javascript:") {
        return XssValidationResult {
            exploitable: true,
            confidence: 0.85,
            severity: ExecutionSeverity::High,
            reason: format!("JavaScript protocol in {} attribute", attr),
            technical_details: "javascript: protocol will execute when the element is triggered".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        };
    }
    
    XssValidationResult {
        exploitable: false,
        confidence: 0.3,
        severity: ExecutionSeverity::Low,
        reason: "Payload stayed within attribute value".to_string(),
        technical_details: "No successful breakout or protocol injection detected".to_string(),
        breakout_required: true,
        csp_bypass_needed: false,
    }
}

fn validate_js_string_execution(
    response_body: &str,
    payload: &str,
    quote_type: &QuoteType,
) -> XssValidationResult {
    // Check if payload breaks out of string
    let breaks_out = match quote_type {
        QuoteType::Double => payload.contains('"') || payload.contains("</script>"),
        QuoteType::Single => payload.contains('\'') || payload.contains("</script>"),
        QuoteType::Backtick => payload.contains('`') || payload.contains("</script>"),
        QuoteType::None => false,
    };
    
    if breaks_out {
        // Check if breakout leads to code execution
        if payload.contains(";alert(") || payload.contains(";confirm(") || payload.contains(";prompt(") {
            return XssValidationResult {
                exploitable: true,
                confidence: 0.95,
                severity: ExecutionSeverity::Critical,
                reason: "JavaScript string breakout with code execution".to_string(),
                technical_details: format!(
                    "Successfully broke out of {} string and injected executable code",
                    format!("{:?}", quote_type)
                ),
                breakout_required: false,
                csp_bypass_needed: false,
            };
        }
        
        // Check for script tag closure and new script
        if payload.contains("</script>") && payload.contains("<script>") {
            return XssValidationResult {
                exploitable: true,
                confidence: 0.93,
                severity: ExecutionSeverity::Critical,
                reason: "Script tag breakout and reinsertion".to_string(),
                technical_details: "Closed existing script tag and opened a new one".to_string(),
                breakout_required: false,
                csp_bypass_needed: check_csp_present(response_body),
            };
        }
    }
    
    // Check for template literal expression injection
    if payload.contains("${") && payload.contains("}") {
        return XssValidationResult {
            exploitable: true,
            confidence: 0.90,
            severity: ExecutionSeverity::Critical,
            reason: "Template literal expression injection".to_string(),
            technical_details: "Injected code will execute within template literal expression".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        };
    }
    
    XssValidationResult {
        exploitable: false,
        confidence: 0.4,
        severity: ExecutionSeverity::Low,
        reason: "Payload inside JavaScript string but no breakout".to_string(),
        technical_details: "Unable to escape the string context to execute code".to_string(),
        breakout_required: true,
        csp_bypass_needed: false,
    }
}

fn validate_js_code_execution(response_body: &str, payload: &str) -> XssValidationResult {
    // If injected directly into JS code, it's highly likely to execute
    XssValidationResult {
        exploitable: true,
        confidence: 0.98,
        severity: ExecutionSeverity::Critical,
        reason: "Direct JavaScript code injection".to_string(),
        technical_details: "Payload is injected directly into executable JavaScript context".to_string(),
        breakout_required: false,
        csp_bypass_needed: false,
    }
}

fn validate_url_execution(
    response_body: &str,
    payload: &str,
    protocol_allowed: bool,
) -> XssValidationResult {
    if !protocol_allowed {
        return XssValidationResult {
            exploitable: false,
            confidence: 0.2,
            severity: ExecutionSeverity::Low,
            reason: "URL context but protocol injection blocked".to_string(),
            technical_details: "Dangerous protocols are filtered or blocked".to_string(),
            breakout_required: true,
            csp_bypass_needed: false,
        };
    }
    
    if payload.starts_with("javascript:") {
        XssValidationResult {
            exploitable: true,
            confidence: 0.88,
            severity: ExecutionSeverity::High,
            reason: "JavaScript protocol injection in URL".to_string(),
            technical_details: "javascript: protocol will execute when user clicks/navigates".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        }
    } else if payload.starts_with("data:") && payload.contains("text/html") {
        XssValidationResult {
            exploitable: true,
            confidence: 0.85,
            severity: ExecutionSeverity::High,
            reason: "Data URI with HTML content".to_string(),
            technical_details: "data: URI can execute JavaScript in some contexts".to_string(),
            breakout_required: false,
            csp_bypass_needed: false,
        }
    } else {
        XssValidationResult {
            exploitable: false,
            confidence: 0.3,
            severity: ExecutionSeverity::Low,
            reason: "URL injection but no dangerous protocol".to_string(),
            technical_details: "Injection does not use javascript: or data: protocols".to_string(),
            breakout_required: true,
            csp_bypass_needed: false,
        }
    }
}

fn validate_comment_execution(response_body: &str, payload: &str) -> XssValidationResult {
    // Check if payload breaks out of comment
    if payload.contains("-->") {
        XssValidationResult {
            exploitable: true,
            confidence: 0.85,
            severity: ExecutionSeverity::Critical,
            reason: "HTML comment breakout".to_string(),
            technical_details: "Successfully closed the comment and can inject executable code".to_string(),
            breakout_required: false,
            csp_bypass_needed: check_csp_present(response_body),
        }
    } else {
        XssValidationResult {
            exploitable: false,
            confidence: 0.1,
            severity: ExecutionSeverity::Info,
            reason: "Payload trapped in HTML comment".to_string(),
            technical_details: "Unable to break out of comment block".to_string(),
            breakout_required: true,
            csp_bypass_needed: false,
        }
    }
}

fn validate_css_execution(response_body: &str, payload: &str) -> XssValidationResult {
    if payload.contains("</style>") && payload.contains("<script>") {
        XssValidationResult {
            exploitable: true,
            confidence: 0.90,
            severity: ExecutionSeverity::Critical,
            reason: "Style tag breakout with script injection".to_string(),
            technical_details: "Closed the style tag and injected a script tag".to_string(),
            breakout_required: false,
            csp_bypass_needed: check_csp_present(response_body),
        }
    } else {
        XssValidationResult {
            exploitable: false,
            confidence: 0.2,
            severity: ExecutionSeverity::Low,
            reason: "CSS context with limited execution".to_string(),
            technical_details: "CSS injection alone rarely leads to JavaScript execution".to_string(),
            breakout_required: true,
            csp_bypass_needed: false,
        }
    }
}

fn validate_json_execution(response_body: &str, payload: &str) -> XssValidationResult {
    // JSON context is typically safe unless interpreted as HTML
    XssValidationResult {
        exploitable: false,
        confidence: 0.3,
        severity: ExecutionSeverity::Medium,
        reason: "JSON context (low execution likelihood)".to_string(),
        technical_details: "Payload in JSON is typically not executed unless improperly parsed".to_string(),
        breakout_required: true,
        csp_bypass_needed: false,
    }
}

fn validate_unknown_execution(response_body: &str, payload: &str) -> XssValidationResult {
    // Perform generic checks for unknown contexts
    if contains_script_tag(payload) || contains_event_handler(payload) {
        XssValidationResult {
            exploitable: true,
            confidence: 0.70,
            severity: ExecutionSeverity::High,
            reason: "Executable payload in unknown context".to_string(),
            technical_details: "Cannot determine exact context but payload appears executable".to_string(),
            breakout_required: false,
            csp_bypass_needed: check_csp_present(response_body),
        }
    } else {
        XssValidationResult {
            exploitable: false,
            confidence: 0.4,
            severity: ExecutionSeverity::Low,
            reason: "Unknown context, unclear execution likelihood".to_string(),
            technical_details: "More analysis needed to determine exploitability".to_string(),
            breakout_required: true,
            csp_bypass_needed: false,
        }
    }
}

// Helper functions

fn is_safely_encoded(body: &str, payload: &str) -> bool {
    // Check for HTML entity encoding of dangerous characters
    let dangerous_chars = ['<', '>', '"', '\'', '&'];
    
    for ch in dangerous_chars {
        if payload.contains(ch) {
            let html_encoded = match ch {
                '<' => vec!["&lt;", "&#60;", "&#x3c;"],
                '>' => vec!["&gt;", "&#62;", "&#x3e;"],
                '"' => vec!["&quot;", "&#34;", "&#x22;"],
                '\'' => vec!["&#39;", "&#x27;", "&apos;"],
                '&' => vec!["&amp;", "&#38;"],
                _ => vec![],
            };
            
            // Check if this character appears encoded in the response
            if html_encoded.iter().any(|enc| body.contains(enc)) {
                return true;
            }
        }
    }
    
    false
}

fn is_sanitized(body: &str, payload: &str) -> bool {
    // Check if dangerous parts of payload were stripped
    if payload.contains('<') && !body.contains('<') {
        return true;
    }
    if payload.contains("script") && !body.contains("script") {
        return true;
    }
    if payload.contains("javascript:") && !body.contains("javascript:") {
        return true;
    }
    
    false
}

fn contains_script_tag(payload: &str) -> bool {
    payload.to_lowercase().contains("<script")
}

fn contains_event_handler(payload: &str) -> bool {
    let events = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur"];
    events.iter().any(|event| payload.to_lowercase().contains(event))
}

fn contains_svg_tag(payload: &str) -> bool {
    payload.to_lowercase().contains("<svg")
}

fn requires_user_interaction(payload: &str) -> bool {
    let interactive_events = ["onclick", "onmouseover", "onmouseout", "onfocus", "onblur"];
    interactive_events.iter().any(|event| payload.to_lowercase().contains(event))
}

fn is_script_tag_intact(body: &str, payload: &str) -> bool {
    // Check if the script tag wasn't broken up or commented
    body.contains("<script") && body.contains("</script>")
}

fn is_url_attribute(attr: &str) -> bool {
    matches!(
        attr,
        "href" | "src" | "action" | "formaction" | "data" | "poster"
    )
}

fn check_csp_present(body: &str) -> bool {
    // Simple heuristic: check for CSP meta tag
    // In production, would check actual HTTP headers
    body.to_lowercase().contains("content-security-policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_script_tag_detection() {
        assert!(contains_script_tag("<script>alert(1)</script>"));
        assert!(contains_script_tag("<SCRIPT>alert(1)</SCRIPT>"));
        assert!(!contains_script_tag("alert(1)"));
    }
    
    #[test]
    fn test_event_handler_detection() {
        assert!(contains_event_handler("onload=alert(1)"));
        assert!(contains_event_handler("ONCLICK=alert(1)"));
        assert!(!contains_event_handler("alert(1)"));
    }
    
    #[test]
    fn test_encoding_detection() {
        let body = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>";
        let payload = "<script>alert(1)</script>";
        assert!(is_safely_encoded(body, payload));
    }
}
