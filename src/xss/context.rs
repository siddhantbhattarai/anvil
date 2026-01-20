// XSS Context Detection Module
// Precisely classifies where user input is reflected to select appropriate payloads

use scraper::{Html, Selector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XssContext {
    /// Reflected in HTML body text between tags
    /// Example: <div>USER_INPUT</div>
    HtmlText,
    
    /// Reflected inside an HTML attribute value
    /// Example: <input value="USER_INPUT">
    HtmlAttribute {
        tag: String,
        attr: String,
        quote_type: QuoteType,
    },
    
    /// Reflected inside a JavaScript string literal
    /// Example: var x = "USER_INPUT";
    JavaScriptString {
        quote_type: QuoteType,
    },
    
    /// Reflected directly in JavaScript code (not in a string)
    /// Example: var x = USER_INPUT;
    JavaScriptCode,
    
    /// Reflected in a URL/URI context (href, src, action, etc.)
    /// Example: <a href="USER_INPUT">
    Url {
        protocol_allowed: bool,
    },
    
    /// Reflected inside an HTML comment
    /// Example: <!-- USER_INPUT -->
    HtmlComment,
    
    /// Reflected in a CSS context
    /// Example: <style>body { background: USER_INPUT; }</style>
    Css,
    
    /// Reflected in JSON data
    /// Example: {"data": "USER_INPUT"}
    Json,
    
    /// Unknown or mixed context (use polyglots)
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteType {
    Double,   // "
    Single,   // '
    Backtick, // `
    None,     // No quotes
}

#[derive(Debug, Clone)]
pub struct ContextAnalysis {
    pub context: XssContext,
    pub confidence: f32,
    pub marker_position: Vec<usize>,
    pub surrounding_html: String,
    pub encoding_detected: bool,
    pub waf_signatures: Vec<String>,
}

impl ContextAnalysis {
    pub fn new(context: XssContext, confidence: f32) -> Self {
        Self {
            context,
            confidence,
            marker_position: Vec::new(),
            surrounding_html: String::new(),
            encoding_detected: false,
            waf_signatures: Vec::new(),
        }
    }
}

/// Main entry point: Classify where a marker/payload is reflected in the response
pub fn classify_context(response_body: &str, marker: &str) -> ContextAnalysis {
    // Find all occurrences of the marker
    let positions: Vec<usize> = response_body
        .match_indices(marker)
        .map(|(pos, _)| pos)
        .collect();
    
    if positions.is_empty() {
        // Check for encoded versions
        if is_html_encoded(response_body, marker) {
            return ContextAnalysis {
                context: XssContext::HtmlText,
                confidence: 0.3,
                marker_position: Vec::new(),
                surrounding_html: String::new(),
                encoding_detected: true,
                waf_signatures: vec!["HTML entity encoding detected".to_string()],
            };
        }
        
        return ContextAnalysis::new(XssContext::Unknown, 0.0);
    }
    
    // Analyze the most promising occurrence
    let pos = positions[0];
    let analysis = analyze_context_at_position(response_body, marker, pos);
    
    ContextAnalysis {
        context: analysis.context,
        confidence: analysis.confidence,
        marker_position: positions,
        surrounding_html: extract_surrounding_html(response_body, pos, 100),
        encoding_detected: false,
        waf_signatures: detect_waf_signatures(response_body),
    }
}

#[derive(Debug, Clone)]
struct PositionContext {
    context: XssContext,
    confidence: f32,
}

fn analyze_context_at_position(body: &str, marker: &str, pos: usize) -> PositionContext {
    // Extract context window around the marker
    let start = pos.saturating_sub(200);
    let end = (pos + marker.len() + 200).min(body.len());
    let window = &body[start..end];
    let marker_offset = pos - start;
    
    // Check if inside <script> tag
    if is_inside_script_tag(body, pos) {
        return classify_javascript_context(window, marker_offset);
    }
    
    // Check if inside <style> tag
    if is_inside_style_tag(body, pos) {
        return PositionContext {
            context: XssContext::Css,
            confidence: 0.85,
        };
    }
    
    // Check if inside HTML comment
    if is_inside_comment(window, marker_offset) {
        return PositionContext {
            context: XssContext::HtmlComment,
            confidence: 0.9,
        };
    }
    
    // Check if inside an HTML tag (attribute context)
    if let Some(attr_ctx) = check_attribute_context(window, marker_offset) {
        return PositionContext {
            context: attr_ctx,
            confidence: 0.9,
        };
    }
    
    // Check if in JSON response
    if is_json_context(body) {
        return PositionContext {
            context: XssContext::Json,
            confidence: 0.85,
        };
    }
    
    // Default: HTML text context
    PositionContext {
        context: XssContext::HtmlText,
        confidence: 0.8,
    }
}

fn classify_javascript_context(window: &str, marker_offset: usize) -> PositionContext {
    // Look backwards for quote characters
    let before = &window[..marker_offset];
    let after = &window[marker_offset..];
    
    // Check for string contexts
    if let Some(quote) = find_enclosing_quote(before, after) {
        return PositionContext {
            context: XssContext::JavaScriptString { quote_type: quote },
            confidence: 0.95,
        };
    }
    
    // If not in a string, it's executable JS code
    PositionContext {
        context: XssContext::JavaScriptCode,
        confidence: 0.95,
    }
}

fn is_inside_script_tag(body: &str, pos: usize) -> bool {
    let before = &body[..pos];
    let after = &body[pos..];
    
    // Find the most recent opening script tag
    let last_open = before.rfind("<script");
    let last_close = before.rfind("</script>");
    
    // Check if we're inside a script block
    match (last_open, last_close) {
        (Some(open), Some(close)) if open > close => true,
        (Some(_), None) => true,
        _ => false,
    }
}

fn is_inside_style_tag(body: &str, pos: usize) -> bool {
    let before = &body[..pos];
    
    let last_open = before.rfind("<style");
    let last_close = before.rfind("</style>");
    
    match (last_open, last_close) {
        (Some(open), Some(close)) if open > close => true,
        (Some(_), None) => true,
        _ => false,
    }
}

fn is_inside_comment(window: &str, marker_offset: usize) -> bool {
    let before = &window[..marker_offset];
    let after = &window[marker_offset..];
    
    before.rfind("<!--").is_some() && after.find("-->").is_some()
}

fn check_attribute_context(window: &str, marker_offset: usize) -> Option<XssContext> {
    let before = &window[..marker_offset];
    
    // Look for the most recent < character
    let tag_start = before.rfind('<')?;
    let tag_close = window[marker_offset..].find('>')?;
    
    // Extract the full tag
    let tag_content = &window[tag_start..marker_offset + tag_close];
    
    // Check if inside quotes (attribute value)
    let attr_start = before[tag_start..].rfind('=')?;
    let after_eq = &before[tag_start + attr_start + 1..];
    
    // Determine quote type
    let quote_type = if after_eq.trim_start().starts_with('"') {
        QuoteType::Double
    } else if after_eq.trim_start().starts_with('\'') {
        QuoteType::Single
    } else {
        QuoteType::None
    };
    
    // Extract tag name and attribute name
    let tag_name = extract_tag_name(tag_content)?;
    let attr_name = extract_attribute_name(&before[tag_start..], marker_offset - tag_start)?;
    
    // Check if it's a URL attribute
    if is_url_attribute(&attr_name) {
        return Some(XssContext::Url {
            protocol_allowed: true,
        });
    }
    
    Some(XssContext::HtmlAttribute {
        tag: tag_name,
        attr: attr_name,
        quote_type,
    })
}

fn find_enclosing_quote(before: &str, after: &str) -> Option<QuoteType> {
    // Count quotes backwards
    let double_count = before.matches('"').count();
    let single_count = before.matches('\'').count();
    let backtick_count = before.matches('`').count();
    
    // Check which quote type we're inside (odd count means we're inside)
    if double_count % 2 == 1 && after.contains('"') {
        return Some(QuoteType::Double);
    }
    if single_count % 2 == 1 && after.contains('\'') {
        return Some(QuoteType::Single);
    }
    if backtick_count % 2 == 1 && after.contains('`') {
        return Some(QuoteType::Backtick);
    }
    
    None
}

fn extract_tag_name(tag_content: &str) -> Option<String> {
    let without_bracket = tag_content.trim_start_matches('<').trim();
    let name = without_bracket.split_whitespace().next()?;
    Some(name.to_lowercase())
}

fn extract_attribute_name(tag_fragment: &str, marker_pos: usize) -> Option<String> {
    let up_to_marker = &tag_fragment[..marker_pos];
    let last_space_or_bracket = up_to_marker.rfind(|c: char| c.is_whitespace() || c == '<')?;
    let attr_fragment = &up_to_marker[last_space_or_bracket..];
    let attr_name = attr_fragment
        .trim()
        .split('=')
        .next()?
        .trim()
        .to_lowercase();
    Some(attr_name)
}

fn is_url_attribute(attr: &str) -> bool {
    matches!(
        attr,
        "href" | "src" | "action" | "formaction" | "data" | "poster" | "background" | "cite" | "codebase"
    )
}

fn is_json_context(body: &str) -> bool {
    // Check Content-Type header would be ideal, but we work with body only
    // Simple heuristic: starts with { or [
    let trimmed = body.trim();
    (trimmed.starts_with('{') || trimmed.starts_with('['))
        && (trimmed.ends_with('}') || trimmed.ends_with(']'))
}

fn is_html_encoded(body: &str, marker: &str) -> bool {
    let encoded_versions = vec![
        marker.replace('<', "&lt;").replace('>', "&gt;"),
        marker.replace('<', "&#60;").replace('>', "&#62;"),
        marker.replace('<', "&#x3c;").replace('>', "&#x3e;"),
        marker.replace('"', "&quot;"),
        marker.replace('\'', "&#x27;"),
        marker.replace('\'', "&#39;"),
    ];
    
    encoded_versions.iter().any(|enc| body.contains(enc))
}

fn extract_surrounding_html(body: &str, pos: usize, radius: usize) -> String {
    let start = pos.saturating_sub(radius);
    let end = (pos + radius).min(body.len());
    body[start..end].to_string()
}

fn detect_waf_signatures(body: &str) -> Vec<String> {
    let mut signatures = Vec::new();
    
    // Common WAF signatures
    let waf_patterns = [
        ("Cloudflare", "cloudflare"),
        ("ModSecurity", "mod_security"),
        ("AWS WAF", "aws"),
        ("Akamai", "akamai"),
        ("Imperva", "imperva"),
        ("F5 BIG-IP", "f5"),
    ];
    
    let body_lower = body.to_lowercase();
    for (name, pattern) in waf_patterns {
        if body_lower.contains(pattern) {
            signatures.push(name.to_string());
        }
    }
    
    signatures
}

/// Additional helper: Check if a payload would break out of the current context
pub fn would_break_context(context: &XssContext, payload: &str) -> bool {
    match context {
        XssContext::HtmlText => {
            // Need to inject tags
            payload.contains('<') && payload.contains('>')
        }
        XssContext::HtmlAttribute { quote_type, .. } => {
            match quote_type {
                QuoteType::Double => payload.contains('"'),
                QuoteType::Single => payload.contains('\''),
                QuoteType::None => payload.contains(|c: char| c.is_whitespace()),
                QuoteType::Backtick => payload.contains('`'),
            }
        }
        XssContext::JavaScriptString { quote_type } => {
            match quote_type {
                QuoteType::Double => payload.contains('"') || payload.contains("</script>"),
                QuoteType::Single => payload.contains('\'') || payload.contains("</script>"),
                QuoteType::Backtick => payload.contains('`') || payload.contains("</script>"),
                QuoteType::None => false,
            }
        }
        XssContext::JavaScriptCode => true, // Already in executable context
        XssContext::Url { protocol_allowed } => {
            *protocol_allowed && (payload.starts_with("javascript:") || payload.starts_with("data:"))
        }
        XssContext::HtmlComment => payload.contains("-->"),
        XssContext::Css => payload.contains("</style>"),
        XssContext::Json => payload.contains('"'),
        XssContext::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_html_text_context() {
        let html = r#"<div>MARKER</div>"#;
        let analysis = classify_context(html, "MARKER");
        assert_eq!(analysis.context, XssContext::HtmlText);
    }
    
    #[test]
    fn test_attribute_context_double_quotes() {
        let html = r#"<input value="MARKER">"#;
        let analysis = classify_context(html, "MARKER");
        match analysis.context {
            XssContext::HtmlAttribute { quote_type, .. } => {
                assert_eq!(quote_type, QuoteType::Double);
            }
            _ => panic!("Expected HtmlAttribute context"),
        }
    }
    
    #[test]
    fn test_javascript_string_context() {
        let html = r#"<script>var x = "MARKER";</script>"#;
        let analysis = classify_context(html, "MARKER");
        match analysis.context {
            XssContext::JavaScriptString { .. } => {}
            _ => panic!("Expected JavaScriptString context, got {:?}", analysis.context),
        }
    }
    
    #[test]
    fn test_html_encoded() {
        let html = r#"<div>&lt;MARKER&gt;</div>"#;
        let analysis = classify_context(html, "<MARKER>");
        assert!(analysis.encoding_detected);
    }
}

