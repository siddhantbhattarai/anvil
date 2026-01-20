// DOM-based XSS Detection Module
// Analyzes client-side JavaScript for source-to-sink data flows

use scraper::{Html, Selector};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DomXssSink {
    pub sink_type: String,
    pub dangerous_function: String,
    pub line_context: String,
}

#[derive(Debug, Clone)]
pub struct DomXssSource {
    pub source_type: String,
    pub property: String,
}

#[derive(Debug, Clone)]
pub struct DomXssFlow {
    pub source: DomXssSource,
    pub sink: DomXssSink,
    pub confidence: f32,
    pub exploitable: bool,
}

/// Analyze JavaScript for DOM-based XSS vulnerabilities
pub fn analyze_dom_xss(html: &str, js_code: &str) -> Vec<DomXssFlow> {
    let mut flows = Vec::new();
    
    // Extract sources from the page
    let sources = extract_sources(js_code);
    
    // Extract sinks from the page
    let sinks = extract_sinks(js_code);
    
    // Correlate sources to sinks
    for source in &sources {
        for sink in &sinks {
            if could_flow_to_sink(&source.property, &sink.line_context) {
                let confidence = calculate_flow_confidence(source, sink, js_code);
                
                flows.push(DomXssFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    confidence,
                    exploitable: confidence > 0.6,
                });
            }
        }
    }
    
    flows
}

fn extract_sources(js_code: &str) -> Vec<DomXssSource> {
    let mut sources = Vec::new();
    
    // Common DOM XSS sources
    let source_patterns = [
        ("location.hash", "URL Fragment"),
        ("location.search", "URL Query String"),
        ("location.href", "URL"),
        ("document.URL", "Document URL"),
        ("document.documentURI", "Document URI"),
        ("document.referrer", "Referrer"),
        ("window.name", "Window Name"),
        ("document.cookie", "Cookie"),
        ("localStorage", "Local Storage"),
        ("sessionStorage", "Session Storage"),
    ];
    
    for (property, source_type) in source_patterns {
        if js_code.contains(property) {
            sources.push(DomXssSource {
                source_type: source_type.to_string(),
                property: property.to_string(),
            });
        }
    }
    
    sources
}

fn extract_sinks(js_code: &str) -> Vec<DomXssSink> {
    let mut sinks = Vec::new();
    
    // Common dangerous sinks
    let sink_patterns = [
        ("innerHTML", "HTML Injection"),
        ("outerHTML", "HTML Injection"),
        ("document.write", "Document Write"),
        ("document.writeln", "Document Write"),
        ("eval(", "Code Execution"),
        ("setTimeout(", "Code Execution"),
        ("setInterval(", "Code Execution"),
        ("Function(", "Code Execution"),
        ("location.href", "Open Redirect"),
        ("location.assign", "Open Redirect"),
        ("location.replace", "Open Redirect"),
        (".html(", "jQuery HTML"),
        (".append(", "jQuery Append"),
    ];
    
    for line in js_code.lines() {
        for (function, sink_type) in sink_patterns {
            if line.contains(function) {
                sinks.push(DomXssSink {
                    sink_type: sink_type.to_string(),
                    dangerous_function: function.to_string(),
                    line_context: line.trim().to_string(),
                });
            }
        }
    }
    
    sinks
}

fn could_flow_to_sink(source_property: &str, sink_line: &str) -> bool {
    // Simple heuristic: check if the source property name appears in the sink line
    // In production, this would use proper data flow analysis
    
    let source_var = source_property.split('.').last().unwrap_or(source_property);
    sink_line.contains(source_var) || sink_line.contains("hash") || sink_line.contains("search")
}

fn calculate_flow_confidence(source: &DomXssSource, sink: &DomXssSink, js_code: &str) -> f32 {
    let mut confidence: f32 = 0.5;
    
    // Higher confidence for direct flows
    if sink.line_context.contains(&source.property) {
        confidence += 0.3;
    }
    
    // Higher confidence for dangerous sinks
    if sink.sink_type.contains("HTML Injection") || sink.sink_type.contains("Code Execution") {
        confidence += 0.1;
    }
    
    // Lower confidence if sanitization detected
    if js_code.contains("encodeURIComponent") || js_code.contains("escape") {
        confidence -= 0.2;
    }
    
    confidence.min(0.95).max(0.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_source_extraction() {
        let js = "var hash = location.hash; var search = location.search;";
        let sources = extract_sources(js);
        assert!(!sources.is_empty());
    }
    
    #[test]
    fn test_sink_extraction() {
        let js = "element.innerHTML = data;";
        let sinks = extract_sinks(js);
        assert!(!sinks.is_empty());
    }
}
