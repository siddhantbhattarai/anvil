use crate::reporting::model::{Finding, Severity};
use unicode_width::UnicodeWidthStr;

// ==============================
// BOX CONFIGURATION
// ==============================

const BOX_WIDTH: usize = 70;
const INNER_WIDTH: usize = BOX_WIDTH - 2;

// ==============================
// WIDTH HANDLING
// ==============================

fn visual_width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

// ==============================
// BOX RENDERING HELPERS
// ==============================

fn top_border() -> String {
    format!("╔{}╗", "═".repeat(INNER_WIDTH))
}

fn middle_border() -> String {
    format!("╠{}╣", "═".repeat(INNER_WIDTH))
}

fn bottom_border() -> String {
    format!("╚{}╝", "═".repeat(INNER_WIDTH))
}

/// Left-aligned box line (emoji-safe)
fn box_line(content: &str) -> String {
    // SAFETY: isolate content from borders
    let safe_content = format!(" {} ", content);
    let width = visual_width(&safe_content);

    let padding = INNER_WIDTH.saturating_sub(width);
    format!("║{}{}║", safe_content, " ".repeat(padding))
}

/// Centered box line (emoji-safe)
fn box_line_centered(content: &str) -> String {
    let safe_content = format!(" {} ", content);
    let width = visual_width(&safe_content);

    if width >= INNER_WIDTH {
        return box_line(content);
    }

    let remaining = INNER_WIDTH - width;
    let left = remaining / 2;
    let right = remaining - left;

    format!(
        "║{}{}{}║",
        " ".repeat(left),
        safe_content,
        " ".repeat(right)
    )
}

// ==============================
// MAIN REPORT RENDERER
// ==============================

pub fn render(findings: &[Finding]) {
    // ------------------------------
    // NO FINDINGS CASE
    // ------------------------------
    if findings.is_empty() {
        println!("\n{}", top_border());
        println!("{}", box_line_centered("🎉 SCAN COMPLETE"));
        println!("{}", middle_border());
        println!("{}", box_line("✅ No vulnerabilities detected"));
        println!("{}", box_line("✅ All tested endpoints appear secure"));
        println!("{}\n", bottom_border());
        return;
    }

    // ------------------------------
    // SUMMARY COUNTS
    // ------------------------------
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high     = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium   = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    let low      = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();

    // ------------------------------
    // SUMMARY BOX
    // ------------------------------
    println!("\n{}", top_border());
    println!("{}", box_line_centered("SECURITY VULNERABILITIES DETECTED"));
    println!("{}", middle_border());

    println!("{}", box_line(&format!("Total Findings: {}", findings.len())));

    if critical > 0 {
        println!("{}", box_line(&format!("🔴 Critical: {}", critical)));
    }
    if high > 0 {
        println!("{}", box_line(&format!("🟠 High: {}", high)));
    }
    if medium > 0 {
        println!("{}", box_line(&format!("🟡 Medium: {}", medium)));
    }
    if low > 0 {
        println!("{}", box_line(&format!("🟢 Low: {}", low)));
    }

    println!("{}\n", bottom_border());

    // ------------------------------
    // DETAILED FINDINGS
    // ------------------------------
    for (idx, f) in findings.iter().enumerate() {
        println!("{}", "═".repeat(80));
        println!("FINDING #{}: {} [{}]", idx + 1, f.vuln_type, f.severity);
        println!("{}", "═".repeat(80));

        println!("\n📍 VULNERABILITY DETAILS:");
        println!("   Type:       {}", f.vuln_type);
        println!("   Technique:  {}", f.technique);
        println!("   CWE:        {}", f.cwe);
        if let Some(cvss) = f.cvss_score {
            println!("   CVSS Score: {:.1}/10.0", cvss);
        }
        println!("   Severity:   {}", f.severity);
        println!("   Confidence: {:.0}%", f.confidence * 100.0);

        println!("\n🎯 LOCATION:");
        println!("   Endpoint:   {} {}", f.http_method, f.endpoint);
        if let Some(param) = &f.parameter {
            println!("   Parameter:  {}", param);
        }
        if let Some(db) = &f.database {
            println!("   Database:   {}", db);
        }

        println!("\n🔍 EVIDENCE:");
        for line in f.evidence.lines() {
            println!("   {}", line);
        }

        if let Some(payload) = &f.payload_sample {
            println!("\n💉 PAYLOAD SAMPLE:");
            println!("   {}", payload);
        }

        println!("\n📋 DESCRIPTION:");
        for line in f.description.lines() {
            if !line.trim().is_empty() {
                println!("   {}", line.trim());
            }
        }

        println!("\n💥 IMPACT:");
        for line in f.impact.lines() {
            if !line.trim().is_empty() {
                println!("   {}", line.trim());
            }
        }

        println!("\n🛠️ REMEDIATION:");
        for line in f.remediation.lines() {
            if !line.trim().is_empty() {
                println!("   {}", line);
            }
        }

        println!("\n📚 REFERENCES:");
        for (i, reference) in f.references.iter().enumerate() {
            println!("   [{}] {}", i + 1, reference);
        }

        println!();
    }

    // ------------------------------
    // FINAL RECOMMENDATIONS
    // ------------------------------
    println!("{}", "═".repeat(80));
    println!("RECOMMENDATIONS:");
    println!("{}", "═".repeat(80));
    println!("1. Address CRITICAL and HIGH severity findings immediately");
    println!("2. Follow remediation steps for each vulnerability");
    println!("3. Re-scan after fixes to verify resolution");
    println!("4. Implement defense-in-depth (CSP, WAF, hardening)");
    println!("5. Integrate ANVIL into your SDLC");
    println!("{}", "═".repeat(80));
}
