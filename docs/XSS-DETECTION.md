# ANVIL XSS Detection - Professional Evidence-Driven Methodology

## Table of Contents
- [Overview](#overview)
- [Core Principle](#core-principle)
- [5-Stage Detection Pipeline](#5-stage-detection-pipeline)
- [Output Modes](#output-modes)
- [XSS Types](#xss-types)
- [Usage Examples](#usage-examples)
- [Classification System](#classification-system)
- [Confidence Scoring](#confidence-scoring)
- [Professional Features](#professional-features)
- [Comparison with Other Tools](#comparison-with-other-tools)

---

## Overview

ANVIL's XSS detection engine implements professional pentesting methodology where vulnerabilities are reported **only when untrusted input demonstrably crosses trust boundaries and reaches browser-executable contexts without sufficient encoding**.

### Key Differentiators
- ✅ **Reflection ≠ Execution**: Never reports XSS based on reflection alone
- ✅ **Evidence-driven**: Explicit proof at every stage
- ✅ **Zero false positives**: Multiple validation checkpoints
- ✅ **Professional classification**: "Confirmed" vs "Likely Exploitable"
- ✅ **Interaction-aware**: Detects if user action is required
- ✅ **Context-first**: Validates encoding appropriateness for context

---

## Core Principle

**Reflection ≠ Execution**

Many scanners report XSS when input is merely reflected in the response. ANVIL verifies:
1. Input reaches response (reflection)
2. Encoding is absent or incorrect for the context
3. Payload can break out of its container
4. Payload would actually execute JavaScript

### Example: False Positive vs Real XSS

```
Input: <script>alert(1)</script>

❌ FALSE POSITIVE (reported by naive scanners):
Response: <textarea><script>alert(1)</script></textarea>
Issue: Reflected but trapped in non-executable <textarea>

✅ REAL XSS (reported by ANVIL):
Response: <div><script>alert(1)</script></div>
Evidence: Unencoded in HTML context, will execute
```

---

## 5-Stage Detection Pipeline

### Stage 1: Data Reachability
**Purpose**: Confirm user input reaches the response

```bash
# ANVIL sends benign marker
Marker: ANVIL_REFLECTION_TEST_12345

# If marker appears in response → proceed to Stage 2
# If not → parameter is safe (not reflected)
```

**Output**:
- Verbose mode: Shows reflection confirmation
- Default mode: Silent (only final verdict shown)

---

### Stage 2: Context Classification
**Purpose**: Determine exact execution context

**Contexts Detected**:
- HTML text content (`<div>USER_INPUT</div>`)
- HTML attribute (`<img src="USER_INPUT">`)
- JavaScript string (`var x = "USER_INPUT"`)
- JavaScript code (`var x = USER_INPUT`)
- URL context (`<a href="USER_INPUT">`)
- CSS context (`<style>USER_INPUT</style>`)
- HTML comment (`<!-- USER_INPUT -->`)
- Non-executable containers (`<textarea>USER_INPUT</textarea>`)

**Confidence Scoring**:
- Each context classification has 80-95% confidence
- Used to validate detection accuracy

---

### Stage 3: Encoding Assessment
**Purpose**: Check if encoding is appropriate for the context

**Context-Specific Requirements**:

| Context | Required Encoding | Example |
|---------|------------------|---------|
| HTML Text | HTML entities (`&lt; &gt;`) | `<div>&lt;script&gt;</div>` |
| HTML Attribute | HTML + quoted | `<img src="&lt;script&gt;">` |
| JavaScript String | JS escaping (`\x3C`) | `var x = "\x3Cscript\x3E"` |
| URL | URL encoding (`%3C%3E`) | `href="search?q=%3Cscript%3E"` |

**Validation Logic**:
```
IF encoding matches context → Safe (stop here)
IF encoding missing/wrong → Continue to Stage 4
```

---

### Stage 4: Structural Breakout Verification
**Purpose**: Prove payload can escape its container

**Explicit Checkpoints**:
- ❌ Trapped in `<textarea>`, `<title>`, `<noscript>`
- ❌ Trapped in HTML comments `<!-- -->`
- ❌ Inside quoted attribute without breakout
- ✅ Direct `<script>` tag in HTML context
- ✅ Event handler in HTML tag
- ✅ Successful attribute quote breakout

**Example Breakout Evidence**:
```
LOW Security:
  Evidence: "Direct <script> tag injection in HTML context"
  
MEDIUM Security:
  Evidence: "Event handler introduced in HTML tag context"
```

---

### Stage 5: Dual Confidence Scoring
**Purpose**: Calculate independent confidence metrics

**Two Scores Calculated**:

1. **Injection Confidence** (0-100%)
   - Did input reach executable context?
   - Is encoding missing/incorrect?
   - Threshold: ≥70% to continue

2. **Execution Likelihood** (0-100%)
   - Would payload actually execute?
   - Are there interaction requirements?
   - Threshold: ≥70% to report as XSS

**Classification Logic**:
```
IF injection ≥90% AND execution ≥90% AND no_interaction:
    → "Confirmed XSS" (CRITICAL)

ELIF injection ≥70% AND execution ≥70%:
    → "Likely Exploitable XSS" (MEDIUM/HIGH)

ELSE:
    → Not reported as XSS
```

---

## Output Modes

ANVIL provides three intentional output modes based on user intent:

### 1. Default Mode (Clean Summary)

**Command**:
```bash
anvil -t "https://example.com/search?q=test" -p q --xss
```

**Output**:
```
[+] Confirmed XSS detected
    Endpoint  : /search
    Parameter : q
    Severity  : 🔴 CRITICAL
    Confidence: 95%
    Type      : Direct execution
    Evidence  : Direct <script> tag injection in HTML context
```

**Use Case**: Quick pentests, scanning multiple targets, immediate actionability

**Characteristics**:
- No phase logging
- No methodology details
- No payload information
- Just the essential verdict

---

### 2. Verbose Mode (Full Methodology)

**Command**:
```bash
anvil -t "https://example.com/search?q=test" -p q --xss --verbose
```

**Output**:
```
[Phase 1] Testing for reflection...
  → Reflection confirmed - marker found in response

[Phase 2] Testing for XSS execution...
  Testing 7 payloads with execution validation
  ✓ Context breakout confirmed: Direct <script> tag injection

  ✗ CONFIRMED XSS DETECTED
    Payload #1: script tag
    Payload: <script>document.ANVIL_XSS_EXEC_1=1</script>
    Execution Confidence: 95%
    Breakout: Direct <script> tag injection in HTML context

╔════════════════════════════════════════════════════════╗
║  SECURITY VULNERABILITIES DETECTED                     ║
╠════════════════════════════════════════════════════════╣
║  Total Findings: 1                                     ║
║  🔴 Critical: 1  ← IMMEDIATE ACTION REQUIRED          ║
╚════════════════════════════════════════════════════════╝

(Full detailed report with evidence chain, impact, remediation...)
```

**Use Case**: Understanding detection logic, debugging, learning

**Characteristics**:
- Shows all 5 stages
- Payload details
- Confidence calculations
- Complete report to stdout

---

### 3. Report Mode (Documentation)

**Command**:
```bash
# Text report
anvil -t "https://example.com/search?q=test" -p q --xss -o xss-report.txt

# JSON report
anvil -t "https://example.com/search?q=test" -p q --xss --format json -o results.json
```

**Stdout Output**:
```
[+] Confirmed XSS detected
    (clean summary)

📄 Full report saved to: xss-report.txt
```

**Report File Contains**:
- **WHY THIS IS XSS**: One-line justification
- **Evidence Chain**: All 5 stages documented
- **Classification**: Confirmed vs Likely Exploitable
- **Context Details**: Breakout evidence
- **CVSS Score**: Risk rating
- **Impact Analysis**: Attacker capabilities
- **Remediation**: Step-by-step fixes with code examples
- **References**: OWASP, CWE, PortSwigger links

**Use Case**: Client deliverables, compliance documentation, knowledge sharing

---

## XSS Types

### 1. Reflected XSS (Default)

**Detection**: Execution in same response as injection

**Command**:
```bash
anvil -t "https://example.com/search?q=test" -p q --xss
```

**Example**:
```
Input: q=<script>alert(1)</script>
Response: <div>Results for: <script>alert(1)</script></div>
Detection: Immediate reflection + execution
```

---

### 2. Stored/Persistent XSS

**Detection**: Payload persists and executes in different requests

**Command**:
```bash
anvil -t "https://example.com/comment" -p message --xss-stored
```

**Methodology**:
1. Inject unique marker with payload
2. Crawl application to find reflection
3. Verify execution in different context
4. Track correlation between injection and execution

**Example**:
```
POST /comment: message=<script>alert(1)</script>
GET /comments: Payload executes on page load
Detection: Cross-request persistence + execution
```

---

### 3. DOM-Based XSS

**Detection**: Client-side source-to-sink analysis

**Command**:
```bash
anvil -t "https://example.com/page" --xss-dom
```

**Sources Tracked**:
- `location.hash`, `location.search`
- `document.URL`, `document.referrer`
- `window.name`, `localStorage`, `sessionStorage`

**Sinks Tracked**:
- `eval()`, `setTimeout()`, `setInterval()`
- `innerHTML`, `outerHTML`, `document.write()`
- `location.href`, `location.assign()`

**Example**:
```javascript
// Source: URL fragment
var name = location.hash.substring(1);

// Sink: innerHTML
document.getElementById('output').innerHTML = name;

// Payload: #<img src=x onerror=alert(1)>
```

---

### 4. Blind XSS

**Detection**: Out-of-band callback confirmation

**Command**:
```bash
anvil -t "https://example.com/support" -p message --xss-blind --callback attacker.com
```

**Methodology**:
1. Inject payload with unique correlation ID
2. Payload calls back to attacker server
3. Correlation ID confirms which injection succeeded
4. Tracks async/delayed execution

**Payloads**:
```javascript
<script src="https://attacker.com/xss/CORRELATION_ID"></script>
<img src="https://attacker.com/xss/CORRELATION_ID">
```

**Use Case**: Admin panels, support tickets, logs, review systems

---

## Classification System

ANVIL uses precise classification to avoid overstating exploitability:

### Confirmed XSS

**Criteria**:
- Execution confidence ≥ 90%
- No user interaction required
- Context breakout verified
- Direct, unambiguous execution

**Example**:
```
Classification: Confirmed XSS
Severity: 🔴 CRITICAL
CVSS: 9.6/10.0
Evidence: Direct <script> tag injection in HTML context
Type: Direct execution
```

**Exploitability**: Immediate, no barriers

---

### Likely Exploitable XSS

**Criteria**:
- Execution confidence 70-89%
- OR requires technical interaction (image load error)
- OR context-dependent (browser behavior)
- Breakout verified but execution may vary

**Example**:
```
Classification: Likely Exploitable XSS
Severity: 🟡 MEDIUM
CVSS: 6.8/10.0
Evidence: Event handler introduced in HTML tag context
Type: Interaction-required (image load error)
```

**Exploitability**: High in targeted attacks, lower for opportunistic

---

### Why This Distinction Matters

**In Enterprise Environments**:
- Prevents disputes ("Why is this marked Critical?")
- Increases finding credibility
- Aligns with how senior pentesters classify

**In Real-World Testing**:
- DVWA LOW: "Confirmed XSS" (direct `<script>`)
- DVWA MEDIUM: "Likely Exploitable" (`<img onerror>`)
- Both are valid XSS, but exploitability differs

---

## Confidence Scoring

ANVIL decouples execution confidence from severity:

### Confidence Calculation

**Base Factors** (starts at 70% if breakout confirmed):
- +20% if `<script>` tags completely unmodified
- +5% if no HTML encoding detected anywhere
- +3% if payload appears multiple times
- +2% if early in document (faster execution)

**Capped at 99%** (never 100% without browser execution)

### Severity Calculation

**Independent from confidence** - factors in interaction:

```
IF Confirmed XSS (90%+) AND no_interaction:
    Severity: CRITICAL, CVSS: 9.6

ELIF 85%+ AND no_interaction:
    Severity: HIGH, CVSS: 8.2

ELIF 70%+ OR requires_interaction:
    Severity: MEDIUM, CVSS: 6.8 (reduced for interaction)

ELSE:
    Severity: LOW, CVSS: 5.3
```

### Example: Same Confidence, Different Severity

```
Payload A: <script>alert(1)</script>
  Confidence: 95%
  Interaction: None required
  Severity: CRITICAL (9.6)

Payload B: <img src=x onerror=alert(1)>
  Confidence: 75%
  Interaction: Image load error required
  Severity: MEDIUM (6.8)
```

---

## Professional Features

### 1. Interaction Requirement Detection

**Categories**:
- **None**: `<script>`, `<body onload=>`
- **Technical**: `<img onerror=>` (image load error)
- **User**: `onclick`, `onmouseover`, `onfocus`
- **Autofocus Bypass**: `onfocus + autofocus` (counts as "none")

**Labeling**:
```
Type: Direct execution (no interaction)
Type: Interaction-required (image load error)
Type: Interaction-required (user click)
```

---

### 2. Context Breakout Verification

**Checkpoint Before Reporting**:
- Not just "payload reflected"
- Not just "tags present"
- **Explicit proof of breakout**

**Breakout Evidence Examples**:
```
✓ Direct <script> tag injection in HTML context
✓ Event handler introduced in HTML tag context
✓ Attribute quote breakout successful
✗ Payload trapped inside <textarea> container
✗ Payload inside quoted attribute without breakout
```

---

### 3. "Why This Is XSS" Justification

**Format**:
```
Untrusted input reached [CONTEXT] without [ENCODING],
[BREAKOUT EVIDENCE] and introduced executable code via [TECHNIQUE]
```

**Examples**:
```
Confirmed XSS:
  "Untrusted input reached HTML context without proper encoding,
   direct <script> tag injection in html context and introduced
   executable code via script tag"

Likely Exploitable:
  "Untrusted input reached HTML context without proper encoding,
   event handler introduced in html tag context and introduced
   executable code via img onerror"
```

**Benefit**: Self-explanatory to non-security stakeholders

---

### 4. CSP Detection

**Implementation**: CSP as exploitability modifier, not dismissal

**Detection**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

**Impact on Severity**:
- XSS found + CSP blocks inline scripts → severity reduced
- XSS found + no CSP → severity as calculated
- XSS found + weak CSP (`unsafe-inline`) → severity unchanged

**Reporting**:
```
CSP Present: Yes
Blocks inline scripts: Yes
Exploitability Impact: HIGH - CSP significantly reduces exploitability
```

---

## Usage Examples

### Basic XSS Detection

```bash
# Single parameter
anvil -t "https://example.com/search?q=test" -p q --xss

# Auto-detect parameters
anvil -t "https://example.com/search?q=test&lang=en" --xss

# With authentication
anvil -t "https://example.com/search?q=test" -p q --xss \
  --cookie "session=abc123"
```

### Verbose Mode (See Methodology)

```bash
anvil -t "https://example.com/search?q=test" -p q --xss --verbose
```

### Generate Report

```bash
# Text report
anvil -t "https://example.com/search?q=test" -p q --xss \
  -o xss-report.txt

# JSON report for automation
anvil -t "https://example.com/search?q=test" -p q --xss \
  --format json -o results.json
```

### Stored XSS

```bash
anvil -t "https://example.com/comment" -p message --xss-stored
```

### All XSS Types

```bash
anvil -t "https://example.com/page" --xss-all
```

### Custom Callback for Blind XSS

```bash
anvil -t "https://example.com/support" -p message \
  --xss-blind --callback attacker.com
```

### With Rate Limiting

```bash
anvil -t "https://example.com/search?q=test" -p q --xss \
  --rate 5  # 5 requests per second
```

---

## Comparison with Other Tools

| Feature | ANVIL | Burp Scanner | OWASP ZAP | XSStrike |
|---------|-------|-------------|-----------|----------|
| **Reflection ≠ Execution** | ✅ Yes | ❌ No | ❌ No | ✅ Yes |
| **Context Breakout Verification** | ✅ Explicit | ⚠️ Basic | ⚠️ Basic | ✅ Good |
| **"Confirmed" vs "Likely" Classification** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Interaction Detection** | ✅ Yes | ⚠️ Basic | ❌ No | ❌ No |
| **WHY THIS IS XSS Justification** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Professional Reporting** | ✅ Yes | ✅ Yes | ⚠️ Basic | ❌ No |
| **False Positive Rate** | ✅ Very Low | ❌ High | ❌ High | ⚠️ Medium |
| **Output Modes** | ✅ 3 modes | ⚠️ 1 mode | ⚠️ 1 mode | ⚠️ 1 mode |
| **Cost** | ✅ Free | ❌ $449/year | ✅ Free | ✅ Free |

---

## Best Practices

### 1. Start with Default Mode
```bash
anvil -t URL -p param --xss
```
- Get immediate signal
- No scrolling fatigue
- Move quickly through targets

### 2. Use Verbose for Learning
```bash
anvil -t URL -p param --xss --verbose
```
- Understand methodology
- Debug unexpected results
- Learn pentesting techniques

### 3. Generate Reports for Clients
```bash
anvil -t URL -p param --xss -o client-report.txt
```
- Professional documentation
- Complete evidence chain
- Remediation guidance included

### 4. Automate with JSON
```bash
anvil -t URL -p param --xss --format json | jq '.findings[]'
```
- Parse in CI/CD pipelines
- Integrate with other tools
- Track findings over time

### 5. Combine with Authentication
```bash
anvil -t URL -p param --xss \
  --cookie "session=xyz" \
  -H "Authorization: Bearer token"
```
- Test authenticated pages
- Access control bypass scenarios

---

## Troubleshooting

### No XSS Detected but Expected

**Check**:
1. Is input actually reflected? (use `--verbose`)
2. Is encoding appropriate for context?
3. Is breakout actually possible?
4. Check confidence threshold (≥70% required)

**Verbose Output Helps**:
```bash
anvil -t URL -p param --xss --verbose
# Look for:
# - "No reflection detected" → input not echoed
# - "properly encoded/escaped" → safe encoding present
# - "trapped in safe context" → container blocks execution
```

### False Negatives

**ANVIL prioritizes accuracy over volume**:
- Won't report XSS if breakout isn't verified
- Requires 70%+ confidence threshold
- This is intentional (zero false positives)

**If you believe there's a real XSS**:
1. Use `--verbose` to see why it wasn't reported
2. Check if encoding is actually correct
3. Verify context breakout manually

---

## Advanced Topics

### Custom Payload Lists

```bash
# Coming soon: custom payload files
anvil -t URL -p param --xss --payload-file custom-xss.txt
```

### Context-Specific Testing

```bash
# Target specific context
anvil -t URL -p param --xss --xss-context attribute
anvil -t URL -p param --xss --xss-context js_string
```

### Maximum Payloads

```bash
# Limit payload count for faster scans
anvil -t URL -p param --xss --max-payloads 10
```

---

## References

- **OWASP XSS Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **CWE-79**: https://cwe.mitre.org/data/definitions/79.html
- **PortSwigger XSS**: https://portswigger.net/web-security/cross-site-scripting
- **DOM XSS Wiki**: https://github.com/wisec/domxsswiki

---

## Summary

ANVIL's XSS detection represents professional pentesting methodology:

✅ **Evidence-driven**: Explicit proof at every stage  
✅ **Context-first**: Validates encoding for actual context  
✅ **Classification precision**: "Confirmed" vs "Likely"  
✅ **Zero false positives**: Multiple validation checkpoints  
✅ **Professional output**: Three modes for different intents  
✅ **Defensible findings**: One-line "WHY THIS IS XSS" justification  

**Principle**: Detection stays complex, output becomes intentional.

