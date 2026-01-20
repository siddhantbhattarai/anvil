# ANVIL Quick Start Guide

## Installation

```bash
cd /home/shiddhant/anvil
cargo build --release
cargo install --path .
```

## Basic Usage

### 1. Detect SQL Injection (Default: Text Report)

```bash
anvil -t "http://target.com/page?id=1" -p id --sqli
```

**Output:** Professional text report to console with:
- CWE-89 classification
- CVSS scoring
- Impact analysis
- 6-layer remediation strategy
- OWASP/CWE references

---

### 2. Save Text Report to File

```bash
anvil -t "http://target.com/page?id=1" -p id --sqli -o report.txt
```

**Output:** `report.txt` with full vulnerability details

---

### 3. Generate JSON Report

```bash
anvil -t "http://target.com/page?id=1" -p id --sqli --format json
```

**Output:** Structured JSON to stdout (pipe to `jq`, upload to SIEM, etc.)

---

### 4. Save JSON Report to File

```bash
anvil -t "http://target.com/page?id=1" -p id --sqli --format json -o results.json
```

**Output:** `results.json` with scan metadata and findings

---

### 5. Authenticated Scanning

```bash
anvil -t "http://dvwa.local/vulnerabilities/sqli/?id=1" \
  -p id \
  --cookie "PHPSESSID=abc123; security=low" \
  --sqli
```

**Tip:** Get cookie from browser DevTools → Application → Cookies

---

### 6. Database Enumeration + Report

```bash
# Enumerate databases
anvil -t "http://target.com/page?id=1" -p id --sqli --dbs -o report.txt

# Enumerate tables in a database
anvil -t "http://target.com/page?id=1" -p id --sqli -D mydb --tables

# Dump table data
anvil -t "http://target.com/page?id=1" -p id --sqli -D mydb -T users --dump
```

---

### 7. Full Enumeration + JSON Report

```bash
anvil -t "http://target.com/page?id=1" \
  -p id \
  --sqli --dbs \
  --format json \
  -o comprehensive_report.json
```

**Output:** Detects SQLi + enumerates databases + generates JSON report

---

## Report Formats

### Text Report (Human-Readable)

```
╔════════════════════════════════════════════════════════════════════╗
║                  ⚠️  SECURITY VULNERABILITIES DETECTED             ║
╠════════════════════════════════════════════════════════════════════╣
║  Total Findings: 1                                                 ║
║  🔴 Critical: 1  ← IMMEDIATE ACTION REQUIRED                       ║
╚════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════
FINDING #1: SQL Injection [🔴 CRITICAL]
═══════════════════════════════════════════════════════════════════════

📍 VULNERABILITY DETAILS:
   Type:       SQL Injection
   Technique:  Time-based
   CWE:        CWE-89
   CVSS Score: 9.8/10.0
   Confidence: 95%

🎯 LOCATION:
   Endpoint:   GET http://target.com/page?id=1
   Parameter:  id
   Database:   MySQL

🔍 EVIDENCE:
   Injected latency mean 5234.56ms vs baseline 123.45ms

💥 IMPACT:
   CRITICAL RISK: An attacker exploiting this vulnerability could:
   • Read sensitive data (credentials, PII, financial data)
   • Modify or delete database contents
   • Bypass authentication
   • Execute administrative operations
   ...

🛠️  REMEDIATION:
   IMMEDIATE ACTIONS REQUIRED:

   1. USE PARAMETERIZED QUERIES (Primary Defense)
      ❌ NEVER: query = "SELECT * FROM users WHERE id = '" + userId + "'"
      ✅ ALWAYS: Use parameterized queries with placeholders

   2. INPUT VALIDATION (Defense in Depth)
      • Whitelist allowed characters
      • Type checking (numeric IDs should be integers)
      • Length limits
      ...

📚 REFERENCES:
   [1] https://owasp.org/www-community/attacks/SQL_Injection
   [2] https://cwe.mitre.org/data/definitions/89.html
   ...
```

### JSON Report (Machine-Parseable)

```json
{
  "scan_metadata": {
    "tool": "ANVIL",
    "version": "0.1.0",
    "scan_date": "2025-12-16T10:30:00Z",
    "report_format": "application/json"
  },
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "vuln_type": "SQL Injection",
      "technique": "Time-based",
      "endpoint": "http://target.com/page?id=1",
      "parameter": "id",
      "confidence": 0.95,
      "severity": "Critical",
      "cwe": "CWE-89",
      "cvss_score": 9.8,
      "description": "SQL Injection vulnerability detected...",
      "impact": "CRITICAL RISK: An attacker could...",
      "remediation": "IMMEDIATE ACTIONS REQUIRED:\n1. USE PARAMETERIZED QUERIES...",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html"
      ],
      "payload_sample": "' AND SLEEP(5)--",
      "evidence": "Statistical analysis..."
    }
  ]
}
```

---

## Viewing JSON Reports

```bash
# Pretty print full report
cat results.json | jq .

# View summary only
jq '.summary' results.json

# View first finding
jq '.findings[0]' results.json

# Extract specific fields
jq '.findings[0] | {severity, confidence, cvss_score}' results.json

# Check for critical vulnerabilities
jq '.summary.critical' results.json
```

---

## CI/CD Integration

```bash
#!/bin/bash
# Fail build if critical vulnerabilities found

anvil -t $TARGET_URL --sqli --format json -o anvil_report.json

CRITICAL=$(jq '.summary.critical' anvil_report.json)
HIGH=$(jq '.summary.high' anvil_report.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ CRITICAL vulnerabilities found! Failing build."
  jq '.findings[] | select(.severity == "Critical") | {vuln_type, endpoint}' anvil_report.json
  exit 1
fi

if [ "$HIGH" -gt 0 ]; then
  echo "⚠️  HIGH severity vulnerabilities found. Review required."
  jq '.findings[] | select(.severity == "High") | {vuln_type, endpoint}' anvil_report.json
fi

echo "✅ No critical vulnerabilities detected"
```

---

## Common Options

| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target URL | `-t http://example.com` |
| `-p, --param` | Parameter to test | `-p id` |
| `--sqli` | Enable SQLi detection | `--sqli` |
| `--cookie` | Authentication cookie | `--cookie "PHPSESSID=abc123"` |
| `--format` | Output format (text/json) | `--format json` |
| `-o, --output` | Output file | `-o report.json` |
| `--dbs` | Enumerate databases | `--dbs` |
| `-D` | Specify database | `-D mydb` |
| `--tables` | Enumerate tables | `--tables` |
| `-T` | Specify table | `-T users` |
| `--dump` | Dump table data | `--dump` |
| `--level` | Test level (1-5) | `--level 3` |
| `--risk` | Risk level (1-3) | `--risk 2` |

---

## Help & Documentation

```bash
# Full help
anvil --help

# View specific documentation
cat docs/USAGE.md         # CLI reference
cat docs/SQL-INJECTION.md # Detection techniques
cat docs/EXPLOITATION.md  # Enumeration guide
cat docs/REPORTING.md     # Report format details
```

---

## Example: DVWA Testing

```bash
# Step 1: Get session cookie from browser
# Open DVWA in browser → Login → DevTools → Application → Cookies

# Step 2: Run ANVIL
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -p id \
  --cookie "PHPSESSID=YOUR_SESSION_ID; security=low" \
  --sqli --dbs \
  --format json \
  -o dvwa_report.json

# Step 3: View results
cat dvwa_report.json | jq .
```

---

## What Makes ANVIL Reports Superior

### vs sqlmap
- ✅ CWE/CVSS classification (sqlmap = none)
- ✅ Detailed remediation guide (sqlmap = none)
- ✅ Impact analysis (sqlmap = none)
- ✅ Professional formatting (sqlmap = raw text)
- ✅ Database-specific code examples (sqlmap = none)

### vs Burp Scanner
- ✅ Database-specific remediation (Burp = generic)
- ✅ Statistical evidence (Burp = simple threshold)
- ✅ 6-layer defense guidance (Burp = basic)
- ✅ Free & open source (Burp = $$$)
- ✅ CLI automation (Burp = GUI-focused)

### vs Commercial Tools
- ✅ Transparent confidence scoring (others = vague)
- ✅ Explainable results (others = black box)
- ✅ No false positives (others = many)
- ✅ Fast execution (others = slow)
- ✅ Open source (others = proprietary)

---

## Support

- GitHub: https://github.com/siddhantbhattarai/anvil
- Docs: `/home/shiddhant/anvil/docs/`
- Issues: Report bugs and feature requests on GitHub

---

**ANVIL** - Enterprise-grade Adversarial Security Testing Framework

