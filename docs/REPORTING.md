# ANVIL Security Reporting

## Overview

ANVIL generates comprehensive, security-engineer-grade vulnerability reports with:
- **CWE/CVSS Classifications**: Industry-standard vulnerability identification
- **Detailed Impact Analysis**: Business and technical implications
- **Actionable Remediation**: Step-by-step fix instructions with code examples
- **Evidence & Proof**: Detailed technical evidence of each finding
- **Multiple Formats**: Text (human-readable) and JSON (machine-parseable)

## Report Features

### 📋 What's Included in Each Finding

1. **Vulnerability Classification**
   - Type (SQL Injection, XSS, etc.)
   - Technique (Boolean-based, Time-based, UNION, etc.)
   - CWE identifier (CWE-89 for SQLi)
   - CVSS score (0.0-10.0)
   - Severity level (Critical, High, Medium, Low, Info)
   - Confidence score (0-100%)

2. **Location Information**
   - Endpoint URL
   - HTTP method (GET, POST, etc.)
   - Vulnerable parameter
   - Database type (MySQL, PostgreSQL, etc.)

3. **Evidence**
   - Technical proof of vulnerability
   - Response analysis
   - Timing data for blind SQLi
   - Sample payload used

4. **Impact Analysis**
   - What an attacker could do
   - Data at risk
   - Potential business consequences

5. **Remediation Guidance**
   - **Parameterized Queries**: Primary defense with code examples
   - **Input Validation**: Secondary defense measures
   - **Least Privilege**: Database permission hardening
   - **WAF Deployment**: Defense-in-depth strategies
   - **Monitoring**: Detection and alerting recommendations

6. **References**
   - OWASP documentation
   - CWE/MITRE references
   - Security best practices

## Output Formats

### 1. Text Format (Default - Human-Readable)

Rich, formatted text report with:
- Color-coded severity indicators
- Organized sections with clear headings
- Easy-to-read remediation steps
- Professional formatting

```bash
# Display report in terminal
anvil -t http://target.com --sqli

# Save text report to file
anvil -t http://target.com --sqli -o report.txt
```

**Example Output:**
```
╔════════════════════════════════════════════════════════════════════╗
║                  ⚠️  SECURITY VULNERABILITIES DETECTED             ║
╠════════════════════════════════════════════════════════════════════╣
║  Total Findings: 2                                                 ║
║  🔴 Critical: 1  ← IMMEDIATE ACTION REQUIRED                       ║
║  🟠 High:     1                                                    ║
╚════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════
FINDING #1: SQL Injection [🔴 CRITICAL]
═══════════════════════════════════════════════════════════════════════

📍 VULNERABILITY DETAILS:
   Type:       SQL Injection
   Technique:  Time-based
   CWE:        CWE-89
   CVSS Score: 9.8/10.0
   Severity:   🔴 CRITICAL
   Confidence: 95%

🎯 LOCATION:
   Endpoint:   GET http://target.com/vulnerable.php?id=1
   Parameter:  id
   Database:   MySQL

🔍 EVIDENCE:
   Injected latency mean 5234.56ms vs baseline 123.45ms
   Signal ratio: 42.38 (high confidence time-based SQLi)

💉 PAYLOAD SAMPLE:
   ' AND SLEEP(5)--

📋 DESCRIPTION:
   SQL Injection vulnerability detected using Time-based technique on MySQL database.
   An attacker can inject malicious SQL commands into the 'id' parameter,
   potentially gaining unauthorized access to the database, modifying data,
   or executing administrative operations.

💥 IMPACT:
   CRITICAL RISK: An attacker exploiting this vulnerability could:
   • Read sensitive data from the database (user credentials, PII, financial data)
   • Modify or delete database contents
   • Bypass authentication and authorization mechanisms
   • Execute administrative operations on the database
   • In some cases, execute operating system commands (possible with this database)
   • Gain access to other internal systems

🛠️  REMEDIATION:
   IMMEDIATE ACTIONS REQUIRED:

   1. **USE PARAMETERIZED QUERIES (Primary Defense)**
      ❌ NEVER concatenate user input into SQL:
      query = "SELECT * FROM users WHERE id = '" + userId + "'"

      ✅ ALWAYS use parameterized queries:
      -- MySQL/MariaDB parameterized query:
      SELECT * FROM users WHERE id = ? AND status = ?

   2. **INPUT VALIDATION (Defense in Depth)**
      • Validate data type (e.g., numeric IDs should only contain digits)
      • Whitelist acceptable values where possible
      • Enforce strict length limits
      • Reject special characters if not needed: ' " ; -- /* */ xp_ sp_

   3. **LEAST PRIVILEGE PRINCIPLE**
      • Database user should have minimal permissions
      • READ-ONLY access for SELECT operations
      • No GRANT, DROP, CREATE permissions for application users
      • Disable xp_cmdshell, LOAD_FILE() and other dangerous functions

   4. **WEB APPLICATION FIREWALL (WAF)**
      • Deploy ModSecurity or cloud WAF (Cloudflare, AWS WAF)
      • Enable SQL injection rule sets (OWASP Core Rule Set)
      • Log and alert on suspicious patterns

   5. **SECURE CODING PRACTICES**
      • Use ORM frameworks (SQLAlchemy, Hibernate, Entity Framework)
      • Enable prepared statements by default
      • Escape output when displaying data
      • Implement CSRF tokens for GET requests

   6. **MONITORING & DETECTION**
      • Log all database queries with user context
      • Alert on unusual query patterns (UNION, SLEEP, @@version)
      • Monitor for authentication bypasses
      • Implement rate limiting on endpoints

   TESTING & VERIFICATION:
      • Re-scan with ANVIL after fixes: anvil -t <url> -p GET --sqli
      • Test with sqlmap for thorough validation
      • Perform manual penetration testing
      • Add security unit tests for input validation

📚 REFERENCES:
   [1] https://owasp.org/www-community/attacks/SQL_Injection
   [2] https://cwe.mitre.org/data/definitions/89.html
   [3] https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
   [4] https://portswigger.net/web-security/sql-injection

═══════════════════════════════════════════════════════════════════════
RECOMMENDATIONS:
═══════════════════════════════════════════════════════════════════════
1. Address CRITICAL and HIGH severity findings immediately
2. Follow the remediation steps for each vulnerability
3. Re-scan after implementing fixes to verify resolution
4. Implement a Web Application Firewall (WAF) for defense-in-depth
5. Conduct regular security testing as part of your SDLC
═══════════════════════════════════════════════════════════════════════
```

### 2. JSON Format (Machine-Parseable)

Structured JSON output for integration with:
- CI/CD pipelines
- Security dashboards
- Ticketing systems (Jira, ServiceNow)
- SIEM platforms

```bash
# Output JSON to stdout
anvil -t http://target.com --sqli --format json

# Save JSON report to file
anvil -t http://target.com --sqli --format json -o report.json
```

**JSON Structure:**
```json
{
  "scan_metadata": {
    "tool": "ANVIL",
    "version": "0.1.0",
    "scan_date": "2025-12-16T08:30:00Z",
    "report_format": "application/json"
  },
  "summary": {
    "total_findings": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "vuln_type": "SQL Injection",
      "technique": "Time-based",
      "endpoint": "http://target.com/vulnerable.php?id=1",
      "parameter": "id",
      "confidence": 0.95,
      "severity": "Critical",
      "evidence": "Injected latency mean 5234.56ms vs baseline 123.45ms...",
      "http_method": "GET",
      "database": "MySQL",
      "cwe": "CWE-89",
      "cvss_score": 9.8,
      "description": "SQL Injection vulnerability detected...",
      "impact": "CRITICAL RISK: An attacker exploiting this...",
      "remediation": "IMMEDIATE ACTIONS REQUIRED:\n1. USE PARAMETERIZED QUERIES...",
      "references": [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        ...
      ],
      "payload_sample": "' AND SLEEP(5)--"
    }
  ]
}
```

## Usage Examples

### Basic Scanning with Report

```bash
# Scan and display text report
anvil -t http://dvwa.local/vulnerabilities/sqli/?id=1 \
  --sqli \
  --cookie "PHPSESSID=abc123; security=low"

# Scan and save JSON report
anvil -t http://dvwa.local/vulnerabilities/sqli/?id=1 \
  --sqli \
  --cookie "PHPSESSID=abc123; security=low" \
  --format json \
  -o scan_results.json
```

### Full Enumeration with Report

```bash
# Detect + enumerate databases + generate report
anvil -t http://target.com/page?id=1 \
  -p id \
  --sqli \
  --dbs \
  -o full_report.txt

# Dump data and save JSON report for ticketing
anvil -t http://target.com/page?id=1 \
  -p id \
  --sqli \
  -D production \
  -T users \
  --dump \
  --format json \
  -o jira_ticket_data.json
```

### CI/CD Integration

```bash
#!/bin/bash
# security_scan.sh

# Run ANVIL and save JSON report
anvil -t $TARGET_URL \
  --sqli \
  --format json \
  -o anvil_report.json

# Parse JSON and fail build if critical findings
CRITICAL=$(jq '.summary.critical' anvil_report.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Critical vulnerabilities found! Failing build."
  exit 1
fi

echo "✅ No critical vulnerabilities detected"
```

### Integrate with Jira

```python
import json
import requests

# Load ANVIL JSON report
with open('anvil_report.json') as f:
    report = json.load(f)

# Create Jira tickets for each critical/high finding
for finding in report['findings']:
    if finding['severity'] in ['Critical', 'High']:
        jira_ticket = {
            'fields': {
                'project': {'key': 'SEC'},
                'summary': f"{finding['vuln_type']} in {finding['endpoint']}",
                'description': f"""
*Severity:* {finding['severity']}
*CWE:* {finding['cwe']}
*CVSS:* {finding['cvss_score']}

*Description:*
{finding['description']}

*Remediation:*
{finding['remediation']}
                """,
                'issuetype': {'name': 'Security Bug'},
                'priority': {'name': 'Critical' if finding['severity'] == 'Critical' else 'High'}
            }
        }
        
        response = requests.post(
            'https://jira.company.com/rest/api/2/issue/',
            auth=('user', 'token'),
            json=jira_ticket
        )
```

## Report Quality

### Why ANVIL Reports Are Better

✅ **CWE/CVSS Compliance**: Industry-standard classifications  
✅ **Actionable Remediation**: Not just "use parameterized queries" - provides actual code examples  
✅ **Database-Specific Guidance**: Tailored advice for MySQL, PostgreSQL, MSSQL, Oracle, SQLite  
✅ **Defense in Depth**: Multiple layers of security recommendations  
✅ **Evidence-Based**: Clear technical proof for each finding  
✅ **Confidence Scoring**: Transparent confidence levels (not just "possible"/"confirmed")  
✅ **No False Positives**: Statistical analysis ensures high-confidence results  

### Comparison with Other Tools

| Feature | ANVIL | sqlmap | Burp Scanner |
|---------|-------|--------|--------------|
| CWE/CVSS | ✅ | ❌ | ✅ |
| Detailed Remediation | ✅ | ❌ | Limited |
| Code Examples | ✅ | ❌ | ❌ |
| JSON Export | ✅ | ✅ | ✅ |
| Confidence Scoring | ✅ 0-100% | ❌ | ✅ |
| Statistical Analysis | ✅ | ❌ | ❌ |
| Professional Format | ✅ | ❌ | ✅ |

## Best Practices

1. **Always Save Reports**: Use `-o filename` to maintain audit trail
2. **Use JSON for Automation**: Parse structured data in scripts/CI/CD
3. **Review Text Reports**: Human review of formatted reports catches context
4. **Re-scan After Fixes**: Verify remediation by running ANVIL again
5. **Track Over Time**: Compare reports to measure security improvements

## Troubleshooting

### No Report Generated

```bash
# Check if --quiet mode is enabled (suppresses output)
anvil -t http://target.com --sqli  # Don't use -q/--quiet

# Check output format
anvil -t http://target.com --sqli --format text
```

### Report File Not Created

```bash
# Ensure directory exists
mkdir -p reports
anvil -t http://target.com --sqli -o reports/scan.txt

# Check permissions
ls -la reports/
```

### JSON Parsing Errors

```bash
# Validate JSON output
anvil -t http://target.com --sqli --format json | jq .

# Pretty-print JSON
anvil -t http://target.com --sqli --format json | jq . > report.json
```

## Additional Resources

- **USAGE.md**: Full CLI reference
- **SQL-INJECTION.md**: Detection techniques
- **EXPLOITATION.md**: Data extraction guide
- **architecture.md**: System design overview

