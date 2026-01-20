# ANVIL 🔨

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**ANVIL** is an enterprise-grade vulnerability scanning and adversarial testing framework written in Rust. It provides comprehensive security testing capabilities with a focus on accuracy, performance, and professional reporting.

## 🚀 Features

- **🔍 Multiple Vulnerability Detection**
  - SQL Injection (Boolean, Time-based, Error-based, Stacked Queries, Out-of-Band, Second-Order)
  - Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based
  - Server-Side Request Forgery (SSRF)
  - Application Fingerprinting & Reconnaissance

- **⚡ High Performance**
  - Async, concurrent HTTP engine built on Tokio
  - Rate limiting and request throttling
  - Efficient payload management

- **📊 Professional Reporting**
  - Text and JSON output formats
  - CWE/CVSS classification
  - Detailed remediation guidance
  - Impact analysis and references

- **🎯 Flexible Testing**
  - Authenticated scanning (cookies, headers)
  - POST/GET parameter testing
  - Custom payload support
  - Second-order vulnerability detection

- **🛡️ Safe by Default**
  - Human-in-the-loop exploitation workflow
  - Proof-of-concept mode for safe testing
  - Configurable risk levels

## 📦 Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo (comes with Rust)

### Build from Source

```bash
# Clone the repository
git clone git@github.com:siddhantbhattarai/anvil.git
cd anvil

# Build in release mode
cargo build --release

# Install to system
cargo install --path .
```

The binary will be available at `target/release/anvil` or installed to `~/.cargo/bin/anvil`.

## 🎯 Quick Start

### Basic SQL Injection Detection

```bash
# Test a specific parameter
anvil -t "http://target.com/page?id=1" -p id --sqli

# Authenticated scanning
anvil -t "http://target.com/page?id=1" -p id --sqli \
  --cookie "PHPSESSID=abc123; security=low"
```

### Generate JSON Report

```bash
# Output to stdout
anvil -t "http://target.com/page?id=1" -p id --sqli --format json

# Save to file
anvil -t "http://target.com/page?id=1" -p id --sqli --format json -o report.json
```

### XSS Detection

```bash
anvil -t "http://target.com/search?q=test" -p q --xss
```

### SSRF Detection

```bash
anvil -t "http://target.com/fetch?url=example.com" -p url --ssrf
```

### Full Application Scan

```bash
anvil -t "http://target.com" --all --format json -o full_report.json
```

## 📖 Usage

### Command-Line Options

```bash
anvil [OPTIONS] --target <URL>

Options:
  -t, --target <URL>          Target URL (required)
  -p, --param <NAME>          Parameter to test
  
Scan Modules:
  --all                       Enable all scan modules
  --sqli                      SQL Injection detection
  --xss                       Cross-Site Scripting detection
  --ssrf                      Server-Side Request Forgery detection
  --fingerprint               Server/framework fingerprinting
  --crawl                     Application crawling

SQL Injection Options:
  --time-sqli                 Time-based blind SQLi
  --stacked                   Stacked queries detection
  --oob                       Out-of-band SQLi
  --sqli-all                  All SQLi techniques
  --dbs                       Enumerate databases
  -D <DB>                     Specify database
  --tables                    Enumerate tables
  -T <TABLE>                  Specify table
  --dump                      Dump table data

Authentication:
  --cookie <STRING>           Cookie header
  --header <STRING>           Custom HTTP header (repeatable)

Request Options:
  --method <METHOD>           HTTP method (GET/POST)
  --data <STRING>             POST body data
  --extra-data <STRING>       Extra data to include

Output Options:
  --format <FORMAT>           Output format: text, json (default: text)
  -o, --output <FILE>         Output file
  --quiet                     Minimal output
  --verbose                   Debug output

Performance:
  --rate <N>                  Max requests per second (default: 5)
  --depth <N>                 Crawl depth limit (default: 2)

Help:
  -h, --help                  Print help
  -V, --version               Print version
```

### Examples

#### Test Login Form for SQLi

```bash
anvil -t "http://target.com/login" \
  --param username \
  --method POST \
  --extra-data "password=test&submit=Login" \
  --sqli
```

#### Authenticated API Testing

```bash
anvil -t "https://api.example.com/v1/users" \
  --header "Authorization: Bearer eyJhbGc..." \
  --param user_id \
  --sqli --format json
```

#### Database Enumeration

```bash
# List databases
anvil -t "http://target.com/page?id=1" -p id --sqli --dbs

# List tables in a database
anvil -t "http://target.com/page?id=1" -p id --sqli -D mydb --tables

# Dump table contents
anvil -t "http://target.com/page?id=1" -p id --sqli -D mydb -T users --dump
```

#### CI/CD Integration

```bash
#!/bin/bash
# Fail build if critical vulnerabilities found

anvil -t $TARGET_URL --all --format json -o anvil_report.json

CRITICAL=$(jq '.summary.critical' anvil_report.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ CRITICAL vulnerabilities found! Failing build."
  jq '.findings[] | select(.severity == "Critical")' anvil_report.json
  exit 1
fi

echo "✅ No critical vulnerabilities detected"
```

## 📊 Report Formats

### Text Report (Human-Readable)

Professional, formatted output with:
- Executive summary with severity breakdown
- Detailed vulnerability information
- CWE/CVSS classification
- Impact analysis
- Step-by-step remediation guidance
- OWASP/CWE references

### JSON Report (Machine-Parseable)

Structured JSON output for:
- SIEM integration
- CI/CD pipelines
- Custom reporting tools
- Automated analysis

Example JSON structure:

```json
{
  "scan_metadata": {
    "tool": "ANVIL",
    "version": "0.1.0",
    "scan_date": "2026-01-20T10:30:00Z"
  },
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "vuln_type": "SQL Injection",
      "severity": "Critical",
      "confidence": 0.95,
      "cvss_score": 9.8,
      "endpoint": "http://target.com/page?id=1",
      "parameter": "id",
      "evidence": "...",
      "remediation": "..."
    }
  ]
}
```

## 🏗️ Architecture

ANVIL is built with a modular architecture:

- **Core Engine**: Manages scan orchestration and context
- **HTTP Client**: Async request handling with connection pooling
- **Payload System**: Flexible payload loading and injection
- **Detection Modules**: Specialized vulnerability detectors (SQLi, XSS, SSRF)
- **Validation Engine**: Statistical analysis and false positive reduction
- **Reporting System**: Multi-format output generation

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_sqli_detection
```

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Quick Start Guide](docs/QUICK_START.md) - Get started quickly
- [Usage Guide](docs/USAGE.md) - Complete CLI reference
- [SQL Injection Detection](docs/SQL-INJECTION.md) - SQLi techniques
- [XSS Detection](docs/XSS-DETECTION.md) - XSS detection methods
- [SSRF Detection](docs/SSRF-DETECTION.md) - SSRF testing
- [Architecture](docs/architecture.md) - System design
- [Testing Guide](docs/TESTING_GUIDE.md) - Testing methodology
- [Exploitation Guide](docs/EXPLOITATION.md) - Safe exploitation
- [Reporting](docs/REPORTING.md) - Report format details

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚖️ Legal & Ethical Use

**IMPORTANT**: ANVIL is a security testing tool designed for authorized security assessments only.

- ✅ Use ONLY on systems you own or have explicit written permission to test
- ✅ Obtain proper authorization before conducting any security testing
- ✅ Follow responsible disclosure practices
- ❌ NEVER use against systems without authorization
- ❌ NEVER use for malicious purposes

**Unauthorized access to computer systems is illegal.** The authors and contributors of ANVIL are not responsible for misuse or damage caused by this tool. By using ANVIL, you agree to use it responsibly and ethically.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

```
Copyright 2026 Siddhant Bhattarai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## 👤 Author

**Siddhant Bhattarai**

- GitHub: [@siddhantbhattarai](https://github.com/siddhantbhattarai)

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) and [Tokio](https://tokio.rs/)
- Inspired by industry-leading security tools
- Thanks to the open-source security community

## 📈 Roadmap

See [roadmap.md](docs/roadmap.md) for planned features and improvements.

## 🐛 Bug Reports & Feature Requests

Please use the [GitHub Issues](https://github.com/siddhantbhattarai/anvil/issues) page to report bugs or request features.

---

**ANVIL** - Forging Security Through Adversarial Testing 🔨
