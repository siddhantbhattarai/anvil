# ANVIL 🔨

**Evidence-driven web application security scanner, written in Rust.**

[![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.0-green.svg)](https://github.com/siddhantbhattarai/anvil)
[![Install](https://img.shields.io/badge/install-apt-important.svg)](#install)

ANVIL detects and safely **proves** **11 active vulnerability classes** plus
**5 passive audits** — covering **8 of the OWASP Top 10** — with a low
false-positive rate. It emits machine-readable reports (text, JSON, CSV) for
triage and CI gating, and ships a built-in **MCP server** so AI agents can call
it as a native tool.

```
anvil -t http://target/page?id=1 -p id --sqli          # prove a single class
anvil -t http://target/ --owasp --crawl -f json        # full OWASP sweep, JSON report
anvil -t http://target/ --owasp --fail-on high         # CI gate: exit 2 on High+
anvil --mcp                                             # run as an MCP server for AI agents
```

## Install

### Debian / Ubuntu (apt)

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://siddhantbhattarai.github.io/anvil/pubkey.gpg \
  | sudo tee /etc/apt/keyrings/anvil.asc > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/anvil.asc] https://siddhantbhattarai.github.io/anvil stable main" \
  | sudo tee /etc/apt/sources.list.d/anvil.list

sudo apt update
sudo apt install anvil
```

Updates then arrive through `apt upgrade` like any other package. To uninstall:

```bash
sudo apt remove anvil
sudo rm /etc/apt/sources.list.d/anvil.list /etc/apt/keyrings/anvil.asc
```

> The headless-browser XSS **execution** check drives a system Chrome/Chromium
> over the DevTools protocol. It is optional — every other class works without a
> browser — but installing `chromium` unlocks it: `sudo apt install chromium`.

## Why it's different

Most scanners flag; ANVIL **proves**. Every finding is backed by evidence — a
reflected-and-executed canary, a boolean/time oracle that actually flips, a
metadata response that actually came back — so the report is a list of things
demonstrated true, not a list of guesses to triage.

- **Evidence over heuristics.** XSS is confirmed by real execution in a headless
  browser (a canary sets `window.__ANVIL_XSS__`); SQLi by differential boolean
  and time oracles; SSRF by a callback or a metadata response — not by matching
  an error string.
- **OWASP in one command.** `--owasp` runs every reliable active class plus the
  passive audits and maps each finding back to its OWASP 2021 category and CWE.
- **Built for automation and agents.** Deterministic `--fail-on` exit codes for
  CI gating, a stable JSON schema, and a native **MCP server** (`--mcp`) that
  exposes an `anvil_scan` tool to agents like Claude Code.
- **Rust-fast.** Fully async; a whole-target sweep with crawling completes in
  minutes, single-class checks in seconds.

## OWASP Top 10 coverage

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

## Capabilities

### Active detection classes

| Flag | Class | CWE |
|------|-------|-----|
| `--sqli` | SQL injection (UNION, boolean/time blind, error, OOB, stacked, second-order) | CWE-89 |
| `--nosqli` | NoSQL (MongoDB operator) injection | CWE-943 |
| `--xss` | Cross-site scripting, verified by real headless execution | CWE-79 |
| `--ssrf` | Server-side request forgery (RFC1918, cloud metadata, blind) | CWE-918 |
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

### SQL injection — deep engine

UNION / boolean-blind / time-blind / error-based / OOB-DNS / stacked / second-order
detection, then full post-exploitation: database, table, column and schema
enumeration; data dumping; banner, current-user/db, hostname and DBA checks;
user, password-hash, privilege and role enumeration; 18 tamper scripts for WAF
bypass; an interactive SQL shell; server file read/write and OS command
execution. Supports MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite and Access.

## Usage

```bash
# Full OWASP sweep (recommended): every reliable class + passive audit
anvil -t "http://target.com" --owasp --crawl -o report.json --format json

# CI / agent gating: exit 2 if anything High or worse is found
anvil -t "http://target.com" --owasp --fail-on high --format json

# Targeted single-class checks
anvil -t "http://host/page?id=1"    -p id   --sqli
anvil -t "http://host/search?q=t"   -p q    --xss --xss-all
anvil -t "http://host/fetch?url=x"  -p url  --ssrf
anvil -t "http://host/ping?host=x"  -p host --cmdi
anvil -t "http://host/view?file=a"  -p file --path-traversal

# Passive audits
anvil -t "https://host/"            --security-headers
anvil -t "https://host/api" --cookie 'session=eyJ...' --jwt
anvil -t "https://host/"            --components --sri --secrets

# SQLi post-exploitation
anvil -t "http://host/p?id=1" -p id --sqli --dbs
anvil -t "http://host/p?id=1" -p id --sqli -D shop -T users --dump
```

### MCP server (for AI agents)

```bash
anvil --mcp    # stdio JSON-RPC
```

Register it with an MCP-capable agent (e.g. Claude Code):

```json
{ "mcpServers": { "anvil": { "command": "anvil", "args": ["--mcp"] } } }
```

The server exposes one `anvil_scan` tool taking `target`, `profile` (`owasp` or a
single class), optional `param`, and optional `fail_on`.

## Exit codes

`0` clean · `1` error · `2` findings at or above the `--fail-on` threshold —
convenient for scripting and CI pipelines.

## Data & overrides

The bundled payload sets (XSS contexts, SSRF schemes, SQLi vectors, …) install to
`/usr/share/anvil/payloads/`. anvil resolves payload paths against the current
directory first, then `$ANVIL_DATA`, then `/usr/share/anvil` — so you can point
`ANVIL_DATA` at your own tuned set without reinstalling:

```bash
ANVIL_DATA=~/.anvil anvil -t "http://target/" --xss
```

## Legal & ethical

For **authorised security testing only**. Always obtain written permission
before testing any system you do not own. Unauthorised access to computer
systems is illegal, and the authors accept no liability for misuse.

## License

ANVIL is **source-available** under the
[PolyForm Noncommercial License 1.0.0](LICENSE):

- ✅ Free for **noncommercial** use — personal projects, research, education.
- ❌ No commercial use, resale, or hosting for others without a separate
  commercial license.
- 🔒 Authorised testing only — the license carries an acceptable-use condition.

All commercial rights are reserved by the author. For a commercial license,
contact [@siddhantbhattarai](https://github.com/siddhantbhattarai).
