# ANVIL Threat Model

## Purpose

This document defines ANVIL's threat model, security boundaries, and safety guarantees for enterprise deployments.

## Threat Categories

### 1. Accidental Scope Violation

**Risk**: Scanner requests targets outside authorized scope.

**Mitigations**:
- Strict URL validation before every request
- Redirect destination checking (no open redirect exploitation)
- Domain allowlist/blocklist enforcement
- Subdomain scope control (`*.example.com` vs `example.com`)

```rust
// Every request passes through scope check
if !self.scope.is_in_scope(&request.url) {
    bail!("Blocked out-of-scope request: {}", request.url);
}
```

### 2. Denial of Service (Self-Inflicted)

**Risk**: Scanner overwhelms target with requests.

**Mitigations**:
- Configurable rate limiting (default: 5 req/sec)
- Token bucket algorithm for burst control
- Per-domain rate tracking
- Backoff on 429/503 responses

### 3. Data Exfiltration (Uncontrolled)

**Risk**: Exploit modules extract sensitive data without authorization.

**Mitigations**:
- **Proof Mode** (default): Only extracts metadata (DB version, user, etc.)
- **Exploit Mode**: Requires explicit `--exploit` flag
- **Extraction Limits**: Row/column limits on data extraction
- **Hash-Only Mode**: Export password hashes without plaintext

### 4. Detection/Attribution

**Risk**: Scanner leaves obvious fingerprints.

**Mitigations**:
- Configurable User-Agent
- Request timing randomization (future)
- Payload obfuscation options (future)
- Proxy/Tor support (future)

### 5. False Positives Leading to Incorrect Action

**Risk**: Scanner reports vulnerability that doesn't exist.

**Mitigations**:
- Statistical confidence scoring
- Multiple verification requests
- Baseline comparison for all tests
- Time-based detection uses 6+ samples with variance analysis

## Security Boundaries

### Trust Boundary 1: User Input

```
┌─────────────────────────────────────────────┐
│              UNTRUSTED                       │
│  • Target URL                               │
│  • Custom payloads                          │
│  • Configuration files                      │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│           VALIDATION LAYER                  │
│  • URL parsing and validation               │
│  • Scope enforcement                        │
│  • Payload sanitization                     │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│              TRUSTED                         │
│  • Internal state                           │
│  • HTTP client                              │
│  • Result processing                        │
└─────────────────────────────────────────────┘
```

### Trust Boundary 2: Target Responses

```
┌─────────────────────────────────────────────┐
│              UNTRUSTED                       │
│  • HTTP response headers                    │
│  • Response body content                    │
│  • Timing information                       │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│           PARSING LAYER                     │
│  • Safe HTML parsing (scraper)              │
│  • Size limits on body                      │
│  • Timeout enforcement                      │
└─────────────────────────────────────────────┘
```

## Attack Vectors by Module

### SQL Injection Module

| Vector | Risk Level | Mitigation |
|--------|------------|------------|
| Boolean inference | LOW | Read-only, no data extraction |
| Time-based | LOW | Only delays, no data extraction |
| Stacked queries | MEDIUM | Detection only, no execution |
| OOB (DNS) | MEDIUM | Controlled callback server |
| Data extraction | HIGH | Requires `--exploit` flag |

### Exploitation Safety Levels

```
LEVEL 0: PASSIVE (default)
├── Fingerprinting
├── Crawling
└── No injection

LEVEL 1: INFERENCE (--sqli, --xss)
├── Payload injection
├── Response analysis
└── No data extraction

LEVEL 2: PROOF (--proof)
├── Metadata extraction (DB version, user)
├── Capability detection
└── Limited, safe queries

LEVEL 3: EXPLOIT (--exploit)
├── Full data extraction
├── Hash export
└── Requires explicit confirmation
```

## Incident Response

### If Out-of-Scope Request Detected

1. Scanner immediately terminates the request
2. Error logged with full URL
3. Scan continues with other targets
4. Summary includes scope violations

### If Rate Limit Exceeded

1. Scanner pauses for backoff period
2. Warning logged
3. Automatic retry with reduced rate

### If Exploitation Fails Safely

1. No changes made to target
2. Partial results preserved
3. Error context for debugging

## Compliance Considerations

### SOC 2 Type II

- All actions logged with timestamps
- Scope enforcement auditable
- Rate limiting demonstrates control

### PCI DSS

- No storage of cardholder data
- Hash-only extraction for credentials
- Encryption of results (future)

### GDPR

- No PII extraction by default
- Data minimization in proof mode
- Results can be anonymized

## Responsible Disclosure

ANVIL is designed for authorized security testing only. Users must:

1. Obtain written authorization before scanning
2. Define clear scope boundaries
3. Use appropriate rate limits
4. Handle discovered vulnerabilities responsibly

## Author
Siddhant Bhattarai

## License
Apache-2.0

