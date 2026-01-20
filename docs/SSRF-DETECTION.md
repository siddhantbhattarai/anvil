# SSRF Detection - Evidence-Driven, Low-False-Positive Model

## Overview

ANVIL's SSRF module treats Server-Side Request Forgery as a **controlled server-initiated network interaction problem**, not a simple "URL reflection" issue. Detection is based on **provable server-side request behavior** rather than payload presence.

## Key Principles

1. **Reflection ≠ SSRF** (same as XSS principle: Reflection ≠ Execution)
2. **Errors ≠ Proof** - Error messages alone don't prove SSRF
3. **Outbound behavior must be demonstrated** - Server must actually make requests
4. **OOB beats everything** - Out-of-band callbacks are strongest evidence
5. **Internal vs external targets must behave differently** - Timing, responses, errors
6. **Classification matters more than payload count** - Quality over quantity

## Detection Methodology

### Stage 1: Parameter Identification

Identifies parameters that plausibly influence outbound requests:

- **URL/Host parameters**: `url`, `uri`, `link`, `href`, `host`, `domain`, `ip`
- **Webhook/Callback parameters**: `webhook`, `callback`, `notify`, `ping`
- **File/Resource parameters**: `file`, `image`, `document`, `resource`
- **Import/Fetch parameters**: `import`, `fetch`, `load`, `get`, `download`
- **API/Remote parameters**: `api`, `remote`, `external`, `proxy`
- **PDF/Document generation**: `pdf`, `html`, `template`, `render`

### Stage 2: Reachability Testing

Confirms the server actually initiates outbound requests:

- Tests with **benign external endpoints** (example.com, httpbin.org)
- Looks for indicators that server fetched external content
- Only proceeds if outbound request behavior is confirmed
- **No false positives from client-side fetches**

### Stage 3: Controlled Probes

Tests various targets with escalating sensitivity:

#### Internal IP Ranges
- **Loopback**: 127.0.0.1, localhost
- **RFC1918 Private**: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
- **Link-local**: 169.254.169.254 (AWS/Cloud metadata)

#### Cloud Metadata Endpoints
- **AWS**: http://169.254.169.254/latest/meta-data/
- **Google Cloud**: http://metadata.google.internal/computeMetadata/v1/
- **Azure**: http://169.254.169.254/metadata/instance
- **DigitalOcean**: http://169.254.169.254/metadata/v1/
- **Oracle Cloud**: http://169.254.169.254/opc/v1/instance/

#### Non-HTTP Schemes
- **file://**: Local file system access
- **gopher://**: Protocol smuggling
- **ftp://**: FTP protocol
- **dict://**: Dictionary protocol
- **ldap://**: LDAP protocol

#### Bypass Techniques
- IP encoding (decimal, octal, hex)
- URL encoding (single, double)
- @ bypass (user@host)
- \# bypass (fragment)
- CRLF injection
- Null byte injection
- Unicode bypass

### Stage 4: Evidence Analysis

Collects multiple types of evidence:

#### Strong Evidence (High Confidence)
1. **OOB Callback Received** (0.95 confidence)
   - Out-of-band DNS/HTTP callback confirmed
   - Strongest possible evidence
   
2. **Cloud Metadata Access** (0.95 confidence)
   - AWS/GCP/Azure metadata endpoint accessible
   - Response contains metadata signatures (ami-id, instance-id, etc.)

3. **Internal IP Reachable** (0.85 confidence)
   - Internal service responds with distinct content
   - Response differs from external targets

#### Medium Evidence (Medium Confidence)
4. **Timing Differential** (0.70 confidence)
   - Internal requests significantly faster than external
   - Consistent with local network access

5. **Protocol-Specific Errors** (0.75 confidence)
   - file:// returns "file not found" or file contents
   - gopher:// returns protocol-specific errors
   - ftp:// shows FTP banner

#### Weak Evidence (Low Confidence)
6. **Response Behavior Differences** (0.60 confidence)
   - Different HTTP status codes for internal vs external
   - Different error messages

7. **Parameter Control** (0.50 confidence)
   - Parameter influences request destination
   - But execution not fully proven

### Stage 5: Classification

Based on strongest evidence observed:

#### Confirmed SSRF (Critical - 95% confidence)
- **Evidence**: OOB callback received OR metadata access proven
- **Impact**: Full SSRF with high-value target access
- **Severity**: CRITICAL
- **CVSS**: 9.8

#### Internal Network SSRF (High - 85% confidence)
- **Evidence**: Internal IP reachable with response/timing proof
- **Impact**: Access to internal network resources
- **Severity**: HIGH
- **CVSS**: 8.5

#### Blind SSRF (High - 80% confidence)
- **Evidence**: Asynchronous OOB callback only
- **Impact**: Server makes outbound requests but no response visible
- **Severity**: HIGH
- **CVSS**: 8.0

#### Limited SSRF (Medium - 70% confidence)
- **Evidence**: Outbound request control but restricted
- **Impact**: Protocol control but limited targets
- **Severity**: MEDIUM
- **CVSS**: 6.5

#### SSRF Candidate (Info - 50% confidence)
- **Evidence**: Parameter influences fetch but not fully proven
- **Impact**: Requires manual verification
- **Severity**: INFO
- **CVSS**: 4.0

## Usage Examples

### Basic SSRF Scan
```bash
# Scan a parameter for SSRF
anvil -t https://example.com/fetch?url=http://example.com -p url --ssrf
```

### Comprehensive SSRF Scan (All Tests)
```bash
# Enable all SSRF detection types
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-all
```

### Specific Test Types

#### Internal Network Testing
```bash
# Test internal IP ranges only
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-internal
```

#### Cloud Metadata Testing
```bash
# Test cloud metadata endpoints
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-metadata
```

#### Non-HTTP Scheme Testing
```bash
# Test file://, gopher://, ftp://, etc.
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-schemes
```

### Blind SSRF with OOB Callbacks
```bash
# Use out-of-band callbacks for blind SSRF
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-callback attacker.com
```

### With Authentication
```bash
# Authenticated SSRF testing
anvil -t https://example.com/fetch?url=test -p url --ssrf \
  --cookie "session=abc123" \
  -H "Authorization: Bearer token"
```

### Verbose Output
```bash
# See full detection methodology
anvil -t https://example.com/fetch?url=test -p url --ssrf --ssrf-all --verbose
```

### Report Generation
```bash
# Generate full SSRF report
anvil -t https://example.com/fetch?url=test -p url --ssrf -o ssrf-report.txt

# JSON format
anvil -t https://example.com/fetch?url=test -p url --ssrf --format json -o results.json
```

## Configuration Options

### CLI Flags

- `--ssrf`: Enable SSRF scanning
- `--ssrf-all`: Enable ALL SSRF detection types
- `--ssrf-internal`: Test internal network ranges
- `--ssrf-metadata`: Test cloud metadata endpoints
- `--ssrf-schemes`: Test non-HTTP schemes
- `--ssrf-callback <domain>`: Callback domain for blind SSRF
- `--ssrf-max-payloads <n>`: Maximum payloads per parameter (default: 20)

### Tuning Parameters

- `--threshold <0.0-1.0>`: Confidence threshold for reporting (default: 0.5)
- `--rate <n>`: Request rate limit (default: 5 req/sec)
- `--verbose`: Show full detection methodology

## Output Formats

### Default Output (Clean Summary)
```
[+] Server-Side Request Forgery to internal network confirmed
    Endpoint  : /fetch
    Parameter : url
    Severity  : 🟠 HIGH
    Confidence: 85%
    Classification: InternalNetworkSsrf
    Target Reached: http://192.168.1.1
```

### Verbose Output (Full Methodology)
```
  ✗ INTERNAL NETWORK SSRF DETECTED
    Endpoint: /fetch
    Parameter: url
    Payload: http://192.168.1.1
    Confidence: 85%
    Request Control: 85%
    Impact Reachability: 80%
    Evidence:
      1. Internal IP address accessible (confidence: 85%)
      2. Fast response suggests internal network access (confidence: 70%)
    Details: Server successfully accessed internal IP: http://192.168.1.1
```

### Report Output (Documentation)
Full professional report with:
- Vulnerability classification
- Evidence summary
- Confidence breakdown
- Impact analysis
- Remediation steps
- References

## Why This Approach is Superior

### Traditional SSRF Scanners Fail Because They:

1. **Assume "URL parameter = SSRF"**
   - ANVIL: Requires proof of outbound request behavior

2. **Rely on error messages**
   - ANVIL: Error messages are weak evidence, requires stronger proof

3. **Ignore whether server actually made request**
   - ANVIL: Reachability testing confirms outbound behavior

4. **Cannot distinguish client-side from server-side fetches**
   - ANVIL: Tests for server-observable effects only

5. **Generate false positives from reflection**
   - ANVIL: Reflection ≠ SSRF (requires network interaction)

### ANVIL's Advantages:

1. **Evidence-based classification** - Not just payload reflection
2. **Dual confidence scoring** - Request control + Impact reachability
3. **OOB callback system** - Strongest possible evidence
4. **Timing differential analysis** - Detects internal network access
5. **Cloud metadata detection** - High-value targets
6. **Protocol smuggling detection** - Advanced attacks
7. **Zero false positives** - Only reports provable SSRF
8. **Professional output** - Defensible in enterprise environments

## Attack Scenarios Detected

### 1. Cloud Metadata Access (Critical)
```bash
# AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/
```

### 2. Internal Network Scanning (High)
```bash
# Internal services
http://192.168.1.1
http://10.0.0.1:8080
http://172.16.0.1:3306
```

### 3. Local File Access (High)
```bash
# Unix
file:///etc/passwd

# Windows
file:///c:/windows/win.ini
```

### 4. Protocol Smuggling (Medium)
```bash
# Gopher protocol
gopher://127.0.0.1:6379/_INFO

# Dict protocol
dict://127.0.0.1:11211/stat
```

### 5. Blind SSRF (High)
```bash
# Out-of-band callback
http://unique-id.attacker.com
```

## Remediation Guidance

ANVIL provides comprehensive remediation steps:

1. **Input Validation** (Primary Defense)
   - Strict allowlist of permitted domains/IPs
   - Reject internal IP ranges
   - Block cloud metadata IPs
   - Validate URL scheme

2. **Network Segmentation**
   - Isolate application servers
   - Use separate VLAN for outbound requests
   - Implement egress filtering
   - Block metadata endpoints at network level

3. **Response Handling**
   - Don't return raw responses
   - Sanitize response content
   - Implement timeout controls
   - Log all outbound requests

4. **Cloud-Specific Protections**
   - Use IMDSv2 on AWS
   - Block 169.254.169.254 at application level
   - Use workload identity (GCP) or managed identities (Azure)

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

## Technical Implementation

The SSRF module is located in `src/ssrf/` with the following structure:

- `mod.rs` - Module definition and configuration
- `scanner.rs` - High-level scanning orchestration
- `detector.rs` - Core detection logic with evidence analysis
- `params.rs` - Parameter identification
- `probes.rs` - Probe generation (internal IPs, metadata, schemes)
- `oob.rs` - Out-of-band callback system
- `evidence.rs` - Evidence collection and classification

Payload files are in `payloads/ssrf/`:
- `internal_ips.txt` - Internal IP addresses
- `metadata.txt` - Cloud metadata endpoints
- `schemes.txt` - Non-HTTP schemes
- `bypass.txt` - Bypass techniques

## Contributing

To extend SSRF detection:

1. Add new probe types in `probes.rs`
2. Add new evidence types in `evidence.rs`
3. Update detection logic in `detector.rs`
4. Add payload files in `payloads/ssrf/`

## License

Apache-2.0

