# ANVIL Architecture

## Overview

ANVIL (Adversarial Network Vulnerability Intelligence Layer) is an enterprise-grade security testing framework built with a modular, domain-driven architecture.

```
┌─────────────────────────────────────────────────────────────────────┐
│                           ANVIL CORE                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │    CLI      │  │   Engine    │  │   Context   │  │   Scope    │ │
│  │  (clap)     │──▶│ Orchestrator│──▶│   Store     │──▶│  Enforcer  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    HTTP CLIENT LAYER                         │   │
│  │  • Rate Limiting    • Scope Enforcement    • TLS Support    │   │
│  │  • Cookie Handling  • Redirect Control     • Response Diff  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   SCANNER MODULES                            │   │
│  ├─────────────┬─────────────┬─────────────┬──────────────────┤   │
│  │ Fingerprint │   Crawler   │    SQLi     │       XSS        │   │
│  │  (passive)  │  (active)   │  (domain)   │    (domain)      │   │
│  └─────────────┴─────────────┴─────────────┴──────────────────┘   │
│                          │                                          │
│                          ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  VALIDATION LAYER                            │   │
│  │  • Baseline Comparison  • Response Diffing  • Confidence    │   │
│  │  • Statistical Analysis • False Positive Reduction          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Principles

### 1. Domain-Driven Design
Each vulnerability class (SQLi, XSS, etc.) is a **domain** with:
- **Inference**: Detection logic
- **Proof**: Safe verification
- **Exploit**: Opt-in dangerous operations
- **Workflow**: Advanced attack chains

### 2. Enterprise Safety
- **Scope Enforcement**: Never touch out-of-scope targets
- **Rate Limiting**: Configurable request throttling
- **Opt-in Exploitation**: Dangerous operations require explicit flags
- **Audit Logging**: Full traceability

### 3. Statistical Confidence
- Baseline comparison for all tests
- Multiple samples for time-based attacks
- Signal-to-noise ratio analysis
- Explainable confidence scores

## Module Structure

```
src/
├── cli/              # Command-line interface
│   └── args.rs       # Argument parsing (clap)
│
├── core/             # Core infrastructure
│   ├── engine.rs     # Main orchestrator
│   ├── context.rs    # Global state
│   ├── scope.rs      # Target scope enforcement
│   ├── rate_limit.rs # Request throttling
│   ├── capability.rs # Feature flags
│   └── profile.rs    # Scan profiles
│
├── http/             # HTTP abstraction
│   ├── client.rs     # HTTP client with safety
│   ├── request.rs    # Request builder
│   └── response.rs   # Response wrapper
│
├── scanner/          # Active scanning
│   ├── fingerprint.rs # Passive fingerprinting
│   └── crawler.rs    # Application crawling
│
├── sqli/             # SQL Injection domain
│   ├── inference/    # Detection methods
│   ├── proof/        # Safe exploitation
│   ├── exploit/      # Dangerous (opt-in)
│   └── workflow/     # Advanced attacks
│
├── payload/          # Payload management
│   ├── loader.rs     # File loading
│   ├── iterator.rs   # Payload iteration
│   └── injector.rs   # Parameter injection
│
└── validation/       # Result validation
    ├── baseline.rs   # Baseline capture
    ├── diff.rs       # Response diffing
    └── verdict.rs    # Confidence scoring
```

## Data Flow

```
1. CLI Parse → Context Creation
2. Context → Engine Initialization
3. Engine → Baseline Request
4. Baseline → Fingerprinting (passive)
5. Fingerprint → Crawler (active)
6. Sitemap → SQLi Domain
   a. Inference: Detect vulnerability
   b. Proof: Verify safely (metadata)
   c. Exploit: Extract data (opt-in)
7. Results → Report Generation
```

## Threading Model

- **Async/Await**: All I/O operations use Tokio
- **Rate Limiter**: Token bucket per-domain
- **Concurrent Requests**: Configurable parallelism
- **Graceful Shutdown**: Signal handling

## Configuration

```yaml
# anvil.yaml (future)
target: https://example.com
scope:
  include:
    - "*.example.com"
  exclude:
    - "admin.example.com"
rate_limit: 10
modules:
  sqli:
    inference: [boolean, time, stacked, oob]
    proof: true
    exploit: false
  xss:
    enabled: true
```

## Author
Siddhant Bhattarai

## License
Apache-2.0

