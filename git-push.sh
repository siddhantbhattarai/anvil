#!/bin/bash
# ANVIL Git Push Script - Push code to GitHub in multiple commits
# This script breaks down the project into logical commits for better history

set -e

REPO_URL="git@github.com:siddhantbhattarai/anvil.git"
BRANCH="Development"

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║              ANVIL - GitHub Push Script                           ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
    echo "✅ Git initialized"
else
    echo "✅ Git repository already initialized"
fi

echo ""
echo "🔗 Setting up remote..."
if git remote | grep -q "origin"; then
    echo "⚠️  Remote 'origin' already exists, removing..."
    git remote remove origin
fi
git remote add origin "$REPO_URL"
echo "✅ Remote added: $REPO_URL"

echo ""
echo "🌿 Creating branch: $BRANCH"
git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"

echo ""
echo "📝 Starting incremental commits..."
echo ""

# Commit 1: Project configuration and license
echo "📌 Commit 1/25: Project configuration and license"
git add Cargo.toml Cargo.lock LICENSE .gitignore
git commit -m "feat: Initialize project with Cargo configuration and Apache 2.0 license

- Add Cargo.toml with project metadata and dependencies
- Add Cargo.lock for dependency locking
- Add Apache 2.0 LICENSE
- Add .gitignore for Rust project" || echo "Already committed"

# Commit 2: README and documentation
echo "📌 Commit 2/25: Add comprehensive README"
git add README.md
git commit -m "docs: Add comprehensive README with installation and usage guide

- Complete feature overview
- Installation instructions
- Usage examples
- Documentation structure" || echo "Already committed"

# Commit 3: Setup script
echo "📌 Commit 3/25: Add setup script"
git add setup.sh
git commit -m "feat: Add automated setup script for easy installation

- Rust installation check
- Automated build and install
- PATH configuration guidance" || echo "Already committed"

# Commit 4: Core module structure
echo "📌 Commit 4/25: Core module structure"
git add src/main.rs src/core/mod.rs
git commit -m "feat: Add main entry point and core module structure

- Initialize main.rs with CLI entry point
- Set up core module organization" || echo "Already committed"

# Commit 5: Core engine
echo "📌 Commit 5/25: Core scanning engine"
git add src/core/engine.rs src/core/context.rs
git commit -m "feat: Implement core scanning engine and context management

- Async scanning engine with task orchestration
- Scan context for state management
- Result aggregation" || echo "Already committed"

# Commit 6: Core capabilities and profiles
echo "📌 Commit 6/25: Core capabilities and profiles"
git add src/core/capability.rs src/core/profile.rs src/core/scope.rs src/core/rate_limit.rs
git commit -m "feat: Add scanning capabilities, profiles, and rate limiting

- Capability detection system
- Scan profiles for different scenarios
- Scope management
- Rate limiting for responsible scanning" || echo "Already committed"

# Commit 7: HTTP client infrastructure
echo "📌 Commit 7/25: HTTP client infrastructure"
git add src/http/mod.rs src/http/client.rs src/http/request.rs src/http/response.rs
git commit -m "feat: Implement async HTTP client with connection pooling

- Async HTTP client built on reqwest
- Request/response abstractions
- Connection pooling and timeout handling
- Cookie and header management" || echo "Already committed"

# Commit 8: CLI argument parsing
echo "📌 Commit 8/25: CLI argument parsing"
git add src/cli/mod.rs src/cli/args.rs
git commit -m "feat: Add comprehensive CLI argument parsing

- Complete argument structure with clap
- Support for all scan types
- Authentication options
- Output formatting options" || echo "Already committed"

# Commit 9: Payload system
echo "📌 Commit 9/25: Payload management system"
git add src/payload/mod.rs src/payload/loader.rs src/payload/injector.rs src/payload/iterator.rs
git commit -m "feat: Implement flexible payload management system

- Payload loader from files
- Injection point detection
- Payload iteration strategies
- Custom payload support" || echo "Already committed"

# Commit 10: Validation engine
echo "📌 Commit 10/25: Validation and verification engine"
git add src/validation/mod.rs src/validation/baseline.rs src/validation/diff.rs src/validation/verdict.rs src/validation/time_sqli.rs
git commit -m "feat: Add validation engine for vulnerability verification

- Baseline establishment
- Response diff analysis
- Statistical validation for time-based attacks
- Verdict system with confidence scoring" || echo "Already committed"

# Commit 11: SQL Injection - Core module
echo "📌 Commit 11/25: SQL Injection detection - Core"
git add src/sqli/mod.rs
git commit -m "feat: Add SQL Injection detection module structure

- Module organization for SQLi detection
- Type definitions and interfaces" || echo "Already committed"

# Commit 12: SQL Injection - Inference techniques
echo "📌 Commit 12/25: SQL Injection - Inference techniques"
git add src/sqli/inference/
git commit -m "feat: Implement SQL Injection inference techniques

- Boolean-based blind SQLi
- Time-based blind SQLi
- Stacked queries detection
- Out-of-band SQLi" || echo "Already committed"

# Commit 13: SQL Injection - Extraction
echo "📌 Commit 13/25: SQL Injection - Data extraction"
git add src/sqli/extract/
git commit -m "feat: Add SQL Injection data extraction capabilities

- Blind extraction algorithms
- Error-based extraction
- Union-based extraction
- Database-specific queries" || echo "Already committed"

# Commit 14: SQL Injection - Proof of concept
echo "📌 Commit 14/25: SQL Injection - Proof of concept"
git add src/sqli/proof/
git commit -m "feat: Add SQL Injection proof-of-concept features

- Capability detection
- Metadata extraction
- Safe verification methods" || echo "Already committed"

# Commit 15: SQL Injection - Advanced workflows
echo "📌 Commit 15/25: SQL Injection - Advanced workflows"
git add src/sqli/workflow/
git commit -m "feat: Implement advanced SQL Injection workflows

- Second-order SQLi detection
- OOB listener for DNS/HTTP callbacks
- Stacked query detection" || echo "Already committed"

# Commit 16: XSS Detection engine
echo "📌 Commit 16/25: XSS detection engine"
git add src/xss/
git commit -m "feat: Implement Cross-Site Scripting (XSS) detection

- Context-aware XSS detection
- Reflected XSS scanning
- Stored XSS detection
- DOM-based XSS analysis
- Blind XSS with callbacks
- Payload validation and verification" || echo "Already committed"

# Commit 17: SSRF Detection
echo "📌 Commit 17/25: SSRF detection engine"
git add src/ssrf/
git commit -m "feat: Implement Server-Side Request Forgery (SSRF) detection

- Internal network probing
- Cloud metadata endpoint testing
- Protocol scheme testing
- Blind SSRF with OOB callbacks
- Evidence collection and validation" || echo "Already committed"

# Commit 18: Scanner modules
echo "📌 Commit 18/25: Scanner modules (crawler, fingerprint)"
git add src/scanner/
git commit -m "feat: Add application scanning modules

- Web crawler for endpoint discovery
- Fingerprinting for server/framework detection
- Sitemap parsing
- Parameter discovery" || echo "Already committed"

# Commit 19: Reporting system
echo "📌 Commit 19/25: Reporting system"
git add src/reporting/
git commit -m "feat: Implement comprehensive reporting system

- Text report formatter with professional layout
- JSON report for automation
- Report model with CWE/CVSS
- Multi-format output support" || echo "Already committed"

# Commit 20: SQL Injection payloads
echo "📌 Commit 20/25: SQL Injection payloads"
git add payloads/sqli/
git commit -m "feat: Add SQL Injection payload database

- Boolean-based payloads
- Time-based payloads
- Stacked query payloads
- Out-of-band payloads" || echo "Already committed"

# Commit 21: XSS payloads
echo "📌 Commit 21/25: XSS payloads"
git add payloads/xss/
git commit -m "feat: Add XSS payload database

- HTML context payloads
- JavaScript context payloads
- Attribute context payloads
- URL context payloads
- Polyglot payloads
- Blind XSS markers" || echo "Already committed"

# Commit 22: SSRF payloads
echo "📌 Commit 22/25: SSRF payloads"
git add payloads/ssrf/
git commit -m "feat: Add SSRF payload database

- Internal IP ranges
- Cloud metadata endpoints
- Protocol schemes
- Bypass techniques" || echo "Already committed"

# Commit 23: Common payloads
echo "📌 Commit 23/25: Common payloads"
git add payloads/common.txt payloads/xss.txt
git commit -m "feat: Add common payload collections

- General injection payloads
- XSS quick test payloads" || echo "Already committed"

# Commit 24: Documentation
echo "📌 Commit 24/25: Technical documentation"
git add docs/
git commit -m "docs: Add comprehensive technical documentation

- Architecture overview
- SQL Injection methodology
- XSS detection guide
- SSRF testing guide
- Usage examples
- Testing guide
- Threat model
- Roadmap" || echo "Already committed"

# Commit 25: Final cleanup
echo "📌 Commit 25/25: Final project cleanup"
git add .
git commit -m "chore: Final project cleanup and organization

- Remove temporary files
- Clean up build artifacts
- Finalize project structure" || echo "Already committed"

echo ""
echo "✅ All commits created successfully!"
echo ""
echo "📤 Pushing to GitHub..."
echo "   Repository: $REPO_URL"
echo "   Branch: $BRANCH"
echo ""

# Push to GitHub
git push -u origin "$BRANCH"

echo ""
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║              ✅ Successfully pushed to GitHub!                     ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "🔗 Repository: https://github.com/siddhantbhattarai/anvil"
echo "🌿 Branch: $BRANCH"
echo ""
echo "Next steps:"
echo "  1. Visit: https://github.com/siddhantbhattarai/anvil"
echo "  2. Review the commits"
echo "  3. Set up branch protection rules (optional)"
echo "  4. Add collaborators (optional)"
echo ""
