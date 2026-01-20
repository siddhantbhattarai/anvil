# ANVIL Development Roadmap

## Version History

### v0.1.0 (Current)
- [x] Core architecture
- [x] HTTP client with scope enforcement
- [x] Rate limiting
- [x] Passive fingerprinting
- [x] Application crawling
- [x] Boolean/Error-based SQLi detection
- [x] Time-based SQLi detection (statistical)
- [x] CLI with module flags
- [x] Confidence scoring

## Planned Features

### v0.2.0 - Advanced SQLi
- [ ] Stacked queries detection
- [ ] Out-of-band (OOB) SQLi with callback server
- [ ] Second-order SQLi detection
- [ ] Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle)
- [ ] Safe metadata extraction (proof mode)
- [ ] UNION-based data extraction

### v0.3.0 - XSS Domain
- [ ] Reflected XSS detection
- [ ] DOM-based XSS detection
- [ ] Stored XSS detection
- [ ] Context-aware payload generation
- [ ] WAF bypass techniques
- [ ] CSP analysis

### v0.4.0 - Enterprise Features
- [ ] HTML/JSON/Markdown report generation
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] SARIF output format
- [ ] Scan scheduling
- [ ] Result persistence (SQLite/PostgreSQL)
- [ ] Web dashboard

### v0.5.0 - Advanced Exploitation
- [ ] Controlled data extraction with limits
- [ ] Password hash export
- [ ] Privilege escalation detection
- [ ] Command execution (opt-in, sandboxed)
- [ ] File read/write detection

### v1.0.0 - Production Ready
- [ ] Full test coverage (>80%)
- [ ] Performance optimization
- [ ] Memory safety audit
- [ ] Documentation complete
- [ ] Stable API
- [ ] Plugin architecture

## Future Considerations

### Additional Vulnerability Classes
- [ ] SSRF detection
- [ ] XXE detection
- [ ] SSTI detection
- [ ] Path traversal
- [ ] IDOR detection
- [ ] Authentication bypass

### Advanced Features
- [ ] AI-assisted payload generation
- [ ] Behavioral analysis
- [ ] Session handling
- [ ] Multi-step attack chains
- [ ] GraphQL support
- [ ] WebSocket testing

### Integration
- [ ] Burp Suite extension
- [ ] OWASP ZAP plugin
- [ ] Nuclei template export
- [ ] DefectDojo integration

## Architecture Goals

### Performance Targets
- 100+ requests/second (configurable)
- <100MB memory for standard scans
- Parallel scanning across domains

### Safety Targets
- Zero false positives for high-confidence findings
- <5% false positive rate for medium confidence
- No accidental data modification
- Full audit trail

### Usability Targets
- Single binary distribution
- Configuration file support (YAML)
- Progress indicators
- Verbose/quiet modes

## Contributing

### Priority Areas
1. SQLi inference techniques
2. XSS detection
3. Report generation
4. Test coverage

### Code Quality
- All code must pass `cargo clippy`
- Documentation for public APIs
- Integration tests for scanners
- Benchmarks for performance-critical paths

## Timeline

```
Q1 2025: v0.2.0 - Advanced SQLi
Q2 2025: v0.3.0 - XSS Domain
Q3 2025: v0.4.0 - Enterprise Features
Q4 2025: v0.5.0 - Advanced Exploitation
Q1 2026: v1.0.0 - Production Ready
```

## Contact

- **Author**: Siddhant Bhattarai
- **License**: Apache-2.0
- **Repository**: https://github.com/siddhantbhattarai/anvil

## Changelog

### Unreleased
- Stacked queries detection
- OOB listener infrastructure
- Second-order SQLi workflow
- Proof mode for safe exploitation

