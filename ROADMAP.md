# PENT Product Roadmap

> Penetration Testing Assistant — from educational tool to professional-grade platform.

---

## Current State (v0.1)

PENT is a modular white-hat security testing tool with CLI and web UI interfaces, covering reconnaissance, vulnerability scanning, web application testing, JavaScript analysis, subdomain takeover detection, custom checks, and reporting. It includes educational guides and supports Markdown, HTML, and JSON report formats.

**Strengths:** Modular architecture, dual CLI/web interface, real-time WebSocket output, educational guides, multi-format reporting, scope enforcement.

**Gaps:** No persistence layer, no authentication on web UI, limited scanning depth, no proxy support, high false-positive rate on secret detection, no authenticated testing support.

---

## Phase 1: Foundation Hardening (v0.2)

*Goal: Make PENT reliable and production-ready for individual security testers.*

### Data Persistence
- [ ] Add SQLite backend for scan history, findings, and configuration
- [ ] Migrate in-memory scan storage to database-backed storage
- [ ] Add scan comparison (diff two scans of the same target over time)
- [ ] Implement finding deduplication across scans

### Web UI Security
- [ ] Add API key authentication for the web server
- [ ] Remove wildcard CORS — restrict to configured origins
- [ ] Add rate limiting on API endpoints
- [ ] Add CSRF protection on all forms

### Scanning Reliability
- [ ] Add configurable request timeouts and retry logic across all modules
- [ ] Implement respectful scanning: configurable delays between requests
- [ ] Add robots.txt awareness (opt-in bypass)
- [ ] Improve error handling — no scan should crash on a single failed request

### Reporting Improvements
- [ ] Add finding deduplication in reports
- [ ] Support custom report templates (Jinja2-based)
- [ ] Add CVSS v3.1 scoring to findings
- [ ] Include evidence screenshots (URL + response snippet) in HTML reports

---

## Phase 2: Deeper Testing Capabilities (v0.3)

*Goal: Move beyond surface-level detection into meaningful vulnerability assessment.*

### Authenticated Testing
- [ ] Support cookie-based and header-based authentication
- [ ] Add login sequence recording (form-based auth flows)
- [ ] Session management testing (token expiration, fixation, rotation)
- [ ] Authenticated path discovery and form testing

### Advanced Web Testing
- [ ] Blind SQL injection detection (time-based, boolean-based)
- [ ] Stored XSS detection via crawl-and-check patterns
- [ ] DOM-based XSS detection using headless browser (Playwright)
- [ ] Server-Side Request Forgery (SSRF) testing
- [ ] Insecure deserialization checks
- [ ] HTTP request smuggling detection
- [ ] WebSocket security testing

### Enhanced Reconnaissance
- [ ] Parallel async port scanning (replace socket-based scanner)
- [ ] Expand port range options (top 100, top 1000, full)
- [ ] Add Shodan/Censys API integration (optional, user-provided keys)
- [ ] DNS zone transfer testing
- [ ] Virtual host discovery
- [ ] WAF detection and fingerprinting

### Secret Detection v2
- [ ] Reduce false positives with entropy-based filtering
- [ ] Add secret validation (test if detected keys are live)
- [ ] Expand patterns: Datadog, New Relic, Cloudflare, DigitalOcean, Mapbox
- [ ] Support source map parsing for deeper JS analysis

---

## Phase 3: Professional Workflow (v0.4)

*Goal: Support team workflows and integrate with professional security tooling.*

### Proxy & Interception Support
- [ ] Route all requests through configurable HTTP/SOCKS proxy
- [ ] Burp Suite / OWASP ZAP integration (import/export findings)
- [ ] Support upstream proxy authentication

### API Security Testing Module
- [ ] OpenAPI/Swagger spec import and auto-test generation
- [ ] GraphQL introspection and query fuzzing
- [ ] REST API parameter fuzzing
- [ ] Broken Object Level Authorization (BOLA/IDOR) detection
- [ ] Rate limiting and quota bypass testing

### Cloud & Infrastructure Checks
- [ ] AWS S3 bucket permission testing
- [ ] Azure Blob Storage misconfiguration checks
- [ ] GCP Storage bucket enumeration
- [ ] Kubernetes API exposure detection
- [ ] Docker registry enumeration
- [ ] Cloud metadata endpoint checks (169.254.169.254)

### Collaboration Features
- [ ] Multi-user support with role-based access (admin, tester, viewer)
- [ ] Shared scan workspaces and finding annotations
- [ ] Finding status workflow (new → confirmed → fixed → verified)
- [ ] Export to Jira, GitHub Issues, or GitLab Issues

---

## Phase 4: Automation & Intelligence (v0.5)

*Goal: Smart scanning with reduced noise and automated workflows.*

### Scan Profiles & Scheduling
- [ ] Predefined scan profiles (quick, standard, thorough, stealth)
- [ ] Scheduled recurring scans with change detection
- [ ] Webhook notifications on scan completion or new critical findings
- [ ] Scan queuing and concurrency management

### Smart Scanning
- [ ] Technology-aware scanning (only run relevant checks per detected stack)
- [ ] Adaptive crawling depth based on target size
- [ ] Automatic scope inference from target input
- [ ] Finding correlation — link related findings across modules

### Custom Checks Engine v2
- [ ] Multi-step check chains (use output of one check as input to next)
- [ ] Conditional logic in YAML templates (if/then/else)
- [ ] Variable extraction and reuse across checks
- [ ] Community check repository (import/share YAML templates)
- [ ] Check validation and schema enforcement

### Reporting & Compliance
- [ ] OWASP Top 10 compliance mapping
- [ ] PCI DSS relevant check tagging
- [ ] Executive summary auto-generation
- [ ] Trend analysis across scan history
- [ ] PDF report export

---

## Phase 5: Ecosystem & Extensibility (v1.0)

*Goal: PENT becomes an extensible platform, not just a tool.*

### Plugin Architecture
- [ ] Formal plugin API for third-party modules
- [ ] Plugin discovery and installation (pip-based or registry)
- [ ] Sandboxed plugin execution
- [ ] Plugin lifecycle hooks (pre-scan, post-scan, on-finding)

### CI/CD Integration
- [ ] GitHub Actions integration (run PENT as a pipeline step)
- [ ] GitLab CI template
- [ ] Fail-build thresholds (e.g., fail if any high/critical findings)
- [ ] SARIF output format for GitHub Security tab
- [ ] JSON Schema for machine-readable results

### Performance & Scale
- [ ] Full async I/O with `asyncio` + `aiohttp`
- [ ] Distributed scanning across multiple workers
- [ ] Result streaming to external stores (S3, Elasticsearch)
- [ ] Memory-efficient scanning for large targets (100k+ pages)

### Mobile & Thick Client
- [ ] Mobile API proxy testing support
- [ ] Certificate pinning bypass guidance
- [ ] Deep link and intent testing (Android)
- [ ] IPA/APK static analysis integration

---

## Non-Goals

These are explicitly out of scope for PENT:

- **Exploitation frameworks** — PENT detects vulnerabilities, not exploits them. Use Metasploit for that.
- **DDoS / stress testing** — PENT is for security assessment, not availability testing.
- **Social engineering** — Phishing and social engineering are out of scope.
- **Malware analysis** — PENT focuses on network and web application testing.
- **Full network mapping** — Use dedicated tools like Nmap directly for comprehensive network audits.

---

## Versioning & Release Cadence

| Version | Phase | Focus |
|---------|-------|-------|
| v0.2 | Foundation Hardening | Persistence, auth, reliability |
| v0.3 | Deeper Testing | Authenticated scans, advanced vulns, better recon |
| v0.4 | Professional Workflow | Proxy support, API testing, cloud checks, collaboration |
| v0.5 | Automation & Intelligence | Scheduling, smart scanning, compliance |
| v1.0 | Ecosystem & Extensibility | Plugins, CI/CD, async performance |

---

*This roadmap is a living document. Priorities may shift based on user feedback and security landscape changes.*
