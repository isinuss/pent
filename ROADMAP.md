# PENT Product Roadmap

> Penetration Testing Assistant — from educational tool to professional-grade security platform.

---

## Strategy: Two Tracks, One Engine

PENT ships two interfaces that share the same scanning engine:

| Track | Audience | Purpose |
|-------|----------|---------|
| **Web UI** (primary) | Companies, security teams | Hosted server with modern interactive dashboard — the product face. Visual scan management, team collaboration, real-time results, polished reports. |
| **CLI** (secondary) | Individual professionals | Power-user tool for scripting, automation, SSH sessions, CI/CD pipelines. Fast, composable, no browser needed. |

Both tracks consume the same module layer. UI gets priority for new features; CLI follows. The backend API serves both — the web UI is a client of the same REST + WebSocket API that powers automation.

---

## Current State (v0.1)

PENT has a modular scanning engine with 8 modules (recon, vuln scan, web test, JS analysis, subdomain takeover, custom checks, guides, reporting). The CLI uses Click + Rich. The web UI is server-rendered Jinja2 templates with Flask and WebSocket streaming.

**What works:** Modular architecture, real-time scan output, multi-format reports, educational guides, scope enforcement.

**What doesn't:** Jinja2 templates are not interactive. No persistence (results lost on restart). No auth on the web server. Limited scan depth. High false-positive rate. No team features.

---

## Phase 1: Modern UI Foundation + Backend Hardening (v0.2)

*Goal: Replace the template-based UI with a modern SPA and make the backend production-ready.*

### Modern Web UI — React SPA
- [ ] Set up React frontend with Vite, TypeScript, and Tailwind CSS
- [ ] Implement dark-themed design system (component library)
- [ ] Build real-time scan terminal with WebSocket streaming (xterm.js or similar)
- [ ] Dashboard page — scan history, severity breakdown charts, quick actions
- [ ] New Scan page — target input, module picker, options panel, live progress
- [ ] Results page — sortable/filterable findings table with severity badges
- [ ] Scan Detail page — findings list, evidence viewer, inline remediation advice
- [ ] Guides page — searchable methodology browser with syntax-highlighted checklists
- [ ] Report export — download MD/HTML/JSON directly from the UI
- [ ] Responsive layout — usable on tablet and desktop

### Backend API Overhaul
- [ ] Clean REST API design with versioned endpoints (`/api/v1/`)
- [ ] OpenAPI/Swagger spec auto-generated from routes
- [ ] Consistent JSON response envelope (`{data, error, meta}`)
- [ ] WebSocket channels per scan (multiplexed output streaming)
- [ ] Request validation with Pydantic or Marshmallow

### Data Persistence
- [ ] Add PostgreSQL (primary) with SQLite fallback for single-user mode
- [ ] Schema: targets, scans, findings, users, configurations
- [ ] Scan history with full result persistence across restarts
- [ ] Finding deduplication across scans on the same target
- [ ] Scan diffing — compare two scans side-by-side

### Server Security
- [ ] JWT-based authentication (login/register)
- [ ] API key support for programmatic access (CLI + integrations)
- [ ] CORS restricted to configured origins
- [ ] Rate limiting on all endpoints
- [ ] CSRF protection

### CLI Improvements
- [ ] `pent login` — authenticate CLI against hosted server
- [ ] `pent push` — upload local scan results to server
- [ ] `pent pull` — download scan results from server
- [ ] Structured JSON output mode (`--json`) for all commands

---

## Phase 2: Interactive UI + Deeper Scanning (v0.3)

*Goal: Make the UI truly interactive and expand scan capabilities beyond surface-level checks.*

### Interactive UI Features
- [ ] Live findings feed — findings appear in real-time as scan runs (not just terminal output)
- [ ] Finding detail drawer — click a finding to see full evidence, request/response, remediation
- [ ] Target management — save targets, group by project/client, track scope
- [ ] Scan configuration builder — visual module picker with toggles and options
- [ ] Interactive recon map — visual graph of subdomains, IPs, DNS records, tech stack
- [ ] Severity trend charts — line/bar charts showing findings over time per target
- [ ] Dark/light theme toggle

### Authenticated Testing
- [ ] Auth profile management in UI — save cookie/header/bearer token configs
- [ ] Login sequence recorder — define form-based login flows visually
- [ ] Session-aware scanning — maintain auth state across modules
- [ ] Authenticated path discovery and form testing

### Advanced Web Testing
- [ ] Blind SQL injection (time-based, boolean-based)
- [ ] Stored XSS detection via crawl-then-check
- [ ] DOM-based XSS via headless browser (Playwright)
- [ ] Server-Side Request Forgery (SSRF) checks
- [ ] HTTP request smuggling detection
- [ ] WebSocket security testing

### Enhanced Reconnaissance
- [ ] Async port scanning (replace socket-based scanner with masscan/async)
- [ ] Expanded port range options (top 100 / 1000 / full)
- [ ] Shodan & Censys integration (user-provided API keys, configured in UI)
- [ ] DNS zone transfer testing
- [ ] Virtual host discovery
- [ ] WAF detection and fingerprinting

### Secret Detection v2
- [ ] Entropy-based filtering to reduce false positives
- [ ] Live secret validation (test if detected keys are active)
- [ ] Expanded patterns: Datadog, New Relic, Cloudflare, DigitalOcean, Mapbox
- [ ] Source map parsing for deeper JS analysis

---

## Phase 3: Team Platform + Professional Tooling (v0.4)

*Goal: PENT becomes a team platform that integrates into professional security workflows.*

### Team & Collaboration
- [ ] Multi-user with roles: admin, tester, viewer
- [ ] Organization/workspace model — isolated scan data per team
- [ ] Finding annotations — add notes, screenshots, proof-of-concept
- [ ] Finding workflow: new → confirmed → mitigated → verified → closed
- [ ] Activity feed — who scanned what, when
- [ ] @mention and comments on findings

### Proxy & Tool Integration
- [ ] Route scans through configurable HTTP/SOCKS proxy (Burp, ZAP)
- [ ] Import findings from Burp Suite XML / OWASP ZAP reports
- [ ] Export findings to Burp / ZAP format
- [ ] Upstream proxy authentication support

### API Security Module
- [ ] OpenAPI/Swagger spec import — auto-generate test cases
- [ ] GraphQL introspection detection and query fuzzing
- [ ] REST parameter fuzzing
- [ ] BOLA/IDOR detection patterns
- [ ] Rate limiting and quota bypass testing
- [ ] API endpoint discovered from JS analysis auto-fed into API testing

### Cloud & Infrastructure
- [ ] AWS S3 bucket permission checks
- [ ] Azure Blob Storage misconfiguration detection
- [ ] GCP Storage bucket enumeration
- [ ] Kubernetes API exposure
- [ ] Docker registry enumeration
- [ ] Cloud metadata endpoint checks (169.254.169.254)

### Integrations & Export
- [ ] Export findings to Jira, GitHub Issues, GitLab Issues
- [ ] Webhook notifications (Slack, Discord, Teams) on scan events
- [ ] CSV/PDF report export from UI

---

## Phase 4: Automation & Intelligence (v0.5)

*Goal: Smart, scheduled scanning with reduced noise and compliance-ready reporting.*

### Scan Automation
- [ ] Scan profiles: quick, standard, thorough, stealth (configurable in UI)
- [ ] Scheduled recurring scans with cron-like configuration
- [ ] Change detection — alert only on new/changed findings
- [ ] Scan queue with concurrency limits
- [ ] Scan templates — save and reuse scan configurations

### Smart Scanning
- [ ] Technology-aware module selection (skip irrelevant checks)
- [ ] Adaptive crawl depth based on target size
- [ ] Automatic scope inference from target input
- [ ] Finding correlation — link related findings across modules
- [ ] Confidence scoring on findings (reduce noise)

### Custom Checks Engine v2
- [ ] Multi-step check chains (output of one → input of next)
- [ ] Conditional logic in YAML templates
- [ ] Variable extraction and reuse
- [ ] Community check marketplace (browse/import/share templates in UI)
- [ ] Visual check builder in UI (no YAML required)

### Compliance & Reporting
- [ ] OWASP Top 10 mapping — show compliance status per target
- [ ] PCI DSS check tagging
- [ ] Executive summary auto-generation (non-technical overview)
- [ ] Trend dashboards — severity over time, mean-time-to-fix
- [ ] Branded PDF reports with company logo

---

## Phase 5: Platform & Ecosystem (v1.0)

*Goal: PENT is an extensible platform — not just a scanner.*

### Plugin Architecture
- [ ] Plugin API for third-party scanning modules
- [ ] Plugin registry — discover, install, update from UI
- [ ] Sandboxed execution for untrusted plugins
- [ ] Plugin hooks: pre-scan, post-scan, on-finding, on-report

### CI/CD Integration
- [ ] GitHub Actions action (`uses: pent/scan@v1`)
- [ ] GitLab CI template
- [ ] Fail-build thresholds (block merge on critical/high findings)
- [ ] SARIF output for GitHub Security tab
- [ ] JSON Schema for machine-readable results

### Performance & Scale
- [ ] Full async I/O (`asyncio` + `aiohttp`) in scanning engine
- [ ] Distributed scanning — worker nodes for parallel target scanning
- [ ] Result streaming to Elasticsearch / S3
- [ ] Memory-efficient crawling for large targets (100k+ pages)

### Deployment
- [ ] Docker Compose single-command deployment
- [ ] Helm chart for Kubernetes
- [ ] Environment-based configuration (12-factor)
- [ ] Health check and monitoring endpoints (`/healthz`, `/metrics`)
- [ ] Horizontal scaling guide

### Mobile & Thick Client
- [ ] Mobile API proxy testing
- [ ] Certificate pinning bypass guidance
- [ ] Deep link / intent testing (Android)
- [ ] IPA/APK static analysis integration

---

## Non-Goals

These are explicitly out of scope:

- **Exploitation** — PENT detects, it doesn't exploit. Use Metasploit for that.
- **DDoS / load testing** — Security assessment only.
- **Social engineering** — No phishing, pretexting, or vishing features.
- **Malware analysis** — Focus is network and web application testing.
- **Full network mapping** — Use Nmap directly for comprehensive network audits.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    CLIENTS                           │
│                                                     │
│   ┌──────────┐   ┌──────────┐   ┌───────────────┐  │
│   │ React UI │   │   CLI    │   │ CI/CD / API   │  │
│   │  (SPA)   │   │ (Click)  │   │  Consumers    │  │
│   └────┬─────┘   └────┬─────┘   └──────┬────────┘  │
│        │              │                 │            │
└────────┼──────────────┼─────────────────┼────────────┘
         │              │                 │
    ┌────▼──────────────▼─────────────────▼────┐
    │          REST API + WebSocket             │
    │       (Flask / FastAPI + SocketIO)        │
    │         JWT Auth · Rate Limiting          │
    ├──────────────────────────────────────────-┤
    │            Scanning Engine                │
    │                                           │
    │  ┌───────┐ ┌──────┐ ┌───────┐ ┌───────┐  │
    │  │ Recon │ │ Vuln │ │  Web  │ │  JS   │  │
    │  │       │ │ Scan │ │ Test  │ │Analyze│  │
    │  └───────┘ └──────┘ └───────┘ └───────┘  │
    │  ┌────────┐ ┌───────┐ ┌──────┐ ┌──────┐  │
    │  │Takeover│ │Checks │ │Guide │ │Report│  │
    │  └────────┘ └───────┘ └──────┘ └──────┘  │
    ├───────────────────────────────────────────┤
    │          Data Layer                       │
    │   PostgreSQL / SQLite · File Storage      │
    └───────────────────────────────────────────┘
```

---

## Versioning & Release Cadence

| Version | Phase | UI Focus | CLI Focus |
|---------|-------|----------|-----------|
| v0.2 | Foundation | React SPA, dashboard, live terminal | Server auth, JSON output, push/pull |
| v0.3 | Deeper Testing | Interactive findings, recon graph, auth profiles | Advanced scan flags, async scanning |
| v0.4 | Team Platform | Collaboration, annotations, integrations | Proxy routing, API testing commands |
| v0.5 | Automation | Scan scheduler, visual check builder, dashboards | Profiles, cron, compliance reports |
| v1.0 | Platform | Plugin marketplace, branded reports | CI/CD actions, SARIF, plugin CLI |

---

*This roadmap is a living document. UI leads, CLI follows, engine powers both.*
