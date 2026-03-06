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

## Current State (v0.2.1)

PENT has a modular scanning engine with 8 modules (recon, vuln scan, web test, JS analysis, subdomain takeover, custom checks, guides, reporting). The web UI is a React SPA (Vite + Tailwind) with JWT auth, SQLite persistence, and real-time WebSocket streaming. The CLI uses Click + Rich and shares the same module layer.

**What works:** React SPA with full CRUD, real-time scan output via WebSocket, scan persistence across restarts, JWT + API key auth, rate limiting, multi-format reports, interactive findings with detail drawer, target management with project grouping, automated testing pipeline with recommendations, enhanced port scanner with banner grabbing.

**What's next:** Deeper scanning (blind SQLi, DOM XSS), auth profile UI, trend charts, recon visualization, async scanning engine.

---

## Phase 1: Modern UI Foundation + Backend Hardening (v0.2) — ~85% Complete

*Goal: Replace the template-based UI with a modern SPA and make the backend production-ready.*

### Modern Web UI — React SPA
- [x] Set up React frontend with Vite, TypeScript, and Tailwind CSS
- [x] Implement dark-themed design system (component library)
- [x] Build real-time scan terminal with WebSocket streaming
- [x] Dashboard page — scan history, severity breakdown charts, quick actions
- [x] New Scan page — target input, module picker, options panel, live progress
- [x] Results page — sortable/filterable findings table with severity badges
- [x] Scan Detail page — findings list, evidence viewer, inline remediation advice
- [x] Guides page — searchable methodology browser
- [x] Report export — download MD/HTML/JSON directly from the UI
- [x] Responsive layout — usable on tablet and desktop

### Backend API Overhaul
- [x] Clean REST API design with versioned endpoints (`/api/v1/`)
- [ ] OpenAPI/Swagger spec auto-generated from routes
- [x] Consistent JSON response envelope (`{data, error}`)
- [x] WebSocket channels per scan (multiplexed output streaming)
- [ ] Request validation with Pydantic or Marshmallow

### Data Persistence
- [x] SQLite with WAL mode (PostgreSQL deferred to Phase 3)
- [x] Schema: targets, scans, findings, users, api_keys, auth_profiles
- [x] Scan history with full result persistence across restarts
- [x] Finding normalization layer (detail→description, evidence parsing, auto-recommendations)
- [ ] Finding deduplication across scans on the same target
- [ ] Scan diffing — compare two scans side-by-side

### Server Security
- [x] JWT-based authentication (login/register)
- [x] API key support for programmatic access (CLI + integrations)
- [x] CORS restricted to configured origins
- [x] Rate limiting on all endpoints (per-IP token bucket)
- [x] Role-based access control (admin, tester, viewer)
- [ ] CSRF protection

### CLI Improvements
- [ ] `pent login` — authenticate CLI against hosted server
- [ ] `pent push` — upload local scan results to server
- [ ] `pent pull` — download scan results from server
- [ ] Structured JSON output mode (`--json`) for all commands

---

## Phase 2: Interactive UI + Deeper Scanning (v0.3) — ~80% Complete

*Goal: Make the UI truly interactive and expand scan capabilities beyond surface-level checks.*

### Interactive UI Features
- [x] Live findings feed — findings appear in real-time as scan runs via WebSocket
- [x] Finding detail drawer — click a finding to see full evidence, request/response, remediation
- [x] Target management — save targets, group by project/client, track scope
- [x] Scan configuration builder — visual module picker with toggles and options
- [x] Dark/light theme toggle (ThemeToggle component)
- [x] Interactive recon map — visual force-directed graph of subdomains, IPs, DNS records, tech stack
- [x] Severity trend charts — stacked area chart showing findings over time per target

### Testing Pipeline *(new — not in original roadmap)*
- [x] Automated lateral testing pipeline — run all scan phases sequentially against a target
- [x] Pipeline API endpoints (`/api/v1/pipeline/phases`, `/pipeline/start`, `/pipeline/<target>/recommendations`)
- [x] Real-time pipeline progress tracking via WebSocket (per-phase status)
- [x] Auto-generated recommendations based on aggregated findings
- [x] Pipeline accessible from sidebar nav and target action buttons
- [x] Phase selection UI — choose which phases to include

### Enhanced Port Scanner *(upgraded from original roadmap)*
- [x] Concurrent port scanning with ThreadPoolExecutor (20 workers)
- [x] Banner grabbing for open services (SSH, FTP, SMTP, HTTP)
- [x] Service version detection from banners
- [x] 50+ ports including modern services (Docker, K8s, RabbitMQ, Prometheus, etc.)
- [x] Risky service warnings (Redis, MongoDB, Docker, K8s exposed)
- [ ] Full async port scanning with asyncio (Phase 5)
- [ ] Shodan & Censys integration (user-provided API keys)

### Authenticated Testing
- [x] Auth profile backend — save cookie/header/bearer token/form-based configs
- [x] Session-aware scanning — apply auth profiles to web testing module
- [x] Auth profile management UI — visual config editor in frontend
- [ ] Login sequence recorder — define form-based login flows visually
- [ ] Authenticated path discovery and form testing

### Advanced Web Testing
- [x] Blind SQL injection (time-based, boolean-based)
- [x] Stored XSS detection via crawl-then-check
- [ ] DOM-based XSS via headless browser (Playwright)
- [x] Server-Side Request Forgery (SSRF) checks
- [x] HTTP request smuggling detection
- [x] WebSocket security testing

### Enhanced Reconnaissance
- [x] DNS zone transfer testing
- [x] Virtual host discovery
- [x] WAF detection and fingerprinting

### Secret Detection v2
- [x] Entropy-based filtering to reduce false positives
- [x] Live secret validation (test if detected keys are active)
- [x] Expanded patterns: Datadog, New Relic, Cloudflare, DigitalOcean, Mapbox
- [x] Source map parsing for deeper JS analysis

---

## Phase 3: Team Platform + Professional Tooling (v0.4)

*Goal: PENT becomes a team platform that integrates into professional security workflows.*

### Team & Collaboration
- [x] Multi-user with roles: admin, tester, viewer *(done in Phase 1)*
- [ ] Organization/workspace model — isolated scan data per team
- [ ] Finding annotations — add notes, screenshots, proof-of-concept
- [ ] Finding workflow: new → confirmed → mitigated → verified → closed
- [ ] Activity feed — who scanned what, when
- [ ] @mention and comments on findings

### Data Layer Upgrade
- [ ] PostgreSQL support for team deployments
- [ ] Finding deduplication across scans
- [ ] Scan diffing — compare two scans side-by-side

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
    │         (Flask + SocketIO)                │
    │     JWT Auth · Rate Limiting · RBAC      │
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
    │  ┌────────────────────────────────────┐   │
    │  │  Pipeline Orchestrator (new)       │   │
    │  │  Sequential phase execution +      │   │
    │  │  recommendation engine             │   │
    │  └────────────────────────────────────┘   │
    ├───────────────────────────────────────────┤
    │          Data Layer                       │
    │   SQLite (WAL) · Finding Normalizer      │
    └───────────────────────────────────────────┘
```

---

## Versioning & Release Cadence

| Version | Phase | Status | UI Focus | CLI Focus |
|---------|-------|--------|----------|-----------|
| v0.2 | Foundation | **~85%** | React SPA, dashboard, live terminal | Server auth, JSON output |
| v0.3 | Deeper Testing | **~80%** | Pipeline, findings drawer, auth profiles, trend charts, recon map | Advanced scan flags, async scanning |
| v0.4 | Team Platform | Planned | Collaboration, annotations, integrations | Proxy routing, API testing commands |
| v0.5 | Automation | Planned | Scan scheduler, visual check builder, dashboards | Profiles, cron, compliance reports |
| v1.0 | Platform | Planned | Plugin marketplace, branded reports | CI/CD actions, SARIF, plugin CLI |

---

*This roadmap is a living document. UI leads, CLI follows, engine powers both.*
