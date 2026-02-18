# PENT - Penetration Testing Assistant

A guided white-hat security testing and bug bounty tool with a **browser-based Web UI** and CLI.

> **Legal Disclaimer:** This tool is for **authorized security testing** and **bug bounty programs** only. Unauthorized access to computer systems is illegal. Always obtain written permission before testing any target.

## Web UI

PENT features a full browser-based interface with a dark hacker theme, real-time scan output via WebSockets, and exportable reports.

### Quick Start

```bash
# 1. Setup
chmod +x setup.sh
./setup.sh

# 2. Start the web server
source venv/bin/activate
python web/server.py

# 3. Open in your browser
#    http://localhost:5000
```

### Server Options

```bash
python web/server.py                    # Default: 0.0.0.0:5000
python web/server.py --port 8080        # Custom port
python web/server.py --host 127.0.0.1   # Localhost only
python web/server.py --debug            # Debug mode
```

## Features

| Module | Description |
|--------|-------------|
| **Recon** | DNS enumeration, subdomain discovery (crt.sh), HTTP header analysis, SSL/TLS cert info, WHOIS, technology detection, port scanning |
| **Vuln Scan** | Nmap integration, SSL/TLS vuln checks, HTTP vulnerability checks (CORS, clickjacking, cookies, open redirect, HTTPS enforcement), sensitive path discovery |
| **Web Test** | Form discovery, XSS reflection testing, SQL injection checks, CSRF analysis, directory traversal testing, link/resource enumeration, secret detection |
| **JS Analyze** | JavaScript file discovery, endpoint/URL extraction, secret/credential detection (AWS, Stripe, GitHub tokens, etc.), S3 bucket & cloud URL enumeration |
| **Takeover** | Subdomain takeover detection with 18+ service fingerprints (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel, etc.) |
| **Checks** | 12 built-in nuclei-style checks (exposed .env/.git, debug endpoints, backup files, CORS, source maps) + custom YAML check engine |
| **Guide** | OWASP Top 10 checklists, bug bounty methodology, API testing guide, mobile testing, network testing, Google dorking cheat sheet, report writing guide |
| **Report** | Generate Markdown, HTML, or JSON reports with findings, severity ratings, and remediation recommendations |
| **Full Auto** | Run all modules in sequence with a single click and get a combined report |

## Web UI Pages

| Page | Path | Description |
|------|------|-------------|
| **Dashboard** | `/` | Overview stats, recent scans, quick actions |
| **New Scan** | `/scan` | Select scan type, enter target, live terminal output |
| **Results** | `/results` | List all scans with status and findings count |
| **Scan Detail** | `/results/<id>` | Findings table with severity filter, search, report download |
| **Guides** | `/guides` | Browse all methodology guides |
| **Guide Detail** | `/guides/<topic>` | Rendered markdown guide with checklists |

## API Endpoints

The web server exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan/start` | POST | Start a new scan `{target, scan_type, options}` |
| `/api/scan/<id>` | GET | Get scan status and findings |
| `/api/scans` | GET | List all scans |
| `/api/scan/<id>/findings` | GET | Get findings for a scan |
| `/api/scan/<id>/report/<fmt>` | GET | Download report (md/html/json) |
| `/api/guides` | GET | List all guide topics |
| `/api/guides/<topic>` | GET | Get guide content |

## CLI Mode (Alternative)

The CLI still works for scripting and automation:

```bash
python pent.py                                  # Interactive menu
python pent.py recon TARGET --passive           # Passive recon
python pent.py scan TARGET --quick              # Vulnerability scan
python pent.py webtest URL --full               # Web app tests
python pent.py jsanalyze URL                    # JS analysis
python pent.py takeover DOMAIN                  # Subdomain takeover
python pent.py checks TARGET                    # Security checks
python pent.py auto TARGET --fmt html           # Full auto assessment
python pent.py guide --topic bugbounty          # View guide
```

## Custom YAML Checks

```yaml
id: my-custom-check
name: Check for exposed admin panel
severity: medium
method: GET
paths:
  - /admin/
  - /admin/login
matchers:
  status: [200]
  body_contains: ["login", "password"]
```

## Project Structure

```
pent/
├── web/
│   ├── server.py              # Flask + WebSocket server & API
│   ├── templates/             # Jinja2 HTML templates
│   │   ├── base.html          # Layout with sidebar
│   │   ├── index.html         # Dashboard
│   │   ├── scan.html          # New scan + live terminal
│   │   ├── results.html       # Scan results list
│   │   ├── result_detail.html # Findings + report export
│   │   ├── guides.html        # Guide grid
│   │   └── guide_detail.html  # Rendered guide
│   └── static/
│       ├── css/style.css      # Dark theme
│       └── js/app.js          # Shared JS
├── pent.py                    # CLI entry point
├── modules/                   # Scan engine modules
│   ├── recon.py, vuln_scanner.py, web_tester.py
│   ├── js_analyzer.py, takeover.py, custom_checks.py
│   ├── reporter.py, guide.py, utils.py
├── wordlists/                 # Fuzzing wordlists
├── templates/                 # Custom YAML checks
├── reports/                   # Generated reports
├── requirements.txt
└── setup.sh
```

## Requirements

- Python 3.8+
- Optional system tools: `nmap`, `whois` (for enhanced scanning)
