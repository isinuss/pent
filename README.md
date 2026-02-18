# PENT - Penetration Testing Assistant

A guided white-hat security testing and bug bounty tool built in Python.

> **Legal Disclaimer:** This tool is for **authorized security testing** and **bug bounty programs** only. Unauthorized access to computer systems is illegal. Always obtain written permission before testing any target.

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
| **Full Auto** | Run all modules in sequence with a single command and get a combined report |

## Quick Start

```bash
# Setup
chmod +x setup.sh
./setup.sh

# Activate environment
source venv/bin/activate

# Interactive mode (recommended for first use)
python pent.py

# Or use CLI commands directly
python pent.py recon example.com
python pent.py scan example.com --quick
python pent.py webtest https://example.com
python pent.py jsanalyze https://example.com
python pent.py takeover example.com
python pent.py checks example.com
python pent.py guide --topic bugbounty
python pent.py auto example.com --fmt html
```

## CLI Commands

```
python pent.py                                  # Interactive menu
python pent.py recon TARGET                     # Run reconnaissance
python pent.py recon TARGET --passive           # Passive recon only
python pent.py scan TARGET                      # Full vulnerability scan
python pent.py scan TARGET --quick              # Quick scan (top ports)
python pent.py webtest URL                      # Web application tests
python pent.py webtest URL --full               # All web tests including dir traversal
python pent.py jsanalyze URL                    # JS endpoint & secret extraction
python pent.py takeover DOMAIN                  # Subdomain takeover check
python pent.py checks TARGET                    # Run built-in security checks
python pent.py checks TARGET --custom-dir DIR   # Run custom YAML checks
python pent.py guide                            # List guide topics
python pent.py guide --topic web                # View specific guide
python pent.py report --fmt md                  # Generate Markdown report
python pent.py report --fmt html                # Generate HTML report
python pent.py report --fmt json                # Generate JSON report
python pent.py auto TARGET                      # Full auto assessment (all modules)
python pent.py auto TARGET --fmt html           # Auto assessment with HTML report
```

## Guide Topics

| Key | Topic |
|-----|-------|
| `recon` | Reconnaissance checklist |
| `web` | OWASP Top 10 testing guide |
| `api` | API security testing |
| `bugbounty` | Bug bounty workflow |
| `mobile` | Mobile app testing |
| `network` | Network penetration testing |
| `report_writing` | Writing effective reports |
| `google_dorks` | Google dorking cheat sheet |

## Custom Checks (YAML Templates)

You can create custom security checks as YAML files. Place them in `templates/` and run:

```bash
python pent.py checks example.com --custom-dir templates
```

Example template:
```yaml
id: my-custom-check
name: Check for exposed admin panel
severity: medium
method: GET
paths:
  - /admin/
  - /admin/login
  - /dashboard/
matchers:
  status: [200]
  body_contains: ["login", "password", "admin"]
```

## Project Structure

```
pent/
├── pent.py                 # Main entry point & CLI
├── requirements.txt        # Python dependencies
├── setup.sh               # Setup script
├── modules/
│   ├── recon.py           # Reconnaissance module
│   ├── vuln_scanner.py    # Vulnerability scanning
│   ├── web_tester.py      # Web application testing
│   ├── js_analyzer.py     # JavaScript analysis
│   ├── takeover.py        # Subdomain takeover detection
│   ├── custom_checks.py   # Built-in & YAML check engine
│   ├── reporter.py        # Report generation
│   ├── guide.py           # Methodology guides
│   └── utils.py           # Shared utilities
├── wordlists/
│   ├── common_paths.txt   # Common sensitive paths (200+)
│   └── params.txt         # Common parameter names (150+)
├── templates/
│   └── example_check.yaml # Example custom check template
└── reports/               # Generated reports output
```

## Requirements

- Python 3.8+
- Optional system tools: `nmap`, `whois` (for enhanced scanning)
