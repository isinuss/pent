"""
Guide Module - Methodology checklists, OWASP guidance, and learning resources.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich import box


METHODOLOGIES = {
    "recon": {
        "title": "Reconnaissance Checklist",
        "content": """
## Reconnaissance Phase

### Passive Recon (No direct contact with target)
- [ ] **WHOIS lookup** - Registrant info, nameservers, dates
- [ ] **DNS records** - A, AAAA, MX, NS, TXT, CNAME, SOA
- [ ] **Subdomain enumeration** - crt.sh, SecurityTrails, Subfinder
- [ ] **Google dorking** - site:, inurl:, filetype:, intitle:
- [ ] **Shodan / Censys** - Exposed services and banners
- [ ] **Wayback Machine** - Historical snapshots, old endpoints
- [ ] **GitHub/GitLab recon** - Leaked secrets, old configs, API keys
- [ ] **Social media / LinkedIn** - Employee info, tech stack clues
- [ ] **Job postings** - Technologies mentioned in job listings
- [ ] **Pastebin / paste sites** - Leaked credentials or data

### Active Recon (Direct contact with target)
- [ ] **Port scanning** - nmap full TCP + top UDP ports
- [ ] **Service enumeration** - Version detection on open ports
- [ ] **Web crawling** - Discover pages, endpoints, parameters
- [ ] **Technology fingerprinting** - Wappalyzer, WhatWeb
- [ ] **SSL/TLS analysis** - Certificate info, protocol versions
- [ ] **HTTP header analysis** - Security headers, server info
- [ ] **robots.txt / sitemap.xml** - Discover hidden paths
- [ ] **Virtual host enumeration** - Different sites on same IP

### Tools
| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning & service detection |
| `subfinder` | Subdomain discovery |
| `amass` | Attack surface mapping |
| `httpx` | HTTP probing & tech detection |
| `nuclei` | Template-based vulnerability scanning |
| `waybackurls` | Historical URL discovery |
| `gau` | Get All URLs from multiple sources |
| `ffuf` | Web fuzzing |
""",
    },
    "web": {
        "title": "Web Application Testing (OWASP Top 10)",
        "content": """
## OWASP Top 10 Testing Guide

### A01:2021 - Broken Access Control
- [ ] Test IDOR (Insecure Direct Object References)
  - Change ID parameters: `/api/user/123` -> `/api/user/124`
  - Try accessing other users' resources
- [ ] Test privilege escalation
  - Access admin endpoints as regular user
  - Modify role/permission parameters
- [ ] Test forced browsing
  - Access pages that should require auth
- [ ] Check CORS configuration
  - Test with malicious Origin headers
- [ ] Test HTTP method tampering
  - Try PUT/DELETE on GET-only endpoints

### A02:2021 - Cryptographic Failures
- [ ] Check SSL/TLS configuration (testssl.sh)
- [ ] Look for sensitive data in URLs
- [ ] Check for data transmitted over HTTP
- [ ] Verify password storage (no plaintext/MD5/SHA1)
- [ ] Check for hardcoded secrets in source

### A03:2021 - Injection
- [ ] **SQL Injection** - Test all input points
  - `' OR 1=1--`, `' UNION SELECT`, time-based blind
  - Use sqlmap for thorough testing
- [ ] **XSS (Cross-Site Scripting)**
  - Reflected: test URL parameters
  - Stored: test form inputs, comments, profiles
  - DOM-based: check client-side JS for sink/source
  - Payloads: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
- [ ] **Command Injection** - `; ls`, `| cat /etc/passwd`, `$(whoami)`
- [ ] **SSTI** - `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- [ ] **LDAP/XPath/NoSQL injection**

### A04:2021 - Insecure Design
- [ ] Test business logic flaws
- [ ] Check rate limiting on sensitive operations
- [ ] Test for race conditions
- [ ] Review API design for security issues

### A05:2021 - Security Misconfiguration
- [ ] Default credentials check
- [ ] Directory listing enabled?
- [ ] Stack traces / error details exposed?
- [ ] Unnecessary HTTP methods enabled?
- [ ] Security headers missing?
- [ ] Debug endpoints accessible? (/debug, /actuator, /elmah)

### A06:2021 - Vulnerable Components
- [ ] Identify all frameworks and libraries
- [ ] Check versions against CVE databases
- [ ] Look for outdated JavaScript libraries
- [ ] Check for known vulnerable dependencies

### A07:2021 - Authentication Failures
- [ ] Test for brute force (is there rate limiting?)
- [ ] Test default / weak credentials
- [ ] Test password reset flow
- [ ] Check session management
  - Session fixation
  - Session doesn't expire
  - Session token in URL
- [ ] Test 2FA bypass techniques
- [ ] Check "remember me" functionality

### A08:2021 - Software & Data Integrity
- [ ] Check for unsigned updates
- [ ] Test deserialization vulnerabilities
- [ ] Verify integrity of CI/CD pipelines

### A09:2021 - Logging & Monitoring Failures
- [ ] Verify login attempts are logged
- [ ] Check if access control failures are logged
- [ ] Test if alerts are triggered on suspicious activity

### A10:2021 - SSRF (Server-Side Request Forgery)
- [ ] Test URL parameters that fetch external resources
- [ ] Try internal IPs: `http://127.0.0.1`, `http://169.254.169.254`
- [ ] Try URL schemes: `file:///etc/passwd`, `gopher://`
- [ ] Test PDF generators, image fetchers, webhooks
""",
    },
    "api": {
        "title": "API Security Testing",
        "content": """
## API Security Testing Checklist

### Authentication & Authorization
- [ ] Test API without authentication
- [ ] Test with expired / invalid tokens
- [ ] Test JWT manipulation (none algorithm, key confusion)
- [ ] Test IDOR via API endpoints
- [ ] Check for API key leakage in client-side code
- [ ] Test OAuth flows for misconfigurations

### Input Validation
- [ ] Test all parameters for injection (SQLi, NoSQLi, XSS)
- [ ] Send unexpected data types (string where int expected)
- [ ] Test boundary values (negative numbers, huge numbers)
- [ ] Test with special characters and unicode
- [ ] Check for mass assignment vulnerabilities

### Rate Limiting & Resource
- [ ] Test rate limiting on all endpoints
- [ ] Check for resource exhaustion (large payloads)
- [ ] Test pagination limits
- [ ] Check for GraphQL depth/complexity limits

### Information Disclosure
- [ ] Check API error responses for stack traces
- [ ] Look for verbose error messages
- [ ] Test for user enumeration via API responses
- [ ] Check API documentation endpoints (/swagger, /openapi)
- [ ] Look for hidden/undocumented endpoints

### Tools
| Tool | Purpose |
|------|---------|
| `Burp Suite` | HTTP proxy & scanner |
| `Postman` | API testing & collections |
| `ffuf` | API endpoint fuzzing |
| `jwt_tool` | JWT token testing |
| `Arjun` | HTTP parameter discovery |
| `GraphQLmap` | GraphQL endpoint testing |
""",
    },
    "bugbounty": {
        "title": "Bug Bounty Workflow",
        "content": """
## Bug Bounty Methodology

### Phase 1: Scope & Setup
1. **Read the program rules carefully**
   - What's in scope? What's out of scope?
   - What vulnerability types are accepted?
   - What are the severity definitions?
   - Are there any special testing requirements?
2. **Set up your environment**
   - Burp Suite / OWASP ZAP configured
   - Subfinder, httpx, nuclei installed
   - Note-taking system ready (Obsidian, Notion)

### Phase 2: Recon (Spend 40% of time here)
1. **Asset discovery**
   - Subdomain enumeration (multiple tools)
   - Port scanning on discovered hosts
   - Identify web applications, APIs, services
2. **Content discovery**
   - Directory brute-forcing (ffuf, dirsearch)
   - Parameter discovery (Arjun, ParamSpider)
   - JavaScript file analysis (LinkFinder, SecretFinder)
   - Wayback Machine URL extraction
3. **Prioritize targets**
   - Focus on less-tested assets
   - Look for acquisition domains
   - Find forgotten/legacy applications

### Phase 3: Vulnerability Hunting
1. **Low-hanging fruit first**
   - Subdomain takeovers
   - Exposed sensitive files (.env, .git, backups)
   - Default credentials
   - Known CVEs on identified tech
2. **OWASP Top 10 testing** (see web checklist)
3. **Business logic testing**
   - Price manipulation
   - Coupon/discount abuse
   - Account takeover chains
   - Race conditions
4. **Chaining vulnerabilities**
   - Combine low-severity issues for higher impact
   - Self-XSS + CSRF = Stored XSS
   - SSRF + cloud metadata = RCE

### Phase 4: Reporting
1. **Write a clear, professional report**
   - **Title**: Descriptive, includes vuln type and location
   - **Summary**: 1-2 sentences about the issue
   - **Steps to Reproduce**: Numbered, detailed steps
   - **Impact**: What can an attacker actually do?
   - **Proof of Concept**: Screenshots, videos, HTTP requests
   - **Remediation**: Suggest how to fix it
   - **Severity**: Use CVSS or program's rating system
2. **Review before submitting** - Clear? Reproducible? Impactful?

### Tips for Success
- **Be patient** - Good bugs take time to find
- **Automate recon** - But manually verify everything
- **Stay in scope** - Never test out-of-scope assets
- **Document everything** - You'll forget details later
- **Don't duplicate** - Search for existing reports first
- **Learn continuously** - Read disclosed reports on HackerOne/Bugcrowd
""",
    },
    "mobile": {
        "title": "Mobile App Testing",
        "content": """
## Mobile Application Security Testing

### Static Analysis
- [ ] Decompile the app (jadx for Android, class-dump for iOS)
- [ ] Search for hardcoded secrets, API keys, URLs
- [ ] Check for insecure data storage paths
- [ ] Review AndroidManifest.xml / Info.plist
- [ ] Check for debug flags left enabled
- [ ] Review certificate pinning implementation

### Dynamic Analysis
- [ ] Set up proxy (Burp Suite) with device
- [ ] Bypass certificate pinning (Frida/objection)
- [ ] Monitor API calls and parameters
- [ ] Test authentication and session management
- [ ] Check for sensitive data in logs
- [ ] Test for insecure local storage
- [ ] Review inter-process communication

### Tools
| Tool | Purpose |
|------|---------|
| `jadx` | Android APK decompilation |
| `apktool` | APK disassembly |
| `Frida` | Dynamic instrumentation |
| `objection` | Runtime exploration |
| `MobSF` | Automated mobile analysis |
| `drozer` | Android security assessment |
""",
    },
    "network": {
        "title": "Network Testing",
        "content": """
## Network Penetration Testing Checklist

### Discovery
- [ ] Host discovery (nmap -sn)
- [ ] Port scanning (TCP full + UDP top 1000)
- [ ] Service version detection (nmap -sV)
- [ ] OS fingerprinting (nmap -O)

### Service-Specific Testing
- [ ] **SSH (22)** - Weak algorithms, auth methods, version vulns
- [ ] **FTP (21)** - Anonymous login, version exploits
- [ ] **SMB (445)** - Null sessions, shares, EternalBlue
- [ ] **RDP (3389)** - BlueKeep, NLA bypass
- [ ] **DNS (53)** - Zone transfer, cache poisoning
- [ ] **SMTP (25)** - Open relay, user enumeration
- [ ] **SNMP (161)** - Default community strings
- [ ] **Database ports** - Default creds, version exploits

### Post-Exploitation Considerations
- [ ] Credential harvesting (with authorization)
- [ ] Lateral movement mapping
- [ ] Privilege escalation paths
- [ ] Data exfiltration risks

### Tools
| Tool | Purpose |
|------|---------|
| `nmap` | Network scanning |
| `masscan` | Fast port scanning |
| `crackmapexec` | Network protocol testing |
| `enum4linux` | SMB/NetBIOS enumeration |
| `hydra` | Service brute-forcing |
| `Metasploit` | Exploitation framework |
""",
    },
    "report_writing": {
        "title": "Report Writing Guide",
        "content": """
## Writing Effective Security Reports

### Structure of a Good Report

```
## Title
[Vuln Type] in [Component] allows [Impact] via [Vector]

## Severity
Critical / High / Medium / Low / Informational
CVSS: X.X (if applicable)

## Description
Brief description of the vulnerability and its context.

## Steps to Reproduce
1. Navigate to https://target.com/endpoint
2. Intercept the request with Burp Suite
3. Modify the parameter `id` to `../../../etc/passwd`
4. Forward the request
5. Observe the file contents in the response

## Impact
Describe what an attacker could achieve:
- Read arbitrary files from the server
- Access other users' data
- Execute commands on the server

## Proof of Concept
[Screenshots, HTTP request/response pairs, video]

## Affected Endpoint
- URL: https://target.com/api/v1/files?path=
- Method: GET
- Parameter: path

## Remediation
1. Validate and sanitize file path inputs
2. Use allowlist for permitted file access
3. Implement proper access controls

## References
- CWE-22: Path Traversal
- https://owasp.org/...
```

### CVSS 3.1 Quick Reference
| Score | Rating |
|-------|--------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### Common Mistakes to Avoid
- Don't submit theoretical vulnerabilities without proof
- Don't be vague - include exact URLs, parameters, payloads
- Don't overstate severity - be honest and precise
- Don't submit duplicates - search existing reports first
- Don't test out of scope - instant ban on most programs
""",
    },
    "google_dorks": {
        "title": "Google Dorking Cheat Sheet",
        "content": """
## Google Dorking for Bug Bounties

### Basic Operators
| Operator | Example | Purpose |
|----------|---------|---------|
| `site:` | `site:target.com` | Limit to target domain |
| `inurl:` | `inurl:admin` | Search in URL |
| `intitle:` | `intitle:"index of"` | Search in page title |
| `filetype:` | `filetype:pdf` | Search for file types |
| `ext:` | `ext:sql` | Search by extension |
| `intext:` | `intext:"password"` | Search in page body |
| `cache:` | `cache:target.com` | View Google's cache |

### Useful Dork Patterns

**Find login pages:**
```
site:target.com inurl:login
site:target.com inurl:admin
site:target.com intitle:"login" OR intitle:"sign in"
```

**Find sensitive files:**
```
site:target.com filetype:sql
site:target.com filetype:env
site:target.com filetype:log
site:target.com filetype:bak
site:target.com filetype:conf OR filetype:config
site:target.com ext:xml | ext:json | ext:yaml
```

**Find exposed directories:**
```
site:target.com intitle:"index of /"
site:target.com intitle:"directory listing"
```

**Find error messages:**
```
site:target.com "mysql error" OR "syntax error"
site:target.com "Warning:" filetype:php
site:target.com "stack trace" OR "traceback"
```

**Find API endpoints:**
```
site:target.com inurl:api
site:target.com inurl:"/api/v1" OR inurl:"/api/v2"
site:target.com filetype:json inurl:api
```

**Find subdomains:**
```
site:*.target.com -www
```

**Find secrets in code repos:**
```
site:github.com "target.com" password
site:github.com "target.com" api_key
site:pastebin.com "target.com"
```
""",
    },
}


class GuideModule:
    """Interactive methodology guide and learning resource."""

    def __init__(self, console: Console):
        self.console = console

    def show_topic(self, topic: str):
        """Display a specific methodology guide."""
        guide = METHODOLOGIES.get(topic)
        if not guide:
            self.console.print(f"[red]Unknown topic: {topic}[/red]")
            self.list_topics()
            return

        self.console.print(Panel(f"[bold]{guide['title']}[/bold]", border_style="cyan"))
        md = Markdown(guide["content"])
        self.console.print(md)

    def list_topics(self):
        """List all available guide topics."""
        table = Table(title="Available Guides", box=box.ROUNDED)
        table.add_column("Key", style="bold yellow")
        table.add_column("Topic", style="white")

        for key, data in METHODOLOGIES.items():
            table.add_row(key, data["title"])

        self.console.print(table)

    def run(self, topic: str = None):
        """Display a guide topic or list all topics."""
        if topic:
            self.show_topic(topic)
        else:
            self.list_topics()

    def interactive(self):
        """Interactive guide browser."""
        while True:
            self.list_topics()
            self.console.print()

            keys = list(METHODOLOGIES.keys())
            choice = Prompt.ask(
                "[bold cyan]Enter topic key (or 'back' to return)[/bold cyan]",
                default="back",
            )

            if choice.lower() == "back":
                break

            if choice in METHODOLOGIES:
                self.show_topic(choice)
                self.console.print()
                Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
            else:
                self.console.print(f"[red]Unknown topic: {choice}[/red]")
