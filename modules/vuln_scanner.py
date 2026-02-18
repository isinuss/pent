"""
Vulnerability Scanner Module - Port scanning, service enumeration, and vuln checks.
"""

import socket
import ssl
import re
import subprocess
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class VulnScannerModule:
    """Vulnerability scanning and enumeration."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []

    def _add_finding(self, severity: str, title: str, detail: str):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "title": title,
            "detail": detail,
        })

    # ------------------------------------------------------------------
    # Nmap wrapper (if available)
    # ------------------------------------------------------------------
    def nmap_scan(self, target: str, quick: bool = False):
        """Run nmap scan if available on the system."""
        self.console.print(Panel(f"[bold]Nmap Scan: {target}[/bold]", border_style="cyan"))

        flags = "-sV -sC --top-ports 100" if quick else "-sV -sC -p-"
        cmd = f"nmap {flags} {target}"

        self.console.print(f"[dim]Running: {cmd}[/dim]")
        self.console.print("[dim]This may take a while...[/dim]")

        try:
            result = subprocess.run(
                ["nmap"] + flags.split() + [target],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode == 0:
                self.console.print(result.stdout)
                self._parse_nmap_output(result.stdout)
            else:
                self.console.print(f"[yellow]Nmap error: {result.stderr}[/yellow]")
        except FileNotFoundError:
            self.console.print("[yellow]nmap not found. Install: apt install nmap[/yellow]")
            self.console.print("[dim]Falling back to built-in port scanner...[/dim]")
            self._builtin_scan(target)
        except subprocess.TimeoutExpired:
            self.console.print("[yellow]Nmap scan timed out (10 min limit).[/yellow]")

    def _parse_nmap_output(self, output: str):
        """Extract open ports and services from nmap output."""
        for line in output.split("\n"):
            match = re.match(r"(\d+)/(\w+)\s+open\s+(.+)", line.strip())
            if match:
                port, proto, service = match.groups()
                self._add_finding("info", f"Open port {port}/{proto}", service.strip())

    def _builtin_scan(self, target: str):
        """Fallback port scanner without nmap."""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
            27017: "MongoDB",
        }

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.console.print(f"[red]Cannot resolve {target}[/red]")
            return

        table = Table(title="Open Ports", box=box.SIMPLE)
        table.add_column("Port", style="yellow")
        table.add_column("Service", style="green")
        table.add_column("Banner", style="dim")

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                if sock.connect_ex((ip, port)) == 0:
                    banner = self._grab_banner(sock, port)
                    table.add_row(str(port), service, banner)
                    self._add_finding("info", f"Open port {port}", f"{service} - {banner}")
                sock.close()
            except Exception:
                pass

        self.console.print(table)

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Try to grab service banner from open port."""
        try:
            if port in (80, 8080, 8443, 443):
                return ""
            sock.settimeout(2)
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:100]
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # SSL/TLS vulnerability checks
    # ------------------------------------------------------------------
    def ssl_vuln_check(self, domain: str):
        """Check for common SSL/TLS misconfigurations."""
        self.console.print(Panel(f"[bold]SSL/TLS Vulnerability Check: {domain}[/bold]", border_style="cyan"))

        checks = []

        # Check for SSLv3 (POODLE)
        for proto_name, proto in [("SSLv3", ssl.PROTOCOL_TLS)]:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.options = 0  # Reset options
                ctx.maximum_version = ssl.TLSVersion.SSLv3
                ctx.minimum_version = ssl.TLSVersion.SSLv3
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                checks.append(("SSLv3 (POODLE)", "VULNERABLE", "high"))
                self._add_finding("high", "SSLv3 Enabled (POODLE)", domain)
            except Exception:
                checks.append(("SSLv3 (POODLE)", "Not vulnerable", "ok"))

        # Check for TLS 1.0
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
            checks.append(("TLS 1.0 (deprecated)", "ENABLED", "medium"))
            self._add_finding("medium", "TLS 1.0 Enabled", domain)
        except Exception:
            checks.append(("TLS 1.0", "Disabled (good)", "ok"))

        # Check for TLS 1.1
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
            checks.append(("TLS 1.1 (deprecated)", "ENABLED", "medium"))
            self._add_finding("medium", "TLS 1.1 Enabled", domain)
        except Exception:
            checks.append(("TLS 1.1", "Disabled (good)", "ok"))

        # Check TLS 1.2
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_default_certs()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
            checks.append(("TLS 1.2", "Supported", "ok"))
        except Exception:
            checks.append(("TLS 1.2", "Not supported", "info"))

        # Check TLS 1.3
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_default_certs()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
            checks.append(("TLS 1.3", "Supported (great!)", "ok"))
        except Exception:
            checks.append(("TLS 1.3", "Not supported", "low"))
            self._add_finding("low", "TLS 1.3 Not Supported", domain)

        table = Table(title="SSL/TLS Checks", box=box.SIMPLE)
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")

        for name, result, level in checks:
            style = {"high": "bold red", "medium": "yellow", "low": "dim yellow", "ok": "green", "info": "dim"}.get(level, "white")
            table.add_row(name, f"[{style}]{result}[/{style}]")

        self.console.print(table)

    # ------------------------------------------------------------------
    # Common vulnerability checks via HTTP
    # ------------------------------------------------------------------
    def http_vuln_checks(self, target: str):
        """Check for common HTTP-based vulnerabilities."""
        if not target.startswith("http"):
            target = f"https://{target}"

        self.console.print(Panel(f"[bold]HTTP Vulnerability Checks: {target}[/bold]", border_style="cyan"))

        results = []

        # CORS misconfiguration
        try:
            headers = {"Origin": "https://evil-attacker.com"}
            resp = requests.get(target, headers=headers, timeout=10, allow_redirects=True)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                results.append(("CORS Wildcard", "high", "Access-Control-Allow-Origin: * (allows any origin)"))
                self._add_finding("high", "CORS Wildcard", acao)
            elif "evil-attacker.com" in acao:
                results.append(("CORS Reflection", "high", f"Origin reflected: {acao}"))
                self._add_finding("high", "CORS Origin Reflection", acao)
            else:
                results.append(("CORS", "ok", "Properly configured"))
        except Exception as e:
            results.append(("CORS", "error", str(e)))

        # Clickjacking (X-Frame-Options)
        try:
            resp = requests.get(target, timeout=10)
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            if not xfo and "frame-ancestors" not in csp:
                results.append(("Clickjacking", "medium", "No X-Frame-Options or CSP frame-ancestors"))
                self._add_finding("medium", "Potential Clickjacking", "Missing X-Frame-Options and CSP frame-ancestors")
            else:
                results.append(("Clickjacking", "ok", f"Protected: XFO={xfo or 'N/A'}, CSP frame-ancestors in use"))
        except Exception as e:
            results.append(("Clickjacking", "error", str(e)))

        # Cookie security
        try:
            resp = requests.get(target, timeout=10)
            set_cookies = resp.headers.get("Set-Cookie", "")
            if set_cookies:
                cookie_lower = set_cookies.lower()
                issues = []
                if "secure" not in cookie_lower:
                    issues.append("Missing Secure flag")
                if "httponly" not in cookie_lower:
                    issues.append("Missing HttpOnly flag")
                if "samesite" not in cookie_lower:
                    issues.append("Missing SameSite attribute")
                if issues:
                    detail = "; ".join(issues)
                    results.append(("Cookie Security", "medium", detail))
                    self._add_finding("medium", "Cookie Security Issues", detail)
                else:
                    results.append(("Cookie Security", "ok", "Cookies have proper flags"))
            else:
                results.append(("Cookie Security", "info", "No cookies set on main page"))
        except Exception as e:
            results.append(("Cookie Security", "error", str(e)))

        # Open redirect check
        try:
            test_url = f"{target}?url=https://evil.com&redirect=https://evil.com&next=https://evil.com&return=https://evil.com"
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if "evil.com" in location:
                results.append(("Open Redirect", "medium", f"Redirects to: {location}"))
                self._add_finding("medium", "Potential Open Redirect", location)
            else:
                results.append(("Open Redirect", "ok", "Basic check passed"))
        except Exception as e:
            results.append(("Open Redirect", "error", str(e)))

        # HTTPS enforcement
        try:
            http_target = target.replace("https://", "http://")
            resp = requests.get(http_target, timeout=10, allow_redirects=False)
            if resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc.startswith("https://"):
                    results.append(("HTTPS Redirect", "ok", f"Redirects to HTTPS ({resp.status_code})"))
                else:
                    results.append(("HTTPS Redirect", "low", f"Redirects but not to HTTPS: {loc}"))
            else:
                results.append(("HTTPS Redirect", "medium", f"HTTP does not redirect (status: {resp.status_code})"))
                self._add_finding("medium", "No HTTPS Redirect", f"HTTP returns {resp.status_code}")
        except Exception as e:
            results.append(("HTTPS Redirect", "error", str(e)))

        # Display results
        table = Table(title="HTTP Vulnerability Checks", box=box.SIMPLE)
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="white", width=10)
        table.add_column("Detail", style="dim", max_width=60)

        for name, level, detail in results:
            style = {
                "high": "bold red", "medium": "yellow", "low": "dim yellow",
                "ok": "green", "info": "dim", "error": "red"
            }.get(level, "white")
            table.add_row(name, f"[{style}]{level.upper()}[/{style}]", detail)

        self.console.print(table)

    # ------------------------------------------------------------------
    # Sensitive file/path discovery
    # ------------------------------------------------------------------
    def path_discovery(self, target: str):
        """Check for common sensitive paths and files."""
        if not target.startswith("http"):
            target = f"https://{target}"

        self.console.print(Panel(f"[bold]Sensitive Path Discovery: {target}[/bold]", border_style="cyan"))

        paths = [
            "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.well-known/security.txt", "/security.txt",
            "/wp-admin/", "/wp-login.php", "/administrator/",
            "/admin/", "/login/", "/api/", "/api/v1/", "/api/docs",
            "/swagger.json", "/swagger-ui.html", "/openapi.json",
            "/graphql", "/graphiql",
            "/.htaccess", "/web.config", "/phpinfo.php",
            "/server-status", "/server-info",
            "/backup/", "/backups/", "/db/", "/database/",
            "/config.php", "/config.yml", "/config.json",
            "/debug/", "/_debug/", "/trace",
            "/actuator", "/actuator/health", "/actuator/env",
            "/elmah.axd", "/error_log", "/errors.log",
            "/.DS_Store", "/Thumbs.db",
            "/.svn/entries", "/.hg/",
            "/package.json", "/composer.json",
            "/wp-json/wp/v2/users",
        ]

        found = []
        self.console.print(f"[dim]Checking {len(paths)} common paths...[/dim]")

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Security Audit)"})

        for path in paths:
            try:
                url = target.rstrip("/") + path
                resp = session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    size = len(resp.content)
                    found.append((path, resp.status_code, size, "FOUND"))
                    severity = "high" if any(s in path for s in [".env", ".git", "phpinfo", "actuator/env"]) else "medium"
                    self._add_finding(severity, f"Sensitive path found: {path}", f"Status: {resp.status_code}, Size: {size}")
                elif resp.status_code in (301, 302, 307, 308):
                    loc = resp.headers.get("Location", "")
                    found.append((path, resp.status_code, 0, f"Redirect -> {loc}"))
                elif resp.status_code == 403:
                    found.append((path, resp.status_code, 0, "Forbidden (exists)"))
                    self._add_finding("low", f"Path exists but forbidden: {path}", "403 Forbidden")
            except Exception:
                pass

        if found:
            table = Table(title=f"Path Discovery ({len(found)} results)", box=box.SIMPLE)
            table.add_column("Path", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Size", style="dim")
            table.add_column("Note", style="white")

            for path, status, size, note in found:
                style = "bold red" if status == 200 else "yellow" if status == 403 else "dim"
                table.add_row(path, f"[{style}]{status}[/{style}]", str(size), note)
            self.console.print(table)
        else:
            self.console.print("[green]No sensitive paths found.[/green]")

    # ------------------------------------------------------------------
    # Run all vuln checks
    # ------------------------------------------------------------------
    def run(self, target: str, quick: bool = False):
        """Run full vulnerability scanning workflow."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.nmap_scan(domain, quick=quick)
        self.ssl_vuln_check(domain)
        self.http_vuln_checks(target)
        self.path_discovery(target)

        self.console.print(f"\n[bold green]Vuln scan complete. {len(self.findings)} findings.[/bold green]")
        return self.findings

    # ------------------------------------------------------------------
    # Interactive
    # ------------------------------------------------------------------
    def interactive(self, target: str):
        """Interactive vulnerability scan menu."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        table = Table(title="Vulnerability Scan Options", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="bold yellow", width=4)
        table.add_column("Name", style="white")

        table.add_row("1", "Nmap Scan (quick)")
        table.add_row("2", "Nmap Scan (full)")
        table.add_row("3", "SSL/TLS Vulnerability Check")
        table.add_row("4", "HTTP Vulnerability Checks")
        table.add_row("5", "Sensitive Path Discovery")
        table.add_row("6", "Run ALL Vuln Checks")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5", "6"])

        actions = {
            "1": lambda: self.nmap_scan(domain, quick=True),
            "2": lambda: self.nmap_scan(domain, quick=False),
            "3": lambda: self.ssl_vuln_check(domain),
            "4": lambda: self.http_vuln_checks(target),
            "5": lambda: self.path_discovery(target),
            "6": lambda: self.run(target, quick=True),
        }

        action = actions.get(choice)
        if action:
            action()
