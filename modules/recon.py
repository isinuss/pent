"""
Reconnaissance Module - Passive and active information gathering.
"""

import socket
import ssl
import json
import subprocess
import re
from datetime import datetime
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class ReconModule:
    """Handles passive and active reconnaissance tasks."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []

    def _add_finding(self, category: str, key: str, value: str):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "key": key,
            "value": value,
        })

    # ------------------------------------------------------------------
    # DNS enumeration
    # ------------------------------------------------------------------
    def dns_lookup(self, domain: str):
        """Perform DNS lookups for common record types."""
        self.console.print(Panel(f"[bold]DNS Enumeration: {domain}[/bold]", border_style="cyan"))

        if not HAS_DNS:
            self.console.print("[yellow]dnspython not installed. Using basic socket lookup.[/yellow]")
            try:
                ips = socket.getaddrinfo(domain, None)
                seen = set()
                for info in ips:
                    ip = info[4][0]
                    if ip not in seen:
                        self.console.print(f"  A/AAAA: {ip}")
                        self._add_finding("dns", "A/AAAA", ip)
                        seen.add(ip)
            except socket.gaierror as e:
                self.console.print(f"[red]DNS resolution failed: {e}[/red]")
            return

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        table = Table(title="DNS Records", box=box.SIMPLE)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="white")

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = str(rdata)
                    table.add_row(rtype, val)
                    self._add_finding("dns", rtype, val)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        self.console.print(table)

    # ------------------------------------------------------------------
    # Subdomain enumeration (passive - using crt.sh)
    # ------------------------------------------------------------------
    def subdomain_enum(self, domain: str):
        """Enumerate subdomains using crt.sh certificate transparency logs."""
        self.console.print(Panel(f"[bold]Subdomain Enumeration (crt.sh): {domain}[/bold]", border_style="cyan"))

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                self.console.print(f"[yellow]crt.sh returned status {resp.status_code}[/yellow]")
                return []

            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)

            table = Table(title=f"Subdomains ({len(subdomains)} found)", box=box.SIMPLE)
            table.add_column("#", style="dim")
            table.add_column("Subdomain", style="green")

            for i, sub in enumerate(sorted(subdomains), 1):
                table.add_row(str(i), sub)
                self._add_finding("subdomain", "crt.sh", sub)

            self.console.print(table)
            return sorted(subdomains)

        except Exception as e:
            self.console.print(f"[red]Subdomain enumeration error: {e}[/red]")
            return []

    # ------------------------------------------------------------------
    # HTTP header analysis
    # ------------------------------------------------------------------
    def http_headers(self, target: str):
        """Analyze HTTP response headers for security issues."""
        if not target.startswith("http"):
            target = f"https://{target}"

        self.console.print(Panel(f"[bold]HTTP Header Analysis: {target}[/bold]", border_style="cyan"))

        try:
            resp = requests.get(target, timeout=15, allow_redirects=True, verify=True)
        except requests.RequestException as e:
            self.console.print(f"[red]Request failed: {e}[/red]")
            return

        table = Table(title="Response Headers", box=box.SIMPLE)
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="white", max_width=80)

        for k, v in resp.headers.items():
            table.add_row(k, v)
            self._add_finding("header", k, v)

        self.console.print(table)

        # Security header checks
        security_headers = {
            "Strict-Transport-Security": "HSTS - Forces HTTPS connections",
            "Content-Security-Policy": "CSP - Prevents XSS and injection",
            "X-Content-Type-Options": "Prevents MIME-type sniffing",
            "X-Frame-Options": "Prevents clickjacking",
            "X-XSS-Protection": "Legacy XSS filter (deprecated but still checked)",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features/APIs",
        }

        self.console.print("\n[bold]Security Header Analysis:[/bold]")
        missing = []
        for header, desc in security_headers.items():
            if header.lower() in {h.lower() for h in resp.headers}:
                self.console.print(f"  [green][+][/green] {header}: Present")
            else:
                self.console.print(f"  [red][-][/red] {header}: [bold red]MISSING[/bold red] - {desc}")
                missing.append(header)
                self._add_finding("missing_header", header, desc)

        # Check for information disclosure headers
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        disclosed = []
        for h in info_headers:
            val = resp.headers.get(h)
            if val:
                disclosed.append((h, val))

        if disclosed:
            self.console.print("\n[bold yellow]Information Disclosure:[/bold yellow]")
            for h, v in disclosed:
                self.console.print(f"  [yellow][!][/yellow] {h}: {v}")
                self._add_finding("info_disclosure", h, v)

    # ------------------------------------------------------------------
    # SSL/TLS certificate info
    # ------------------------------------------------------------------
    def ssl_info(self, domain: str):
        """Retrieve and analyze SSL/TLS certificate information."""
        self.console.print(Panel(f"[bold]SSL/TLS Certificate: {domain}[/bold]", border_style="cyan"))

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cert = s.getpeercert()

            table = Table(title="Certificate Details", box=box.SIMPLE)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            table.add_row("Subject CN", subject.get("commonName", "N/A"))
            table.add_row("Issuer", issuer.get("organizationName", "N/A"))
            table.add_row("Not Before", cert.get("notBefore", "N/A"))
            table.add_row("Not After", cert.get("notAfter", "N/A"))
            table.add_row("Serial", str(cert.get("serialNumber", "N/A")))

            # Subject Alternative Names
            san_list = []
            for san_type, san_value in cert.get("subjectAltName", []):
                san_list.append(san_value)
                self._add_finding("ssl_san", san_type, san_value)
            table.add_row("SANs", ", ".join(san_list[:10]) + ("..." if len(san_list) > 10 else ""))

            self.console.print(table)

            # Check expiration
            from datetime import datetime as dt
            not_after = dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - dt.utcnow()).days
            if days_left < 0:
                self.console.print(f"[bold red][!] Certificate EXPIRED {abs(days_left)} days ago![/bold red]")
            elif days_left < 30:
                self.console.print(f"[yellow][!] Certificate expires in {days_left} days[/yellow]")
            else:
                self.console.print(f"[green][+] Certificate valid for {days_left} more days[/green]")

            self._add_finding("ssl", "days_until_expiry", str(days_left))

        except Exception as e:
            self.console.print(f"[red]SSL check failed: {e}[/red]")

    # ------------------------------------------------------------------
    # WHOIS lookup
    # ------------------------------------------------------------------
    def whois_lookup(self, domain: str):
        """Perform WHOIS lookup using system whois command."""
        self.console.print(Panel(f"[bold]WHOIS Lookup: {domain}[/bold]", border_style="cyan"))

        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                output = result.stdout
                # Extract key fields
                important = [
                    "Registrar:", "Creation Date:", "Updated Date:",
                    "Registry Expiry Date:", "Name Server:", "DNSSEC:",
                    "Registrant Organization:", "Registrant Country:",
                ]
                self.console.print("[bold]Key WHOIS Data:[/bold]")
                for line in output.split("\n"):
                    line = line.strip()
                    for field in important:
                        if line.lower().startswith(field.lower()):
                            self.console.print(f"  {line}")
                            key, _, val = line.partition(":")
                            self._add_finding("whois", key.strip(), val.strip())
                            break
            else:
                self.console.print(f"[yellow]whois command failed: {result.stderr}[/yellow]")
        except FileNotFoundError:
            self.console.print("[yellow]whois command not found. Install: apt install whois[/yellow]")
        except Exception as e:
            self.console.print(f"[red]WHOIS error: {e}[/red]")

    # ------------------------------------------------------------------
    # Technology detection
    # ------------------------------------------------------------------
    def tech_detect(self, target: str):
        """Detect technologies used by analyzing response."""
        if not target.startswith("http"):
            target = f"https://{target}"

        self.console.print(Panel(f"[bold]Technology Detection: {target}[/bold]", border_style="cyan"))

        try:
            resp = requests.get(target, timeout=15, allow_redirects=True)
            body = resp.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

            techs = []

            # Server-side indicators
            server = resp.headers.get("Server", "")
            if server:
                techs.append(("Server", server))
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                techs.append(("Framework", powered))

            # Frontend frameworks
            checks = [
                ("React", ["react", "reactdom", "__react", "_reactRoot"]),
                ("Angular", ["ng-version", "ng-app", "angular"]),
                ("Vue.js", ["vue.js", "vue.min.js", "__vue__"]),
                ("jQuery", ["jquery"]),
                ("Bootstrap", ["bootstrap.min.css", "bootstrap.css"]),
                ("Tailwind CSS", ["tailwindcss", "tailwind.css"]),
                ("Next.js", ["_next/", "__next"]),
                ("Nuxt.js", ["_nuxt/", "__nuxt"]),
            ]

            for name, patterns in checks:
                if any(p in body for p in patterns):
                    techs.append(("Frontend", name))

            # CMS detection
            cms_checks = [
                ("WordPress", ["wp-content", "wp-includes", "wordpress"]),
                ("Drupal", ["drupal", "sites/default"]),
                ("Joomla", ["joomla", "/components/com_"]),
                ("Shopify", ["shopify", "cdn.shopify"]),
                ("Squarespace", ["squarespace"]),
            ]

            for name, patterns in cms_checks:
                if any(p in body for p in patterns):
                    techs.append(("CMS", name))

            # Cookie indicators
            cookies = resp.headers.get("Set-Cookie", "").lower()
            cookie_checks = [
                ("PHP", "phpsessid"),
                ("ASP.NET", "asp.net"),
                ("Java", "jsessionid"),
                ("Rails", "_rails"),
            ]
            for name, pattern in cookie_checks:
                if pattern in cookies:
                    techs.append(("Backend", name))

            if techs:
                table = Table(title="Detected Technologies", box=box.SIMPLE)
                table.add_column("Category", style="cyan")
                table.add_column("Technology", style="green")
                for cat, tech in techs:
                    table.add_row(cat, tech)
                    self._add_finding("tech", cat, tech)
                self.console.print(table)
            else:
                self.console.print("[yellow]No technologies confidently detected.[/yellow]")

        except Exception as e:
            self.console.print(f"[red]Tech detection error: {e}[/red]")

    # ------------------------------------------------------------------
    # Port scanning (top ports)
    # ------------------------------------------------------------------
    def port_scan(self, target: str, top_ports: int = 100):
        """Scan common ports using socket connections."""
        self.console.print(Panel(f"[bold]Port Scan: {target} (top {top_ports})[/bold]", border_style="cyan"))

        # Common ports to check
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
            27017: "MongoDB", 9200: "Elasticsearch",
        }

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.console.print(f"[red]Cannot resolve {target}[/red]")
            return

        self.console.print(f"[dim]Scanning {ip}...[/dim]")

        open_ports = []
        ports_to_scan = list(common_ports.keys())[:top_ports]

        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = common_ports.get(port, "unknown")
                    open_ports.append((port, service))
                sock.close()
            except Exception:
                pass

        if open_ports:
            table = Table(title="Open Ports", box=box.SIMPLE)
            table.add_column("Port", style="yellow")
            table.add_column("Service", style="green")
            for port, service in open_ports:
                table.add_row(str(port), service)
                self._add_finding("port", str(port), service)
            self.console.print(table)
        else:
            self.console.print("[yellow]No open ports found in scanned range.[/yellow]")

    # ------------------------------------------------------------------
    # Run all recon
    # ------------------------------------------------------------------
    def run(self, target: str, passive_only: bool = False):
        """Run a complete recon workflow."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.dns_lookup(domain)
        self.subdomain_enum(domain)
        self.http_headers(target)
        self.ssl_info(domain)
        self.whois_lookup(domain)
        self.tech_detect(target)

        if not passive_only:
            self.port_scan(domain)

        self.console.print(f"\n[bold green]Recon complete. {len(self.findings)} findings collected.[/bold green]")
        return self.findings

    # ------------------------------------------------------------------
    # Interactive mode
    # ------------------------------------------------------------------
    def interactive(self, target: str):
        """Interactive recon menu."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        table = Table(title="Recon Options", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="bold yellow", width=4)
        table.add_column("Name", style="white")

        table.add_row("1", "DNS Enumeration")
        table.add_row("2", "Subdomain Enumeration (crt.sh)")
        table.add_row("3", "HTTP Header Analysis")
        table.add_row("4", "SSL/TLS Certificate Info")
        table.add_row("5", "WHOIS Lookup")
        table.add_row("6", "Technology Detection")
        table.add_row("7", "Port Scan (top ports)")
        table.add_row("8", "Run ALL Recon")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])

        actions = {
            "1": lambda: self.dns_lookup(domain),
            "2": lambda: self.subdomain_enum(domain),
            "3": lambda: self.http_headers(target),
            "4": lambda: self.ssl_info(domain),
            "5": lambda: self.whois_lookup(domain),
            "6": lambda: self.tech_detect(target),
            "7": lambda: self.port_scan(domain),
            "8": lambda: self.run(target),
        }

        action = actions.get(choice)
        if action:
            action()
