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
    import dns.query
    import dns.zone
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
    def _grab_banner(self, ip: str, port: int, service: str, timeout: float = 3.0) -> str:
        """Grab service banner from an open port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # HTTP-based services: send GET request
            if service in ("HTTP", "HTTP-Alt", "HTTP-Alt2", "HTTPS", "HTTPS-Alt"):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif service == "SMTP":
                pass  # SMTP sends banner on connect
            elif service == "FTP":
                pass  # FTP sends banner on connect
            elif service == "SSH":
                pass  # SSH sends banner on connect
            else:
                sock.sendall(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            # Truncate and clean
            banner = banner.split("\n")[0][:120].strip()
            return banner
        except Exception:
            return ""

    def _detect_service_version(self, banner: str, service: str) -> str:
        """Extract version info from a service banner."""
        if not banner:
            return ""

        # SSH: OpenSSH_8.9p1 Ubuntu-3
        if "SSH" in banner.upper() or "ssh" in banner.lower():
            return banner.split("\r")[0].strip()

        # HTTP: Server header
        for line in banner.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

        # FTP/SMTP/etc: first line is usually the banner
        if service in ("FTP", "SMTP", "POP3", "IMAP"):
            return banner[:100]

        return banner[:80]

    def port_scan(self, target: str, top_ports: int = 200):
        """Enhanced port scan with banner grabbing, service detection, and concurrent scanning."""
        import concurrent.futures

        self.console.print(Panel(f"[bold]Port Scan: {target} (top {top_ports} ports)[/bold]", border_style="cyan"))

        # Extended port list with services
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub",
            636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
            1433: "MSSQL", 1434: "MSSQL-UDP", 1521: "Oracle",
            1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper",
            2375: "Docker", 2376: "Docker-TLS", 3000: "Grafana",
            3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
            5000: "Flask/Gunicorn", 5432: "PostgreSQL", 5672: "RabbitMQ",
            5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "K8s-API",
            7001: "WebLogic", 8000: "HTTP-Dev", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9000: "SonarQube",
            9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Transport",
            9418: "Git", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
            27017: "MongoDB", 27018: "MongoDB-Shard", 50000: "Jenkins",
        }

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.console.print(f"[red]Cannot resolve {target}[/red]")
            return

        self.console.print(f"[dim]Target IP: {ip}[/dim]")
        self.console.print(f"[dim]Scanning {min(top_ports, len(common_ports))} ports with concurrent workers...[/dim]")

        ports_to_scan = list(common_ports.keys())[:top_ports]
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        # Concurrent port scanning (20 workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports_to_scan}
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port is not None:
                    open_ports.append(port)

        open_ports.sort()

        if not open_ports:
            self.console.print("[yellow]No open ports found in scanned range.[/yellow]")
            self._add_finding("port", "scan_result", "No open ports found")
            return

        self.console.print(f"\n[bold green]{len(open_ports)} open port(s) found.[/bold green]")
        self.console.print("[dim]Grabbing banners and detecting services...[/dim]\n")

        # Banner grabbing for each open port
        results = []
        for port in open_ports:
            service = common_ports.get(port, "unknown")
            banner = self._grab_banner(ip, port, service)
            version = self._detect_service_version(banner, service)
            results.append((port, service, version, banner))

        # Display results table
        table = Table(title=f"Open Ports on {target} ({ip})", box=box.SIMPLE)
        table.add_column("Port", style="yellow", width=8)
        table.add_column("State", style="green", width=6)
        table.add_column("Service", style="cyan", width=16)
        table.add_column("Version / Banner", style="white", max_width=60)

        for port, service, version, banner in results:
            display_info = version or banner or "-"
            table.add_row(str(port), "open", service, display_info)

            # Create detailed finding
            detail_parts = [f"Port {port}/{service} is open on {ip}"]
            if version:
                detail_parts.append(f"Version: {version}")
            if banner and banner != version:
                detail_parts.append(f"Banner: {banner}")

            severity = "info"
            # Flag risky services
            risky_services = {
                "Telnet": "high", "FTP": "medium", "SNMP": "medium",
                "Docker": "high", "Redis": "medium", "MongoDB": "medium",
                "Memcached": "medium", "Elasticsearch": "medium",
                "VNC": "medium", "RDP": "low", "K8s-API": "high",
            }
            if service in risky_services:
                severity = risky_services[service]
                detail_parts.append(f"WARNING: {service} exposed to network")

            self._add_finding("port", f"Open port {port}/{service}",
                              " | ".join(detail_parts))
            # Override severity for the finding (recon module uses category/key/value)
            if self.findings:
                self.findings[-1]["severity"] = severity

        self.console.print(table)

        # Security summary
        risky_found = [
            (p, s) for p, s, _, _ in results
            if s in ("Telnet", "FTP", "Docker", "Redis", "MongoDB",
                     "Memcached", "Elasticsearch", "VNC", "K8s-API", "SNMP")
        ]
        if risky_found:
            self.console.print("\n[bold yellow]Security Warnings:[/bold yellow]")
            for port, service in risky_found:
                self.console.print(f"  [yellow][!][/yellow] Port {port} ({service}) - potentially dangerous if exposed")
            self.console.print("[dim]Consider restricting access with firewall rules.[/dim]")

    # ------------------------------------------------------------------
    # DNS Zone Transfer Testing
    # ------------------------------------------------------------------
    def dns_zone_transfer(self, domain: str):
        """Attempt DNS zone transfer (AXFR) against the domain's nameservers."""
        self.console.print(Panel(f"[bold]DNS Zone Transfer Test: {domain}[/bold]", border_style="cyan"))

        if not HAS_DNS:
            self.console.print("[yellow]dnspython not installed. Cannot test zone transfers.[/yellow]")
            return

        # Resolve nameservers for the domain
        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(ns).rstrip(".") for ns in ns_answers]
        except Exception as e:
            self.console.print(f"[red]Failed to retrieve nameservers for {domain}: {e}[/red]")
            return

        if not nameservers:
            self.console.print("[yellow]No nameservers found for domain.[/yellow]")
            return

        self.console.print(f"[dim]Found {len(nameservers)} nameserver(s): {', '.join(nameservers)}[/dim]")

        transfer_successful = False

        for ns in nameservers:
            self.console.print(f"\n[dim]Attempting AXFR against {ns}...[/dim]")
            try:
                # Resolve the nameserver hostname to an IP
                try:
                    ns_ip = socket.gethostbyname(ns)
                except socket.gaierror:
                    self.console.print(f"  [yellow]Cannot resolve nameserver {ns}, skipping.[/yellow]")
                    continue

                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))

                # Zone transfer succeeded - this is a high-severity finding
                transfer_successful = True
                self.console.print(f"  [bold red][!] Zone transfer SUCCESSFUL against {ns} ({ns_ip})![/bold red]")
                self._add_finding(
                    "dns_zone_transfer",
                    "axfr_vulnerable",
                    f"Zone transfer succeeded on {ns} ({ns_ip}) - HIGH SEVERITY misconfiguration",
                )

                # Enumerate all records from the transferred zone
                table = Table(title=f"Zone Transfer Records from {ns}", box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("TTL", style="dim")
                table.add_column("Type", style="yellow")
                table.add_column("Data", style="white")

                record_count = 0
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record_name = str(name)
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            record_data = str(rdata)
                            table.add_row(record_name, str(rdataset.ttl), record_type, record_data)
                            self._add_finding("dns_zone_transfer", f"{record_type}:{record_name}", record_data)
                            record_count += 1

                self.console.print(table)
                self.console.print(
                    f"[bold red][!] {record_count} records exposed via zone transfer. "
                    f"This is a HIGH severity misconfiguration![/bold red]"
                )

            except dns.exception.FormError:
                self.console.print(f"  [green][+] {ns}: Zone transfer refused (properly configured).[/green]")
            except dns.query.TransferError:
                self.console.print(f"  [green][+] {ns}: Zone transfer denied (properly configured).[/green]")
            except EOFError:
                self.console.print(f"  [green][+] {ns}: Connection closed - transfer not allowed.[/green]")
            except ConnectionRefusedError:
                self.console.print(f"  [yellow]{ns}: Connection refused.[/yellow]")
            except socket.timeout:
                self.console.print(f"  [yellow]{ns}: Connection timed out.[/yellow]")
            except Exception as e:
                self.console.print(f"  [yellow]{ns}: Zone transfer failed: {e}[/yellow]")

        if not transfer_successful:
            self.console.print(
                "\n[green][+] All nameservers properly restrict zone transfers.[/green]"
            )
            self._add_finding("dns_zone_transfer", "axfr_status", "All nameservers properly restrict zone transfers")

    # ------------------------------------------------------------------
    # Virtual Host Discovery
    # ------------------------------------------------------------------
    def vhost_discovery(self, target: str):
        """Discover virtual hosts by sending requests with various Host headers."""
        self.console.print(Panel(f"[bold]Virtual Host Discovery: {target}[/bold]", border_style="cyan"))

        # Extract domain from target
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Resolve target IP
        try:
            target_ip = socket.gethostbyname(domain)
        except socket.gaierror as e:
            self.console.print(f"[red]Cannot resolve {domain}: {e}[/red]")
            return

        self.console.print(f"[dim]Target IP: {target_ip}[/dim]")

        # Common vhost name prefixes
        vhost_names = [
            "www", "mail", "admin", "dev", "staging", "test", "api", "app",
            "portal", "cms", "blog", "shop", "store", "intranet", "vpn",
            "git", "gitlab", "jenkins", "jira", "confluence",
        ]

        # Get baseline response by requesting with the original domain
        baseline_url = f"http://{target_ip}"
        try:
            baseline_resp = requests.get(
                baseline_url,
                headers={"Host": domain},
                timeout=10,
                allow_redirects=False,
                verify=False,
            )
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text)
            # Extract title from baseline
            baseline_title = ""
            title_match = re.search(r"<title>(.*?)</title>", baseline_resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                baseline_title = title_match.group(1).strip()
        except requests.RequestException as e:
            self.console.print(f"[red]Failed to get baseline response: {e}[/red]")
            return

        self.console.print(
            f"[dim]Baseline: status={baseline_status}, length={baseline_length}, "
            f"title=\"{baseline_title}\"[/dim]\n"
        )

        discovered = []

        for name in vhost_names:
            vhost = f"{name}.{domain}"
            try:
                resp = requests.get(
                    baseline_url,
                    headers={"Host": vhost},
                    timeout=10,
                    allow_redirects=False,
                    verify=False,
                )

                resp_status = resp.status_code
                resp_length = len(resp.text)
                resp_title = ""
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    resp_title = title_match.group(1).strip()

                # Check if response differs significantly from baseline
                status_differs = resp_status != baseline_status
                # Allow ~10% length variance to account for dynamic content
                length_threshold = max(100, baseline_length * 0.1)
                length_differs = abs(resp_length - baseline_length) > length_threshold
                title_differs = resp_title != baseline_title and resp_title != ""

                if status_differs or length_differs or title_differs:
                    reason_parts = []
                    if status_differs:
                        reason_parts.append(f"status: {resp_status} vs {baseline_status}")
                    if length_differs:
                        reason_parts.append(f"length: {resp_length} vs {baseline_length}")
                    if title_differs:
                        reason_parts.append(f"title: \"{resp_title}\"")
                    reason = "; ".join(reason_parts)

                    discovered.append({
                        "vhost": vhost,
                        "status": resp_status,
                        "length": resp_length,
                        "title": resp_title,
                        "reason": reason,
                    })

            except requests.RequestException:
                continue
            except Exception:
                continue

        # Display results
        if discovered:
            table = Table(title=f"Discovered Virtual Hosts ({len(discovered)} found)", box=box.SIMPLE)
            table.add_column("Virtual Host", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Length", style="dim")
            table.add_column("Title", style="cyan")
            table.add_column("Reason", style="white")

            for entry in discovered:
                table.add_row(
                    entry["vhost"],
                    str(entry["status"]),
                    str(entry["length"]),
                    entry["title"],
                    entry["reason"],
                )
                self._add_finding("vhost", entry["vhost"], entry["reason"])

            self.console.print(table)
        else:
            self.console.print("[yellow]No additional virtual hosts discovered.[/yellow]")

    # ------------------------------------------------------------------
    # WAF Detection and Fingerprinting
    # ------------------------------------------------------------------
    def waf_detection(self, target: str):
        """Detect and fingerprint Web Application Firewalls (WAF)."""
        if not target.startswith("http"):
            target = f"https://{target}"

        self.console.print(Panel(f"[bold]WAF Detection: {target}[/bold]", border_style="cyan"))

        # Step 1: Send a normal request for baseline
        try:
            baseline_resp = requests.get(target, timeout=15, allow_redirects=True, verify=True)
            baseline_status = baseline_resp.status_code
            baseline_headers = {k.lower(): v for k, v in baseline_resp.headers.items()}
            baseline_body = baseline_resp.text
        except requests.RequestException as e:
            self.console.print(f"[red]Baseline request failed: {e}[/red]")
            return

        self.console.print(f"[dim]Baseline response: status={baseline_status}[/dim]")

        # Step 2: Send a request with a known-malicious payload to trigger WAF
        malicious_payloads = [
            ("?test=<script>alert(1)</script>", "XSS payload"),
            ("?test=' OR 1=1 --", "SQL injection payload"),
            ("?test=../../etc/passwd", "Path traversal payload"),
        ]

        waf_triggered = False
        trigger_status = None
        trigger_headers = {}
        trigger_body = ""
        trigger_cookies = ""

        for payload, desc in malicious_payloads:
            try:
                malicious_url = target.rstrip("/") + "/" + payload
                mal_resp = requests.get(
                    malicious_url,
                    timeout=15,
                    allow_redirects=True,
                    verify=True,
                )
                mal_status = mal_resp.status_code
                mal_headers = {k.lower(): v for k, v in mal_resp.headers.items()}
                mal_body = mal_resp.text
                mal_cookies = "; ".join(
                    [f"{c.name}={c.value}" for c in mal_resp.cookies]
                )

                # Check if response differs indicating WAF presence
                if mal_status in (403, 406, 429, 501, 503) and mal_status != baseline_status:
                    waf_triggered = True
                    trigger_status = mal_status
                    trigger_headers = mal_headers
                    trigger_body = mal_body
                    trigger_cookies = mal_cookies
                    self.console.print(
                        f"[yellow][!] WAF detected: {desc} triggered status {mal_status} "
                        f"(baseline was {baseline_status})[/yellow]"
                    )
                    break
                elif mal_status != baseline_status:
                    waf_triggered = True
                    trigger_status = mal_status
                    trigger_headers = mal_headers
                    trigger_body = mal_body
                    trigger_cookies = mal_cookies

            except requests.RequestException:
                continue
            except Exception:
                continue

        # Combine headers/body from both responses for fingerprinting
        all_headers = {**baseline_headers}
        all_body = baseline_body
        all_cookies = "; ".join(
            [f"{c.name}={c.value}" for c in baseline_resp.cookies]
        )
        if waf_triggered:
            all_headers.update(trigger_headers)
            all_body += trigger_body
            all_cookies += trigger_cookies

        # Step 3: Fingerprint the WAF
        waf_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status"],
                "cookies": ["__cfduid", "__cf_bm"],
                "body": ["attention required", "cloudflare", "ray id"],
                "server": ["cloudflare"],
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amzn-trace-id"],
                "cookies": [],
                "body": [],
                "server": [],
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai"],
                "cookies": [],
                "body": ["akamai"],
                "server": ["akamaighost"],
            },
            "Imperva / Incapsula": {
                "headers": ["x-cdn"],
                "cookies": ["incap_ses", "visid_incap", "nlbi_"],
                "body": ["incapsula", "imperva"],
                "server": [],
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "cookies": [],
                "body": ["sucuri", "access denied - sucuri"],
                "server": ["sucuri"],
            },
            "F5 BIG-IP": {
                "headers": ["x-wa-info"],
                "cookies": ["bigip", "bigipserver"],
                "body": [],
                "server": ["big-ip", "bigip"],
            },
            "ModSecurity": {
                "headers": [],
                "cookies": [],
                "body": ["modsecurity", "mod_security"],
                "server": ["mod_security", "modsecurity", "noyb"],
            },
            "Barracuda": {
                "headers": [],
                "cookies": ["barra_counter_session"],
                "body": ["barracuda"],
                "server": ["barracuda"],
            },
        }

        detected_wafs = []

        for waf_name, signatures in waf_signatures.items():
            confidence_score = 0
            matches = []

            # Check headers
            for sig_header in signatures["headers"]:
                if sig_header in all_headers:
                    confidence_score += 30
                    matches.append(f"header: {sig_header}")

            # Check cookies
            all_cookies_lower = all_cookies.lower()
            for sig_cookie in signatures["cookies"]:
                if sig_cookie.lower() in all_cookies_lower:
                    confidence_score += 25
                    matches.append(f"cookie: {sig_cookie}")

            # Check body patterns
            body_lower = all_body.lower()
            for sig_body in signatures["body"]:
                if sig_body.lower() in body_lower:
                    confidence_score += 20
                    matches.append(f"body: \"{sig_body}\"")

            # Check server header
            server_header = all_headers.get("server", "").lower()
            for sig_server in signatures["server"]:
                if sig_server.lower() in server_header:
                    confidence_score += 35
                    matches.append(f"server: \"{sig_server}\"")

            if confidence_score > 0:
                detected_wafs.append({
                    "name": waf_name,
                    "confidence": min(confidence_score, 100),
                    "matches": matches,
                })

        # Display results
        if detected_wafs:
            # Sort by confidence
            detected_wafs.sort(key=lambda x: x["confidence"], reverse=True)

            table = Table(title="WAF Detection Results", box=box.SIMPLE)
            table.add_column("WAF", style="yellow")
            table.add_column("Confidence", style="cyan")
            table.add_column("Evidence", style="white")

            for waf in detected_wafs:
                confidence_str = f"{waf['confidence']}%"
                if waf["confidence"] >= 70:
                    confidence_style = "[bold green]"
                elif waf["confidence"] >= 40:
                    confidence_style = "[yellow]"
                else:
                    confidence_style = "[dim]"

                table.add_row(
                    waf["name"],
                    f"{confidence_style}{confidence_str}[/]",
                    ", ".join(waf["matches"]),
                )
                self._add_finding(
                    "waf",
                    waf["name"],
                    f"Confidence: {waf['confidence']}% | Evidence: {', '.join(waf['matches'])}",
                )

            self.console.print(table)

            if waf_triggered:
                self.console.print(
                    f"\n[yellow][!] WAF actively blocking malicious payloads "
                    f"(trigger status: {trigger_status})[/yellow]"
                )
        else:
            if waf_triggered:
                self.console.print(
                    f"[yellow][!] A WAF appears to be present (malicious request returned "
                    f"status {trigger_status}) but could not be fingerprinted.[/yellow]"
                )
                self._add_finding("waf", "unknown", f"WAF detected but unidentified (status {trigger_status})")
            else:
                self.console.print("[green][+] No WAF detected. Responses to normal and malicious requests are similar.[/green]")
                self._add_finding("waf", "status", "No WAF detected")

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
            self.waf_detection(target)
            self.vhost_discovery(domain)
            self.dns_zone_transfer(domain)

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
        table.add_row("8", "DNS Zone Transfer Test")
        table.add_row("9", "Virtual Host Discovery")
        table.add_row("10", "WAF Detection")
        table.add_row("11", "Run ALL Recon")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask(
            "Select",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        )

        actions = {
            "1": lambda: self.dns_lookup(domain),
            "2": lambda: self.subdomain_enum(domain),
            "3": lambda: self.http_headers(target),
            "4": lambda: self.ssl_info(domain),
            "5": lambda: self.whois_lookup(domain),
            "6": lambda: self.tech_detect(target),
            "7": lambda: self.port_scan(domain),
            "8": lambda: self.dns_zone_transfer(domain),
            "9": lambda: self.vhost_discovery(domain),
            "10": lambda: self.waf_detection(target),
            "11": lambda: self.run(target),
        }

        action = actions.get(choice)
        if action:
            action()
