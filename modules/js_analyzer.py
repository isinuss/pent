"""
JavaScript Analysis Module - Extract endpoints, secrets, and interesting
data from JavaScript files found on the target.
"""

import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class JSAnalyzerModule:
    """Analyze JavaScript files for endpoints, secrets, and interesting data."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _add_finding(self, severity: str, category: str, title: str, detail: str, source: str = ""):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "source": source,
        })

    # ------------------------------------------------------------------
    # Discover JS files
    # ------------------------------------------------------------------
    def discover_js_files(self, url: str) -> list:
        """Find all JavaScript files referenced on a page."""
        self.console.print(Panel(f"[bold]JS File Discovery: {url}[/bold]", border_style="cyan"))

        js_files = set()

        try:
            resp = self.session.get(url, timeout=15)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Script tags with src
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = urljoin(url, src)
                js_files.add(full_url)

            # Inline script references to .js files
            for script in soup.find_all("script"):
                if script.string:
                    # Look for dynamic imports or fetch calls to .js files
                    js_refs = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', script.string)
                    for ref in js_refs:
                        full_url = urljoin(url, ref)
                        js_files.add(full_url)

            # Also look in link preload/prefetch
            for link in soup.find_all("link", rel=True):
                if "preload" in link.get("rel", []) or "prefetch" in link.get("rel", []):
                    href = link.get("href", "")
                    if href.endswith(".js") or "javascript" in link.get("as", ""):
                        js_files.add(urljoin(url, href))

        except Exception as e:
            self.console.print(f"[red]Discovery error: {e}[/red]")

        self.console.print(f"[green]Found {len(js_files)} JavaScript files.[/green]")
        for js in sorted(js_files):
            self.console.print(f"  [dim]{js}[/dim]")

        return sorted(js_files)

    # ------------------------------------------------------------------
    # Extract endpoints/URLs from JS
    # ------------------------------------------------------------------
    def extract_endpoints(self, js_content: str, base_url: str = "") -> list:
        """Extract API endpoints and URLs from JavaScript content."""
        endpoints = set()

        # Relative and absolute paths
        path_patterns = [
            r'["\'](/[a-zA-Z0-9_\-./]+/[a-zA-Z0-9_\-./]*)["\']',
            r'["\'](https?://[^"\'<>\s]+)["\']',
            r'["\'](\./[a-zA-Z0-9_\-./]+)["\']',
        ]

        for pattern in path_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Filter out obvious non-endpoints
                if any(match.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico"]):
                    continue
                if len(match) < 3 or match.count("/") > 10:
                    continue
                endpoints.add(match)

        # API patterns
        api_patterns = [
            r'(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']',
            r'(?:url|endpoint|api|path|route)\s*[:=]\s*[`"\']([^`"\']+)[`"\']',
            r'(?:baseURL|base_url|apiUrl|API_URL)\s*[:=]\s*[`"\']([^`"\']+)[`"\']',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.update(matches)

        return sorted(endpoints)

    # ------------------------------------------------------------------
    # Extract secrets/credentials from JS
    # ------------------------------------------------------------------
    def extract_secrets(self, js_content: str, source_file: str = "") -> list:
        """Scan JavaScript content for hardcoded secrets and credentials."""
        secrets = []

        secret_patterns = [
            ("AWS Access Key", r'(?:AKIA[0-9A-Z]{16})'),
            ("AWS Secret Key", r'(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
            ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
            ("Google OAuth", r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
            ("GitHub Token", r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
            ("Slack Token", r'xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}'),
            ("Slack Webhook", r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}'),
            ("Stripe Key", r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
            ("Twilio", r'SK[0-9a-fA-F]{32}'),
            ("SendGrid", r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
            ("Mailgun", r'key-[0-9a-zA-Z]{32}'),
            ("Firebase", r'(?:firebase[a-zA-Z]*)\s*[:=]\s*["\']([^"\']{20,})["\']'),
            ("JWT Token", r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+'),
            ("Private Key", r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
            ("Password Field", r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']([^"\']{4,})["\']'),
            ("API Key Generic", r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'),
            ("Bearer Token", r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*'),
            ("Authorization Header", r'["\'](?:Authorization|X-API-Key)["\']:\s*["\']([^"\']+)["\']'),
            ("Database URL", r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+'),
            ("Heroku API Key", r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
        ]

        for name, pattern in secret_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Avoid false positives
                if isinstance(match, str) and len(match) > 200:
                    continue
                # Mask the secret for display
                val = match if isinstance(match, str) else str(match)
                if len(val) > 12:
                    masked = val[:6] + "..." + val[-4:]
                else:
                    masked = val[:3] + "***"
                secrets.append({
                    "type": name,
                    "value_masked": masked,
                    "source": source_file,
                })

        return secrets

    # ------------------------------------------------------------------
    # Extract interesting strings (domains, IPs, emails)
    # ------------------------------------------------------------------
    def extract_interesting(self, js_content: str) -> dict:
        """Extract domains, IPs, emails, and other interesting strings."""
        results = {
            "domains": set(),
            "ips": set(),
            "emails": set(),
            "s3_buckets": set(),
            "cloud_urls": set(),
        }

        # Domains
        domain_matches = re.findall(
            r'["\'](?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)["\'/]',
            js_content
        )
        results["domains"] = set(domain_matches)

        # IPs
        ip_matches = re.findall(
            r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)',
            js_content
        )
        results["ips"] = set(ip_matches)

        # Emails
        email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', js_content)
        results["emails"] = set(email_matches)

        # S3 buckets
        s3_matches = re.findall(
            r'(?:[a-zA-Z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z0-9-]+\.amazonaws\.com))',
            js_content
        )
        results["s3_buckets"] = set(s3_matches)

        # Cloud URLs (Azure, GCP, etc.)
        cloud_patterns = [
            r'[a-zA-Z0-9.-]+\.blob\.core\.windows\.net',
            r'[a-zA-Z0-9.-]+\.storage\.googleapis\.com',
            r'[a-zA-Z0-9.-]+\.firebaseio\.com',
            r'[a-zA-Z0-9.-]+\.appspot\.com',
        ]
        for pattern in cloud_patterns:
            matches = re.findall(pattern, js_content)
            results["cloud_urls"].update(matches)

        return results

    # ------------------------------------------------------------------
    # Analyze a single JS file
    # ------------------------------------------------------------------
    def analyze_file(self, js_url: str) -> dict:
        """Download and analyze a single JavaScript file."""
        result = {
            "url": js_url,
            "size": 0,
            "endpoints": [],
            "secrets": [],
            "interesting": {},
        }

        try:
            resp = self.session.get(js_url, timeout=15)
            content = resp.text
            result["size"] = len(content)

            result["endpoints"] = self.extract_endpoints(content, js_url)
            result["secrets"] = self.extract_secrets(content, js_url)
            result["interesting"] = self.extract_interesting(content)

        except Exception as e:
            self.console.print(f"[red]  Error fetching {js_url}: {e}[/red]")

        return result

    # ------------------------------------------------------------------
    # Full analysis
    # ------------------------------------------------------------------
    def analyze(self, url: str, max_files: int = 30):
        """Discover and analyze all JS files for a target URL."""
        self.console.print(Panel(f"[bold]JavaScript Analysis: {url}[/bold]", border_style="cyan"))

        # Step 1: Discover JS files
        js_files = self.discover_js_files(url)

        if not js_files:
            self.console.print("[yellow]No JavaScript files found.[/yellow]")
            return self.findings

        if len(js_files) > max_files:
            self.console.print(f"[yellow]Found {len(js_files)} files, analyzing first {max_files}.[/yellow]")
            js_files = js_files[:max_files]

        # Step 2: Analyze each file
        all_endpoints = set()
        all_secrets = []
        all_domains = set()
        all_ips = set()
        all_emails = set()
        all_buckets = set()
        all_cloud = set()

        self.console.print(f"\n[bold]Analyzing {len(js_files)} JavaScript files...[/bold]")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.analyze_file, js_url): js_url for js_url in js_files}
            for future in as_completed(futures):
                result = future.result()
                all_endpoints.update(result["endpoints"])
                all_secrets.extend(result["secrets"])
                interesting = result["interesting"]
                all_domains.update(interesting.get("domains", set()))
                all_ips.update(interesting.get("ips", set()))
                all_emails.update(interesting.get("emails", set()))
                all_buckets.update(interesting.get("s3_buckets", set()))
                all_cloud.update(interesting.get("cloud_urls", set()))

        # Step 3: Display results

        # Endpoints
        if all_endpoints:
            table = Table(title=f"Endpoints Found ({len(all_endpoints)})", box=box.SIMPLE)
            table.add_column("#", style="dim")
            table.add_column("Endpoint", style="green")

            for i, ep in enumerate(sorted(all_endpoints)[:50], 1):
                table.add_row(str(i), ep)
                self._add_finding("info", "JS Endpoint", f"Endpoint: {ep}", ep)

            self.console.print(table)
            if len(all_endpoints) > 50:
                self.console.print(f"[dim]  ... and {len(all_endpoints) - 50} more[/dim]")

        # Secrets
        if all_secrets:
            table = Table(title=f"Potential Secrets ({len(all_secrets)})", box=box.SIMPLE)
            table.add_column("Type", style="red")
            table.add_column("Value (masked)", style="yellow")
            table.add_column("Source", style="dim", max_width=50)

            for s in all_secrets:
                table.add_row(s["type"], s["value_masked"], s["source"].split("/")[-1])
                self._add_finding(
                    "high", "JS Secret", f"{s['type']} found in JS",
                    f"Masked: {s['value_masked']}", s["source"]
                )

            self.console.print(table)

        # Interesting data
        sections = [
            ("Domains", all_domains, "cyan"),
            ("IP Addresses", all_ips, "yellow"),
            ("Email Addresses", all_emails, "green"),
            ("S3 Buckets", all_buckets, "red"),
            ("Cloud URLs", all_cloud, "red"),
        ]

        for name, data, color in sections:
            if data:
                self.console.print(f"\n[bold]{name} ({len(data)}):[/bold]")
                for item in sorted(data)[:20]:
                    self.console.print(f"  [{color}]{item}[/{color}]")
                    if name in ("S3 Buckets", "Cloud URLs"):
                        self._add_finding("medium", f"JS {name}", f"{name}: {item}", item)
                if len(data) > 20:
                    self.console.print(f"  [dim]... and {len(data) - 20} more[/dim]")

        self.console.print(f"\n[bold green]JS analysis complete. {len(self.findings)} findings.[/bold green]")
        return self.findings

    # ------------------------------------------------------------------
    # Interactive
    # ------------------------------------------------------------------
    def interactive(self, target: str):
        """Interactive JS analysis menu."""
        table = Table(title="JS Analysis Options", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="bold yellow", width=4)
        table.add_column("Name", style="white")

        table.add_row("1", "Discover JS files")
        table.add_row("2", "Full JS analysis (endpoints + secrets)")
        table.add_row("3", "Analyze specific JS URL")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3"])

        if choice == "1":
            self.discover_js_files(target)
        elif choice == "2":
            self.analyze(target)
        elif choice == "3":
            js_url = Prompt.ask("Enter JS file URL")
            result = self.analyze_file(js_url)
            if result["endpoints"]:
                self.console.print(f"\n[bold]Endpoints ({len(result['endpoints'])}):[/bold]")
                for ep in result["endpoints"][:30]:
                    self.console.print(f"  [green]{ep}[/green]")
            if result["secrets"]:
                self.console.print(f"\n[bold red]Secrets ({len(result['secrets'])}):[/bold red]")
                for s in result["secrets"]:
                    self.console.print(f"  [red]{s['type']}: {s['value_masked']}[/red]")
