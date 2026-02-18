"""
Web Application Testing Module - OWASP-style web security checks.
"""

import re
import html
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box


class WebTesterModule:
    """Web application security testing following OWASP methodology."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _add_finding(self, severity: str, category: str, title: str, detail: str, url: str = ""):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "url": url,
        })

    # ------------------------------------------------------------------
    # Form discovery
    # ------------------------------------------------------------------
    def discover_forms(self, url: str):
        """Discover all HTML forms on a page."""
        self.console.print(Panel(f"[bold]Form Discovery: {url}[/bold]", border_style="cyan"))

        try:
            resp = self.session.get(url, timeout=15)
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            if not forms:
                self.console.print("[dim]No forms found on this page.[/dim]")
                return []

            table = Table(title=f"Forms Found ({len(forms)})", box=box.SIMPLE)
            table.add_column("#", style="dim")
            table.add_column("Action", style="cyan")
            table.add_column("Method", style="yellow")
            table.add_column("Inputs", style="white")

            form_data = []
            for i, form in enumerate(forms, 1):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if name:
                        inputs.append(f"{name}({itype})")

                form_data.append({
                    "action": urljoin(url, action) if action else url,
                    "method": method,
                    "inputs": inputs,
                })
                table.add_row(str(i), action or "(self)", method, ", ".join(inputs[:5]))

            self.console.print(table)
            return form_data

        except Exception as e:
            self.console.print(f"[red]Form discovery error: {e}[/red]")
            return []

    # ------------------------------------------------------------------
    # XSS reflection check
    # ------------------------------------------------------------------
    def xss_check(self, url: str):
        """Check for reflected XSS by testing parameter reflection."""
        self.console.print(Panel(f"[bold]XSS Reflection Check: {url}[/bold]", border_style="cyan"))

        parsed = urlparse(url)
        canary = "pent7x5s9"  # Unique canary string

        # Test URL parameters
        test_payloads = [
            canary,
            f"<{canary}>",
            f'"{canary}',
            f"'{canary}",
            f"javascript:{canary}",
        ]

        results = []

        # Try to find parameters from the page itself
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Find all links with parameters
            params_found = set()
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if "?" in href:
                    for part in href.split("?")[1].split("&"):
                        if "=" in part:
                            params_found.add(part.split("=")[0])

            # Also check form inputs
            for form in soup.find_all("form"):
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if name:
                        params_found.add(name)

            if not params_found:
                params_found = {"q", "search", "query", "s", "id", "page", "name", "url", "redirect", "next"}
                self.console.print("[dim]No parameters found on page, testing common ones...[/dim]")
            else:
                self.console.print(f"[dim]Found {len(params_found)} parameters to test.[/dim]")

            # Test each parameter
            for param in params_found:
                for payload in test_payloads:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                    try:
                        resp = self.session.get(test_url, timeout=10)
                        if payload in resp.text:
                            # Check if it's reflected without encoding
                            context = self._find_reflection_context(resp.text, payload)
                            severity = "high" if "<" in payload and payload in resp.text else "medium"
                            results.append((param, payload, severity, context))
                            self._add_finding(
                                severity, "XSS", f"Reflected XSS in '{param}'",
                                f"Payload '{payload}' reflected in {context}", test_url
                            )
                            break  # One finding per param is enough
                    except Exception:
                        pass

        except Exception as e:
            self.console.print(f"[red]XSS check error: {e}[/red]")
            return

        if results:
            table = Table(title="XSS Reflection Results", box=box.SIMPLE)
            table.add_column("Parameter", style="cyan")
            table.add_column("Payload", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Context", style="dim")

            for param, payload, sev, ctx in results:
                style = "bold red" if sev == "high" else "yellow"
                table.add_row(param, payload, f"[{style}]{sev.upper()}[/{style}]", ctx)

            self.console.print(table)
        else:
            self.console.print("[green]No reflected XSS found with basic checks.[/green]")
            self.console.print("[dim]Note: This tests basic reflection only. Manual testing with browser devtools is recommended.[/dim]")

    def _find_reflection_context(self, body: str, payload: str) -> str:
        """Determine where in the HTML the payload is reflected."""
        idx = body.find(payload)
        if idx == -1:
            return "not found"
        surrounding = body[max(0, idx - 50):idx + len(payload) + 50]
        if f'"{payload}' in surrounding or f"'{payload}" in surrounding:
            return "HTML attribute"
        if f">{payload}<" in surrounding:
            return "HTML body"
        if f"<script" in body[max(0, idx - 200):idx].lower():
            return "JavaScript context"
        return "HTML body"

    # ------------------------------------------------------------------
    # SQL injection basic check
    # ------------------------------------------------------------------
    def sqli_check(self, url: str):
        """Check for basic SQL injection indicators."""
        self.console.print(Panel(f"[bold]SQL Injection Check: {url}[/bold]", border_style="cyan"))

        error_patterns = [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"microsoft ole db provider",
            r"odbc.*driver",
            r"syntax error.*postgresql",
            r"pg_query\(\)",
            r"sqlite3\.operationalerror",
            r"ora-\d{5}",
            r"sql.*error",
            r"database.*error",
        ]

        test_payloads = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--", "1 AND 1=1", "' WAITFOR DELAY '0:0:5'--"]

        try:
            resp_baseline = self.session.get(url, timeout=10)
            baseline_len = len(resp_baseline.text)
        except Exception as e:
            self.console.print(f"[red]Cannot reach target: {e}[/red]")
            return

        # Extract parameters
        parsed = urlparse(url)
        if not parsed.query:
            self.console.print("[dim]No URL parameters found. Testing common parameter names...[/dim]")
            params_to_test = ["id", "page", "cat", "item", "product", "user"]
        else:
            params_to_test = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]

        results = []

        for param in params_to_test:
            for payload in test_payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    body = resp.text.lower()

                    # Check for SQL error messages
                    for pattern in error_patterns:
                        if re.search(pattern, body):
                            results.append((param, payload, "high", f"SQL error: {pattern}"))
                            self._add_finding(
                                "high", "SQLi", f"SQL Injection in '{param}'",
                                f"Error pattern matched: {pattern}", test_url
                            )
                            break

                    # Check for significant response size difference
                    size_diff = abs(len(resp.text) - baseline_len)
                    if size_diff > baseline_len * 0.3 and size_diff > 500:
                        results.append((param, payload, "medium", f"Response size anomaly: {size_diff} bytes diff"))

                except Exception:
                    pass

        if results:
            table = Table(title="SQLi Check Results", box=box.SIMPLE)
            table.add_column("Parameter", style="cyan")
            table.add_column("Payload", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Indicator", style="dim")

            for param, payload, sev, indicator in results:
                style = "bold red" if sev == "high" else "yellow"
                table.add_row(param, payload, f"[{style}]{sev.upper()}[/{style}]", indicator)

            self.console.print(table)
        else:
            self.console.print("[green]No SQL injection indicators found with basic checks.[/green]")
            self.console.print("[dim]Note: This tests error-based SQLi only. Use sqlmap for thorough testing.[/dim]")

    # ------------------------------------------------------------------
    # Directory traversal check
    # ------------------------------------------------------------------
    def directory_traversal_check(self, url: str):
        """Check for directory traversal vulnerabilities."""
        self.console.print(Panel(f"[bold]Directory Traversal Check: {url}[/bold]", border_style="cyan"))

        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]

        linux_indicators = ["root:x:", "root:*:", "daemon:", "bin:x:"]
        windows_indicators = ["# Copyright", "[boot loader]", "[operating systems]"]

        parsed = urlparse(url)
        params_to_test = []
        if parsed.query:
            params_to_test = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        else:
            params_to_test = ["file", "path", "page", "document", "folder", "dir", "include", "template"]

        results = []

        for param in params_to_test:
            for payload in traversal_payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    body = resp.text

                    for indicator in linux_indicators + windows_indicators:
                        if indicator in body:
                            results.append((param, payload, "critical", f"File content leaked: {indicator}"))
                            self._add_finding(
                                "critical", "Path Traversal", f"Directory traversal in '{param}'",
                                f"Indicator: {indicator}", test_url
                            )
                            break
                except Exception:
                    pass

        if results:
            table = Table(title="Directory Traversal Results", box=box.SIMPLE)
            table.add_column("Parameter", style="cyan")
            table.add_column("Payload", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Evidence", style="dim")

            for param, payload, sev, evidence in results:
                table.add_row(param, payload, f"[bold red]{sev.upper()}[/bold red]", evidence)
            self.console.print(table)
        else:
            self.console.print("[green]No directory traversal found with basic checks.[/green]")

    # ------------------------------------------------------------------
    # CSRF check
    # ------------------------------------------------------------------
    def csrf_check(self, url: str):
        """Check forms for CSRF protection."""
        self.console.print(Panel(f"[bold]CSRF Protection Check: {url}[/bold]", border_style="cyan"))

        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            if not forms:
                self.console.print("[dim]No forms found on this page.[/dim]")
                return

            csrf_names = ["csrf", "token", "_token", "authenticity_token", "csrfmiddlewaretoken",
                          "anti-forgery", "xsrf", "__requestverificationtoken", "nonce"]

            table = Table(title="CSRF Analysis", box=box.SIMPLE)
            table.add_column("Form", style="cyan")
            table.add_column("Method", style="yellow")
            table.add_column("CSRF Token", style="white")
            table.add_column("Status", style="white")

            for i, form in enumerate(forms, 1):
                method = form.get("method", "GET").upper()
                action = form.get("action", "(self)")

                # Only POST/PUT/DELETE forms need CSRF
                if method == "GET":
                    table.add_row(f"#{i} {action}", method, "N/A", "[dim]GET form (no CSRF needed)[/dim]")
                    continue

                has_csrf = False
                for inp in form.find_all("input", type="hidden"):
                    name = (inp.get("name") or "").lower()
                    if any(tok in name for tok in csrf_names):
                        has_csrf = True
                        table.add_row(f"#{i} {action}", method, inp.get("name"), "[green]Protected[/green]")
                        break

                if not has_csrf:
                    table.add_row(f"#{i} {action}", method, "MISSING", "[bold red]No CSRF token![/bold red]")
                    self._add_finding(
                        "medium", "CSRF", f"Missing CSRF token in form #{i}",
                        f"Form action: {action}, method: {method}", url
                    )

            self.console.print(table)

            # Check SameSite cookies
            cookies = resp.headers.get("Set-Cookie", "").lower()
            if cookies and "samesite" not in cookies:
                self.console.print("[yellow][!] Session cookies missing SameSite attribute[/yellow]")

        except Exception as e:
            self.console.print(f"[red]CSRF check error: {e}[/red]")

    # ------------------------------------------------------------------
    # Link and resource enumeration
    # ------------------------------------------------------------------
    def crawl_links(self, url: str):
        """Crawl and enumerate links and resources on a page."""
        self.console.print(Panel(f"[bold]Link Enumeration: {url}[/bold]", border_style="cyan"))

        try:
            resp = self.session.get(url, timeout=15)
            soup = BeautifulSoup(resp.text, "html.parser")
            parsed_base = urlparse(url)

            internal = set()
            external = set()
            resources = set()

            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                full = urljoin(url, href)
                parsed = urlparse(full)
                if parsed.netloc == parsed_base.netloc:
                    internal.add(full)
                elif parsed.scheme in ("http", "https"):
                    external.add(full)

            for tag in soup.find_all(["script", "link", "img"], src=True):
                resources.add(urljoin(url, tag.get("src", "")))
            for tag in soup.find_all("link", href=True):
                resources.add(urljoin(url, tag["href"]))

            # Internal links
            self.console.print(f"\n[bold]Internal Links ({len(internal)}):[/bold]")
            for link in sorted(internal)[:30]:
                self.console.print(f"  [green]{link}[/green]")

            # External links
            self.console.print(f"\n[bold]External Links ({len(external)}):[/bold]")
            for link in sorted(external)[:20]:
                self.console.print(f"  [yellow]{link}[/yellow]")

            # Resources
            self.console.print(f"\n[bold]Resources ({len(resources)}):[/bold]")
            for res in sorted(resources)[:20]:
                self.console.print(f"  [dim]{res}[/dim]")

            # Look for interesting patterns
            body = resp.text
            email_pattern = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
            if email_pattern:
                self.console.print(f"\n[bold]Emails Found:[/bold]")
                for email in set(email_pattern):
                    self.console.print(f"  [cyan]{email}[/cyan]")
                    self._add_finding("info", "Email", "Email address found", email, url)

            # Look for API keys / tokens in source
            secret_patterns = [
                (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key"),
                (r"(?:secret|token|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Secret/Token"),
                (r"(?:aws_access_key_id)\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?", "AWS Key"),
            ]
            for pattern, name in secret_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    for m in matches[:3]:
                        masked = m[:4] + "..." + m[-4:] if len(m) > 8 else "***"
                        self.console.print(f"  [bold red][!] Possible {name}: {masked}[/bold red]")
                        self._add_finding("high", "Secret Exposure", f"Possible {name} in source", masked, url)

        except Exception as e:
            self.console.print(f"[red]Crawl error: {e}[/red]")

    # ------------------------------------------------------------------
    # Run all web tests
    # ------------------------------------------------------------------
    def run(self, url: str, full: bool = False):
        """Run complete web testing workflow."""
        self.discover_forms(url)
        self.xss_check(url)
        self.sqli_check(url)
        self.csrf_check(url)
        self.crawl_links(url)

        if full:
            self.directory_traversal_check(url)

        self.console.print(f"\n[bold green]Web testing complete. {len(self.findings)} findings.[/bold green]")
        return self.findings

    # ------------------------------------------------------------------
    # Interactive
    # ------------------------------------------------------------------
    def interactive(self, url: str):
        """Interactive web testing menu."""
        table = Table(title="Web Test Options", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="bold yellow", width=4)
        table.add_column("Name", style="white")

        table.add_row("1", "Discover Forms")
        table.add_row("2", "XSS Reflection Check")
        table.add_row("3", "SQL Injection Check")
        table.add_row("4", "CSRF Protection Check")
        table.add_row("5", "Directory Traversal Check")
        table.add_row("6", "Link & Resource Enumeration")
        table.add_row("7", "Run ALL Web Tests")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5", "6", "7"])

        actions = {
            "1": lambda: self.discover_forms(url),
            "2": lambda: self.xss_check(url),
            "3": lambda: self.sqli_check(url),
            "4": lambda: self.csrf_check(url),
            "5": lambda: self.directory_traversal_check(url),
            "6": lambda: self.crawl_links(url),
            "7": lambda: self.run(url, full=True),
        }

        action = actions.get(choice)
        if action:
            action()
