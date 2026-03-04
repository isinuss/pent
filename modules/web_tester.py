"""
Web Application Testing Module - OWASP-style web security checks.
"""

import re
import html
import time
import socket
import random
import string
import hashlib
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote, urlencode

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
    # Blind SQL injection check
    # ------------------------------------------------------------------
    def blind_sqli_check(self, url: str):
        """Check for blind SQL injection using time-based and boolean-based techniques."""
        self.console.print(Panel(f"[bold]Blind SQL Injection Check: {url}[/bold]", border_style="cyan"))

        # Time-based payloads (target 3-second delay)
        time_payloads = [
            ("MySQL SLEEP", "' AND SLEEP(3)--"),
            ("MSSQL WAITFOR", "1; WAITFOR DELAY '0:0:3'--"),
            ("PostgreSQL pg_sleep", "'; SELECT pg_sleep(3)--"),
        ]

        # Boolean-based payloads
        boolean_true_payload = "' AND 1=1--"
        boolean_false_payload = "' AND 1=2--"

        # Determine parameters to test
        parsed = urlparse(url)
        if parsed.query:
            params_to_test = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        else:
            params_to_test = ["id", "page", "user", "item", "cat"]
            self.console.print("[dim]No URL parameters found. Testing common parameter names...[/dim]")

        self.console.print(f"[dim]Testing {len(params_to_test)} parameter(s) with time-based and boolean-based blind SQLi...[/dim]")

        results = []

        # --- Establish baseline response time ---
        baseline_times = []
        try:
            for _ in range(3):
                start = time.time()
                self.session.get(url, timeout=10)
                elapsed = time.time() - start
                baseline_times.append(elapsed)
            baseline_avg = sum(baseline_times) / len(baseline_times)
            self.console.print(f"[dim]Baseline response time: {baseline_avg:.2f}s (avg of 3 requests)[/dim]")
        except Exception as e:
            self.console.print(f"[red]Cannot reach target for baseline: {e}[/red]")
            return

        # --- Establish baseline response size ---
        try:
            baseline_resp = self.session.get(url, timeout=10)
            baseline_size = len(baseline_resp.text)
        except Exception as e:
            self.console.print(f"[red]Cannot reach target for baseline size: {e}[/red]")
            return

        # --- Time-based blind SQLi ---
        self.console.print("\n[bold]Time-Based Blind SQLi Testing[/bold]")
        for param in params_to_test:
            for db_type, payload in time_payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                try:
                    start = time.time()
                    resp = self.session.get(test_url, timeout=15)
                    elapsed = time.time() - start
                    time_diff = elapsed - baseline_avg

                    if time_diff > 2.5:
                        results.append((param, payload, "high", f"Time-based ({db_type}): {elapsed:.2f}s vs baseline {baseline_avg:.2f}s (+{time_diff:.2f}s)"))
                        self._add_finding(
                            "high", "Blind SQLi",
                            f"Time-based blind SQLi in '{param}' ({db_type})",
                            f"Response delayed by {time_diff:.2f}s (payload: {payload})",
                            test_url
                        )
                        self.console.print(f"  [bold red][!] {param}: {db_type} delay detected ({elapsed:.2f}s vs {baseline_avg:.2f}s)[/bold red]")
                        break  # One finding per param for time-based is enough
                except requests.exceptions.Timeout:
                    # A timeout could also indicate a successful time-based injection
                    results.append((param, payload, "high", f"Time-based ({db_type}): Request timed out (possible sleep injection)"))
                    self._add_finding(
                        "high", "Blind SQLi",
                        f"Time-based blind SQLi in '{param}' ({db_type})",
                        f"Request timed out, possible sleep injection (payload: {payload})",
                        test_url
                    )
                    self.console.print(f"  [bold red][!] {param}: {db_type} timeout detected (possible injection)[/bold red]")
                    break
                except Exception:
                    pass

        # --- Boolean-based blind SQLi ---
        self.console.print("\n[bold]Boolean-Based Blind SQLi Testing[/bold]")
        for param in params_to_test:
            try:
                # Send true condition
                true_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(boolean_true_payload)}"
                true_resp = self.session.get(true_url, timeout=10)
                true_size = len(true_resp.text)

                # Send false condition
                false_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(boolean_false_payload)}"
                false_resp = self.session.get(false_url, timeout=10)
                false_size = len(false_resp.text)

                size_diff = abs(true_size - false_size)
                # Significant difference suggests the condition is being evaluated
                if size_diff > 100 and size_diff > baseline_size * 0.05:
                    results.append((param, f"1=1 vs 1=2", "medium",
                                    f"Boolean-based: true={true_size}B, false={false_size}B (diff={size_diff}B)"))
                    self._add_finding(
                        "medium", "Blind SQLi",
                        f"Boolean-based blind SQLi in '{param}'",
                        f"Response size differs: AND 1=1 -> {true_size}B, AND 1=2 -> {false_size}B (diff={size_diff}B)",
                        true_url
                    )
                    self.console.print(f"  [yellow][!] {param}: Boolean-based size difference detected (true={true_size}B, false={false_size}B)[/yellow]")

                    # Additional verification: compare true response with baseline
                    true_baseline_diff = abs(true_size - baseline_size)
                    if true_baseline_diff < size_diff * 0.2:
                        self.console.print(f"      [dim]True condition response is similar to baseline (higher confidence)[/dim]")

            except Exception:
                pass

        # --- Display results ---
        if results:
            self.console.print("")
            table = Table(title="Blind SQLi Results", box=box.SIMPLE)
            table.add_column("Parameter", style="cyan")
            table.add_column("Technique", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Detail", style="dim")

            for param, technique, sev, detail in results:
                style = "bold red" if sev == "high" else "yellow"
                table.add_row(param, technique, f"[{style}]{sev.upper()}[/{style}]", detail)

            self.console.print(table)
        else:
            self.console.print("\n[green]No blind SQL injection indicators found.[/green]")
            self.console.print("[dim]Note: Blind SQLi detection depends on network stability. Consider manual testing with sqlmap.[/dim]")

    # ------------------------------------------------------------------
    # Stored XSS check
    # ------------------------------------------------------------------
    def stored_xss_check(self, url: str):
        """Check for stored XSS by submitting canary payloads into forms and checking for persistence."""
        self.console.print(Panel(f"[bold]Stored XSS Check: {url}[/bold]", border_style="cyan"))

        # Generate a unique canary tag for this run
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        canary_payload = f"<img src=x onerror=pent_xss_{random_id}>"
        canary_marker = f"pent_xss_{random_id}"

        self.console.print(f"[dim]Canary marker: {canary_marker}[/dim]")

        # Step 1: Discover forms on the page
        self.console.print("[dim]Discovering forms on the target page...[/dim]")
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
        except Exception as e:
            self.console.print(f"[red]Cannot reach target: {e}[/red]")
            return

        if not forms:
            self.console.print("[dim]No forms found on this page. Cannot test for stored XSS.[/dim]")
            return

        self.console.print(f"[dim]Found {len(forms)} form(s). Submitting canary payloads...[/dim]")

        submitted_targets = []

        # Step 2: Submit canary into each form's text fields
        for form_idx, form in enumerate(forms, 1):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(url, action) if action else url

            # Build form data with canary in text fields
            form_data = {}
            has_text_field = False
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue

                inp_type = inp.get("type", "text").lower()

                if inp.name == "textarea" or inp_type in ("text", "search", "url", "email", ""):
                    form_data[name] = canary_payload
                    has_text_field = True
                elif inp_type == "hidden":
                    form_data[name] = inp.get("value", "")
                elif inp_type == "password":
                    form_data[name] = "testpassword123"
                elif inp_type in ("submit", "button", "image"):
                    form_data[name] = inp.get("value", "Submit")
                elif inp_type == "checkbox":
                    form_data[name] = inp.get("value", "on")
                elif inp_type == "radio":
                    form_data[name] = inp.get("value", "")
                elif inp_type == "number":
                    form_data[name] = "1"
                else:
                    form_data[name] = canary_payload
                    has_text_field = True

            if not has_text_field:
                self.console.print(f"  [dim]Form #{form_idx}: No text input fields found, skipping.[/dim]")
                continue

            # Submit the form
            try:
                if method == "POST":
                    submit_resp = self.session.post(form_url, data=form_data, timeout=10, allow_redirects=True)
                else:
                    submit_resp = self.session.get(form_url, params=form_data, timeout=10, allow_redirects=True)

                self.console.print(f"  [dim]Form #{form_idx}: Submitted canary to {form_url} ({method}) -> HTTP {submit_resp.status_code}[/dim]")
                submitted_targets.append((form_idx, form_url, method))
            except Exception as e:
                self.console.print(f"  [red]Form #{form_idx}: Submission failed: {e}[/red]")

        if not submitted_targets:
            self.console.print("[dim]No forms were successfully submitted. Cannot verify stored XSS.[/dim]")
            return

        # Step 3: Re-crawl the page and linked pages to check for the canary
        self.console.print("\n[dim]Re-crawling target to check if canary persists...[/dim]")
        pages_to_check = set()
        pages_to_check.add(url)

        # Add form action URLs
        for _, form_url, _ in submitted_targets:
            pages_to_check.add(form_url)

        # Crawl the original page for linked pages
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            parsed_base = urlparse(url)
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_link = urljoin(url, href)
                parsed_link = urlparse(full_link)
                if parsed_link.netloc == parsed_base.netloc:
                    pages_to_check.add(full_link)
        except Exception:
            pass

        # Limit the number of pages to check
        pages_to_check = list(pages_to_check)[:20]
        self.console.print(f"[dim]Checking {len(pages_to_check)} page(s) for stored canary...[/dim]")

        results = []

        for page_url in pages_to_check:
            try:
                resp = self.session.get(page_url, timeout=10)
                if canary_marker in resp.text:
                    # Check if the full unencoded payload is present
                    if canary_payload in resp.text:
                        results.append((page_url, "Full unencoded payload found", "high"))
                        self._add_finding(
                            "high", "Stored XSS",
                            f"Stored XSS detected on {page_url}",
                            f"Canary payload '{canary_payload}' found unencoded in page response",
                            page_url
                        )
                        self.console.print(f"  [bold red][!] STORED XSS: Unencoded canary found on {page_url}[/bold red]")
                    else:
                        # The marker exists but the full tag might be partially encoded
                        results.append((page_url, "Canary marker found (may be partially encoded)", "medium"))
                        self._add_finding(
                            "medium", "Stored XSS",
                            f"Possible stored XSS on {page_url}",
                            f"Canary marker '{canary_marker}' found in response (verify encoding manually)",
                            page_url
                        )
                        self.console.print(f"  [yellow][!] Canary marker found on {page_url} (check encoding)[/yellow]")
            except Exception:
                pass

        # --- Display results ---
        if results:
            self.console.print("")
            table = Table(title="Stored XSS Results", box=box.SIMPLE)
            table.add_column("Page URL", style="cyan")
            table.add_column("Finding", style="yellow")
            table.add_column("Severity", style="red")

            for page_url, finding, sev in results:
                style = "bold red" if sev == "high" else "yellow"
                table.add_row(page_url, finding, f"[{style}]{sev.upper()}[/{style}]")

            self.console.print(table)
        else:
            self.console.print("\n[green]No stored XSS detected. Canary was not found on re-crawled pages.[/green]")
            self.console.print("[dim]Note: Stored XSS may require authentication or specific workflows. Manual testing recommended.[/dim]")

    # ------------------------------------------------------------------
    # SSRF check
    # ------------------------------------------------------------------
    def ssrf_check(self, url: str):
        """Check for Server-Side Request Forgery (SSRF) vulnerabilities."""
        self.console.print(Panel(f"[bold]SSRF Detection Check: {url}[/bold]", border_style="cyan"))

        # Parameter names that commonly accept URLs
        ssrf_param_names = [
            "url", "redirect", "next", "link", "path", "file",
            "load", "target", "fetch", "uri", "proxy", "callback",
        ]

        # SSRF payloads targeting internal services
        ssrf_payloads = [
            ("Loopback (127.0.0.1)", "http://127.0.0.1"),
            ("Loopback (localhost)", "http://localhost"),
            ("IPv6 loopback", "http://[::1]"),
            ("AWS metadata", "http://169.254.169.254/latest/meta-data/"),
            ("Hex loopback", "http://0x7f000001"),
        ]

        # Known internal service response indicators
        internal_indicators = [
            ("ami-id", "AWS EC2 Metadata"),
            ("instance-id", "AWS EC2 Metadata"),
            ("local-hostname", "AWS EC2 Metadata"),
            ("meta-data", "Cloud Metadata"),
            ("iam/security-credentials", "AWS IAM Credentials"),
            ("computeMetadata", "GCP Metadata"),
            ("Server: Apache", "Internal Apache Server"),
            ("It works!", "Default Apache Page"),
            ("Welcome to nginx", "Internal Nginx Server"),
            ("Directory listing", "Internal Directory Listing"),
        ]

        # Open redirect payload
        open_redirect_payload = "//evil.com"

        # Determine parameters to test
        parsed = urlparse(url)
        params_to_test = set()

        if parsed.query:
            for p in parsed.query.split("&"):
                if "=" in p:
                    param_name = p.split("=")[0]
                    params_to_test.add(param_name)

        # Also try common SSRF-prone parameter names
        for param in ssrf_param_names:
            params_to_test.add(param)

        self.console.print(f"[dim]Testing {len(params_to_test)} parameter(s) for SSRF...[/dim]")

        # Get baseline response for comparison
        try:
            baseline_resp = self.session.get(url, timeout=10)
            baseline_size = len(baseline_resp.text)
            baseline_text = baseline_resp.text
        except Exception as e:
            self.console.print(f"[red]Cannot reach target: {e}[/red]")
            return

        results = []

        # --- Test SSRF payloads ---
        self.console.print("\n[bold]Testing SSRF Payloads[/bold]")
        for param in params_to_test:
            for payload_name, payload_url in ssrf_payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload_url, safe='')}"
                try:
                    resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                    body = resp.text

                    # Check for internal service response indicators
                    for indicator, service_name in internal_indicators:
                        if indicator.lower() in body.lower() and indicator.lower() not in baseline_text.lower():
                            results.append((param, payload_name, "critical",
                                            f"Internal service response detected: {service_name} (indicator: {indicator})"))
                            self._add_finding(
                                "critical", "SSRF",
                                f"SSRF in '{param}' - {service_name} accessible",
                                f"Payload: {payload_url}, Indicator: {indicator}",
                                test_url
                            )
                            self.console.print(f"  [bold red][!] {param}: {payload_name} -> {service_name} detected![/bold red]")
                            break

                    # Check if the response changed significantly (might have fetched internal content)
                    size_diff = abs(len(body) - baseline_size)
                    if size_diff > 500 and size_diff > baseline_size * 0.3:
                        # Avoid duplicate reporting
                        already_found = any(r[0] == param and r[1] == payload_name for r in results)
                        if not already_found:
                            results.append((param, payload_name, "medium",
                                            f"Significant response size change: {len(body)}B vs baseline {baseline_size}B"))
                            self._add_finding(
                                "medium", "SSRF",
                                f"Possible SSRF in '{param}' (response size anomaly)",
                                f"Payload: {payload_url}, Response size: {len(body)}B vs baseline {baseline_size}B",
                                test_url
                            )

                except Exception:
                    pass

        # --- Test Open Redirect ---
        self.console.print("\n[bold]Testing Open Redirect[/bold]")
        for param in params_to_test:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(open_redirect_payload, safe='')}"
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)

                # Check Location header for open redirect
                location = resp.headers.get("Location", "")
                if location and ("evil.com" in location):
                    results.append((param, "Open Redirect (//evil.com)", "medium",
                                    f"Location header redirects to: {location}"))
                    self._add_finding(
                        "medium", "Open Redirect",
                        f"Open redirect in '{param}'",
                        f"Payload: {open_redirect_payload}, Redirects to: {location}",
                        test_url
                    )
                    self.console.print(f"  [yellow][!] {param}: Open redirect detected -> {location}[/yellow]")

            except Exception:
                pass

        # --- Display results ---
        if results:
            self.console.print("")
            table = Table(title="SSRF / Open Redirect Results", box=box.SIMPLE)
            table.add_column("Parameter", style="cyan")
            table.add_column("Payload", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Detail", style="dim")

            for param, payload_name, sev, detail in results:
                if sev == "critical":
                    style = "bold red"
                elif sev == "high":
                    style = "red"
                elif sev == "medium":
                    style = "yellow"
                else:
                    style = "dim"
                table.add_row(param, payload_name, f"[{style}]{sev.upper()}[/{style}]", detail)

            self.console.print(table)
        else:
            self.console.print("\n[green]No SSRF or open redirect indicators found.[/green]")
            self.console.print("[dim]Note: SSRF detection may require out-of-band (OOB) techniques for full coverage.[/dim]")

    # ------------------------------------------------------------------
    # HTTP Request Smuggling check
    # ------------------------------------------------------------------
    def http_smuggling_check(self, url: str):
        """Check for HTTP request smuggling (CL.TE and TE.CL) vulnerabilities."""
        self.console.print(Panel(f"[bold]HTTP Request Smuggling Check: {url}[/bold]", border_style="cyan"))
        self.console.print("[dim]Testing for CL.TE and TE.CL smuggling vectors (detection only)...[/dim]")

        results = []

        # --- CL.TE Test ---
        # Server uses Content-Length, backend uses Transfer-Encoding: chunked
        # We send a short Content-Length but a chunked body that ends early.
        # If the front-end uses CL and the back-end uses TE, the back-end
        # will interpret the chunked encoding differently, potentially causing
        # a timeout or different status code.
        self.console.print("\n[bold]CL.TE Smuggling Test[/bold]")
        try:
            # Build a CL.TE probe: Content-Length says the body is short,
            # but we include Transfer-Encoding: chunked with an incomplete chunk.
            cl_te_body = "0\r\n\r\n"
            cl_te_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(cl_te_body)),
                "Transfer-Encoding": "chunked",
            }

            # Normal request for baseline
            try:
                baseline_start = time.time()
                baseline_resp = self.session.post(url, data="x=1", timeout=10)
                baseline_time = time.time() - baseline_start
                baseline_status = baseline_resp.status_code
            except Exception as e:
                self.console.print(f"  [dim]Baseline POST request failed: {e}. Using GET baseline.[/dim]")
                baseline_status = 200
                baseline_time = 1.0

            # Send CL.TE probe
            try:
                start = time.time()
                resp = self.session.post(
                    url,
                    data=cl_te_body,
                    headers=cl_te_headers,
                    timeout=10,
                )
                elapsed = time.time() - start
                cl_te_status = resp.status_code

                # If we get a different response than baseline (e.g., 400 when baseline was 200),
                # or a significant time difference, it may indicate smuggling potential
                if cl_te_status != baseline_status and cl_te_status >= 400:
                    results.append(("CL.TE", f"HTTP {cl_te_status}", "medium",
                                    f"Status {cl_te_status} (baseline: {baseline_status}). Server may process conflicting headers differently."))
                    self._add_finding(
                        "medium", "HTTP Smuggling",
                        "Possible CL.TE request smuggling",
                        f"CL.TE probe returned HTTP {cl_te_status} (baseline: {baseline_status})",
                        url
                    )
                    self.console.print(f"  [yellow][!] CL.TE: Status difference detected ({cl_te_status} vs baseline {baseline_status})[/yellow]")
                elif elapsed - baseline_time > 2.5:
                    results.append(("CL.TE", f"Time delay: {elapsed:.2f}s", "medium",
                                    f"Response delayed ({elapsed:.2f}s vs baseline {baseline_time:.2f}s). Possible parsing conflict."))
                    self._add_finding(
                        "medium", "HTTP Smuggling",
                        "Possible CL.TE request smuggling (time-based)",
                        f"CL.TE probe response delayed by {elapsed - baseline_time:.2f}s",
                        url
                    )
                    self.console.print(f"  [yellow][!] CL.TE: Time delay detected ({elapsed:.2f}s vs baseline {baseline_time:.2f}s)[/yellow]")
                else:
                    self.console.print(f"  [dim]CL.TE: HTTP {cl_te_status} in {elapsed:.2f}s (no anomaly)[/dim]")

            except requests.exceptions.Timeout:
                results.append(("CL.TE", "Timeout", "medium",
                                "Request timed out. Backend may be waiting for more chunked data."))
                self._add_finding(
                    "medium", "HTTP Smuggling",
                    "Possible CL.TE request smuggling (timeout)",
                    "CL.TE probe caused a timeout, backend may be waiting for chunked data",
                    url
                )
                self.console.print(f"  [yellow][!] CL.TE: Request timed out (possible smuggling indicator)[/yellow]")
            except Exception as e:
                self.console.print(f"  [dim]CL.TE test error: {e}[/dim]")

        except Exception as e:
            self.console.print(f"  [red]CL.TE test failed: {e}[/red]")

        # --- TE.CL Test ---
        # Server uses Transfer-Encoding, backend uses Content-Length.
        # We send Transfer-Encoding: chunked but a Content-Length that is shorter
        # than the actual chunked body.
        self.console.print("\n[bold]TE.CL Smuggling Test[/bold]")
        try:
            # The chunked body is longer than what Content-Length claims
            te_cl_body = "1\r\nZ\r\n0\r\n\r\n"
            te_cl_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "3",
                "Transfer-Encoding": "chunked",
            }

            try:
                start = time.time()
                resp = self.session.post(
                    url,
                    data=te_cl_body,
                    headers=te_cl_headers,
                    timeout=10,
                )
                elapsed = time.time() - start
                te_cl_status = resp.status_code

                if te_cl_status != baseline_status and te_cl_status >= 400:
                    results.append(("TE.CL", f"HTTP {te_cl_status}", "medium",
                                    f"Status {te_cl_status} (baseline: {baseline_status}). Server may process conflicting headers differently."))
                    self._add_finding(
                        "medium", "HTTP Smuggling",
                        "Possible TE.CL request smuggling",
                        f"TE.CL probe returned HTTP {te_cl_status} (baseline: {baseline_status})",
                        url
                    )
                    self.console.print(f"  [yellow][!] TE.CL: Status difference detected ({te_cl_status} vs baseline {baseline_status})[/yellow]")
                elif elapsed - baseline_time > 2.5:
                    results.append(("TE.CL", f"Time delay: {elapsed:.2f}s", "medium",
                                    f"Response delayed ({elapsed:.2f}s vs baseline {baseline_time:.2f}s). Possible parsing conflict."))
                    self._add_finding(
                        "medium", "HTTP Smuggling",
                        "Possible TE.CL request smuggling (time-based)",
                        f"TE.CL probe response delayed by {elapsed - baseline_time:.2f}s",
                        url
                    )
                    self.console.print(f"  [yellow][!] TE.CL: Time delay detected ({elapsed:.2f}s vs baseline {baseline_time:.2f}s)[/yellow]")
                else:
                    self.console.print(f"  [dim]TE.CL: HTTP {te_cl_status} in {elapsed:.2f}s (no anomaly)[/dim]")

            except requests.exceptions.Timeout:
                results.append(("TE.CL", "Timeout", "medium",
                                "Request timed out. Frontend may have forwarded partial body to backend."))
                self._add_finding(
                    "medium", "HTTP Smuggling",
                    "Possible TE.CL request smuggling (timeout)",
                    "TE.CL probe caused a timeout, frontend may be processing differently",
                    url
                )
                self.console.print(f"  [yellow][!] TE.CL: Request timed out (possible smuggling indicator)[/yellow]")
            except Exception as e:
                self.console.print(f"  [dim]TE.CL test error: {e}[/dim]")

        except Exception as e:
            self.console.print(f"  [red]TE.CL test failed: {e}[/red]")

        # --- TE.TE Test (obfuscation) ---
        self.console.print("\n[bold]TE.TE Obfuscation Test[/bold]")
        te_obfuscations = [
            ("Transfer-Encoding: xchunked", {"Transfer-Encoding": "xchunked"}),
            ("Transfer-Encoding : chunked", {"Transfer-Encoding ": "chunked"}),
            ("Transfer-Encoding: chunked (extra space)", {"Transfer-Encoding": " chunked"}),
        ]

        for desc, extra_headers in te_obfuscations:
            try:
                test_headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "4",
                }
                test_headers.update(extra_headers)

                resp = self.session.post(url, data="x=1", headers=test_headers, timeout=10)
                if resp.status_code != baseline_status and resp.status_code >= 400:
                    results.append(("TE.TE", desc, "low",
                                    f"Status {resp.status_code} with obfuscated TE header (baseline: {baseline_status})"))
                    self._add_finding(
                        "low", "HTTP Smuggling",
                        f"TE header obfuscation response anomaly",
                        f"{desc} returned HTTP {resp.status_code} (baseline: {baseline_status})",
                        url
                    )
                    self.console.print(f"  [dim][!] {desc}: HTTP {resp.status_code}[/dim]")
            except Exception:
                pass

        # --- Display results ---
        if results:
            self.console.print("")
            table = Table(title="HTTP Smuggling Results", box=box.SIMPLE)
            table.add_column("Test", style="cyan")
            table.add_column("Observation", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("Detail", style="dim")

            for test_type, observation, sev, detail in results:
                if sev == "medium":
                    style = "yellow"
                elif sev == "low":
                    style = "dim"
                else:
                    style = "bold red"
                table.add_row(test_type, observation, f"[{style}]{sev.upper()}[/{style}]", detail)

            self.console.print(table)
            self.console.print("[dim]Note: HTTP smuggling detection is heuristic-based. Confirm findings with manual testing or dedicated tools (e.g., smuggler.py).[/dim]")
        else:
            self.console.print("\n[green]No HTTP request smuggling indicators found.[/green]")
            self.console.print("[dim]Note: Smuggling detection depends on the proxy/server architecture. Consider manual testing.[/dim]")

    # ------------------------------------------------------------------
    # WebSocket security check
    # ------------------------------------------------------------------
    def websocket_check(self, url: str):
        """Check for WebSocket security issues including CSWSH (Cross-Site WebSocket Hijacking)."""
        self.console.print(Panel(f"[bold]WebSocket Security Check: {url}[/bold]", border_style="cyan"))

        parsed = urlparse(url)
        results = []

        # Step 1: Check if the page references WebSocket endpoints
        self.console.print("[bold]Scanning Page for WebSocket References[/bold]")
        ws_endpoints = set()
        try:
            resp = self.session.get(url, timeout=10)
            body = resp.text

            # Look for ws:// or wss:// references
            ws_pattern = re.findall(r'(wss?://[^\s\'"<>]+)', body)
            for ws_url in ws_pattern:
                ws_endpoints.add(ws_url)
                self.console.print(f"  [cyan]Found WebSocket endpoint: {ws_url}[/cyan]")

            # Also look for common WebSocket JavaScript patterns
            ws_js_patterns = [
                r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'socket\.connect\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'io\.connect\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'io\s*\(\s*[\'"]([^\'"]+)[\'"]',
            ]
            for pattern in ws_js_patterns:
                matches = re.findall(pattern, body)
                for match in matches:
                    if match.startswith("ws://") or match.startswith("wss://"):
                        ws_endpoints.add(match)
                    elif match.startswith("/"):
                        # Relative path, construct full WebSocket URL
                        scheme = "wss" if parsed.scheme == "https" else "ws"
                        ws_full = f"{scheme}://{parsed.netloc}{match}"
                        ws_endpoints.add(ws_full)
                    elif not match.startswith("http"):
                        scheme = "wss" if parsed.scheme == "https" else "ws"
                        ws_full = f"{scheme}://{parsed.netloc}/{match}"
                        ws_endpoints.add(ws_full)

            if not ws_endpoints:
                self.console.print("[dim]No WebSocket references found in page source.[/dim]")

                # Try common WebSocket paths
                common_ws_paths = ["/ws", "/websocket", "/socket.io/", "/sockjs/", "/cable", "/hub"]
                scheme = "wss" if parsed.scheme == "https" else "ws"
                self.console.print("[dim]Probing common WebSocket paths...[/dim]")
                for ws_path in common_ws_paths:
                    ws_test_url = f"{scheme}://{parsed.netloc}{ws_path}"
                    # We can't directly connect with requests, so try HTTP upgrade
                    http_test_url = f"{parsed.scheme}://{parsed.netloc}{ws_path}"
                    try:
                        upgrade_headers = {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            "Sec-WebSocket-Version": "13",
                            "Origin": f"{parsed.scheme}://{parsed.netloc}",
                        }
                        probe_resp = self.session.get(http_test_url, headers=upgrade_headers, timeout=10, allow_redirects=False)
                        if probe_resp.status_code == 101:
                            ws_endpoints.add(ws_test_url)
                            self.console.print(f"  [cyan]WebSocket endpoint found: {ws_test_url} (HTTP 101 Upgrade)[/cyan]")
                        elif probe_resp.status_code == 400 and "upgrade" in probe_resp.text.lower():
                            ws_endpoints.add(ws_test_url)
                            self.console.print(f"  [cyan]Possible WebSocket endpoint: {ws_test_url} (HTTP 400 with upgrade hint)[/cyan]")
                    except Exception:
                        pass

        except Exception as e:
            self.console.print(f"[red]Error scanning for WebSocket references: {e}[/red]")
            return

        if not ws_endpoints:
            self.console.print("\n[green]No WebSocket endpoints detected.[/green]")
            return

        self.console.print(f"\n[dim]Found {len(ws_endpoints)} WebSocket endpoint(s) to test.[/dim]")

        # Step 2: Test each WebSocket endpoint
        for ws_url in ws_endpoints:
            self.console.print(f"\n[bold]Testing WebSocket: {ws_url}[/bold]")

            # Convert ws:// to http:// for upgrade request
            if ws_url.startswith("wss://"):
                http_url = "https://" + ws_url[6:]
            elif ws_url.startswith("ws://"):
                http_url = "http://" + ws_url[5:]
            else:
                http_url = ws_url

            # Step 2a: Test with correct Origin
            self.console.print("  [dim]Testing WebSocket upgrade with correct Origin...[/dim]")
            try:
                correct_origin = f"{parsed.scheme}://{parsed.netloc}"
                upgrade_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": correct_origin,
                }
                resp = self.session.get(http_url, headers=upgrade_headers, timeout=10, allow_redirects=False)
                correct_origin_status = resp.status_code
                ws_accept = resp.headers.get("Sec-WebSocket-Accept", "")

                self.console.print(f"    [dim]Correct Origin ({correct_origin}): HTTP {correct_origin_status}[/dim]")

                if ws_accept:
                    self.console.print(f"    [dim]Sec-WebSocket-Accept: {ws_accept}[/dim]")

                # Check response headers for security
                if correct_origin_status == 101:
                    self.console.print(f"    [green]WebSocket upgrade successful (HTTP 101)[/green]")

                    # Check for Sec-WebSocket-Accept header
                    if not ws_accept:
                        results.append((ws_url, "Missing Sec-WebSocket-Accept header", "low"))
                        self._add_finding(
                            "low", "WebSocket",
                            f"Missing Sec-WebSocket-Accept on {ws_url}",
                            "WebSocket upgrade response missing Sec-WebSocket-Accept header",
                            ws_url
                        )

            except Exception as e:
                self.console.print(f"    [dim]Correct Origin test error: {e}[/dim]")
                correct_origin_status = None

            # Step 2b: Test with malicious Origin (CSWSH check)
            self.console.print("  [dim]Testing WebSocket upgrade with malicious Origin (CSWSH)...[/dim]")
            try:
                evil_origin = "https://evil-attacker.com"
                evil_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": evil_origin,
                }
                resp = self.session.get(http_url, headers=evil_headers, timeout=10, allow_redirects=False)
                evil_origin_status = resp.status_code

                self.console.print(f"    [dim]Evil Origin ({evil_origin}): HTTP {evil_origin_status}[/dim]")

                if evil_origin_status == 101:
                    results.append((ws_url, "CSWSH: Accepts arbitrary Origin", "high"))
                    self._add_finding(
                        "high", "WebSocket",
                        f"Cross-Site WebSocket Hijacking (CSWSH) on {ws_url}",
                        f"WebSocket accepted connection from arbitrary Origin: {evil_origin}",
                        ws_url
                    )
                    self.console.print(f"    [bold red][!] CSWSH: Server accepts WebSocket from arbitrary Origin![/bold red]")
                elif correct_origin_status == 101 and evil_origin_status != 101:
                    self.console.print(f"    [green]Origin validation appears to be in place (rejected evil origin)[/green]")
                elif evil_origin_status == correct_origin_status:
                    # Both have the same non-101 status, might just not support WS
                    if evil_origin_status != 101:
                        self.console.print(f"    [dim]Both origins returned HTTP {evil_origin_status} (WebSocket may not be active)[/dim]")

            except Exception as e:
                self.console.print(f"    [dim]Evil Origin test error: {e}[/dim]")

            # Step 2c: Test with no Origin header
            self.console.print("  [dim]Testing WebSocket upgrade with no Origin header...[/dim]")
            try:
                no_origin_headers = {
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                }
                resp = self.session.get(http_url, headers=no_origin_headers, timeout=10, allow_redirects=False)
                no_origin_status = resp.status_code

                self.console.print(f"    [dim]No Origin: HTTP {no_origin_status}[/dim]")

                if no_origin_status == 101:
                    results.append((ws_url, "Accepts connections with no Origin header", "medium"))
                    self._add_finding(
                        "medium", "WebSocket",
                        f"WebSocket accepts no-Origin connections on {ws_url}",
                        "WebSocket endpoint does not require Origin header, potential CSWSH risk",
                        ws_url
                    )
                    self.console.print(f"    [yellow][!] Server accepts WebSocket without Origin header[/yellow]")

            except Exception as e:
                self.console.print(f"    [dim]No-Origin test error: {e}[/dim]")

            # Step 2d: Check if WSS is enforced (if the original page is HTTPS)
            if parsed.scheme == "https" and ws_url.startswith("ws://"):
                results.append((ws_url, "Unencrypted WebSocket (ws://) on HTTPS page", "medium"))
                self._add_finding(
                    "medium", "WebSocket",
                    f"Unencrypted WebSocket on HTTPS page",
                    f"WebSocket endpoint {ws_url} uses ws:// while the page uses HTTPS",
                    ws_url
                )
                self.console.print(f"  [yellow][!] Unencrypted ws:// used on HTTPS page[/yellow]")

        # --- Display results ---
        if results:
            self.console.print("")
            table = Table(title="WebSocket Security Results", box=box.SIMPLE)
            table.add_column("Endpoint", style="cyan")
            table.add_column("Finding", style="yellow")
            table.add_column("Severity", style="red")

            for endpoint, finding, sev in results:
                if sev == "high":
                    style = "bold red"
                elif sev == "medium":
                    style = "yellow"
                else:
                    style = "dim"
                table.add_row(endpoint, finding, f"[{style}]{sev.upper()}[/{style}]")

            self.console.print(table)
        else:
            self.console.print("\n[green]No WebSocket security issues found.[/green]")

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
            self.blind_sqli_check(url)
            self.stored_xss_check(url)
            self.ssrf_check(url)
            self.http_smuggling_check(url)
            self.websocket_check(url)

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
        table.add_row("7", "Blind SQL Injection Check")
        table.add_row("8", "Stored XSS Check")
        table.add_row("9", "SSRF Detection Check")
        table.add_row("10", "HTTP Request Smuggling Check")
        table.add_row("11", "WebSocket Security Check")
        table.add_row("12", "Run ALL Web Tests")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"])

        actions = {
            "1": lambda: self.discover_forms(url),
            "2": lambda: self.xss_check(url),
            "3": lambda: self.sqli_check(url),
            "4": lambda: self.csrf_check(url),
            "5": lambda: self.directory_traversal_check(url),
            "6": lambda: self.crawl_links(url),
            "7": lambda: self.blind_sqli_check(url),
            "8": lambda: self.stored_xss_check(url),
            "9": lambda: self.ssrf_check(url),
            "10": lambda: self.http_smuggling_check(url),
            "11": lambda: self.websocket_check(url),
            "12": lambda: self.run(url, full=True),
        }

        action = actions.get(choice)
        if action:
            action()
