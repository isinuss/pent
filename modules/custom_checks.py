"""
Custom Checks Engine - Define and run YAML-based security checks.

Lets users create reusable check templates (similar to nuclei templates)
that can be shared, version-controlled, and customized.
"""

import os
import re
import json
from datetime import datetime
from urllib.parse import urljoin

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ------------------------------------------------------------------
# Built-in checks (no YAML dependency needed)
# ------------------------------------------------------------------
BUILTIN_CHECKS = [
    {
        "id": "exposed-env",
        "name": "Exposed .env File",
        "severity": "high",
        "description": "Checks if .env file is publicly accessible",
        "method": "GET",
        "paths": ["/.env", "/.env.local", "/.env.production", "/.env.backup"],
        "matchers": {
            "status": [200],
            "body_contains": ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "AWS_"],
        },
    },
    {
        "id": "exposed-git",
        "name": "Exposed Git Directory",
        "severity": "high",
        "description": "Checks if .git directory is publicly accessible",
        "method": "GET",
        "paths": ["/.git/config", "/.git/HEAD"],
        "matchers": {
            "status": [200],
            "body_contains": ["[core]", "ref: refs/"],
        },
    },
    {
        "id": "exposed-svn",
        "name": "Exposed SVN Directory",
        "severity": "high",
        "description": "Checks if .svn directory is publicly accessible",
        "method": "GET",
        "paths": ["/.svn/entries", "/.svn/wc.db"],
        "matchers": {
            "status": [200],
            "body_contains": ["svn", "dir"],
        },
    },
    {
        "id": "directory-listing",
        "name": "Directory Listing Enabled",
        "severity": "medium",
        "description": "Checks for enabled directory listing",
        "method": "GET",
        "paths": ["/", "/images/", "/uploads/", "/static/", "/assets/", "/backup/", "/temp/"],
        "matchers": {
            "status": [200],
            "body_contains": ["Index of /", "Directory listing", "<title>Index of"],
        },
    },
    {
        "id": "phpinfo",
        "name": "Exposed phpinfo()",
        "severity": "medium",
        "description": "Checks for publicly accessible phpinfo pages",
        "method": "GET",
        "paths": ["/phpinfo.php", "/info.php", "/test.php", "/i.php", "/pi.php"],
        "matchers": {
            "status": [200],
            "body_contains": ["phpinfo()", "PHP Version", "PHP License"],
        },
    },
    {
        "id": "debug-endpoints",
        "name": "Debug Endpoints Exposed",
        "severity": "high",
        "description": "Checks for exposed debug and monitoring endpoints",
        "method": "GET",
        "paths": [
            "/debug/", "/_debug/", "/trace", "/console",
            "/actuator", "/actuator/env", "/actuator/heapdump",
            "/actuator/mappings", "/actuator/configprops",
            "/elmah.axd", "/_profiler/", "/silk/",
        ],
        "matchers": {
            "status": [200],
            "body_not_contains": ["404", "Not Found", "Access Denied"],
        },
    },
    {
        "id": "wordpress-user-enum",
        "name": "WordPress User Enumeration",
        "severity": "medium",
        "description": "Checks if WordPress users can be enumerated via REST API",
        "method": "GET",
        "paths": ["/wp-json/wp/v2/users", "/?author=1"],
        "matchers": {
            "status": [200],
            "body_contains": ["slug", "name", "author"],
        },
    },
    {
        "id": "default-creds-pages",
        "name": "Default Admin Panels",
        "severity": "low",
        "description": "Checks for common admin/login pages",
        "method": "GET",
        "paths": [
            "/admin/", "/admin/login", "/administrator/",
            "/manager/html", "/jmx-console/", "/web-console/",
            "/phpmyadmin/", "/pma/", "/adminer.php",
        ],
        "matchers": {
            "status": [200, 401, 403],
            "body_not_contains": ["404", "Not Found"],
        },
    },
    {
        "id": "cors-wildcard",
        "name": "CORS Wildcard",
        "severity": "high",
        "description": "Checks for overly permissive CORS configuration",
        "method": "GET",
        "paths": ["/", "/api/", "/api/v1/"],
        "headers": {"Origin": "https://evil-attacker.com"},
        "matchers": {
            "status": [200],
            "header_contains": {"Access-Control-Allow-Origin": ["*", "evil-attacker.com"]},
        },
    },
    {
        "id": "open-api-docs",
        "name": "Exposed API Documentation",
        "severity": "low",
        "description": "Checks for publicly accessible API documentation",
        "method": "GET",
        "paths": [
            "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
            "/swagger-ui/", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/redoc", "/graphql", "/graphiql",
        ],
        "matchers": {
            "status": [200],
            "body_contains": ["swagger", "openapi", "paths", "graphql"],
        },
    },
    {
        "id": "backup-files",
        "name": "Backup Files Exposed",
        "severity": "high",
        "description": "Checks for publicly accessible backup files",
        "method": "GET",
        "paths": [
            "/backup.sql", "/backup.zip", "/backup.tar.gz",
            "/db.sql", "/dump.sql", "/database.sql",
            "/site.zip", "/www.zip", "/public.zip",
        ],
        "matchers": {
            "status": [200],
            "min_content_length": 1000,
        },
    },
    {
        "id": "source-maps",
        "name": "JavaScript Source Maps Exposed",
        "severity": "low",
        "description": "Checks if JS source maps are publicly accessible (may reveal original source code)",
        "method": "GET",
        "paths": ["/main.js.map", "/app.js.map", "/bundle.js.map", "/vendor.js.map"],
        "matchers": {
            "status": [200],
            "body_contains": ["mappings", "sources", "sourcesContent"],
        },
    },
]


class CustomChecksModule:
    """Run built-in or custom YAML-based security checks."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _add_finding(self, severity: str, check_id: str, title: str, detail: str, url: str = ""):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": "Custom Check",
            "check_id": check_id,
            "title": title,
            "detail": detail,
            "url": url,
        })

    def _match_response(self, resp: requests.Response, matchers: dict) -> bool:
        """Check if a response matches the defined matchers."""

        # Status code match
        if "status" in matchers:
            if resp.status_code not in matchers["status"]:
                return False

        # Body contains
        if "body_contains" in matchers:
            body = resp.text
            if not any(pattern.lower() in body.lower() for pattern in matchers["body_contains"]):
                return False

        # Body NOT contains (all must be absent)
        if "body_not_contains" in matchers:
            body = resp.text
            if any(pattern.lower() in body.lower() for pattern in matchers["body_not_contains"]):
                return False

        # Header contains
        if "header_contains" in matchers:
            for header_name, patterns in matchers["header_contains"].items():
                header_val = resp.headers.get(header_name, "").lower()
                if not any(p.lower() in header_val for p in patterns):
                    return False

        # Minimum content length
        if "min_content_length" in matchers:
            if len(resp.content) < matchers["min_content_length"]:
                return False

        # Regex match
        if "body_regex" in matchers:
            body = resp.text
            if not any(re.search(pattern, body) for pattern in matchers["body_regex"]):
                return False

        return True

    def run_check(self, target: str, check: dict) -> list:
        """Run a single check against a target."""
        results = []

        if not target.startswith("http"):
            target = f"https://{target}"

        base = target.rstrip("/")
        method = check.get("method", "GET").upper()
        extra_headers = check.get("headers", {})

        for path in check.get("paths", ["/"]):
            url = base + path
            try:
                if method == "GET":
                    resp = self.session.get(url, headers=extra_headers, timeout=10, allow_redirects=False)
                elif method == "POST":
                    resp = self.session.post(url, headers=extra_headers, timeout=10, allow_redirects=False, data=check.get("body", ""))
                else:
                    continue

                if self._match_response(resp, check.get("matchers", {})):
                    results.append({
                        "check_id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "path": path,
                        "url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    })

            except Exception:
                pass

        return results

    def run_all_builtin(self, target: str):
        """Run all built-in checks against a target."""
        self.console.print(Panel(
            f"[bold]Custom Security Checks: {target}[/bold]\n"
            f"[dim]Running {len(BUILTIN_CHECKS)} built-in checks...[/dim]",
            border_style="cyan",
        ))

        all_results = []
        for i, check in enumerate(BUILTIN_CHECKS):
            self.console.print(f"  [dim][{i+1}/{len(BUILTIN_CHECKS)}] {check['name']}...[/dim]", end="\r")
            results = self.run_check(target, check)
            all_results.extend(results)

        self.console.print(" " * 60)  # Clear the progress line

        if all_results:
            table = Table(title=f"Check Results ({len(all_results)} hits)", box=box.SIMPLE)
            table.add_column("Severity", style="white", width=10)
            table.add_column("Check", style="cyan")
            table.add_column("Path", style="yellow")
            table.add_column("Status", style="dim")

            for r in all_results:
                sev = r["severity"]
                style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(sev, "dim")
                table.add_row(
                    f"[{style}]{sev.upper()}[/{style}]",
                    r["name"],
                    r["path"],
                    str(r["status_code"]),
                )
                self._add_finding(
                    sev, r["check_id"], r["name"],
                    f"Path: {r['path']} (Status: {r['status_code']}, Size: {r['content_length']})",
                    r["url"]
                )

            self.console.print(table)
        else:
            self.console.print("[green]No issues found with built-in checks.[/green]")

        return self.findings

    def load_yaml_checks(self, directory: str) -> list:
        """Load custom check definitions from YAML files."""
        if not HAS_YAML:
            self.console.print("[yellow]PyYAML not installed. Run: pip install pyyaml[/yellow]")
            return []

        checks = []
        if not os.path.isdir(directory):
            self.console.print(f"[yellow]Directory not found: {directory}[/yellow]")
            return []

        for filename in os.listdir(directory):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath) as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data:
                        checks.append(data)
                    elif isinstance(data, list):
                        checks.extend(data)
                except Exception as e:
                    self.console.print(f"[yellow]Error loading {filename}: {e}[/yellow]")

        return checks

    def run_custom_checks(self, target: str, check_dir: str):
        """Run custom YAML-based checks."""
        checks = self.load_yaml_checks(check_dir)
        if not checks:
            self.console.print("[yellow]No custom checks found.[/yellow]")
            return

        self.console.print(Panel(
            f"[bold]Custom Checks: {target}[/bold]\n"
            f"[dim]Running {len(checks)} custom checks from {check_dir}[/dim]",
            border_style="cyan",
        ))

        all_results = []
        for check in checks:
            results = self.run_check(target, check)
            all_results.extend(results)

        if all_results:
            for r in all_results:
                self.console.print(
                    f"  [{r['severity'].upper()}] {r['name']} - {r['path']} (Status: {r['status_code']})"
                )
        else:
            self.console.print("[green]No issues found with custom checks.[/green]")

    # ------------------------------------------------------------------
    # Interactive
    # ------------------------------------------------------------------
    def interactive(self, target: str):
        """Interactive custom checks menu."""
        table = Table(title="Custom Checks Options", box=box.ROUNDED, show_header=False)
        table.add_column("Option", style="bold yellow", width=4)
        table.add_column("Name", style="white")

        table.add_row("1", f"Run all built-in checks ({len(BUILTIN_CHECKS)} checks)")
        table.add_row("2", "Run custom YAML checks from directory")
        table.add_row("3", "List built-in checks")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3"])

        if choice == "1":
            self.run_all_builtin(target)
        elif choice == "2":
            check_dir = Prompt.ask("Custom checks directory", default="templates")
            self.run_custom_checks(target, check_dir)
        elif choice == "3":
            tbl = Table(title="Built-in Checks", box=box.SIMPLE)
            tbl.add_column("ID", style="cyan")
            tbl.add_column("Name", style="white")
            tbl.add_column("Severity", style="yellow")
            tbl.add_column("Paths", style="dim")
            for c in BUILTIN_CHECKS:
                sev = c["severity"]
                style = {"high": "red", "medium": "yellow", "low": "green"}.get(sev, "dim")
                tbl.add_row(
                    c["id"], c["name"],
                    f"[{style}]{sev.upper()}[/{style}]",
                    str(len(c["paths"])) + " paths",
                )
            self.console.print(tbl)
