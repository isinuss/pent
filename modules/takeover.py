"""
Subdomain Takeover Detection Module.

Checks discovered subdomains for dangling DNS records that could
allow subdomain takeover via unclaimed cloud services.
"""

import socket
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# Fingerprints: (service_name, cname_patterns, response_fingerprints)
TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cnames": ["github.io", "github.map.fastly.net"],
        "fingerprints": ["There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/)"],
        "status": [404],
    },
    {
        "service": "Heroku",
        "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": ["No such app", "no-such-app.herokuapp.com", "herokucdn.com/error-pages"],
        "status": [404],
    },
    {
        "service": "AWS S3",
        "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": [404],
    },
    {
        "service": "AWS CloudFront",
        "cnames": ["cloudfront.net"],
        "fingerprints": ["Bad request", "ERROR: The request could not be satisfied"],
        "status": [403, 502],
    },
    {
        "service": "Azure",
        "cnames": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                    "trafficmanager.net", "blob.core.windows.net", "azure-api.net",
                    "azurehdinsight.net", "azureedge.net", "azurecontainer.io"],
        "fingerprints": ["404 Web Site not found", "Azure Web App - Your web app is running"],
        "status": [404],
    },
    {
        "service": "Shopify",
        "cnames": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "only-resolve-dns-if-you-are-]"],
        "status": [404],
    },
    {
        "service": "Fastly",
        "cnames": ["fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "status": [500],
    },
    {
        "service": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "fingerprints": ["404 error unknown site", "The gods are wise"],
        "status": [404],
    },
    {
        "service": "Tumblr",
        "cnames": ["domains.tumblr.com"],
        "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
        "status": [404],
    },
    {
        "service": "WordPress.com",
        "cnames": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "status": [404],
    },
    {
        "service": "Surge.sh",
        "cnames": ["surge.sh"],
        "fingerprints": ["project not found"],
        "status": [404],
    },
    {
        "service": "Zendesk",
        "cnames": ["zendesk.com"],
        "fingerprints": ["Help Center Closed"],
        "status": [404],
    },
    {
        "service": "Unbounce",
        "cnames": ["unbouncepages.com"],
        "fingerprints": ["The requested URL was not found on this server"],
        "status": [404],
    },
    {
        "service": "HubSpot",
        "cnames": ["sites.hubspot.net"],
        "fingerprints": ["Domain not found"],
        "status": [404],
    },
    {
        "service": "Ghost",
        "cnames": ["ghost.io"],
        "fingerprints": ["Domain is not configured"],
        "status": [404],
    },
    {
        "service": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
        "status": [404],
    },
    {
        "service": "Fly.io",
        "cnames": ["fly.dev"],
        "fingerprints": ["404 Not Found"],
        "status": [404],
    },
    {
        "service": "Vercel",
        "cnames": ["vercel.app", "now.sh"],
        "fingerprints": ["The deployment could not be found"],
        "status": [404],
    },
    {
        "service": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "fingerprints": ["404 Not Found"],
        "status": [404],
    },
]


class TakeoverModule:
    """Detect potential subdomain takeover vulnerabilities."""

    def __init__(self, console: Console):
        self.console = console
        self.findings = []

    def _add_finding(self, severity: str, subdomain: str, service: str, detail: str):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": "Subdomain Takeover",
            "title": f"Potential takeover: {subdomain} ({service})",
            "detail": detail,
        })

    def _get_cname(self, subdomain: str) -> str:
        """Resolve CNAME record for a subdomain."""
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(subdomain, "CNAME")
                for rdata in answers:
                    return str(rdata.target).rstrip(".")
            except Exception:
                return ""
        else:
            # Fallback: use socket
            try:
                result = socket.getaddrinfo(subdomain, None)
                if result:
                    return result[0][4][0]
            except Exception:
                return ""
        return ""

    def _check_nxdomain(self, subdomain: str) -> bool:
        """Check if a subdomain returns NXDOMAIN."""
        if HAS_DNS:
            try:
                dns.resolver.resolve(subdomain, "A")
                return False
            except dns.resolver.NXDOMAIN:
                return True
            except Exception:
                return False
        else:
            try:
                socket.gethostbyname(subdomain)
                return False
            except socket.gaierror:
                return True

    def _check_http_fingerprint(self, subdomain: str, fingerprint: dict) -> bool:
        """Check if HTTP response matches takeover fingerprint."""
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=10,
                    allow_redirects=False,
                    verify=False,
                )
                # Check status code
                if fingerprint["status"] and resp.status_code in fingerprint["status"]:
                    # Check body fingerprint
                    body = resp.text
                    for fp in fingerprint["fingerprints"]:
                        if fp in body:
                            return True
            except Exception:
                continue
        return False

    def check_subdomain(self, subdomain: str) -> dict:
        """Check a single subdomain for takeover vulnerability."""
        result = {
            "subdomain": subdomain,
            "cname": "",
            "vulnerable": False,
            "service": "",
            "evidence": "",
        }

        # Get CNAME
        cname = self._get_cname(subdomain)
        result["cname"] = cname

        if not cname:
            # Check for dangling A record (NXDOMAIN)
            if self._check_nxdomain(subdomain):
                result["evidence"] = "NXDOMAIN - DNS record exists but doesn't resolve"
            return result

        # Match CNAME against known takeover fingerprints
        cname_lower = cname.lower()
        for fingerprint in TAKEOVER_FINGERPRINTS:
            for pattern in fingerprint["cnames"]:
                if pattern in cname_lower:
                    # CNAME matches a known service - check HTTP fingerprint
                    if self._check_http_fingerprint(subdomain, fingerprint):
                        result["vulnerable"] = True
                        result["service"] = fingerprint["service"]
                        result["evidence"] = (
                            f"CNAME points to {cname} ({fingerprint['service']}) "
                            f"and HTTP response matches takeover fingerprint"
                        )
                    else:
                        result["service"] = fingerprint["service"]
                        result["evidence"] = f"CNAME points to {cname} ({fingerprint['service']}) - verify manually"
                    break
            if result["service"]:
                break

        return result

    def check_subdomains(self, subdomains: list):
        """Check a list of subdomains for takeover vulnerabilities."""
        self.console.print(Panel(
            f"[bold]Subdomain Takeover Check ({len(subdomains)} targets)[/bold]",
            border_style="cyan"
        ))

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        table = Table(title="Takeover Analysis", box=box.SIMPLE)
        table.add_column("Subdomain", style="cyan")
        table.add_column("CNAME", style="dim")
        table.add_column("Service", style="yellow")
        table.add_column("Status", style="white")

        vulnerable_count = 0
        for i, sub in enumerate(subdomains):
            self.console.print(f"[dim]  [{i+1}/{len(subdomains)}] Checking {sub}...[/dim]", end="\r")
            result = self.check_subdomain(sub)

            if result["vulnerable"]:
                vulnerable_count += 1
                table.add_row(
                    sub,
                    result["cname"],
                    result["service"],
                    "[bold red]VULNERABLE[/bold red]",
                )
                self._add_finding("high", sub, result["service"], result["evidence"])
            elif result["service"]:
                table.add_row(
                    sub,
                    result["cname"],
                    result["service"],
                    "[yellow]CHECK MANUALLY[/yellow]",
                )
                self._add_finding("low", sub, result["service"], result["evidence"])
            elif result["evidence"]:
                table.add_row(sub, result["cname"], "N/A", f"[dim]{result['evidence']}[/dim]")

        self.console.print(table)

        if vulnerable_count:
            self.console.print(f"\n[bold red][!] {vulnerable_count} potential takeover(s) found![/bold red]")
        else:
            self.console.print("\n[green][+] No obvious takeover vulnerabilities detected.[/green]")

        return self.findings

    def interactive(self, target: str):
        """Interactive takeover check."""
        self.console.print(Panel("[bold]Subdomain Takeover Checker[/bold]", border_style="cyan"))
        self.console.print("[dim]Enter subdomains one per line (empty line to finish):[/dim]")

        subdomains = []
        while True:
            sub = Prompt.ask("[cyan]Subdomain[/cyan] (or 'done')", default="done")
            if sub.lower() == "done":
                break
            subdomains.append(sub.strip())

        if not subdomains:
            # Try auto-discovery using crt.sh
            from modules.recon import ReconModule
            recon = ReconModule(self.console)
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            subdomains = recon.subdomain_enum(domain)

        if subdomains:
            self.check_subdomains(subdomains)
        else:
            self.console.print("[yellow]No subdomains to check.[/yellow]")
