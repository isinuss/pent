"""
JavaScript Analysis Module - Extract endpoints, secrets, and interesting
data from JavaScript files found on the target.
"""

import re
import math
import json as _json
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


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


class JSAnalyzerModule:
    """Analyze JavaScript files for endpoints, secrets, and interesting data."""

    # Patterns considered structural matches (format alone is strong signal)
    _STRUCTURAL_PATTERNS = {
        "AWS Access Key",
        "GitHub Token",
        "Slack Token",
        "Slack Webhook",
        "Stripe Key",
        "SendGrid",
        "JWT Token",
        "Private Key",
        "Database URL",
        "DigitalOcean Token",
        "Mapbox Token",
        "Discord Webhook",
        "Telegram Bot Token",
        "Azure Storage Key",
        "HashiCorp Vault Token",
        "npm Token",
        "PyPI Token",
    }

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
            # -- Expanded secret patterns --
            ("Datadog API Key", r'(?:datadog|dd)[_-]?(?:api[_-]?key|app[_-]?key)\s*[:=]\s*["\']([a-f0-9]{32})["\']'),
            ("New Relic Key", r'(?:NRAK|NRIQ|NRII)-[A-Za-z0-9]{27}'),
            ("Cloudflare API", r'(?:cloudflare|cf)[_-]?(?:api[_-]?key|token)\s*[:=]\s*["\']([a-zA-Z0-9_-]{37,})["\']'),
            ("DigitalOcean Token", r'dop_v1_[a-f0-9]{64}'),
            ("Mapbox Token", r'(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            ("Discord Token", r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
            ("Discord Webhook", r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'),
            ("Telegram Bot Token", r'[0-9]+:AA[0-9A-Za-z_-]{33}'),
            ("Azure Storage Key", r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
            ("HashiCorp Vault Token", r'(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}'),
            ("npm Token", r'npm_[A-Za-z0-9]{36}'),
            ("PyPI Token", r'pypi-AgE[A-Za-z0-9_-]{50,}'),
        ]

        for name, pattern in secret_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Avoid false positives
                if isinstance(match, str) and len(match) > 200:
                    continue

                val = match if isinstance(match, str) else str(match)

                # Entropy-based filtering
                entropy = _shannon_entropy(val)
                is_structural = name in self._STRUCTURAL_PATTERNS

                if entropy < 3.5 and not is_structural:
                    # Low entropy and not a structural pattern -- likely a false positive
                    continue

                # Mask the secret for display
                if len(val) > 12:
                    masked = val[:6] + "..." + val[-4:]
                else:
                    masked = val[:3] + "***"

                secrets.append({
                    "type": name,
                    "value_masked": masked,
                    "entropy": round(entropy, 2),
                    "source": source_file,
                })

        return secrets

    # ------------------------------------------------------------------
    # Live secret validation (non-destructive, read-only checks)
    # ------------------------------------------------------------------
    def validate_secret(self, secret_type: str, value: str) -> dict:
        """
        Attempt to validate if a detected secret is actually active/live.

        Only performs non-destructive, read-only checks. Returns a dict
        with keys: validated (bool), active (bool), reason (str).
        """
        result = {"validated": False, "active": False, "reason": "No validator available"}

        try:
            if secret_type == "AWS Access Key":
                # Need both access key and secret key for AWS validation.
                # Attempt using boto3 if available.
                try:
                    import boto3
                    from botocore.exceptions import ClientError, NoCredentialsError
                    # value is expected to be "ACCESS_KEY:SECRET_KEY" for full validation
                    if ":" in value:
                        access_key, secret_key = value.split(":", 1)
                    else:
                        return {"validated": False, "active": False, "reason": "Need SECRET_KEY to validate (pass as ACCESS_KEY:SECRET_KEY)"}
                    client = boto3.client(
                        "sts",
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name="us-east-1",
                    )
                    identity = client.get_caller_identity()
                    return {
                        "validated": True,
                        "active": True,
                        "reason": f"Key is active. Account: {identity.get('Account', 'unknown')}",
                    }
                except ImportError:
                    return {"validated": False, "active": False, "reason": "boto3 not installed, skipping AWS validation"}
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                        return {"validated": True, "active": False, "reason": f"Key is invalid or inactive: {error_code}"}
                    return {"validated": True, "active": False, "reason": f"AWS error: {error_code}"}
                except Exception as e:
                    return {"validated": False, "active": False, "reason": f"AWS validation error: {e}"}

            elif secret_type == "GitHub Token":
                resp = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {value}"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    username = resp.json().get("login", "unknown")
                    return {"validated": True, "active": True, "reason": f"Token is active. User: {username}"}
                elif resp.status_code == 401:
                    return {"validated": True, "active": False, "reason": "Token is invalid or expired (401)"}
                else:
                    return {"validated": True, "active": False, "reason": f"Unexpected status: {resp.status_code}"}

            elif secret_type == "Slack Token":
                resp = requests.get(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {value}"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        return {"validated": True, "active": True, "reason": f"Token is active. Team: {data.get('team', 'unknown')}"}
                    else:
                        return {"validated": True, "active": False, "reason": f"Token invalid: {data.get('error', 'unknown')}"}
                else:
                    return {"validated": True, "active": False, "reason": f"Unexpected status: {resp.status_code}"}

            elif secret_type == "Stripe Key":
                resp = requests.get(
                    "https://api.stripe.com/v1/charges?limit=1",
                    auth=(value, ""),
                    timeout=5,
                )
                if resp.status_code == 200:
                    return {"validated": True, "active": True, "reason": "Stripe key is active"}
                elif resp.status_code == 401:
                    return {"validated": True, "active": False, "reason": "Stripe key is invalid (401)"}
                else:
                    return {"validated": True, "active": False, "reason": f"Unexpected status: {resp.status_code}"}

            elif secret_type == "Google API Key":
                resp = requests.get(
                    f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={value}",
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {"validated": True, "active": True, "reason": f"Token is active. Scope: {data.get('scope', 'unknown')}"}
                elif resp.status_code in (400, 401):
                    return {"validated": True, "active": False, "reason": "Token is invalid or expired"}
                else:
                    return {"validated": True, "active": False, "reason": f"Unexpected status: {resp.status_code}"}

        except requests.exceptions.Timeout:
            result = {"validated": False, "active": False, "reason": "Validation request timed out"}
        except requests.exceptions.ConnectionError:
            result = {"validated": False, "active": False, "reason": "Connection error during validation"}
        except Exception as e:
            result = {"validated": False, "active": False, "reason": f"Validation error: {e}"}

        return result

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
    # Source map parsing
    # ------------------------------------------------------------------
    def parse_source_maps(self, url: str) -> list:
        """
        Discover and parse JavaScript source maps.

        For each discovered JS file, checks for a corresponding .map file and
        for sourceMappingURL comments. If a source map is found, parses the
        JSON to extract original source file paths and searches sourcesContent
        for secrets.

        Returns a list of source map URLs found.
        """
        source_map_urls = []

        try:
            js_files = self.discover_js_files(url)
        except Exception as e:
            self.console.print(f"[red]Error discovering JS files for source maps: {e}[/red]")
            return source_map_urls

        for js_url in js_files:
            try:
                resp = self.session.get(js_url, timeout=15)
                js_content = resp.text

                map_urls_to_check = []

                # Strategy 1: Look for sourceMappingURL comment in the JS source
                mapping_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_content)
                if mapping_match:
                    raw_map_url = mapping_match.group(1).strip()
                    resolved_map_url = urljoin(js_url, raw_map_url)
                    map_urls_to_check.append(resolved_map_url)

                # Strategy 2: Try appending .map to the JS URL
                guessed_map_url = js_url + ".map"
                if guessed_map_url not in map_urls_to_check:
                    map_urls_to_check.append(guessed_map_url)

                for map_url in map_urls_to_check:
                    try:
                        map_resp = self.session.get(map_url, timeout=10)
                        if map_resp.status_code != 200:
                            continue

                        # Verify it looks like JSON before parsing
                        content_type = map_resp.headers.get("Content-Type", "")
                        body = map_resp.text.strip()
                        if not (body.startswith("{") or "application/json" in content_type):
                            continue

                        try:
                            source_map = _json.loads(body)
                        except _json.JSONDecodeError:
                            continue

                        if not isinstance(source_map, dict):
                            continue

                        # Successfully found a source map
                        if map_url not in source_map_urls:
                            source_map_urls.append(map_url)

                        self.console.print(f"[yellow][!] Source map found: {map_url}[/yellow]")

                        # Flag source map availability as a medium-severity finding
                        self._add_finding(
                            "medium",
                            "Source Map",
                            f"Source map exposed: {map_url}",
                            "Source maps expose original source code and internal directory structure.",
                            map_url,
                        )

                        # Extract original source file paths (reveals internal directory structure)
                        sources = source_map.get("sources", [])
                        if sources:
                            self.console.print(f"  [cyan]Original source paths ({len(sources)}):[/cyan]")
                            for src_path in sources[:25]:
                                self.console.print(f"    [dim]{src_path}[/dim]")
                                self._add_finding(
                                    "low",
                                    "Source Map Path",
                                    f"Internal path disclosed: {src_path}",
                                    f"Source map reveals internal file path: {src_path}",
                                    map_url,
                                )
                            if len(sources) > 25:
                                self.console.print(f"    [dim]... and {len(sources) - 25} more paths[/dim]")

                        # Search sourcesContent for secrets
                        sources_content = source_map.get("sourcesContent", [])
                        if sources_content:
                            self.console.print(f"  [cyan]Scanning {len(sources_content)} source files for secrets...[/cyan]")
                            for idx, src_content in enumerate(sources_content):
                                if not src_content or not isinstance(src_content, str):
                                    continue
                                source_name = sources[idx] if idx < len(sources) else f"source[{idx}]"
                                found_secrets = self.extract_secrets(src_content, source_file=f"{map_url} -> {source_name}")
                                for secret in found_secrets:
                                    self.console.print(
                                        f"    [red][!] Secret in source map content: {secret['type']} "
                                        f"(entropy: {secret['entropy']}) in {source_name}[/red]"
                                    )
                                    self._add_finding(
                                        "high",
                                        "Source Map Secret",
                                        f"{secret['type']} found in source map content",
                                        f"Masked: {secret['value_masked']} (entropy: {secret['entropy']})",
                                        f"{map_url} -> {source_name}",
                                    )

                        # Found a valid map for this JS file, skip remaining candidates
                        break

                    except requests.exceptions.Timeout:
                        self.console.print(f"  [dim]Timeout checking {map_url}[/dim]")
                    except requests.exceptions.ConnectionError:
                        pass
                    except Exception as e:
                        self.console.print(f"  [dim]Error checking {map_url}: {e}[/dim]")

            except requests.exceptions.Timeout:
                self.console.print(f"[dim]Timeout fetching {js_url}[/dim]")
            except Exception as e:
                self.console.print(f"[dim]Error processing {js_url} for source maps: {e}[/dim]")

        return source_map_urls

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
            table.add_column("Entropy", style="magenta")
            table.add_column("Source", style="dim", max_width=50)

            for s in all_secrets:
                table.add_row(s["type"], s["value_masked"], str(s["entropy"]), s["source"].split("/")[-1])
                self._add_finding(
                    "high", "JS Secret", f"{s['type']} found in JS",
                    f"Masked: {s['value_masked']} (entropy: {s['entropy']})", s["source"]
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

        # Phase: Source map analysis
        self.console.print(Panel("[bold]Source Map Analysis[/bold]", border_style="cyan"))
        source_maps = self.parse_source_maps(url)
        if source_maps:
            self.console.print(f"[yellow][!] Found {len(source_maps)} source maps — internal code may be exposed.[/yellow]")

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
        table.add_row("4", "Source map analysis")
        table.add_row("5", "Validate a secret (live check)")
        table.add_row("0", "Back to main menu")

        self.console.print(table)

        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5"])

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
                    self.console.print(f"  [red]{s['type']}: {s['value_masked']} (entropy: {s['entropy']})[/red]")
        elif choice == "4":
            self.console.print(Panel("[bold]Source Map Analysis[/bold]", border_style="cyan"))
            source_maps = self.parse_source_maps(target)
            if source_maps:
                self.console.print(f"\n[yellow][!] Found {len(source_maps)} source maps:[/yellow]")
                for sm_url in source_maps:
                    self.console.print(f"  [yellow]{sm_url}[/yellow]")
            else:
                self.console.print("[green]No source maps found.[/green]")
        elif choice == "5":
            secret_type = Prompt.ask("Secret type (e.g. GitHub Token, AWS Access Key, Slack Token, Stripe Key, Google API Key)")
            secret_value = Prompt.ask("Secret value (will be used for validation only)")
            self.console.print("[dim]Validating secret (read-only check)...[/dim]")
            result = self.validate_secret(secret_type, secret_value)
            if result["validated"]:
                if result["active"]:
                    self.console.print(f"[bold red][!] SECRET IS ACTIVE: {result['reason']}[/bold red]")
                else:
                    self.console.print(f"[green]Secret is not active: {result['reason']}[/green]")
            else:
                self.console.print(f"[yellow]Could not validate: {result['reason']}[/yellow]")
