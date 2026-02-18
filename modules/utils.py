"""
Utility helpers - Shared functionality across modules.
"""

import re
import time
import socket
from urllib.parse import urlparse
from functools import wraps

from rich.console import Console
from rich.panel import Panel


def validate_target(target: str) -> dict:
    """Validate and normalize a target string. Returns parsed info."""
    result = {
        "original": target,
        "domain": "",
        "ip": "",
        "url": "",
        "scheme": "https",
        "port": None,
        "valid": False,
        "type": "unknown",
    }

    target = target.strip()

    # Check if it's a URL
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        result["url"] = target
        result["domain"] = parsed.hostname or ""
        result["scheme"] = parsed.scheme
        result["port"] = parsed.port
        result["type"] = "url"
        result["valid"] = bool(result["domain"])
        return result

    # Check if it's an IP address
    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    if ip_pattern.match(target):
        result["ip"] = target
        result["domain"] = target
        result["url"] = f"https://{target}"
        result["type"] = "ip"
        result["valid"] = True
        return result

    # Check for port notation (domain:port)
    if ":" in target and not target.startswith("["):
        host, _, port_str = target.rpartition(":")
        if port_str.isdigit():
            result["port"] = int(port_str)
            target = host

    # Treat as domain
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_pattern.match(target):
        result["domain"] = target
        result["url"] = f"https://{target}"
        result["type"] = "domain"
        result["valid"] = True
        return result

    # Last resort - try to resolve it
    try:
        socket.getaddrinfo(target, None)
        result["domain"] = target
        result["url"] = f"https://{target}"
        result["type"] = "hostname"
        result["valid"] = True
    except socket.gaierror:
        result["valid"] = False

    return result


def rate_limit(min_interval: float = 0.5):
    """Decorator to enforce minimum time between calls (be nice to targets)."""
    last_call = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_call[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            last_call[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def resolve_domain(domain: str) -> str:
    """Resolve a domain to its IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return ""


def is_internal_ip(ip: str) -> bool:
    """Check if an IP address is internal/private."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def severity_color(severity: str) -> str:
    """Return Rich color string for a severity level."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


def print_finding(console: Console, severity: str, title: str, detail: str = ""):
    """Print a formatted finding to the console."""
    color = severity_color(severity)
    icon = {"critical": "!!!", "high": "[!]", "medium": "[~]", "low": "[*]", "info": "[i]"}.get(
        severity.lower(), "[?]"
    )
    msg = f"[{color}]{icon} [{severity.upper()}] {title}[/{color}]"
    if detail:
        msg += f"\n    [dim]{detail}[/dim]"
    console.print(msg)


def sanitize_filename(name: str) -> str:
    """Create a safe filename from a string."""
    return re.sub(r'[^\w\-.]', '_', name)[:100]


class ScopedSession:
    """HTTP session that enforces scope restrictions."""

    def __init__(self, allowed_domains: list, console: Console = None):
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.allowed_domains = [d.lower() for d in allowed_domains]
        self.console = console

    def _check_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        for domain in self.allowed_domains:
            if host == domain or host.endswith(f".{domain}"):
                return True
        if self.console:
            self.console.print(f"[red][!] Out of scope: {host}[/red]")
        return False

    def get(self, url: str, **kwargs):
        if not self._check_scope(url):
            raise ValueError(f"URL {url} is out of scope")
        kwargs.setdefault("timeout", 15)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        if not self._check_scope(url):
            raise ValueError(f"URL {url} is out of scope")
        kwargs.setdefault("timeout", 15)
        return self.session.post(url, **kwargs)
