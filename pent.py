#!/usr/bin/env python3
"""
PENT - Penetration Testing Assistant
A guided white-hat security testing and bug bounty tool.

LEGAL DISCLAIMER: This tool is intended for authorized security testing only.
Always obtain written permission before testing any target.
"""

import sys
import os
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich import box

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.recon import ReconModule
from modules.vuln_scanner import VulnScannerModule
from modules.web_tester import WebTesterModule
from modules.reporter import ReporterModule
from modules.guide import GuideModule
from modules.takeover import TakeoverModule
from modules.js_analyzer import JSAnalyzerModule
from modules.custom_checks import CustomChecksModule

console = Console()

BANNER = r"""
    ____  _______   ________
   / __ \/ ____/ | / /_  __/
  / /_/ / __/ /  |/ / / /
 / ____/ /___/ /|  / / /
/_/   /_____/_/ |_/ /_/

  Penetration Testing Assistant
  For authorized testing only.
"""

DISCLAIMER = (
    "[bold red]LEGAL DISCLAIMER[/bold red]\n"
    "This tool is for [bold]authorized security testing[/bold] and "
    "[bold]bug bounty programs[/bold] only.\n"
    "Unauthorized access to computer systems is illegal.\n"
    "Always obtain [bold]written permission[/bold] before testing any target."
)


def show_banner():
    console.print(BANNER, style="bold cyan")
    console.print(Panel(DISCLAIMER, border_style="red", box=box.DOUBLE))
    console.print()


def main_menu():
    """Display the main interactive menu."""
    table = Table(
        title="Main Menu",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=False,
    )
    table.add_column("Option", style="bold yellow", width=6)
    table.add_column("Module", style="bold white")
    table.add_column("Description", style="dim")

    table.add_row("1", "Recon", "Passive & active reconnaissance")
    table.add_row("2", "Vuln Scan", "Vulnerability scanning & enumeration")
    table.add_row("3", "Web Test", "Web application security testing")
    table.add_row("4", "JS Analyze", "JavaScript file analysis for secrets & endpoints")
    table.add_row("5", "Takeover", "Subdomain takeover detection")
    table.add_row("6", "Checks", "Run built-in & custom security checks")
    table.add_row("7", "Guide", "Methodology checklists & learning")
    table.add_row("8", "Report", "Generate findings reports")
    table.add_row("9", "Full Auto", "Run all modules automatically")
    table.add_row("0", "Exit", "Quit the tool")

    console.print(table)
    console.print()


# ======================================================================
# CLI Commands
# ======================================================================

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """PENT - Penetration Testing Assistant for white-hat testing & bug bounties."""
    if ctx.invoked_subcommand is None:
        interactive_mode()


@cli.command()
@click.argument("target")
@click.option("--passive", is_flag=True, help="Passive recon only (no direct contact)")
def recon(target, passive):
    """Run reconnaissance against a target."""
    show_banner()
    mod = ReconModule(console)
    mod.run(target, passive_only=passive)


@cli.command()
@click.argument("target")
@click.option("--quick", is_flag=True, help="Quick scan (top ports only)")
def scan(target, quick):
    """Run vulnerability scan against a target."""
    show_banner()
    mod = VulnScannerModule(console)
    mod.run(target, quick=quick)


@cli.command()
@click.argument("url")
@click.option("--full", is_flag=True, help="Run all web tests")
def webtest(url, full):
    """Run web application tests against a URL."""
    show_banner()
    mod = WebTesterModule(console)
    mod.run(url, full=full)


@cli.command()
@click.argument("url")
def jsanalyze(url):
    """Analyze JavaScript files for endpoints and secrets."""
    show_banner()
    mod = JSAnalyzerModule(console)
    mod.analyze(url)


@cli.command()
@click.argument("target")
def takeover(target):
    """Check subdomains for takeover vulnerabilities."""
    show_banner()
    recon_mod = ReconModule(console)
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    subs = recon_mod.subdomain_enum(domain)
    if subs:
        mod = TakeoverModule(console)
        mod.check_subdomains(subs)


@cli.command()
@click.argument("target")
@click.option("--custom-dir", type=str, default=None, help="Directory with custom YAML checks")
def checks(target, custom_dir):
    """Run built-in and custom security checks."""
    show_banner()
    mod = CustomChecksModule(console)
    mod.run_all_builtin(target)
    if custom_dir:
        mod.run_custom_checks(target, custom_dir)


@cli.command()
@click.option("--topic", type=str, default=None, help="Specific topic to view")
def guide(topic):
    """View methodology guides and checklists."""
    show_banner()
    mod = GuideModule(console)
    mod.run(topic=topic)


@cli.command()
@click.option("--output", type=str, default="reports", help="Output directory")
@click.option("--fmt", type=click.Choice(["md", "html", "json"]), default="md")
def report(output, fmt):
    """Generate a report from findings."""
    show_banner()
    mod = ReporterModule(console)
    mod.run(output_dir=output, fmt=fmt)


@cli.command()
@click.argument("target")
@click.option("--output", type=str, default="reports", help="Report output directory")
@click.option("--fmt", type=click.Choice(["md", "html", "json"]), default="html")
def auto(target, output, fmt):
    """Run full automated assessment (all modules)."""
    show_banner()
    run_full_auto(target, output, fmt)


# ======================================================================
# Full Auto Mode
# ======================================================================

def run_full_auto(target: str, output_dir: str = "reports", fmt: str = "html"):
    """Run all modules in sequence and generate a combined report."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    url = target if target.startswith("http") else f"https://{target}"

    all_findings = []

    # Phase 1: Recon
    console.print(Panel("[bold]Phase 1/6: Reconnaissance[/bold]", border_style="cyan"))
    recon_mod = ReconModule(console)
    all_findings.extend(recon_mod.run(target))

    # Phase 2: Vuln Scan
    console.print(Panel("[bold]Phase 2/6: Vulnerability Scanning[/bold]", border_style="cyan"))
    vuln_mod = VulnScannerModule(console)
    all_findings.extend(vuln_mod.run(target, quick=True))

    # Phase 3: Web Tests
    console.print(Panel("[bold]Phase 3/6: Web Application Testing[/bold]", border_style="cyan"))
    web_mod = WebTesterModule(console)
    all_findings.extend(web_mod.run(url, full=True))

    # Phase 4: JS Analysis
    console.print(Panel("[bold]Phase 4/6: JavaScript Analysis[/bold]", border_style="cyan"))
    js_mod = JSAnalyzerModule(console)
    all_findings.extend(js_mod.analyze(url))

    # Phase 5: Custom Checks
    console.print(Panel("[bold]Phase 5/6: Security Checks[/bold]", border_style="cyan"))
    checks_mod = CustomChecksModule(console)
    all_findings.extend(checks_mod.run_all_builtin(target))

    # Phase 6: Subdomain Takeover
    console.print(Panel("[bold]Phase 6/6: Subdomain Takeover Check[/bold]", border_style="cyan"))
    subs = recon_mod.subdomain_enum(domain)
    if subs:
        takeover_mod = TakeoverModule(console)
        all_findings.extend(takeover_mod.check_subdomains(subs[:50]))

    # Generate Report
    console.print(Panel("[bold]Generating Report[/bold]", border_style="green"))
    reporter = ReporterModule(console)
    reporter.target = domain
    reporter.tester = "PENT Auto Assessment"
    reporter.add_findings(all_findings)
    filepath = reporter.run(output_dir=output_dir, fmt=fmt)

    # Summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    summary = Table(title="Assessment Summary", box=box.DOUBLE)
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", style="bold")

    summary.add_row("[bold red]Critical[/bold red]", str(severity_counts["critical"]))
    summary.add_row("[red]High[/red]", str(severity_counts["high"]))
    summary.add_row("[yellow]Medium[/yellow]", str(severity_counts["medium"]))
    summary.add_row("[green]Low[/green]", str(severity_counts["low"]))
    summary.add_row("[dim]Info[/dim]", str(severity_counts["info"]))
    summary.add_row("[bold]Total[/bold]", f"[bold]{len(all_findings)}[/bold]")

    console.print(summary)
    console.print(f"\n[bold green]Report saved: {filepath}[/bold green]")


# ======================================================================
# Interactive Mode
# ======================================================================

def interactive_mode():
    """Run the tool in interactive menu mode."""
    show_banner()

    accepted = Confirm.ask(
        "[bold yellow]Do you confirm you have authorization to test your target?[/bold yellow]"
    )
    if not accepted:
        console.print("[red]You must have authorization. Exiting.[/red]")
        sys.exit(1)

    target = Prompt.ask("[bold cyan]Enter target domain/IP (or 'none' to browse guides)[/bold cyan]")

    modules = {
        "recon": ReconModule(console),
        "vuln": VulnScannerModule(console),
        "web": WebTesterModule(console),
        "js": JSAnalyzerModule(console),
        "takeover": TakeoverModule(console),
        "checks": CustomChecksModule(console),
        "guide": GuideModule(console),
        "report": ReporterModule(console),
    }

    while True:
        main_menu()
        choice = Prompt.ask(
            "[bold cyan]Select option[/bold cyan]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        )

        if choice == "0":
            console.print("[bold green]Happy hunting! Stay ethical.[/bold green]")
            break

        t = target
        if choice in ("1", "2", "3", "4", "5", "6", "9") and target == "none":
            t = Prompt.ask("Enter target")

        if choice == "1":
            modules["recon"].interactive(t)
        elif choice == "2":
            modules["vuln"].interactive(t)
        elif choice == "3":
            modules["web"].interactive(t)
        elif choice == "4":
            modules["js"].interactive(t)
        elif choice == "5":
            modules["takeover"].interactive(t)
        elif choice == "6":
            modules["checks"].interactive(t)
        elif choice == "7":
            modules["guide"].interactive()
        elif choice == "8":
            modules["report"].interactive()
        elif choice == "9":
            run_full_auto(t)


if __name__ == "__main__":
    cli()
