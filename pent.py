#!/usr/bin/env python3
"""
PENT - Penetration Testing Assistant
A guided white-hat security testing and bug bounty tool.

LEGAL DISCLAIMER: This tool is intended for authorized security testing only.
Always obtain written permission before testing any target.
"""

import sys
import os
import json as json_mod
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
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


def output_json(data):
    """Print JSON output to stdout."""
    click.echo(json_mod.dumps(data, indent=2, default=str))


# ======================================================================
# CLI Commands
# ======================================================================

@click.group(invoke_without_command=True)
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.pass_context
def cli(ctx, json_output):
    """PENT - Penetration Testing Assistant for white-hat testing & bug bounties."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output
    if json_output:
        # Suppress rich output in JSON mode
        ctx.obj["console"] = Console(file=open(os.devnull, "w"), quiet=True)
    else:
        ctx.obj["console"] = console
    if ctx.invoked_subcommand is None:
        if json_output:
            output_json({"error": "No command specified. Use --help to see available commands."})
        else:
            interactive_mode()


@cli.command()
@click.argument("target")
@click.option("--passive", is_flag=True, help="Passive recon only (no direct contact)")
@click.pass_context
def recon(ctx, target, passive):
    """Run reconnaissance against a target."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    mod = ReconModule(c)
    findings = mod.run(target, passive_only=passive)
    if ctx.obj["json"]:
        output_json({"target": target, "scan_type": "recon", "findings": findings})


@cli.command()
@click.argument("target")
@click.option("--quick", is_flag=True, help="Quick scan (top ports only)")
@click.pass_context
def scan(ctx, target, quick):
    """Run vulnerability scan against a target."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    mod = VulnScannerModule(c)
    findings = mod.run(target, quick=quick)
    if ctx.obj["json"]:
        output_json({"target": target, "scan_type": "vuln_scan", "findings": findings})


@cli.command()
@click.argument("url")
@click.option("--full", is_flag=True, help="Run all web tests")
@click.pass_context
def webtest(ctx, url, full):
    """Run web application tests against a URL."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    mod = WebTesterModule(c)
    findings = mod.run(url, full=full)
    if ctx.obj["json"]:
        output_json({"target": url, "scan_type": "web_test", "findings": findings})


@cli.command()
@click.argument("url")
@click.pass_context
def jsanalyze(ctx, url):
    """Analyze JavaScript files for endpoints and secrets."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    mod = JSAnalyzerModule(c)
    findings = mod.analyze(url)
    if ctx.obj["json"]:
        output_json({"target": url, "scan_type": "js_analyze", "findings": findings})


@cli.command()
@click.argument("target")
@click.pass_context
def takeover(ctx, target):
    """Check subdomains for takeover vulnerabilities."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    recon_mod = ReconModule(c)
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    subs = recon_mod.subdomain_enum(domain)
    findings = []
    if subs:
        mod = TakeoverModule(c)
        findings = mod.check_subdomains(subs)
    if ctx.obj["json"]:
        output_json({"target": target, "scan_type": "takeover", "findings": findings})


@cli.command()
@click.argument("target")
@click.option("--custom-dir", type=str, default=None, help="Directory with custom YAML checks")
@click.pass_context
def checks(ctx, target, custom_dir):
    """Run built-in and custom security checks."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    mod = CustomChecksModule(c)
    findings = mod.run_all_builtin(target)
    if custom_dir:
        findings.extend(mod.run_custom_checks(target, custom_dir))
    if ctx.obj["json"]:
        output_json({"target": target, "scan_type": "checks", "findings": findings})


@cli.command()
@click.option("--topic", type=str, default=None, help="Specific topic to view")
@click.pass_context
def guide(ctx, topic):
    """View methodology guides and checklists."""
    if ctx.obj["json"]:
        from modules.guide import METHODOLOGIES
        if topic:
            data = METHODOLOGIES.get(topic)
            if data:
                output_json({"topic": topic, "guide": data})
            else:
                output_json({"error": f"Guide '{topic}' not found", "available": list(METHODOLOGIES.keys())})
        else:
            output_json({"guides": [{"key": k, "title": v["title"]} for k, v in METHODOLOGIES.items()]})
        return
    show_banner()
    mod = GuideModule(ctx.obj["console"])
    mod.run(topic=topic)


@cli.command()
@click.option("--output", type=str, default="reports", help="Output directory")
@click.option("--fmt", type=click.Choice(["md", "html", "json"]), default="md")
@click.pass_context
def report(ctx, output, fmt):
    """Generate a report from findings."""
    if not ctx.obj["json"]:
        show_banner()
    mod = ReporterModule(ctx.obj["console"])
    filepath = mod.run(output_dir=output, fmt=fmt)
    if ctx.obj["json"]:
        output_json({"report_path": filepath, "format": fmt})


@cli.command()
@click.argument("target")
@click.option("--output", type=str, default="reports", help="Report output directory")
@click.option("--fmt", type=click.Choice(["md", "html", "json"]), default="html")
@click.pass_context
def auto(ctx, target, output, fmt):
    """Run full automated assessment (all modules)."""
    c = ctx.obj["console"]
    if not ctx.obj["json"]:
        show_banner()
    findings = run_full_auto(target, output, fmt, c, quiet=ctx.obj["json"])
    if ctx.obj["json"]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        output_json({
            "target": target,
            "scan_type": "full_auto",
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings": findings,
        })


# ======================================================================
# Full Auto Mode
# ======================================================================

def run_full_auto(target: str, output_dir: str = "reports", fmt: str = "html",
                  con: Console = None, quiet: bool = False):
    """Run all modules in sequence and generate a combined report."""
    if con is None:
        con = console
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    url = target if target.startswith("http") else f"https://{target}"

    all_findings = []

    # Phase 1: Recon
    if not quiet:
        con.print(Panel("[bold]Phase 1/6: Reconnaissance[/bold]", border_style="cyan"))
    recon_mod = ReconModule(con)
    all_findings.extend(recon_mod.run(target))

    # Phase 2: Vuln Scan
    if not quiet:
        con.print(Panel("[bold]Phase 2/6: Vulnerability Scanning[/bold]", border_style="cyan"))
    vuln_mod = VulnScannerModule(con)
    all_findings.extend(vuln_mod.run(target, quick=True))

    # Phase 3: Web Tests
    if not quiet:
        con.print(Panel("[bold]Phase 3/6: Web Application Testing[/bold]", border_style="cyan"))
    web_mod = WebTesterModule(con)
    all_findings.extend(web_mod.run(url, full=True))

    # Phase 4: JS Analysis
    if not quiet:
        con.print(Panel("[bold]Phase 4/6: JavaScript Analysis[/bold]", border_style="cyan"))
    js_mod = JSAnalyzerModule(con)
    all_findings.extend(js_mod.analyze(url))

    # Phase 5: Custom Checks
    if not quiet:
        con.print(Panel("[bold]Phase 5/6: Security Checks[/bold]", border_style="cyan"))
    checks_mod = CustomChecksModule(con)
    all_findings.extend(checks_mod.run_all_builtin(target))

    # Phase 6: Subdomain Takeover
    if not quiet:
        con.print(Panel("[bold]Phase 6/6: Subdomain Takeover Check[/bold]", border_style="cyan"))
    subs = recon_mod.subdomain_enum(domain)
    if subs:
        takeover_mod = TakeoverModule(con)
        all_findings.extend(takeover_mod.check_subdomains(subs[:50]))

    # Generate Report
    if not quiet:
        con.print(Panel("[bold]Generating Report[/bold]", border_style="green"))
    reporter = ReporterModule(con)
    reporter.target = domain
    reporter.tester = "PENT Auto Assessment"
    reporter.add_findings(all_findings)
    filepath = reporter.run(output_dir=output_dir, fmt=fmt)

    # Summary
    if not quiet:
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

        con.print(summary)
        con.print(f"\n[bold green]Report saved: {filepath}[/bold green]")

    return all_findings


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
