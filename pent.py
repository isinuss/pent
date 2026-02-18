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
    table.add_row("4", "Guide", "Methodology checklists & learning")
    table.add_row("5", "Report", "Generate findings reports")
    table.add_row("0", "Exit", "Quit the tool")

    console.print(table)
    console.print()


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
        "guide": GuideModule(console),
        "report": ReporterModule(console),
    }

    while True:
        main_menu()
        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", choices=["0", "1", "2", "3", "4", "5"])

        if choice == "0":
            console.print("[bold green]Happy hunting! Stay ethical.[/bold green]")
            break
        elif choice == "1":
            t = target if target != "none" else Prompt.ask("Enter target")
            modules["recon"].interactive(t)
        elif choice == "2":
            t = target if target != "none" else Prompt.ask("Enter target")
            modules["vuln"].interactive(t)
        elif choice == "3":
            url = target if target != "none" else Prompt.ask("Enter URL")
            modules["web"].interactive(url)
        elif choice == "4":
            modules["guide"].interactive()
        elif choice == "5":
            modules["report"].interactive()


if __name__ == "__main__":
    cli()
