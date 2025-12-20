import csv
import json
import os
from io import StringIO
from typing import Any, Dict, List

from rich import box
from rich.console import Console
from rich.table import Table

from ..utils.logging import good
from . import COLORS


def _rows_to_dicts(rows: List[Any]) -> List[Dict]:
    """Convert TaskRow objects to dicts for serialization."""
    return [row.to_dict() if hasattr(row, "to_dict") else row for row in rows]


def _format_task_table(row_dict: Dict[str, Any]) -> Table:
    """
    Format a single task as a Rich table.

    Args:
        row_dict: Task data as dictionary

    Returns:
        Rich Table object
    """
    task_type = row_dict.get("type", "TASK")

    # Select colors based on task type
    if task_type == "TIER-0":
        header_style = COLORS["tier0_header"]
        border_style = COLORS["tier0_border"]
        tag = "[TIER-0]"
    elif task_type == "PRIV":
        header_style = COLORS["priv_header"]
        border_style = COLORS["priv_border"]
        tag = "[PRIV]"
    else:
        header_style = COLORS["task_header"]
        border_style = COLORS["task_border"]
        tag = "[TASK]"

    rel_path = row_dict.get("path", "Unknown")
    title = f"[{header_style}]{tag}[/] {rel_path}"

    table = Table(
        title=title,
        title_style=header_style,
        border_style=border_style,
        box=box.ROUNDED,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )

    table.add_column("Field", style=COLORS["label"], width=18)
    table.add_column("Value", style=COLORS["value"])

    # Build rows from task data
    if row_dict.get("enabled"):
        table.add_row("Enabled", row_dict["enabled"])

    runas = row_dict.get("runas", "")
    resolved = row_dict.get("resolved_runas")
    display_runas = f"{resolved} ({runas})" if resolved and runas.startswith("S-1-5-") else runas
    if display_runas:
        table.add_row("RunAs", display_runas)

    if row_dict.get("decrypted_password"):
        table.add_row("Decrypted Pwd", f"[{COLORS['password']}]{row_dict['decrypted_password']}[/]")

    if row_dict.get("logon_type"):
        table.add_row("Logon Type", row_dict["logon_type"])

    command = row_dict.get("command", "")
    args = row_dict.get("arguments", "")
    what = f"{command} {args}".strip() if args else command
    if what:
        table.add_row("Command", what)

    if row_dict.get("author"):
        table.add_row("Author", row_dict["author"])

    if row_dict.get("date"):
        table.add_row("Date", row_dict["date"])

    if row_dict.get("password_analysis"):
        table.add_row("Password Age", row_dict["password_analysis"])

    if row_dict.get("cred_status"):
        cred_val = row_dict.get("cred_detail", row_dict["cred_status"])
        if row_dict.get("cred_password_valid"):
            table.add_row("Cred Validation", f"[green][+] {cred_val}[/]")
        elif row_dict["cred_status"] == "invalid":
            table.add_row("Cred Validation", f"[red][-] {cred_val}[/]")
        else:
            table.add_row("Cred Validation", f"[yellow][?] {cred_val}[/]")

    # Credential Guard status - show both enabled and disabled states
    if row_dict.get("credential_guard") is not None:
        if row_dict["credential_guard"]:
            table.add_row("Cred Guard", "[red]ENABLED[/] - DPAPI extraction will fail")
        else:
            table.add_row("Cred Guard", "[green]DISABLED[/] - DPAPI extraction possible")

    if row_dict.get("reason"):
        table.add_row("Reason", row_dict["reason"])

    return table


def write_rich_plain(outdir: str, all_rows: List[Any], force_color: bool = True):
    """
    Write Rich-formatted output files grouped by host.

    Creates a directory structure:
        outdir/
        ├── summary.txt          # Overall summary with stats
        ├── host1/
        │   └── tasks.txt        # Rich-formatted task details
        └── host2/
            └── tasks.txt

    Files use ANSI color codes by default for viewing with `cat` or `less -R`.

    Args:
        outdir: Output directory path
        all_rows: List of TaskRow objects or dicts
        force_color: Include ANSI color codes (default True)
    """
    os.makedirs(outdir, exist_ok=True)

    # Group rows by host
    hosts: Dict[str, List[Dict]] = {}
    for row in all_rows:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row
        host = row_dict.get("host", "unknown")
        if host not in hosts:
            hosts[host] = []
        hosts[host].append(row_dict)

    # Write summary.txt in root
    _write_summary_file(outdir, hosts, force_color)

    # Write per-host task files in subdirectories
    for host, rows in hosts.items():
        safe_host = host.replace(":", "_").replace("/", "_").replace("\\", "_")
        host_dir = os.path.join(outdir, safe_host)
        os.makedirs(host_dir, exist_ok=True)

        tasks_path = os.path.join(host_dir, "tasks.txt")
        _write_host_tasks_file(tasks_path, host, rows, force_color)

    good(f"Wrote results to {outdir}/ ({len(hosts)} hosts)")


def _write_summary_file(outdir: str, hosts: Dict[str, List[Dict]], force_color: bool):
    """Write summary.txt with overall stats and per-host breakdown."""
    summary_path = os.path.join(outdir, "summary.txt")

    buffer = StringIO()
    file_console = Console(file=buffer, force_terminal=force_color, width=120)

    # Overall header
    file_console.print("\n[bold cyan]╔══════════════════════════════════════════════════════════════╗[/]")
    file_console.print("[bold cyan]║               TaskHound Scan Summary                         ║[/]")
    file_console.print("[bold cyan]╚══════════════════════════════════════════════════════════════╝[/]\n")

    # Calculate totals
    total_tier0 = 0
    total_priv = 0
    total_task = 0
    total_failures = 0
    decrypted_creds = []

    for _host, rows in hosts.items():
        for r in rows:
            task_type = r.get("type", "TASK")
            if task_type == "TIER-0":
                total_tier0 += 1
            elif task_type == "PRIV":
                total_priv += 1
            elif task_type == "FAILURE":
                total_failures += 1
            else:
                total_task += 1

            if r.get("decrypted_password"):
                decrypted_creds.append(r)

    # Overall stats
    file_console.print("[bold white]Overall Statistics[/]")
    file_console.print(f"  Hosts Scanned  : {len(hosts)}")
    file_console.print(f"  [bold red]TIER-0 Tasks   : {total_tier0}[/]")
    file_console.print(f"  [bold yellow]Privileged     : {total_priv}[/]")
    file_console.print(f"  [bold green]Regular Tasks  : {total_task}[/]")
    if total_failures:
        file_console.print(f"  [red]Failures       : {total_failures}[/]")
    file_console.print()

    # Decrypted credentials highlight
    if decrypted_creds:
        file_console.print(f"[bold green]Decrypted Credentials: {len(decrypted_creds)}[/]\n")

        cred_table = Table(
            title="[bold cyan]Decrypted Credentials[/]",
            border_style="cyan",
            show_header=True,
            header_style="bold white",
        )
        cred_table.add_column("Type", style="dim", width=8)
        cred_table.add_column("Host", style="white")
        cred_table.add_column("RunAs", style="white")
        cred_table.add_column("Password", style="bold green")

        for cred in decrypted_creds:
            task_type = cred.get("type", "TASK")
            if task_type == "TIER-0":
                type_style = "bold red"
            elif task_type == "PRIV":
                type_style = "bold yellow"
            else:
                type_style = "bold green"

            runas = cred.get("runas", "")
            resolved = cred.get("resolved_runas")
            display_runas = f"{resolved}" if resolved else runas

            cred_table.add_row(
                f"[{type_style}]{task_type}[/]",
                cred.get("host", ""),
                display_runas,
                cred.get("decrypted_password", ""),
            )

        file_console.print(cred_table)
        file_console.print()

    # Per-host breakdown table
    file_console.print("[bold white]Per-Host Breakdown[/]\n")

    host_table = Table(
        border_style="dim",
        show_header=True,
        header_style="bold white",
    )
    host_table.add_column("Host", style="white")
    host_table.add_column("TIER-0", style="red", justify="right")
    host_table.add_column("PRIV", style="yellow", justify="right")
    host_table.add_column("TASK", style="green", justify="right")
    host_table.add_column("Status", style="dim")

    for host, rows in sorted(hosts.items()):
        t0 = sum(1 for r in rows if r.get("type") == "TIER-0")
        priv = sum(1 for r in rows if r.get("type") == "PRIV")
        task = sum(1 for r in rows if r.get("type") == "TASK")
        failures = [r for r in rows if r.get("type") == "FAILURE"]

        if failures:
            status = f"[red][-] {failures[0].get('reason', 'Failed')}[/]"
        elif t0 > 0:
            status = "[bold red][!] HIGH VALUE[/]"
        elif priv > 0:
            status = "[yellow][+] Privileged found[/]"
        else:
            status = "[green][+] OK[/]"

        host_table.add_row(host, str(t0), str(priv), str(task), status)

    file_console.print(host_table)
    file_console.print()

    # Footer with output location info
    file_console.print("[dim]─" * 60 + "[/]")
    file_console.print("[dim]Task details are in per-host subdirectories (host/tasks.txt)[/]")
    file_console.print()

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(buffer.getvalue())


def _write_host_tasks_file(path: str, host: str, rows: List[Dict], force_color: bool):
    """Write tasks.txt for a single host."""
    buffer = StringIO()
    file_console = Console(file=buffer, force_terminal=force_color, width=120)

    # Sort rows: TIER-0 first, then PRIV, then TASK
    type_order = {"TIER-0": 0, "PRIV": 1, "TASK": 2, "FAILURE": 3}
    sorted_rows = sorted(rows, key=lambda r: type_order.get(r.get("type", "TASK"), 2))

    # Write header
    file_console.print(f"\n[bold cyan]═══ TaskHound Results: {host} ═══[/]\n")

    # Count tasks by type
    tier0_count = sum(1 for r in rows if r.get("type") == "TIER-0")
    priv_count = sum(1 for r in rows if r.get("type") == "PRIV")
    task_count = sum(1 for r in rows if r.get("type") == "TASK")

    file_console.print(f"[dim]TIER-0: {tier0_count} | PRIV: {priv_count} | TASK: {task_count}[/]\n")

    # Write each task as a table
    for row_dict in sorted_rows:
        if row_dict.get("type") == "FAILURE":
            file_console.print(f"[red][-] FAILURE: {row_dict.get('reason', 'Unknown error')}[/]\n")
            continue

        table = _format_task_table(row_dict)
        file_console.print(table)
        file_console.print()

    # Write to file
    with open(path, "w", encoding="utf-8") as f:
        f.write(buffer.getvalue())


def write_json(path: str, rows: List[Any], silent: bool = False):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_rows_to_dicts(rows), f, indent=2)
    if not silent:
        good(f"Wrote JSON results to {path}")


def write_csv(path: str, rows: List[Any]):
    fieldnames = [
        "host",
        "target_ip",
        "computer_sid",
        "path",
        "type",
        "runas",
        "resolved_runas",
        "command",
        "arguments",
        "author",
        "date",
        "logon_type",
        "enabled",
        "trigger_type",
        "start_boundary",
        "interval",
        "duration",
        "days_interval",
        "reason",
        "credentials_hint",
        "credential_guard",
        "password_analysis",
        "cred_status",
        "cred_password_valid",
        "cred_hijackable",
        "cred_last_run",
        "cred_return_code",
        "cred_detail",
        "decrypted_password",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(_rows_to_dicts(rows))
    good(f"Wrote CSV results to {path}")
