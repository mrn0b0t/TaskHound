from typing import Any, List

from ..utils.console import console
from ..utils.console import print_summary_table as rich_summary_table


def print_summary_table(all_rows: List[Any], backup_dir: str = None, has_hv_data: bool = False):
    """Print a nicely formatted summary table showing task counts per host."""
    if not all_rows:
        return

    # Aggregate data by host
    host_stats = {}
    for row in all_rows:
        # Support both dict and TaskRow objects
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row

        host = row_dict.get("host", "Unknown")
        task_type = row_dict.get("type", "TASK")
        reason = row_dict.get("reason", "")

        if host not in host_stats:
            host_stats[host] = {"tier0": 0, "privileged": 0, "normal": 0, "status": "[+]", "failure_reason": ""}

        if task_type == "FAILURE":
            host_stats[host]["status"] = "[-]"
            host_stats[host]["failure_reason"] = reason
        elif task_type == "TIER-0":
            host_stats[host]["tier0"] += 1
        elif task_type == "PRIV":
            host_stats[host]["privileged"] += 1
        else:
            host_stats[host]["normal"] += 1

    if not host_stats:
        return

    # Use Rich table
    rich_summary_table(host_stats, has_hv_data=has_hv_data, backup_dir=backup_dir)


def print_decrypted_credentials(all_rows: List[Any]) -> int:
    """
    Print a summary of all decrypted credentials found during the scan.

    This is always shown (not just in verbose mode) because decrypted
    credentials are high-value findings that users should not miss.

    Returns:
        Number of decrypted credentials found
    """
    from rich.table import Table
    from rich.panel import Panel

    # Collect all rows with decrypted passwords
    creds_found = []
    for row in all_rows:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row

        decrypted_password = row_dict.get("decrypted_password")
        if decrypted_password:
            # Use resolved_runas if available, otherwise fall back to runas
            runas = row_dict.get("runas", "Unknown")
            resolved_runas = row_dict.get("resolved_runas")

            # Format display: if we have resolved username for a SID, show "username (SID)"
            display_runas = f"{resolved_runas} ({runas})" if resolved_runas and runas.startswith("S-1-5-") else runas

            creds_found.append({
                "host": row_dict.get("host", "Unknown"),
                "path": row_dict.get("path", "Unknown"),
                "runas": display_runas,
                "password": decrypted_password,
                "type": row_dict.get("type", "TASK"),
            })

    if not creds_found:
        return 0

    # Create a table for decrypted credentials
    table = Table(
        title=f"[bold cyan]DECRYPTED CREDENTIALS ({len(creds_found)} found)[/]",
        title_style="bold cyan",
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )

    table.add_column("Type", style="dim", width=8)
    table.add_column("Host", style="white")
    table.add_column("RunAs", style="white")
    table.add_column("Password", style="bold green")
    table.add_column("Task Path", style="dim")

    for cred in creds_found:
        task_type = cred["type"]
        if task_type == "TIER-0":
            type_style = "bold red"
        elif task_type == "PRIV":
            type_style = "bold yellow"
        else:
            type_style = "bold green"

        table.add_row(
            f"[{type_style}]{task_type}[/]",
            cred["host"],
            cred["runas"],
            cred["password"],
            cred["path"],
        )

    console.print()
    console.print(table)
    console.print()

    return len(creds_found)
