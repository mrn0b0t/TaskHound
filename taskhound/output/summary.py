from typing import Any, List

from ..utils.console import console, print_summary_table as rich_summary_table


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
            if resolved_runas and runas.startswith("S-1-5-"):
                display_runas = f"{resolved_runas} ({runas})"
            else:
                display_runas = runas
            
            creds_found.append({
                "host": row_dict.get("host", "Unknown"),
                "path": row_dict.get("path", "Unknown"),
                "runas": display_runas,
                "password": decrypted_password,
                "type": row_dict.get("type", "TASK"),
            })
    
    if not creds_found:
        return 0
    
    # Print header
    console.print()
    console.print("[bold cyan]═" * 70 + "[/]")
    console.print(f"[bold cyan]DECRYPTED CREDENTIALS ({len(creds_found)} found)[/]")
    console.print("[bold cyan]═" * 70 + "[/]")
    console.print()
    
    # Group by host for cleaner output
    creds_by_host = {}
    for cred in creds_found:
        host = cred["host"]
        if host not in creds_by_host:
            creds_by_host[host] = []
        creds_by_host[host].append(cred)
    
    for host, creds in creds_by_host.items():
        console.print(f"[bold white]{host}[/]")
        for cred in creds:
            task_type = cred["type"]
            if task_type == "TIER-0":
                type_color = "red"
            elif task_type == "PRIV":
                type_color = "yellow"
            else:
                type_color = "green"
            
            console.print(f"  [{type_color}][{task_type}][/{type_color}] {cred['runas']}")
            console.print(f"          Task: {cred['path']}")
            console.print(f"          [bold green]Password: {cred['password']}[/]")
            console.print()
    
    console.print("[bold cyan]═" * 70 + "[/]")
    console.print()
    
    return len(creds_found)
