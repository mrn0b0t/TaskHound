from typing import Dict, List

from ..utils.console import print_summary_table as rich_summary_table


def print_summary_table(all_rows: List[Dict], backup_dir: str = None, has_hv_data: bool = False):
    """Print a nicely formatted summary table showing task counts per host."""
    if not all_rows:
        return

    # Aggregate data by host
    host_stats = {}
    for row in all_rows:
        host = row.get("host", "Unknown")
        task_type = row.get("type", "TASK")
        reason = row.get("reason", "")

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
