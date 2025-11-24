from typing import Dict, List

from ..utils.logging import good


def print_summary_table(all_rows: List[Dict], backup_dir: str = None, has_hv_data: bool = False):
    # Print a nicely formatted summary table showing task counts per host
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

    # Calculate column widths
    max_hostname_width = max(len("HOSTNAME"), max(len(host) for host in host_stats))
    tier0_width = len("TIER-0_TASKS")
    priv_width = len("PRIVILEGED_TASKS")
    normal_width = len("NORMAL_TASKS")
    # Calculate status width (max of "STATUS" or failure reason)
    max_status_width = len("STATUS")
    for host in host_stats:
        if host_stats[host]["status"] == "[-]":
            # Limit failure reason width to avoid breaking terminal
            reason_len = len(host_stats[host]["failure_reason"]) + 4 # +4 for "[-] "
            max_status_width = max(max_status_width, min(reason_len, 60))

    # Print header
    print("\n" + "=" * (max_hostname_width + tier0_width + priv_width + normal_width + max_status_width + 13))
    print("SUMMARY")
    print("=" * (max_hostname_width + tier0_width + priv_width + normal_width + max_status_width + 13))

    # Print table header
    header = f"{'HOSTNAME':<{max_hostname_width}} | {'TIER-0_TASKS':<{tier0_width}} | {'PRIVILEGED_TASKS':<{priv_width}} | {'NORMAL_TASKS':<{normal_width}} | {'STATUS':<{max_status_width}}"
    print(header)
    print("-" * len(header))

    # Print rows
    total_tier0 = 0
    total_priv = 0
    total_normal = 0
    for host in sorted(host_stats.keys()):
        stats = host_stats[host]
        tier0_count = stats["tier0"]
        priv_count = stats["privileged"]
        normal_count = stats["normal"]

        if stats["status"] == "[+]":
            total_tier0 += tier0_count
            total_priv += priv_count
            total_normal += normal_count
            status_display = "[+]"
        else:
            # For failed hosts, show N/A for counts
            status_display = f"[-] {stats['failure_reason']}"
            # Truncate if too long
            if len(status_display) > max_status_width:
                status_display = status_display[:max_status_width-3] + "..."

        # Show N/A for privileged tasks if no high-value data was loaded OR if host failed
        if stats["status"] == "[-]":
            tier0_display = "N/A"
            priv_display = "N/A"
            normal_display = "N/A"
        else:
            tier0_display = str(tier0_count) if has_hv_data else "N/A"
            priv_display = str(priv_count) if has_hv_data else "N/A"
            normal_display = str(normal_count)

        row = f"{host:<{max_hostname_width}} | {tier0_display:<{tier0_width}} | {priv_display:<{priv_width}} | {normal_display:<{normal_width}} | {status_display:<{max_status_width}}"
        print(row)

    # Print totals
    if len(host_stats) > 1:
        print("-" * len(header))
        total_tier0_display = str(total_tier0) if has_hv_data else "N/A"
        total_priv_display = str(total_priv) if has_hv_data else "N/A"
        total_row = f"{'TOTAL':<{max_hostname_width}} | {total_tier0_display:<{tier0_width}} | {total_priv_display:<{priv_width}} | {total_normal:<{normal_width}} | {'':<{max_status_width}}"
        print(total_row)

    print("=" * (max_hostname_width + tier0_width + priv_width + normal_width + max_status_width + 13))

    # Print additional info hint
    if not has_hv_data:
        good("NOTE: Tier-0 and privileged task detection requires --bh-data parameter or a live connection.")
        good("Without high-value target data, Tier-0 and privileged tasks are marked as N/A")

    if backup_dir:
        good(f"Raw XML files saved to: {backup_dir}")
        good("Check the backup directory for detailed task information")
    else:
        good("Check the output above or your saved files for detailed task information")

    print()
