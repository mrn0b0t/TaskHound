# Rich-based console for thread-safe, colored terminal output.
#
# This module provides a centralized console for all TaskHound output,
# with proper handling for multi-threaded async scanning.
#
# Features:
# - Thread-safe output (no interleaving)
# - Colored status messages
# - Live progress bar for async scanning
# - Rich tables for summary output

import threading
from contextlib import contextmanager
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# Global console instance - thread-safe by default
console = Console(highlight=False)

# Lock for complex multi-line output
_output_lock = threading.RLock()

# Global progress context for async scanning
_progress: Optional[Progress] = None
_progress_task_id: Optional[int] = None
_live: Optional[Live] = None


# =============================================================================
# Banner
# =============================================================================

# TaskHound purple - matches BloodHound custom icon color
TASKHOUND_PURPLE = "#8B5CF6"

BANNER_ART = f"""
[bold {TASKHOUND_PURPLE}]TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD[/]
[bold {TASKHOUND_PURPLE}]  T   A   A S     K  K  H   H O   O U   U NN  N D   D[/]
[bold {TASKHOUND_PURPLE}]  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D[/]
[bold {TASKHOUND_PURPLE}]  T   A   A     S K  K  H   H O   O U   U N  NN D   D[/]
[bold {TASKHOUND_PURPLE}]  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD[/]

                     [dim]by[/] [bold white]0xr0BIT[/]
"""


def print_banner():
    """Print the colored TaskHound banner."""
    console.print(BANNER_ART)


# =============================================================================
# Status Messages (thread-safe)
# =============================================================================

def status(msg: str):
    """Print a status message (always visible). Thread-safe."""
    with _output_lock:
        console.print(msg)


def good(msg: str, verbose_only: bool = False):
    """Print a success message in green. Thread-safe."""
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[green][+][/] {msg}")


def warn(msg: str, verbose_only: bool = False):
    """Print a warning message in yellow. Thread-safe.

    Args:
        msg: Message to print
        verbose_only: If True, only print in verbose mode
    """
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[yellow][!][/] {msg}")


def error(msg: str):
    """Print an error message in red. Thread-safe."""
    with _output_lock:
        console.print(f"[red][-][/] {msg}")


def info(msg: str, verbose_only: bool = False):
    """Print an info message in blue. Thread-safe."""
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[blue][*][/] {msg}")


def debug(msg: str, exc_info: bool = False):
    """Print a debug message in dim text. Thread-safe."""
    if not _is_debug():
        return
    with _output_lock:
        console.print(f"[dim][DEBUG][/] {msg}")
        if exc_info:
            console.print_exception()


# =============================================================================
# Verbosity Control
# =============================================================================

_VERBOSE = False
_DEBUG = False


def set_verbosity(verbose: bool, debug: bool):
    """Set verbosity levels."""
    global _VERBOSE, _DEBUG
    _VERBOSE = verbose
    _DEBUG = debug


def _is_verbose() -> bool:
    return _VERBOSE or _DEBUG


def _is_debug() -> bool:
    return _DEBUG


# =============================================================================
# Progress Bar for Async Scanning
# =============================================================================

@contextmanager
def scan_progress(total: int, description: str = "Scanning"):
    """
    Context manager for showing a progress bar during async scanning.

    Usage:
        with scan_progress(len(targets), "Scanning targets") as update:
            for target in targets:
                process(target)
                update(target)  # Updates progress and shows current target

    Args:
        total: Total number of items to process
        description: Description shown in progress bar

    Yields:
        update function that takes (current_item, success=True, error_msg=None)
    """
    global _progress, _progress_task_id, _live

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
        transient=False,
    )

    task_id = progress.add_task(description, total=total, status="")

    # Track statistics
    stats = {"success": 0, "failed": 0}

    def update(item: str, success: bool = True, error_msg: Optional[str] = None):
        """Update progress with current item status."""
        if success:
            stats["success"] += 1
            status_text = f"[green][+][/] {item}"
        else:
            stats["failed"] += 1
            status_text = f"[red][-][/] {item}: {error_msg[:30]}" if error_msg else f"[red][-][/] {item}"

        progress.update(task_id, advance=1, status=status_text)

    _progress = progress
    _progress_task_id = task_id

    try:
        with progress:
            yield update
    finally:
        _progress = None
        _progress_task_id = None

        # Print summary after progress completes
        total_done = stats["success"] + stats["failed"]
        if stats["failed"] > 0:
            console.print(
                f"\n[green][+] {stats['success']}[/] succeeded, "
                f"[red][-] {stats['failed']}[/] failed out of {total_done} targets"
            )


@contextmanager
def spinner(description: str = "Processing"):
    """
    Context manager for showing an indeterminate spinner during long operations.

    Use for operations where we don't know the total progress (e.g., API calls,
    waiting for remote processing).

    Example:
        with spinner("Uploading to BloodHound"):
            upload_data()
            wait_for_processing()

    Args:
        description: Text to show next to the spinner
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,  # Remove when done
    )

    progress.add_task(description, total=None)  # None = indeterminate

    try:
        with progress:
            yield
    finally:
        pass  # Spinner removed automatically (transient=True)


# =============================================================================
# Summary Table
# =============================================================================

def print_summary_table(
    host_stats: dict,
    has_hv_data: bool = False,
    backup_dir: Optional[str] = None,
):
    """
    Print a rich summary table with host statistics.

    Shows successful hosts first with task counts, then failed hosts in a separate table.

    Args:
        host_stats: Dict of {hostname: {tier0, privileged, normal, status, failure_reason}}
        has_hv_data: Whether high-value data was loaded
        backup_dir: Optional backup directory path
    """
    if not host_stats:
        return

    # Separate successful and failed hosts
    success_hosts = {}
    failed_hosts = {}
    for host, stats in host_stats.items():
        if stats["status"] == "[+]":
            success_hosts[host] = stats
        else:
            failed_hosts[host] = stats

    total_tier0 = 0
    total_priv = 0
    total_normal = 0

    # Print successful hosts table
    if success_hosts:
        table = Table(
            title="[bold]TASK SUMMARY[/]",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )

        table.add_column("Hostname", style="white", no_wrap=True)
        table.add_column("Tier-0", justify="center", style="red")
        table.add_column("Privileged", justify="center", style="yellow")
        table.add_column("Normal", justify="center", style="green")

        for host in sorted(success_hosts.keys()):
            stats = success_hosts[host]
            tier0 = str(stats["tier0"]) if has_hv_data else "N/A"
            priv = str(stats["privileged"]) if has_hv_data else "N/A"
            normal = str(stats["normal"])

            total_tier0 += stats["tier0"]
            total_priv += stats["privileged"]
            total_normal += stats["normal"]

            table.add_row(host, tier0, priv, normal)

        # Add totals row if multiple hosts
        if len(success_hosts) > 1:
            table.add_section()
            tier0_total = str(total_tier0) if has_hv_data else "N/A"
            priv_total = str(total_priv) if has_hv_data else "N/A"
            table.add_row(
                "[bold]TOTAL[/]",
                f"[bold]{tier0_total}[/]",
                f"[bold]{priv_total}[/]",
                f"[bold]{total_normal}[/]",
            )

        console.print()
        console.print(table)

    # Print failed hosts table
    if failed_hosts:
        fail_table = Table(
            title=f"[bold red]FAILED HOSTS ({len(failed_hosts)})[/]",
            show_header=True,
            header_style="bold red",
            border_style="dim red",
        )

        fail_table.add_column("Hostname", style="white", no_wrap=True)
        fail_table.add_column("Reason", style="dim")

        for host in sorted(failed_hosts.keys()):
            stats = failed_hosts[host]
            reason = stats.get("failure_reason", "Unknown error")
            if len(reason) > 60:
                reason = reason[:57] + "..."
            fail_table.add_row(host, reason)

        console.print()
        console.print(fail_table)

    console.print()

    # Additional hints
    if not has_hv_data and success_hosts:
        console.print(
            "[dim]Note: Tier-0/Privileged detection requires --bh-data, --bh-live, or --ldap-tier0[/]"
        )

    if backup_dir:
        console.print(f"[dim]Raw XML files saved to: {backup_dir}[/]")


# =============================================================================
# Scan Complete Summary
# =============================================================================

def print_scan_complete(
    succeeded: int,
    failed: int,
    total_time: float,
    avg_time_ms: float,
    skipped: int = 0,
):
    """Print scan completion summary."""
    console.print()

    # Build the content lines
    content_lines = [
        "[bold green]Scan Complete[/]\n",
        f"  [green][+][/] Succeeded: [bold]{succeeded}[/]",
    ]

    if skipped > 0:
        content_lines.append(f"  [yellow][~][/] Skipped: [bold]{skipped}[/] [dim](dual-homed)[/]")

    content_lines.extend([
        f"  [red][-][/] Failed: [bold]{failed}[/]",
        f"  [dim]Total time: {total_time:.2f}s[/]",
        f"  [dim]Avg per target: {avg_time_ms:.0f}ms[/]",
    ])

    console.print(
        Panel(
            "\n".join(content_lines),
            border_style="green" if failed == 0 else "yellow",
        )
    )


# =============================================================================
# Task Output Formatting
# =============================================================================

def format_task_line(
    task_name: str,
    run_as: str,
    is_tier0: bool = False,
    is_privileged: bool = False,
    command: Optional[str] = None,
) -> str:
    """Format a single task line with colors."""
    if is_tier0:
        prefix = "[bold red][TIER-0][/]"
    elif is_privileged:
        prefix = "[yellow][PRIV][/]"
    else:
        prefix = "[dim][TASK][/]"

    line = f"{prefix} {task_name} [dim]→[/] {run_as}"

    if command:
        # Truncate long commands
        if len(command) > 60:
            command = command[:57] + "..."
        line += f"\n        [dim]{command}[/]"

    return line
