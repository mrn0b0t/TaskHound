import re
from typing import Any, Dict, List, Optional

from rich.table import Table

from ..parsers.highvalue import HighValueLoader
from ..utils import logging as log_utils
from ..utils.console import console
from ..utils.date_parser import parse_iso_date
from ..utils.sid_resolver import format_runas_with_sid_resolution

# Color scheme for task output
COLORS = {
    "tier0_header": "bold red",
    "tier0_border": "red",
    "priv_header": "bold yellow",
    "priv_border": "yellow",
    "task_header": "bold green",
    "task_border": "green",
    "label": "dim",
    "value": "white",
    "password": "bold green",
    "warning": "yellow",
    "error": "red",
    "success": "green",
}


def print_results(lines: List[str]):
    """
    Legacy print function - no longer prints to console.

    Tables are now printed directly by format_block() via print_task_table().
    This function exists for backward compatibility but does nothing since
    the Rich tables are already printed when format_block is called.

    The text lines are still used for file output (--plain flag).
    """
    # Tables are already printed by print_task_table() in format_block()
    # This function is kept for API compatibility but no longer prints
    pass


def print_task_table(
    kind: str,
    rel_path: str,
    rows: List[tuple],
) -> None:
    """
    Print a task as a Rich table with colored borders.

    Args:
        kind: Task classification ('TIER-0', 'PRIV', or 'TASK')
        rel_path: Task path for the header
        rows: List of (label, value) tuples to display
    """
    if not (log_utils._VERBOSE or log_utils._DEBUG):
        return

    # Select colors based on task kind
    if kind == "TIER-0":
        header_style = COLORS["tier0_header"]
        border_style = COLORS["tier0_border"]
        tag = "[TIER-0]"
    elif kind == "PRIV":
        header_style = COLORS["priv_header"]
        border_style = COLORS["priv_border"]
        tag = "[PRIV]"
    else:
        header_style = COLORS["task_header"]
        border_style = COLORS["task_border"]
        tag = "[TASK]"

    # Build the title with tag and path
    title = f"[{header_style}]{tag}[/] {rel_path}"

    # Create a simple two-column table
    table = Table(
        title=title,
        title_style=header_style,
        border_style=border_style,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )

    table.add_column("Field", style=COLORS["label"], width=18)
    table.add_column("Value", style=COLORS["value"])

    # Add rows with special coloring for certain fields
    for label, value in rows:
        value_style = COLORS["value"]

        # Apply special styling to certain values
        if label == "Decrypted Pwd" and value:
            value_style = COLORS["password"]
        elif label == "Cred Validation":
            if "[+]" in value:
                value_style = COLORS["success"]
            elif "[-]" in value:
                value_style = COLORS["error"]
            elif "[?]" in value:
                value_style = COLORS["warning"]
        elif label == "Pwd Analysis":
            if "GOOD" in value.upper() or "newer" in value.lower():
                value_style = COLORS["success"]
            elif "BAD" in value.upper() or "stale" in value.lower():
                value_style = COLORS["warning"]
        elif label == "Enabled":
            if value.lower() == "true":
                value_style = COLORS["success"]
            elif value.lower() == "false":
                value_style = COLORS["warning"]

        table.add_row(f"[{COLORS['label']}]{label}[/]", f"[{value_style}]{value}[/]")

    console.print()
    console.print(table)


def format_trigger_info(meta: Dict[str, str]) -> Optional[str]:
    """Format trigger information for display"""
    trigger_type = meta.get("trigger_type")
    if not trigger_type:
        return None

    trigger_parts = [trigger_type]

    if trigger_type == "Calendar":
        # Format calendar trigger details
        start_boundary = meta.get("start_boundary")
        interval = meta.get("interval")
        duration = meta.get("duration")
        days_interval = meta.get("days_interval")

        details = []
        if start_boundary:
            # Parse the start boundary for better display
            dt = parse_iso_date(start_boundary)
            if dt:
                details.append(f"starts {dt.strftime('%Y-%m-%d %H:%M')}")
            else:
                details.append(f"starts {start_boundary}")

        if interval:
            # Parse ISO 8601 duration format (PT5M = 5 minutes)
            interval_display = interval
            if interval.startswith("PT"):
                interval_clean = interval[2:]  # Remove 'PT' prefix
                if interval_clean.endswith("M"):
                    minutes = interval_clean[:-1]
                    interval_display = f"{minutes} minutes"
                elif interval_clean.endswith("H"):
                    hours = interval_clean[:-1]
                    interval_display = f"{hours} hours"
                elif interval_clean.endswith("S"):
                    seconds = interval_clean[:-1]
                    interval_display = f"{seconds} seconds"
            details.append(f"every {interval_display}")

        if duration:
            # Parse ISO 8601 duration format (P1D = 1 day)
            duration_display = duration
            if duration.startswith("P"):
                duration_clean = duration[1:]  # Remove 'P' prefix
                if duration_clean.endswith("D"):
                    days = duration_clean[:-1]
                    duration_display = f"{days} day{'s' if days != '1' else ''}"
                elif "T" in duration_clean:
                    # Has time component
                    duration_display = duration  # Keep original for complex durations
            details.append(f"for {duration_display}")

        if days_interval:
            if days_interval == "1":
                details.append("daily")
            else:
                details.append(f"every {days_interval} days")

        if details:
            trigger_parts.append(f"({', '.join(details)})")

    elif trigger_type == "Time":
        start_boundary = meta.get("start_boundary")
        if start_boundary:
            dt = parse_iso_date(start_boundary)
            if dt:
                trigger_parts.append(f"at {dt.strftime('%Y-%m-%d %H:%M')}")
            else:
                trigger_parts.append(f"at {start_boundary}")

    return " ".join(trigger_parts) if len(trigger_parts) > 1 else trigger_type


def _check_gmsa_account(display_runas: str, resolved_username: Optional[str] = None) -> Optional[str]:
    """
    Check if the runas account is a gMSA (Group Managed Service Account).

    gMSA accounts:
    - End with '$' character
    - Are NOT machine/computer accounts (typically match computer name)
    - Are NOT well-known system accounts (NT AUTHORITY, etc.)

    Args:
        display_runas: The display string for the runas account
        resolved_username: The resolved username (if SID was resolved)

    Returns:
        Hint message if gMSA detected, None otherwise
    """
    # Get the username to check - prefer resolved, fall back to display
    username = resolved_username or display_runas
    if not username:
        return None

    # Extract just the username part (remove domain prefix)
    if "\\" in username:
        username = username.split("\\")[-1]
    elif "@" in username:
        username = username.split("@")[0]

    # Check if it ends with $ (service or machine account)
    if not username.endswith("$"):
        return None

    # Skip well-known system accounts
    well_known_skip = {
        "system", "local service", "network service",
        "nt authority", "nt service", "iis apppool"
    }
    display_lower = display_runas.lower()

    for skip in well_known_skip:
        if skip in display_lower:
            return None

    # At this point we have an account ending with $
    # This is likely a gMSA - machine accounts are less common for scheduled tasks
    return "gMSA credentials are stored in LSA secrets, not DPAPI. Consider LSA dump if you have SYSTEM access."


def format_block(
    kind: str,
    rel_path: str,
    runas: str,
    what: str,
    author: str,
    date: str,
    extra_reason: Optional[str] = None,
    password_analysis: Optional[str] = None,
    hv: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    enabled: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    meta: Optional[Dict[str, str]] = None,
    decrypted_creds: Optional[List] = None,
    concise: bool = False,
    cred_validation: Optional[Dict[str, Any]] = None,
    resolved_runas: Optional[str] = None,
) -> List[str]:
    """
    Format a task block for CLI output.

    Returns list of strings for file output, and prints a Rich table to console.

    Args:
        kind: 'TIER-0', 'PRIV' (privileged/high-value) or 'TASK' (normal task)
        rel_path: Task path relative to Tasks folder
        runas: The RunAs user/SID
        what: Command/action the task executes
        ... (other args for enrichment)
    """
    if kind == "TIER-0":
        header = "[TIER-0]"
    elif kind == "PRIV":
        header = "[PRIV]"
    else:
        header = "[TASK]"

    # Use pre-resolved username if available, otherwise resolve now
    if resolved_runas:
        # Already resolved - format display string
        from ..utils.sid_resolver import is_sid
        display_runas = f"{resolved_runas} ({runas})" if is_sid(runas) else runas
        resolved_username = resolved_runas
    else:
        # Resolve SID in RunAs field for better display (uses 4-tier fallback: offline BH → API → SMB → LDAP)
        display_runas, resolved_username = format_runas_with_sid_resolution(
            runas,
            hv,
            bh_connector,
            smb_connection,
            no_ldap,
            domain,
            dc_ip,
            username,
            password,
            hashes,
            kerberos,
            ldap_domain,
            ldap_user,
            ldap_password,
            ldap_hashes,
        )

    if concise:
        # Concise output: One line per task
        # Format: [KIND] RunAs | Path | What | (optional reason) | (optional password)
        line = f"{header} {display_runas} | {rel_path} | {what}"
        if extra_reason:
            line += f" | {extra_reason}"

        # In concise mode, show decrypted password inline if available for ALL task types
        if decrypted_creds:
            runas_normalized = runas.lower()
            if " (s-1-5-" in runas_normalized:
                runas_normalized = runas_normalized.split(" (s-1-5-")[0].strip()

            for cred in decrypted_creds:
                if cred.username:
                    cred_user_normalized = cred.username.lower()
                    matched = False
                    if cred_user_normalized == runas_normalized:
                        matched = True
                    elif "\\" in cred_user_normalized and "\\" not in runas_normalized:
                        if cred_user_normalized.split("\\")[-1] == runas_normalized:
                            matched = True
                    elif "\\" in runas_normalized and "\\" not in cred_user_normalized:
                        if runas_normalized.split("\\")[-1] == cred_user_normalized:
                            matched = True
                    if matched:
                        line += f" | PWD: {cred.password}"
                        break

        return [line]

    # Build rows for table output: list of (label, value) tuples
    rows: List[tuple] = []

    # Add task state information as first field
    if enabled is not None:
        enabled_display = enabled.capitalize() if enabled.lower() in ["true", "false"] else enabled
        rows.append(("Enabled", enabled_display))

    # Core task information
    rows.append(("RunAs", display_runas))
    rows.append(("What", what))

    if author:
        rows.append(("Author", author))
    if date:
        rows.append(("Date", date))

    # Trigger information
    if meta:
        trigger_info = format_trigger_info(meta)
        if trigger_info:
            rows.append(("Trigger", trigger_info))

    # Password analysis
    if password_analysis:
        rows.append(("Pwd Analysis", password_analysis))

    # Credential validation results
    if cred_validation:
        cred_status = cred_validation.get("cred_status")
        cred_valid = cred_validation.get("cred_password_valid")
        cred_hijackable = cred_validation.get("cred_hijackable")
        cred_detail = cred_validation.get("cred_detail")
        cred_code = cred_validation.get("cred_return_code")
        cred_last_run = cred_validation.get("cred_last_run")

        # Build status display
        if cred_status == "unknown":
            if password_analysis and "GOOD" in password_analysis.upper():
                status_display = "[+] LIKELY VALID (task never ran, but password newer than pwdLastSet)"
            elif password_analysis and "BAD" in password_analysis.upper():
                status_display = "[-] LIKELY INVALID (task never ran, password older than pwdLastSet)"
            else:
                status_display = f"[?] UNKNOWN - task never ran ({cred_code})"
        elif cred_valid is True:
            status_display = "[+] VALID (hijackable)" if cred_hijackable else f"[+] VALID (restricted: {cred_status})"
        elif cred_status == "invalid":
            status_display = "[-] INVALID (wrong password)"
        elif cred_status == "blocked":
            status_display = "[-] BLOCKED (account disabled/expired)"
        else:
            status_display = f"[?] {cred_status} ({cred_code})"

        rows.append(("Cred Validation", status_display))

        if cred_last_run:
            rows.append(("Last Run", cred_last_run))

        if cred_code:
            from ..smb.task_rpc import get_return_code_description
            try:
                code_int = int(cred_code, 16) if cred_code.startswith("0x") else int(cred_code)
                code_desc = get_return_code_description(code_int)
                rows.append(("Return Code", f"{cred_code} ({code_desc})"))
            except (ValueError, TypeError):
                rows.append(("Return Code", cred_code))

        if cred_detail and not cred_hijackable:
            rows.append(("Cred Detail", cred_detail))

    # Find decrypted password for this user
    decrypted_password = _find_decrypted_password(
        decrypted_creds, runas, display_runas, resolved_username
    )

    if decrypted_password:
        rows.append(("Decrypted Pwd", decrypted_password))

    # gMSA hint
    gmsa_hint = _check_gmsa_account(display_runas, resolved_username)
    if gmsa_hint:
        rows.append(("gMSA Hint", gmsa_hint))

    # Reason for privileged tasks
    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            rows.append(("Reason", extra_reason))
        elif kind == "TIER-0":
            rows.append(("Reason", "Tier 0 privileged group membership"))
        else:
            rows.append(("Reason", "High Value match found (Check BloodHound Outbound Object Control for Details)"))

        if not decrypted_password and (not extra_reason or "no saved credentials" not in extra_reason.lower()):
            rows.append(("Next Step", "Try DPAPI Dump / Task Manipulation"))

    # Print Rich table to console
    print_task_table(kind, rel_path, rows)

    # Return text format for file output (backward compatibility)
    # Label width is 18 chars + 1 space before colon = 19 chars total before ":"
    base = [f"\n{header} {rel_path}"]
    for label, value in rows:
        base.append(f"        {label:<18} : {value}")

    return base


def _find_decrypted_password(
    decrypted_creds: Optional[List],
    runas: str,
    display_runas: str,
    resolved_username: Optional[str],
) -> Optional[str]:
    """Find decrypted password matching the runas user."""
    if not decrypted_creds:
        return None

    usernames_to_try = []

    # Add resolved username from SID resolution
    if resolved_username:
        usernames_to_try.append(resolved_username.lower())

    # Extract from display_runas format "username (S-1-5-21-...)"
    display_runas_lower = display_runas.lower()
    if " (s-1-5-" in display_runas_lower:
        username_part = display_runas_lower.split(" (s-1-5-")[0].strip()
        if username_part and username_part not in usernames_to_try:
            usernames_to_try.append(username_part)
    elif not display_runas_lower.startswith("s-1-5-"):
        if display_runas_lower not in usernames_to_try:
            usernames_to_try.append(display_runas_lower)

    # Try the original runas if it's not a raw SID
    runas_normalized = runas.lower()
    if not runas_normalized.startswith("s-1-5-"):
        if " (s-1-5-" in runas_normalized:
            username_part = runas_normalized.split(" (s-1-5-")[0].strip()
            if username_part and username_part not in usernames_to_try:
                usernames_to_try.append(username_part)
        elif runas_normalized not in usernames_to_try:
            usernames_to_try.append(runas_normalized)

    for cred in decrypted_creds:
        if cred.username:
            cred_user_normalized = cred.username.lower()

            for try_username in usernames_to_try:
                if cred_user_normalized == try_username:
                    return cred.password
                elif "\\" in cred_user_normalized and "\\" not in try_username:
                    if cred_user_normalized.split("\\")[-1] == try_username:
                        return cred.password
                elif "\\" in try_username and "\\" not in cred_user_normalized:
                    if try_username.split("\\")[-1] == cred_user_normalized:
                        return cred.password

    return None

