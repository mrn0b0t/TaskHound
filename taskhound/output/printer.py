import re
from typing import Any, Dict, List, Optional

from ..parsers.highvalue import HighValueLoader
from ..utils import logging as log_utils
from ..utils.console import console
from ..utils.date_parser import parse_iso_date
from ..utils.sid_resolver import format_runas_with_sid_resolution


def print_results(lines: List[str]):
    """Print task results with colored tags in verbose mode."""
    if not lines:
        return
    if log_utils._VERBOSE or log_utils._DEBUG:
        for line in lines:
            # Colorize task type tags
            colored_line = line
            if line.startswith("[TIER-0]") or "\n[TIER-0]" in line:
                colored_line = re.sub(
                    r"\[TIER-0\](.*)$",
                    r"[bold red][TIER-0][/][red]\1[/]",
                    line,
                    flags=re.MULTILINE,
                )
            elif line.startswith("[PRIV]") or "\n[PRIV]" in line:
                colored_line = re.sub(
                    r"\[PRIV\](.*)$",
                    r"[bold yellow][PRIV][/][yellow]\1[/]",
                    line,
                    flags=re.MULTILINE,
                )
            elif line.startswith("[TASK]") or "\n[TASK]" in line:
                colored_line = re.sub(
                    r"\[TASK\](.*)$",
                    r"[bold green][TASK][/][green]\1[/]",
                    line,
                    flags=re.MULTILINE,
                )
            console.print(colored_line)


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
    # Format a small pretty-print block used by the CLI output.
    #
    # kind is either 'TIER-0', 'PRIV' (privileged/high-value) or 'TASK' (normal task).
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
        if is_sid(runas):
            display_runas = f"{resolved_runas} ({runas})"
        else:
            display_runas = runas
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
        # Even [TASK] entries may have useful credentials (lateral movement, password reuse)
        if decrypted_creds:
            # Normalize the runas for comparison
            # Handle resolved SID format: "username (S-1-5-21-...)" -> extract just username
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

    base = [f"\n{header} {rel_path}"]

    # Add task state information as first field
    if enabled is not None:
        enabled_display = enabled.capitalize() if enabled.lower() in ["true", "false"] else enabled
        base.append(f"        Enabled : {enabled_display}")

    # Add other task information with proper alignment
    base.extend([f"        RunAs   : {display_runas}", f"        What    : {what}"])
    if author:
        base.append(f"        Author  : {author}")
    if date:
        base.append(f"        Date    : {date}")

    # Add trigger information if available
    if meta:
        trigger_info = format_trigger_info(meta)
        if trigger_info:
            base.append(f"        Trigger : {trigger_info}")

    # Add password analysis if available - show for ALL task types
    # Even [TASK] entries benefit from knowing if credentials are fresh/stale
    if password_analysis:
        base.append(f"        Password Analysis : {password_analysis}")

    # Add credential validation results if available (from --validate-creds)
    # Logic: RPC validation is authoritative when available, but falls back to
    # password analysis when RPC returns UNKNOWN (task never ran)
    # Show for ALL task types - credential validity is useful regardless of classification
    if cred_validation:
        cred_status = cred_validation.get("cred_status")
        cred_valid = cred_validation.get("cred_password_valid")
        cred_hijackable = cred_validation.get("cred_hijackable")
        cred_detail = cred_validation.get("cred_detail")
        cred_code = cred_validation.get("cred_return_code")
        cred_last_run = cred_validation.get("cred_last_run")

        # Check status enum first, then password_valid boolean
        if cred_status == "unknown":
            # RPC couldn't determine - fall back to password analysis if available
            if password_analysis and "GOOD" in password_analysis.upper():
                status_display = "[+] LIKELY VALID (task never ran, but password newer than pwdLastSet)"
            elif password_analysis and "BAD" in password_analysis.upper():
                status_display = "[-] LIKELY INVALID (task never ran, password older than pwdLastSet)"
            else:
                status_display = f"[?] UNKNOWN - task never ran ({cred_code})"
        elif cred_valid is True:
            if cred_hijackable:
                status_display = "[+] VALID (hijackable)"
            else:
                status_display = f"[+] VALID (restricted: {cred_status})"
        elif cred_status == "invalid":
            status_display = "[-] INVALID (wrong password)"
        elif cred_status == "blocked":
            status_display = "[-] BLOCKED (account disabled/expired)"
        else:
            status_display = f"[?] {cred_status} ({cred_code})"

        base.append(f"        Cred Validation : {status_display}")
        
        # Show detailed credential validation info
        # Last run time (human readable)
        if cred_last_run:
            base.append(f"        Last Run        : {cred_last_run}")
        
        # Return code with description
        if cred_code:
            from ..smb.task_rpc import get_return_code_description
            # Parse hex code back to int for description lookup
            try:
                code_int = int(cred_code, 16) if cred_code.startswith("0x") else int(cred_code)
                code_desc = get_return_code_description(code_int)
                base.append(f"        Return Code     : {cred_code} ({code_desc})")
            except (ValueError, TypeError):
                base.append(f"        Return Code     : {cred_code}")
        
        # Show detail for restricted accounts or failures
        if cred_detail and not cred_hijackable:
            base.append(f"        Cred Detail     : {cred_detail}")

    # Check if we have a decrypted password for this user - show for ALL task types
    # Even [TASK] entries may have useful credentials (lateral movement, password reuse)
    decrypted_password = None
    if decrypted_creds:
        # Use resolved_username if available (handles SID-only runas fields)
        # Also try the display_runas which may have "username (SID)" format
        usernames_to_try = []
        
        # Add resolved username from SID resolution
        if resolved_username:
            usernames_to_try.append(resolved_username.lower())
        
        # Also try extracting from display_runas format "username (S-1-5-21-...)"
        display_runas_lower = display_runas.lower()
        if " (s-1-5-" in display_runas_lower:
            username_part = display_runas_lower.split(" (s-1-5-")[0].strip()
            if username_part and username_part not in usernames_to_try:
                usernames_to_try.append(username_part)
        elif not display_runas_lower.startswith("s-1-5-"):
            # Not a raw SID, add as-is
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
                    # Match full domain\user or partial matches
                    if cred_user_normalized == try_username:
                        # Exact match
                        decrypted_password = cred.password
                        break
                    elif "\\" in cred_user_normalized and "\\" not in try_username:
                        # Cred has domain, try_username doesn't - match on username part only
                        if cred_user_normalized.split("\\")[-1] == try_username:
                            decrypted_password = cred.password
                            break
                    elif "\\" in try_username and "\\" not in cred_user_normalized:
                        # try_username has domain, cred doesn't - match on username part only
                        if try_username.split("\\")[-1] == cred_user_normalized:
                            decrypted_password = cred.password
                            break
                
                if decrypted_password:
                    break

    # Show decrypted password if available
    if decrypted_password:
        base.append(f"        Decrypted Password : {decrypted_password}")

    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            base.append(f"        Reason  : {extra_reason}")
        elif kind == "TIER-0":
            base.append("        Reason  : Tier 0 privileged group membership")
        else:
            base.append(
                "        Reason  : High Value match found (Check BloodHound Outbound Object Control for Details)"
            )

        # Show next step hint only if we didn't find a decrypted password
        if not decrypted_password and (not extra_reason or "no saved credentials" not in extra_reason.lower()):
            base.append("        Next Step: Try DPAPI Dump / Task Manipulation")

    return base

