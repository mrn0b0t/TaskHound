from typing import Dict, List, Optional

from ..parsers.highvalue import HighValueLoader
from ..utils import logging as log_utils
from ..utils.date_parser import parse_iso_date
from ..utils.sid_resolver import format_runas_with_sid_resolution


def print_results(lines: List[str]):
    if not lines:
        return
    if log_utils._VERBOSE or log_utils._DEBUG:
        print("\n".join(lines))


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
        # Format: [KIND] RunAs | Path | What
        line = f"{header} {display_runas} | {rel_path} | {what}"
        if extra_reason:
            line += f" | {extra_reason}"
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

    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            base.append(f"        Reason  : {extra_reason}")
        elif kind == "TIER-0":
            base.append("        Reason  : Tier 0 privileged group membership")
        else:
            base.append(
                "        Reason  : High Value match found (Check BloodHound Outbound Object Control for Details)"
            )

        # Add password analysis if available
        if password_analysis:
            base.append(f"        Password Analysis : {password_analysis}")

        # Check if we have a decrypted password for this user
        decrypted_password = None
        if decrypted_creds:
            # Normalize the runas for comparison
            runas_normalized = runas.lower()
            for cred in decrypted_creds:
                if cred.username:
                    cred_user_normalized = cred.username.lower()
                    # Match full domain\user or partial matches
                    if cred_user_normalized == runas_normalized:
                        # Exact match
                        decrypted_password = cred.password
                        break
                    elif "\\" in cred_user_normalized and "\\" not in runas_normalized:
                        # Cred has domain, runas doesn't - match on username part only
                        if cred_user_normalized.split("\\")[-1] == runas_normalized:
                            decrypted_password = cred.password
                            break
                    # Note: We DON'T match when runas has domain but cred doesn't
                    # A credential without domain is likely a local account, not domain account

        # Show decrypted password if available, otherwise show next step
        if decrypted_password:
            base.append(f"        Decrypted Password : {decrypted_password}")
        elif not extra_reason or "no saved credentials" not in extra_reason.lower():
            base.append("        Next Step: Try DPAPI Dump / Task Manipulation")

    # Add password analysis for regular TASK entries too (if available)
    elif kind == "TASK":
        if password_analysis:
            base.append(f"        Password Analysis : {password_analysis}")

    return base
