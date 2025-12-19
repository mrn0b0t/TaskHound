# Online processing for live target hosts via SMB.
#
# This module handles connecting to targets via SMB, enumerating scheduled
# tasks, and processing them with privilege detection. The main entry point
# is `process_target()` which returns printable output and populates the
# result rows for export.

import contextlib
import os
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union

from impacket.smbconnection import SessionError

from ..auth import AuthContext
from ..classification import PwdLastSetCache, classify_task
from ..laps import (
    LAPS_ERRORS,
    LAPSCache,
    LAPSFailure,
    get_laps_credential_for_host,
)
from ..models.task import TaskRow
from ..output.printer import format_block
from ..parsers.highvalue import HighValueLoader
from ..parsers.task_xml import parse_task_xml
from ..smb.connection import (
    _dns_ptr_lookup,
    get_server_fqdn,
    get_server_sid,
    smb_connect,
    smb_login,
    smb_negotiate,
)
from ..smb.credguard import check_credential_guard
from ..smb.task_rpc import CredentialStatus, TaskRunInfo, TaskSchedulerRPC
from ..smb.tasks import crawl_tasks, smb_listdir
from ..utils.helpers import is_ipv4
from ..utils.logging import debug as log_debug
from ..utils.logging import good, info, status, warn
from ..utils.sid_resolver import (
    format_runas_with_sid_resolution,
    is_sid,
)
from .helpers import sort_tasks_by_priority


def _match_decrypted_password(runas: str, decrypted_creds: List, resolved_runas: Optional[str] = None) -> Optional[str]:
    """
    Match a task's runas field to decrypted credentials and return the password.

    Handles various runas formats:
    - Simple username: "highpriv"
    - Domain\\user: "DOMAIN\\highpriv"
    - Raw SID: "S-1-5-21-..." (uses resolved_runas if provided)

    Args:
        runas: The RunAs field from the task (may be raw SID)
        decrypted_creds: List of ScheduledTaskCredential objects
        resolved_runas: Pre-resolved username if runas was a SID (from earlier resolution)

    Returns:
        Decrypted password if found, None otherwise
    """
    if not decrypted_creds or not runas:
        return None

    # Build list of usernames to try matching
    usernames_to_try = []

    # If we have a pre-resolved username, use it
    if resolved_runas:
        usernames_to_try.append(resolved_runas.lower())

    # Also try the original runas if it's not a raw SID
    runas_normalized = runas.lower()
    if not is_sid(runas) and runas_normalized not in usernames_to_try:
        usernames_to_try.append(runas_normalized)

    # If no valid usernames to try (unresolved SID), can't match
    if not usernames_to_try:
        return None

    for cred in decrypted_creds:
        if not cred.username:
            continue

        cred_user_normalized = cred.username.lower()

        for try_username in usernames_to_try:
            # Match full domain\user or partial matches
            if cred_user_normalized == try_username:
                # Exact match
                return cred.password
            elif "\\" in cred_user_normalized and "\\" not in try_username:
                # Cred has domain, try_username doesn't - match on username part only
                if cred_user_normalized.split("\\")[-1] == try_username:
                    return cred.password
            elif "\\" in try_username and "\\" not in cred_user_normalized:
                # try_username has domain, cred doesn't - match on username part only
                if try_username.split("\\")[-1] == cred_user_normalized:
                    return cred.password

    return None


def process_target(
    target: str,
    all_rows: List[TaskRow],
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
    ldap_tier0: bool = False,
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
        ldap_tier0: Check Tier-0 group membership via LDAP (when no BloodHound data)

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
    aes_key = auth.aes_key
    kerberos = auth.kerberos
    dc_ip = auth.dc_ip
    timeout = auth.timeout
    dns_tcp = auth.dns_tcp
    ldap_domain = auth.ldap_domain
    ldap_user = auth.ldap_user
    ldap_password = auth.ldap_password
    ldap_hashes = auth.ldap_hashes
    gc_server = auth.gc_server

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
                if is_ipv4(target):
                    # Try DC first, then system DNS
                    if dc_ip:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=dc_ip, use_tcp=dns_tcp)
                    if not discovered_hostname:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=None, use_tcp=dns_tcp)

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
                warn(laps_failure.message, verbose_only=True)
                status(f"[Collecting] {target} [-] (No LAPS password)")
                # Map failure types to human-readable messages
                laps_failure_labels = {
                    "not_found": "LAPS: No password in cache",
                    "encrypted": "LAPS: Encrypted (unsupported)",
                    "auth_failed": "LAPS: Auth failed",
                    "remote_uac": "LAPS: Remote UAC blocked",
                }
                failure_reason = laps_failure_labels.get(laps_failure.failure_type, f"LAPS: {laps_failure.failure_type}")
                all_rows.append(TaskRow.failure(
                    discovered_hostname,
                    failure_reason,
                    target_ip=target,
                ))
                with contextlib.suppress(Exception):
                    smb.close()
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
                warn(LAPS_ERRORS["auth_failed"].format(hostname=discovered_hostname), verbose_only=True)
                status(f"[Collecting] {target} [-] (LAPS auth failed)")
                laps_failure = LAPSFailure(
                    hostname=discovered_hostname,
                    failure_type="auth_failed",
                    message=f"LAPS authentication failed: {e}",
                    laps_user_tried=laps_cred.username,
                    laps_type_tried=laps_cred.laps_type,
                )
                all_rows.append(TaskRow.failure(
                    discovered_hostname,
                    f"LAPS auth failed: {e}",
                    target_ip=target,
                ))
                with contextlib.suppress(Exception):
                    smb.close()
                return out_lines, laps_failure
        else:
            # Standard mode: Direct SMB connection
            smb = smb_connect(
                target, domain, username, hashes or password, kerberos=kerberos, dc_ip=dc_ip, timeout=timeout, aes_key=aes_key
            )

        good(f"{target}: Connected via SMB")

        # Resolve the actual FQDN from SMB connection
        # This is critical when target is an IP address - BloodHound needs FQDNs
        # Tries: 1) SMB hostname, 2) DNS via DC, 3) System DNS

        server_fqdn = get_server_fqdn(smb, target_ip=target, dc_ip=dc_ip, dns_tcp=dns_tcp)
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
        from ..utils.cache_manager import get_cache
        cache = get_cache()
        if cache and server_fqdn != "UNKNOWN_HOST":
            was_first, previous_target = cache.try_mark_host_processed(server_fqdn, target)
            if not was_first:
                warn(f"{target}: Skipping - already processed as {previous_target} (dual-homed host: {server_fqdn})", verbose_only=True)
                status(f"[Collecting] {target} [SKIP] (duplicate of {previous_target})")
                # Add SKIPPED row so async_runner can detect this was a dual-homed skip
                all_rows.append(TaskRow.skipped(
                    host=server_fqdn,
                    reason=f"duplicate of {previous_target}",
                    target_ip=target,
                ))
                # Close SMB connection before returning
                if smb:
                    with contextlib.suppress(Exception):
                        smb.close()
                return [], None

        # Extract the computer account SID using unified resolution
        # Fallback chain: Cache → BloodHound data → LDAP
        # Skipped in OPSEC mode to avoid noisy LDAP calls
        server_sid = None
        if not opsec:
            server_sid = get_server_sid(
                smb, dc_ip=dc_ip, username=username, password=password, hashes=hashes, kerberos=kerberos,
                hv_loader=hv
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
        all_rows.append(TaskRow.failure(
            target,
            f"SMB connection failed: {msg}",
        ))
        if "STATUS_MORE_PROCESSING_REQUIRED" in msg:
            warn(f"{target}: Kerberos auth failed (SPN not found?). Try using FQDNs or switch to NTLM (-k off).", verbose_only=True)
        else:
            warn(f"{target}: SMB connection failed: {e}", verbose_only=True)
        return out_lines, laps_result

    # Quick local admin presence check
    # For LAPS mode, this also detects Remote UAC (LocalAccountTokenFilterPolicy)
    try:
        _ = smb_listdir(smb, "C$", r"\Windows\System32\Tasks")
        good(f"{target}: Local Admin Access confirmed")
    except Exception as e:
        if debug:
            traceback.print_exc()

        error_msg = str(e)

        # Check if this is Remote UAC blocking LAPS
        if laps_used and "STATUS_ACCESS_DENIED" in error_msg:
            warn(LAPS_ERRORS["remote_uac_short"].format(hostname=discovered_hostname or target), verbose_only=True)
            info("Remote UAC (LocalAccountTokenFilterPolicy=0) is filtering the local admin token", verbose_only=True)
            info("This is common on workstations. Servers typically don't have this issue.", verbose_only=True)
            status(f"[Collecting] {target} [-] (Remote UAC)")
            laps_failure = LAPSFailure(
                hostname=discovered_hostname or target,
                failure_type="remote_uac",
                message=LAPS_ERRORS["remote_uac"].format(hostname=discovered_hostname or target),
                laps_user_tried=laps_cred.username if laps_cache else None,
                laps_type_tried=laps_type_used,
            )
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "Remote UAC (token filtered)",
                target_ip=target,
            ))
            return out_lines, laps_failure

        # Check if C$ admin share doesn't exist (DCs, hardened servers, non-Windows)
        elif "STATUS_BAD_NETWORK_NAME" in error_msg:
            warn(f"{target}: C$ admin share not found (may be disabled or non-Windows host)", verbose_only=True)
            status(f"[Collecting] {target} [-] (No C$ share)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "C$ admin share not found",
                target_ip=target,
            ))
            return out_lines, laps_result

        # General access denied (not LAPS-specific)
        elif "STATUS_ACCESS_DENIED" in error_msg:
            warn(f"{target}: Access denied to C$ share", verbose_only=True)
            status(f"[Collecting] {target} [-] (Access Denied)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "Access Denied to C$ share",
                target_ip=target,
            ))
            return out_lines, laps_result

        else:
            warn(f"{target}: Local admin check failed: {e}", verbose_only=True)
            status(f"[Collecting] {target} [-] (Admin check failed)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                f"Admin check failed: {e}",
                target_ip=target,
            ))
            return out_lines, laps_result

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
        all_rows.append(TaskRow.failure(
            target,
            "Access Denied (Failed to crawl tasks)",
        ))
        warn(f"{target}: Failed to Crawl Tasks. Skipping... (Are you Local Admin?)", verbose_only=True)
        return out_lines, laps_result
    except Exception as e:
        if debug:
            traceback.print_exc()
        status(f"[Collecting] {target} [-] ({e})")
        all_rows.append(TaskRow.failure(
            target,
            f"Crawling failed: {e}",
        ))
        warn(f"{target}: Unexpected error while crawling tasks: {e}", verbose_only=True)
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
        # Skip if using ccache-only Kerberos (no credentials to use for RPC)
        if kerberos and not password and not hashes and not aes_key:
            warn(f"{target}: Credential validation not supported with ccache-only Kerberos (use password, --hashes, or --aes-key)")
        else:
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
                    aes_key=aes_key or "",
                    kerberos=kerberos,
                    dc_ip=dc_ip or "",
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
                from ..dpapi.looter import loot_credentials

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
                from ..dpapi.looter import collect_dpapi_files

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
    filtered_count = 0  # Count of tasks that pass should_include filter
    priv_count = 0
    priv_lines: List[str] = []
    task_lines: List[str] = []

    # Pre-fetch pwdLastSet for all unique users via single LDAP batch query
    # This provides password freshness analysis when BloodHound is not available
    # Skipped in OPSEC mode to avoid LDAP queries that may be audited
    pwd_cache: PwdLastSetCache = {}
    if not no_ldap and not opsec and (not hv or not hv.loaded):
        # Collect unique runas users from all tasks with stored credentials
        unique_users = set()
        for _rel_path, xml_bytes in items:
            meta = parse_task_xml(xml_bytes)
            runas = meta.get("runas")
            if not runas:
                continue
            logon_type = (meta.get("logon_type") or "").strip().lower()
            # Only query users from tasks with stored credentials
            if logon_type == "password":
                # Skip SIDs - we can't look them up by SID in LDAP easily
                if not is_sid(runas):
                    unique_users.add(runas)

        if unique_users:
            info(f"{target}: Querying LDAP for password age data ({len(unique_users)} users)...")
            try:
                from ..utils.sid_resolver import batch_get_user_attributes

                ldap_auth_domain = ldap_domain or domain
                ldap_auth_user = ldap_user or username
                ldap_auth_pass = ldap_password or password
                ldap_auth_hashes = ldap_hashes or hashes

                results = batch_get_user_attributes(
                    usernames=list(unique_users),
                    domain=ldap_auth_domain,
                    dc_ip=dc_ip,
                    username=ldap_auth_user,
                    password=ldap_auth_pass,
                    hashes=ldap_auth_hashes,
                    kerberos=kerberos,
                    aes_key=aes_key,
                    attributes=["pwdLastSet", "sAMAccountName"],
                )

                # Build cache: normalized_username -> pwdLastSet datetime
                for norm_user, attrs in results.items():
                    pwd_last_set = attrs.get("pwdLastSet")
                    if pwd_last_set:
                        pwd_cache[norm_user] = pwd_last_set

                if pwd_cache:
                    good(f"{target}: Retrieved password age data for {len(pwd_cache)} users")
                else:
                    info(f"{target}: No password age data available from LDAP")

            except Exception as e:
                warn(f"{target}: LDAP batch query failed: {e}")
                if debug:
                    traceback.print_exc()

    # Pre-fetch Tier-0 group members via LDAP (pre-flight approach)
    # This queries each Tier-0 group once and builds a lookup cache
    # Only enabled with --ldap-tier0 flag (OPSEC: group membership queries may be logged)
    tier0_cache: Dict[str, Tuple[bool, list]] = {}  # username -> (is_tier0, group_list)
    if ldap_tier0 and not no_ldap and (not hv or not hv.loaded):
        info(f"{target}: Fetching Tier-0 group members via LDAP (pre-flight)...")
        try:
            from ..utils.sid_resolver import fetch_tier0_members

            ldap_auth_domain = ldap_domain or domain
            ldap_auth_user = ldap_user or username
            ldap_auth_pass = ldap_password or password
            ldap_auth_hashes = ldap_hashes or hashes

            tier0_cache = fetch_tier0_members(
                domain=ldap_auth_domain,
                dc_ip=dc_ip,
                auth_username=ldap_auth_user,
                auth_password=ldap_auth_pass,
                hashes=ldap_auth_hashes,
                kerberos=kerberos,
                aes_key=aes_key,
            )

            if tier0_cache:
                good(f"{target}: Loaded {len(tier0_cache)} Tier-0 users from LDAP")
            else:
                info(f"{target}: No Tier-0 users found in domain")

        except Exception as e:
            warn(f"{target}: LDAP Tier-0 pre-flight failed: {e}")
            if debug:
                traceback.print_exc()

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
        row = TaskRow.from_meta(hostname, rel_path, meta, target_ip=target, computer_sid=server_sid)

        # Enrich row with credential validation data if available
        # Task paths need normalization: SMB uses "TaskName", RPC uses "\TaskName"
        if cred_validation_results:
            # Try both with and without leading backslash
            rpc_path = "\\" + rel_path if not rel_path.startswith("\\") else rel_path
            rpc_path_alt = rel_path.lstrip("\\")

            task_run_info = cred_validation_results.get(rpc_path) or cred_validation_results.get(rpc_path_alt)
            if task_run_info:
                row.cred_status = task_run_info.credential_status.value
                row.cred_password_valid = task_run_info.password_valid
                row.cred_hijackable = task_run_info.task_hijackable
                row.cred_last_run = task_run_info.last_run.isoformat() if task_run_info.last_run else None
                row.cred_return_code = f"0x{task_run_info.return_code:08X}" if task_run_info.return_code is not None else None
                # Build human-readable detail
                if task_run_info.password_valid:
                    if task_run_info.task_hijackable:
                        row.cred_detail = "Password VALID - task can be hijacked"
                    else:
                        row.cred_detail = f"Password VALID but restricted ({task_run_info.credential_status.value})"
                elif task_run_info.credential_status == CredentialStatus.INVALID:
                    row.cred_detail = "Password INVALID - DPAPI dump not viable"
                elif task_run_info.credential_status == CredentialStatus.BLOCKED:
                    row.cred_detail = "Account blocked/expired - DPAPI dump not viable"
                else:
                    row.cred_detail = f"Unknown status (code: {row.cred_return_code})"

        # Resolve SID early if runas is a SID - store result for credential matching and output
        # This ensures we only resolve once per task, and the result is available for all uses
        # Skipped in OPSEC mode to avoid SMB/LSARPC and LDAP queries
        # Also skip well-known local SIDs (S-1-5-18 SYSTEM, S-1-5-19, S-1-5-20) - they'll be filtered anyway
        if is_sid(runas) and not opsec:
            # Skip SID resolution for well-known local SIDs that will be filtered out
            # This avoids unnecessary cache lookups for SYSTEM (S-1-5-18), etc.
            from ..utils.sid_resolver import looks_like_domain_user
            if not looks_like_domain_user(runas) and not include_local:
                # This SID is a local/system account and we're not including locals
                # Skip resolution - the task will be filtered out in classify_task()
                pass
            else:
                # Derive local domain SID prefix from computer SID for foreign domain detection
                from ..utils.sid_resolver import get_domain_sid_prefix
                local_domain_prefix = get_domain_sid_prefix(server_sid) if server_sid else None

                # Get known domain SID prefixes for unknown domain detection
                # Pass full dict (prefix -> FQDN) for trust-aware display
                known_prefixes = hv.hv_domain_sids if hv and hasattr(hv, 'hv_domain_sids') and hv.hv_domain_sids else None

                _, row.resolved_runas = format_runas_with_sid_resolution(
                    runas,
                    hv_loader=hv,
                    bh_connector=bh_connector,
                    smb_connection=smb,
                    no_ldap=no_ldap,
                    domain=domain,
                    dc_ip=dc_ip,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    local_domain_sid_prefix=local_domain_prefix,
                    known_domain_prefixes=known_prefixes,
                    gc_server=gc_server,
                )

        # Enrich row with decrypted password if available from DPAPI loot
        if decrypted_creds:
            row.decrypted_password = _match_decrypted_password(runas, decrypted_creds, row.resolved_runas)

        # Add Credential Guard status to each row
        row.credential_guard = credguard_status
        # Determine if the task stores credentials or runs with token/S4U (no saved credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in (
            "interactivetoken",
            "s4u",
            "interactivetokenorpassword",
        )
        if no_saved_creds:
            row.credentials_hint = "no_saved_credentials"
        elif logon_type.lower() == "password":
            row.credentials_hint = "stored_credentials"

        # Use shared classification logic
        # pwd_cache was pre-fetched before the loop for password freshness analysis
        # tier0_cache was pre-fetched for LDAP-based Tier-0 detection (when --ldap-tier0)
        result = classify_task(
            row=row,
            meta=meta,
            runas=runas,
            rel_path=rel_path,
            hv=hv,
            show_unsaved_creds=show_unsaved_creds,
            include_local=include_local,
            pwd_cache=pwd_cache,
            tier0_cache=tier0_cache,
            resolved_runas=row.resolved_runas,
        )

        if not result.should_include:
            continue

        filtered_count += 1  # Task passed the filter

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
                    hostname=hostname,
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
                    cred_validation=row.to_dict() if row.cred_status else None,
                    resolved_runas=row.resolved_runas,
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
                    hostname=hostname,
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
                    cred_validation=row.to_dict() if row.cred_status else None,
                    resolved_runas=row.resolved_runas,
                )
            )

        all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = sort_tasks_by_priority(lines)
    backup_msg = f", {total} raw XMLs backed up" if backup_target_dir else ""
    laps_msg = f" (LAPS: {laps_type_used})" if laps_used else ""

    priv_display = priv_count if (hv and hv.loaded) else 'N/A'
    # Show filtered count (domain tasks) vs total (all tasks including SYSTEM)
    if filtered_count < total:
        status(f"[Collected] {target}: {filtered_count} domain tasks ({total} total), {priv_display} Privileged")
    else:
        status(f"[Collected] {target}: {total} Tasks, {priv_display} Privileged")
    good(f"{target}: Found {filtered_count} tasks (of {total} total), privileged {priv_display}{backup_msg}{laps_msg}")

    # Combine credential loot output with task listing output
    # Put credentials first since they're the most valuable
    return out_lines + sorted_lines, laps_result
