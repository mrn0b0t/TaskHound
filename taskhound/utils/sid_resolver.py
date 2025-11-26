# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.
# REFACTORED: Now uses Impacket LDAP with NTLM hash support

import re
import socket
import struct
from typing import Optional, Tuple

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..parsers.highvalue import HighValueLoader
from ..utils.cache_manager import get_cache
from ..utils.ldap import LDAPConnectionError, get_ldap_connection
from ..utils.logging import debug, info, warn


def resolve_sid_via_smb(sid: str, smb_connection) -> Optional[str]:
    """
    Resolve SID to username using LSARPC over an existing SMB connection.

    This is useful when we have a valid SMB session (e.g. via Kerberos CIFS ticket)
    but cannot authenticate to the DC via LDAP (e.g. missing TGT/LDAP ticket).

    Args:
        sid: Windows SID to resolve
        smb_connection: Active impacket.smbconnection.SMBConnection

    Returns:
        Resolved username (DOMAIN\\User) or None
    """
    if not smb_connection:
        return None

    try:
        from impacket.dcerpc.v5 import lsad, lsat, transport
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        debug(f"Attempting SMB/LSARPC resolution for SID: {sid}")

        # Connect to LSARPC pipe
        # We reuse the existing SMB connection
        rpctransport = transport.SMBTransport(
            smb_connection.getRemoteName(),
            smb_connection.getRemoteHost(),
            filename=r"\lsarpc",
            smb_connection=smb_connection,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        # Open policy using lsad module (hLsarOpenPolicy2 is in lsad, not lsat)
        # We need POLICY_LOOKUP_NAMES to resolve SIDs
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp["PolicyHandle"]

        # Lookup SID
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]

            if names:
                name_entry = names[0]
                domain_idx = name_entry["DomainIndex"]
                name = name_entry["Name"]

                # If we have a domain index, try to resolve domain name too
                domain_name = ""
                if domain_idx >= 0 and domain_idx < len(domains):
                    domain_name = domains[domain_idx]["Name"]

                full_name = f"{domain_name}\\{name}" if domain_name else name
                info(f"Resolved SID {sid} to {full_name} via SMB/LSARPC")
                return full_name

        except DCERPCException as e:
            debug(f"LSARPC lookup failed for {sid}: {e}")
        finally:
            # Always try to close the handle if we opened it, though dce.disconnect handles cleanup usually
            pass

        dce.disconnect()

    except Exception as e:
        debug(f"SMB SID resolution failed: {e}")

    return None


def is_sid(value: str) -> bool:
    """Check if a string looks like a Windows SID."""
    if not value:
        return False
    # SID pattern: S-1-<revision>-<authority>-<sub-authorities>
    # Must have at least revision and authority, sub-authorities are optional but common
    pattern = r"^S-1-\d+(-\d+)+$"  # At least one sub-authority required
    return bool(re.match(pattern, value.strip()))


def sid_to_binary(sid_string: str) -> Optional[bytes]:
    """
    Convert a SID string (S-1-5-21-...) to binary format for LDAP queries.

    Args:
        sid_string: String representation of SID

    Returns:
        Binary representation of SID for LDAP queries, None if invalid
    """
    try:
        if not sid_string.startswith("S-"):
            return None

        parts = sid_string[2:].split("-")
        if len(parts) < 3:
            return None

        revision = int(parts[0])
        authority = int(parts[1])
        subauthorities = [int(x) for x in parts[2:]]

        # Pack the SID according to Windows SID binary format
        # Revision (1 byte) + SubAuthorityCount (1 byte) + Authority (6 bytes) + SubAuthorities (4 bytes each)
        binary_sid = struct.pack("B", revision)  # Revision
        binary_sid += struct.pack("B", len(subauthorities))  # SubAuthorityCount
        binary_sid += struct.pack(">Q", authority)[2:]  # Authority (6 bytes, big-endian)

        for subauth in subauthorities:
            binary_sid += struct.pack("<I", subauth)  # SubAuthorities (little-endian)

        return binary_sid

    except (ValueError, struct.error) as e:
        debug(f"Error converting SID {sid_string} to binary: {e}")
        return None


def binary_to_sid(binary_sid: bytes) -> Optional[str]:
    """
    Convert a binary SID (from LDAP objectSid attribute) to string format.

    Args:
        binary_sid: Binary representation of SID from LDAP

    Returns:
        String representation like "S-1-5-21-...", None if invalid
    """
    try:
        if not binary_sid or len(binary_sid) < 8:
            return None

        # Unpack the SID binary format
        revision = struct.unpack("B", binary_sid[0:1])[0]
        subauth_count = struct.unpack("B", binary_sid[1:2])[0]

        # Authority is 6 bytes, big-endian (bytes 2-8)
        # We need to pad it to 8 bytes for unpacking as Q
        authority = struct.unpack(">Q", b"\x00\x00" + binary_sid[2:8])[0]

        # Build the SID string
        sid_parts = [f"S-{revision}-{authority}"]

        # Extract sub-authorities (4 bytes each, little-endian)
        offset = 8
        for _ in range(subauth_count):
            if offset + 4 > len(binary_sid):
                debug("Binary SID too short for claimed sub-authority count")
                return None
            subauth = struct.unpack("<I", binary_sid[offset : offset + 4])[0]
            sid_parts.append(str(subauth))
            offset += 4

        return "-".join(sid_parts)

    except (ValueError, struct.error) as e:
        debug(f"Error converting binary SID to string: {e}")
        return None


def resolve_sid_from_bloodhound(sid: str, hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Resolve SID to username using BloodHound data.

    Args:
        sid: Windows SID to resolve
        hv_loader: Loaded BloodHound data (can be None)

    Returns:
        Username if found in BloodHound data, None otherwise
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Check if SID exists in BloodHound data
    user_data = hv_loader.hv_sids.get(sid)
    if user_data:
        # Try to get samaccountname or name
        username = user_data.get("samaccountname") or user_data.get("name")
        if username:
            info(f"Resolved SID {sid} to {username} via BloodHound data")
            return username.strip().strip('"')

    return None


def resolve_sid_via_bloodhound_api(sid: str, bh_connector) -> Optional[str]:
    """
    Resolve SID to username using live BloodHound API queries.

    This extends offline BloodHound data by querying the live database for SIDs
    that may exist in BloodHound but weren't in the offline export.

    **Roadmap Feature:** Enhanced SID Resolution fallback chain
    Combines BloodHound offline data, live API queries, and LDAP for comprehensive SID lookups.

    Args:
        sid: Windows SID to resolve
        bh_connector: BloodHoundConnector instance with active connection

    Returns:
        Username if found via BloodHound API, None otherwise
    """
    if not bh_connector:
        return None

    try:
        # Build Cypher query to find user or computer by objectId (SID)
        query = f'MATCH (n) WHERE n.objectid = "{sid}" RETURN n.name AS name LIMIT 1'

        data = bh_connector.run_cypher_query(query)

        if data:
            # Extract name from Cypher query result
            if "data" in data and "data" in data["data"] and len(data["data"]["data"]) > 0:
                result = data["data"]["data"][0]
                if result and "name" in result:
                    username = result["name"]
                    info(f"Resolved SID {sid} to {username} via BloodHound API")
                    return username
        else:
            debug(f"BloodHound API SID query returned no data")

    except Exception as e:
        debug(f"BloodHound API SID resolution failed: {e}")

    return None


def resolve_sid_via_ldap(
    sid: str,
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a SID to a username using LDAP queries to a domain controller.

    This function attempts to query Active Directory via LDAP to resolve a SID to a username.
    It uses the provided credentials for authentication and supports both NTLM and Kerberos.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!

    Args:
        sid: The Windows SID to resolve (e.g., "S-1-5-21-...")
        domain: The domain name (e.g., "corp.local")
        dc_ip: Domain controller IP address (optional, will try to resolve from domain if not provided)
        username: LDAP authentication username (can be different from the SID being resolved)
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash (format: lm:nt or just nt)
        kerberos: Use Kerberos authentication

    Returns:
        The resolved username (sAMAccountName), None if resolution fails
    """
    try:
        debug(f"Attempting LDAP resolution for SID: {sid}")

        if not username or not (password or hashes or kerberos):
            debug("No valid credentials provided for LDAP SID resolution")
            return None

        # If no DC IP provided, try to resolve it
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to DC IP: {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP address")
                return None

        # Convert SID to binary format for LDAP search
        binary_sid = sid_to_binary(sid)
        if not binary_sid:
            warn(f"Could not convert SID {sid} to binary format")
            return None

        # Get LDAP connection using shared utility
        try:
            conn = get_ldap_connection(
                dc_ip=dc_ip,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
        except LDAPConnectionError as e:
            warn(f"Failed to connect to LDAP server {dc_ip} for SID resolution: {e}")
            return None

        # Build search base DN from domain
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter using binary SID
        # Impacket expects hex-escaped binary format
        binary_sid_escaped = "".join([f"\\{b:02x}" for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName", "name", "displayName", "objectClass"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Try different name attributes in order of preference
                        sam_account_name = attributes.get("sAMAccountName")
                        display_name = attributes.get("displayName")
                        name = attributes.get("name")

                        username_resolved = sam_account_name or display_name or name

                        if username_resolved:
                            info(f"Resolved SID {sid} to {username_resolved} via LDAP")
                            return username_resolved.strip()
                        else:
                            debug(f"No usable name attribute found in LDAP entry for SID {sid}")
            else:
                debug(f"No LDAP entries found for SID {sid}")

        except Exception as e:
            warn(f"LDAP search error during SID resolution: {e}")
            return None

        return None

    except Exception as e:
        warn(f"Unexpected error during LDAP SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_name_to_sid_via_ldap(
    name: str,
    domain: str,
    is_computer: bool = False,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a computer name or username to its SID using LDAP.
    This is the reverse operation of resolve_sid_via_ldap.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!

    Args:
        name: Computer name (without domain) or username (USER@DOMAIN.TLD format or just USER)
        domain: Domain name (e.g., "corp.local")
        is_computer: True if resolving a computer account, False for user
        dc_ip: Domain controller IP address (optional, will try to resolve if not provided)
        username: LDAP authentication username (can be different from the name being resolved)
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash (format: lm:nt or just nt)
        kerberos: Use Kerberos authentication

    Returns:
        SID string (e.g., "S-1-5-21-..."), None if resolution fails
    """
    try:
        # Extract just the name part if it's in USER@DOMAIN format
        search_name = name
        if "@" in name and not is_computer:
            search_name = name.split("@")[0]

        # For computers, strip the trailing $ if present
        if is_computer and search_name.endswith("$"):
            search_name = search_name[:-1]
        
        # For computers, also strip the domain suffix (FQDN -> hostname)
        # e.g., "testclient2.badsuccessor.lab" -> "testclient2"
        if is_computer and "." in search_name:
            search_name = search_name.split(".")[0]

        # If no DC IP provided, try to resolve it
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to DC IP: {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP address")
                return None

        # Get LDAP connection using shared utility
        try:
            conn = get_ldap_connection(
                dc_ip=dc_ip,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
        except LDAPConnectionError as e:
            warn(f"Failed to connect to LDAP server {dc_ip} for name resolution: {e}")
            return None

        debug(f"Successfully bound to LDAP server {dc_ip}")

        # Build search base DN from domain
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter based on object type
        if is_computer:
            # For computers, search by cn (computer name without $)
            search_filter = f"(&(objectClass=computer)(cn={search_name}))"
        else:
            # For users, try both samAccountName and userPrincipalName
            if "@" in name:
                search_filter = f"(&(objectClass=user)(|(userPrincipalName={name})(samAccountName={search_name})))"
            else:
                search_filter = f"(&(objectClass=user)(samAccountName={search_name}))"

        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["objectSid", "sAMAccountName", "cn"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            # objectSid is binary, keep as bytes
                            if attr_name.lower() == "objectsid":
                                # Get raw bytes
                                attr_vals = [bytes(val) for val in attribute["vals"]]
                            else:
                                attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Extract the binary objectSid
                        binary_sid = attributes.get("objectSid")

                        if binary_sid and isinstance(binary_sid, bytes):
                            # Convert binary SID to string
                            sid_string = binary_to_sid(binary_sid)

                            if sid_string:
                                account_name = attributes.get("sAMAccountName") or attributes.get("cn") or name
                                info(f"Resolved {account_name} to SID {sid_string} via LDAP")
                                return sid_string
                            else:
                                debug(f"Failed to convert binary SID to string for {name}")
                        else:
                            debug(f"No objectSid attribute found in LDAP entry for {name}")
            else:
                debug(f"No LDAP entries found for {name}")

        except Exception as e:
            warn(f"LDAP search error during name→SID resolution: {e}")
            return None

        return None

    except Exception as e:
        warn(f"Unexpected error during LDAP name→SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def looks_like_domain_user(runas: str) -> bool:
    r"""
    Return True when `runas` appears to represent a domain account.

    The function returns False for well-known local/system principals
    (including common German translations seen in German-language
    Windows installations). It treats values with a backslash (NETBIOS\user)
    or values containing a dot (user@domain-like or UPN) as domain-like.
    It also recognizes domain SIDs (S-1-5-21-*-*-*-RID) as domain accounts.
    """
    if not runas:
        return False

    val = runas.strip()

    # Check if this is a SID format
    if val.upper().startswith("S-1-"):
        # Exclude well-known local SIDs (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
        up = val.upper()
        if up.startswith("S-1-5-18") or up.startswith("S-1-5-19") or up.startswith("S-1-5-20"):
            return False

        # Domain SIDs have pattern S-1-5-21-domain-domain-domain-rid
        return up.startswith("S-1-5-21-")

    # If username contains a backslash (DOMAIN\user), check for local/system principals
    if "\\" in val:
        domain, user = val.split("\\", 1)
        domain = domain.strip().lower()
        user = user.strip().lower()

        # Known local domains / authority names (English + some common misspellings/variants)
        local_domain_markers = ("nt authority", "nt_autority", "nt_autoritat", "nt_autorität", "localhost")
        if any(ld in domain for ld in local_domain_markers):
            return False

        # Known local users / service accounts (English + German variants)
        local_user_names = {
            "system",
            "netzwerkdienst",
            "networkservice",
            "lokaler dienst",
            "localservice",
            "administrator",
            "guest",
            "gast",
            "wdagutilityaccount",
            "defaultaccount",
        }
        if user in local_user_names:
            return False

        # If domain is the computer name (often represented as dot), it's local
        return domain != "."

    # If username contains @ (UPN format), it's likely a domain user
    return "@" in val


def extract_domain_sid_from_hv(hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Extract domain SID from BloodHound data. Returns Admin SID (RID 500) for testing.

    Searches through all available SID sources in the HighValueLoader and returns
    the first valid domain SID with RID 500 appended (well-known Administrator).

    Args:
        hv_loader: HighValueLoader instance with BloodHound data

    Returns:
        Domain SID with RID 500 (e.g., "S-1-5-21-XXX-XXX-XXX-500") or None if not found
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Try hv_sids first (keys are SIDs, values are metadata)
    hv_sids = getattr(hv_loader, "hv_sids", {})
    for sid in hv_sids:
        if sid and sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 7:
                domain_sid = "-".join(parts[:-1])
                return f"{domain_sid}-500"

    # Try other sources (values contain 'objectid' or 'sid' fields)
    sid_sources = [
        getattr(hv_loader, "hv_users", {}),
        getattr(hv_loader, "tier_zero_users", {}),
        getattr(hv_loader, "high_value_users", {}),
    ]

    for source in sid_sources:
        for item in source.values():
            sid = item.get("objectid") or item.get("sid")
            if sid and sid.startswith("S-1-5-21-"):
                parts = sid.split("-")
                if len(parts) >= 7:
                    domain_sid = "-".join(parts[:-1])
                    return f"{domain_sid}-500"

    return None


def resolve_sid(
    sid: str,
    hv_loader: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Comprehensive SID resolution with 4-tier fallback chain.

    Fallback order:
    1. BloodHound offline data (JSON file from --bloodhound flag)
    2. BloodHound live API (if bh_connector provided and has active connection)
    3. SMB/LSARPC via existing connection (uses target's LSA to resolve SIDs)
    4. LDAP queries to domain controller (if credentials provided and not disabled)

    Args:
        sid: Windows SID to resolve
        hv_loader: BloodHound data loader (optional)
        bh_connector: BloodHound API connector (optional, for live queries)
        smb_connection: Active SMB connection to target (optional, for LSARPC)
        no_ldap: Disable LDAP resolution
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes
        kerberos: Use Kerberos
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)

    Returns:
        Tuple of (display_name, resolved_username)
        - display_name: What to show in output (SID + username or just SID)
        - resolved_username: Just the resolved username (for internal use)
    """
    if not is_sid(sid):
        # Not a SID, return as-is
        return sid, None

    # Check cache first
    cache = get_cache()
    if cache:
        cached_username = cache.get("sids", sid)
        if cached_username:
            debug(f"Using cached SID resolution: {sid} → {cached_username}")
            return f"{cached_username} ({sid})", cached_username

        # Check fail count
        fail_count = cache.get("sid_failures", sid) or 0
        if fail_count >= 3:
            debug(f"Skipping resolution for {sid} (failed {fail_count} times previously)")
            return f"{sid} (Unresolvable)", None

    debug(f"Attempting to resolve SID: {sid}")

    # Helper to cache success and clear failures
    def _cache_success(resolved_name):
        if cache:
            cache.set("sids", sid, resolved_name)
            cache.delete("sid_failures", sid)

    # Tier 1: Try BloodHound offline data first
    debug("Tier 1 check")
    resolved = resolve_sid_from_bloodhound(sid, hv_loader)
    if resolved:
        debug(f"SID {sid} resolved via BloodHound offline data: {resolved}")
        _cache_success(resolved)
        return f"{resolved} ({sid})", resolved

    # Tier 2: Try BloodHound live API if connector available
    if bh_connector:
        resolved = resolve_sid_via_bloodhound_api(sid, bh_connector)
        if resolved:
            debug(f"SID {sid} resolved via BloodHound API: {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Tier 3: Try SMB/LSARPC if connection available
    # This is very useful when using Kerberos CIFS tickets where LDAP auth might fail
    if smb_connection:
        resolved = resolve_sid_via_smb(sid, smb_connection)
        if resolved:
            debug(f"SID {sid} resolved via SMB/LSARPC: {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Tier 4: Try LDAP if enabled and we have sufficient authentication info
    # Prioritize dedicated LDAP credentials over main auth credentials
    ldap_auth_domain = ldap_domain if ldap_domain else domain
    ldap_auth_user = ldap_user if ldap_user else username
    ldap_auth_password = ldap_password if ldap_password else password
    ldap_auth_hashes = ldap_hashes if ldap_hashes else hashes

    # Only use Kerberos for LDAP if no explicit LDAP credentials provided
    # This prevents using wrong service ticket (CIFS vs LDAP)
    use_kerberos_for_ldap = kerberos and not (ldap_password or ldap_hashes)

    if not no_ldap and ldap_auth_domain and ldap_auth_user:
        debug(f"Attempting LDAP resolution for SID {sid}")
        resolved = resolve_sid_via_ldap(
            sid, ldap_auth_domain, dc_ip, ldap_auth_user, ldap_auth_password, ldap_auth_hashes, use_kerberos_for_ldap
        )
        if resolved:
            debug(f"SID {sid} resolved via LDAP: {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Could not resolve - return SID with appropriate explanation
    if cache:
        # Increment fail count
        try:
            fail_count = int(cache.get("sid_failures", sid) or 0)
        except (ValueError, TypeError):
            fail_count = 0
        fail_count += 1
        cache.set("sid_failures", sid, fail_count)
        debug(f"SID {sid} resolution failed (attempt {fail_count}/3)")

    if no_ldap:
        debug(f"SID {sid} not resolved: LDAP resolution disabled")
        return f"{sid} (SID - LDAP resolution disabled)", None
    elif not ldap_auth_domain or not ldap_auth_user:
        debug(f"SID {sid} not resolved: insufficient authentication information")
        return f"{sid} (SID - insufficient auth for LDAP resolution)", None
    else:
        debug(f"SID {sid} not resolved: could not find in BloodHound offline, BloodHound API, SMB, or LDAP")
        return f"{sid} (SID - could not resolve: deleted user, cross-domain, or access denied)", None


def format_runas_with_sid_resolution(
    runas: str,
    hv_loader: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Format RunAs field with SID resolution if needed.

    Args:
        runas: The RunAs field value to potentially resolve
        hv_loader: BloodHound data loader (optional)
        bh_connector: BloodHound API connector (optional, for live queries)
        smb_connection: Active SMB connection (optional)
        no_ldap: Disable LDAP resolution
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes
        kerberos: Use Kerberos
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)

    Returns:
        Tuple of (display_runas, resolved_username)
        - display_runas: Formatted string for display
        - resolved_username: Just the resolved username (for internal use)
    """
    if not runas:
        return runas, None

    # Check if it's a SID
    if is_sid(runas):
        return resolve_sid(
            runas,
            hv_loader,
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
    else:
        # Regular username, return as-is
        return runas, None
