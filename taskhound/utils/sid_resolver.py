# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.
# REFACTORED: Now uses Impacket LDAP with NTLM hash support

import re
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..parsers.highvalue import HighValueLoader
from ..utils.cache_manager import get_cache
from ..utils.ldap import LDAPConnectionError, get_ldap_connection
from ..utils.logging import debug, info, status, warn


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


def get_domain_sid_prefix(sid: str) -> Optional[str]:
    """
    Extract domain SID prefix from a full SID.

    Domain SIDs have the format: S-1-5-21-{domain1}-{domain2}-{domain3}-{RID}
    The domain prefix is S-1-5-21-{domain1}-{domain2}-{domain3} (without RID).

    Args:
        sid: Full SID string (e.g., "S-1-5-21-123-456-789-1001")

    Returns:
        Domain prefix (e.g., "S-1-5-21-123-456-789") or None if not a domain SID
    """
    if not sid or not sid.startswith("S-1-5-21-"):
        return None

    parts = sid.split("-")
    # Domain SID: S-1-5-21-{d1}-{d2}-{d3}-{RID} = 8 parts minimum
    if len(parts) < 8:
        return None

    # Return everything except the RID (last part)
    return "-".join(parts[:-1])


def is_foreign_domain_sid(sid: str, local_domain_sid_prefix: Optional[str]) -> bool:
    """
    Check if a SID belongs to a foreign (trusted) domain.

    Args:
        sid: SID to check
        local_domain_sid_prefix: Known local domain prefix (e.g., "S-1-5-21-123-456-789")

    Returns:
        True if SID is from a different domain than local_domain_sid_prefix
    """
    if not local_domain_sid_prefix:
        return False  # Can't determine without local domain info

    sid_prefix = get_domain_sid_prefix(sid)
    if not sid_prefix:
        return False  # Not a domain SID (built-in, well-known, etc.)

    return sid_prefix != local_domain_sid_prefix


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
            debug("BloodHound API SID query returned no data")

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

        # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
        if not domain or "." not in domain:
            debug(f"Invalid domain '{domain}' for LDAP SID resolution - must be FQDN")
            return None

        # Convert SID to binary format for LDAP search
        binary_sid = sid_to_binary(sid)
        if not binary_sid:
            warn(f"Could not convert SID {sid} to binary format")
            return None

        # Get LDAP connection using shared utility (handles DC discovery if dc_ip is None)
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
    Results are cached persistently to avoid redundant LDAP queries.
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
    # Check cache first (before any processing)
    from ..utils.cache_manager import get_cache
    cache = get_cache()

    if cache and is_computer:
        # Normalize for cache key: strip $ and domain suffix
        cache_name = name.upper()
        if cache_name.endswith("$"):
            cache_name = cache_name[:-1]
        if "." in cache_name:
            cache_name = cache_name.split(".")[0]
        cache_key = f"name:{cache_name}:{domain.upper()}"

        cached_sid = cache.get("computers", cache_key)
        if cached_sid:
            debug(f"Cache hit for computer {name}: {cached_sid}")
            return cached_sid
    else:
        cache_key = None  # Only cache computers for now

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for LDAP resolution - must be FQDN (e.g., 'corp.local')")
        return None

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

        # Get LDAP connection using shared utility (handles DC discovery if dc_ip is None)
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
            warn(f"Failed to connect to LDAP server for name resolution: {e}")
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
                                # Cache for future lookups (computers only)
                                if cache and cache_key:
                                    cache.set("computers", cache_key, sid_string)
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


def resolve_name_to_sid(
    name: str,
    domain: str,
    is_computer: bool = False,
    hv_loader=None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a name (computer or user) to its SID using a multi-tier fallback chain.

    Fallback order:
    1. Cache (fast, persistent)
    2. BloodHound data (if hv_loader provided)
    3. LDAP query (if credentials provided)

    Args:
        name: Computer name (FQDN or hostname) or username
        domain: Domain name (e.g., "corp.local")
        is_computer: True if resolving a computer account, False for user
        hv_loader: HighValueLoader with BloodHound data (optional)
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication

    Returns:
        SID string (e.g., "S-1-5-21-..."), None if resolution fails
    """
    if not name:
        return None

    # Normalize name for lookups
    lookup_name = name.upper()
    if is_computer:
        # Strip trailing $ and domain suffix
        if lookup_name.endswith("$"):
            lookup_name = lookup_name[:-1]
        if "." in lookup_name:
            lookup_name = lookup_name.split(".")[0]

    # Tier 1: Check cache first
    cache = get_cache()
    if cache:
        cache_key = f"name:{lookup_name}:{domain.upper() if domain else 'LOCAL'}"
        cache_type = "computers" if is_computer else "users"
        cached_sid = cache.get(cache_type, cache_key)
        if cached_sid:
            debug(f"Cache hit for {name}: {cached_sid}")
            return cached_sid

    # Tier 2: Try BloodHound data
    if hv_loader and hasattr(hv_loader, "loaded") and hv_loader.loaded:
        if is_computer:
            # Try hv_computers dict (maps hostname → SID)
            hv_computers = getattr(hv_loader, "hv_computers", {})
            if hv_computers:
                sid = hv_computers.get(lookup_name)
                if sid:
                    debug(f"Resolved {name} to {sid} via BloodHound computer data")
                    # Cache for future lookups
                    if cache:
                        cache.set("computers", cache_key, sid)
                    return sid
        else:
            # Try hv_users dict (maps samaccountname → metadata with SID)
            hv_users = getattr(hv_loader, "hv_users", {})
            if hv_users:
                # Try exact match first
                user_data = hv_users.get(lookup_name) or hv_users.get(lookup_name.lower())
                if user_data:
                    sid = user_data.get("sid") or user_data.get("objectid")
                    if sid:
                        debug(f"Resolved {name} to {sid} via BloodHound data")
                        # Cache for future lookups
                        if cache:
                            cache.set("users", cache_key, sid)
                        return sid

    # Tier 3: Try LDAP if credentials available
    if domain and username and (password or hashes):
        sid = resolve_name_to_sid_via_ldap(
            name=name,
            domain=domain,
            is_computer=is_computer,
            dc_ip=dc_ip,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )
        if sid:
            # Already cached by resolve_name_to_sid_via_ldap
            return sid

    debug(f"Could not resolve {name} to SID (checked cache, BloodHound, LDAP)")
    return None


def prefetch_computer_sids(
    targets: List[str],
    domain: str,
    hv_loader=None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Dict[str, str]:
    """
    Batch pre-fetch computer SIDs for known targets before scanning begins.

    This function efficiently resolves computer SIDs for all targets upfront,
    using BloodHound data first (instant) and falling back to LDAP only for
    computers not found in BloodHound. Results are cached for the scan.

    Fallback order:
    1. BloodHound data (if hv_loader provided with hv_computers)
    2. Cache (check if already resolved)
    3. Batch LDAP query for remaining computers

    Args:
        targets: List of target hostnames (FQDN or short names)
        domain: Domain name (e.g., "corp.local")
        hv_loader: HighValueLoader with BloodHound data (optional)
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication

    Returns:
        Dict mapping normalized hostname -> SID for all resolved targets
    """
    if not targets:
        return {}

    resolved: Dict[str, str] = {}
    remaining: List[str] = []
    cache = get_cache()

    # Normalize all target names
    normalized_targets = {}
    for target in targets:
        # Strip domain suffix and normalize to uppercase
        hostname = target.upper()
        if "." in hostname:
            hostname = hostname.split(".")[0]
        normalized_targets[hostname] = target

    # Step 1: Check BloodHound data first (instant lookups)
    bh_hits = 0
    if hv_loader and hasattr(hv_loader, "hv_computers") and hv_loader.hv_computers:
        hv_computers = hv_loader.hv_computers
        for hostname, _original in normalized_targets.items():
            sid = hv_computers.get(hostname)
            if sid:
                resolved[hostname] = sid
                bh_hits += 1
                # Cache the result
                if cache:
                    cache_key = f"name:{hostname}:{domain.upper() if domain else 'LOCAL'}"
                    cache.set("computers", cache_key, sid)

        if bh_hits > 0:
            status(f"[SID Prefetch] {bh_hits} computer SIDs from BloodHound")

    # Step 2: Check cache for remaining
    cache_hits = 0
    for hostname in normalized_targets:
        if hostname in resolved:
            continue

        if cache:
            cache_key = f"name:{hostname}:{domain.upper() if domain else 'LOCAL'}"
            cached_sid = cache.get("computers", cache_key)
            if cached_sid:
                resolved[hostname] = cached_sid
                cache_hits += 1
            else:
                remaining.append(hostname)
        else:
            remaining.append(hostname)

    if cache_hits > 0:
        debug(f"Pre-fetch: {cache_hits} computer SIDs from cache")

    # Step 3: Batch LDAP query for remaining (if credentials available)
    if remaining and domain and username and (password or hashes):
        debug(f"Pre-fetch: Querying LDAP for {len(remaining)} remaining computers")
        for hostname in remaining:
            sid = resolve_name_to_sid_via_ldap(
                name=hostname,
                domain=domain,
                is_computer=True,
                dc_ip=dc_ip,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
            if sid:
                resolved[hostname] = sid
                # Already cached by resolve_name_to_sid_via_ldap

        ldap_resolved = len(resolved) - bh_hits - cache_hits
        if ldap_resolved > 0:
            status(f"[SID Prefetch] {ldap_resolved} computer SIDs via LDAP")

    total = len(resolved)
    if total > 0:
        debug(f"Pre-fetch complete: {total} computer SIDs resolved")

    return resolved


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
    local_domain_sid_prefix: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Comprehensive SID resolution with 4-tier fallback chain.

    Fallback order:
    1. BloodHound offline data (JSON file from --bloodhound flag)
    2. BloodHound live API (if bh_connector provided and has active connection)
    3. SMB/LSARPC via existing connection (uses target's LSA to resolve SIDs)
       - SKIPPED for foreign domain SIDs (different domain prefix)
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
        local_domain_sid_prefix: Known local domain SID prefix for foreign domain detection

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

    # Check for foreign domain SID before attempting LSARPC
    # Foreign SIDs cannot be resolved via local domain's LSARPC (returns STATUS_NONE_MAPPED)
    is_foreign = is_foreign_domain_sid(sid, local_domain_sid_prefix)
    if is_foreign:
        debug(f"SID {sid} is from foreign domain (prefix mismatch with {local_domain_sid_prefix}), skipping LSARPC")

    # Tier 3: Try SMB/LSARPC if connection available (skip for foreign domain SIDs)
    # This is very useful when using Kerberos CIFS tickets where LDAP auth might fail
    if smb_connection and not is_foreign:
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
    elif is_foreign:
        debug(f"SID {sid} not resolved: foreign domain SID (cross-trust)")
        return f"{sid} (SID - foreign domain/trust)", None
    else:
        debug(f"SID {sid} not resolved: could not find in BloodHound offline, BloodHound API, SMB, or LDAP")
        return f"{sid} (SID - could not resolve: deleted user or access denied)", None


def batch_get_user_attributes(
    usernames: list[str],
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    attributes: list[str] = None,
) -> dict[str, dict]:
    """
    Batch query LDAP for user attributes (pwdLastSet, etc.).

    Results are cached in both session memory and persistent SQLite cache.
    Uses a single LDAP connection for all queries (efficient batching).

    Args:
        usernames: List of usernames to query (DOMAIN\\user or just user format)
        domain: Domain name (FQDN format, e.g., "domain.local")
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication (128 or 256 bit)
        attributes: List of attributes to fetch (default: pwdLastSet, lastLogon)

    Returns:
        Dictionary mapping normalized username (lowercase, no domain) to attribute dict
        e.g., {"jsmith": {"pwdLastSet": datetime(...), "lastLogon": datetime(...)}}
    """
    if not usernames:
        return {}

    if attributes is None:
        attributes = ["pwdLastSet", "lastLogon", "sAMAccountName", "objectSid"]

    # Normalize usernames - extract just the username part
    users_to_query = set()
    username_mapping = {}  # original -> normalized
    for user in usernames:
        if not user:
            continue
        # Strip domain prefix if present (DOMAIN\user -> user)
        normalized = user.split("\\")[-1].lower() if "\\" in user else user.lower()
        users_to_query.add(normalized)
        username_mapping[user] = normalized

    if not users_to_query:
        return {}

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for batch user attribute lookup - must be FQDN")
        return {}

    # Check cache first
    cache = get_cache()
    results = {}
    users_needing_query = []

    for norm_user in users_to_query:
        cached = cache.get("user_attrs", norm_user) if cache else None
        if cached:
            results[norm_user] = cached
            debug(f"Cache hit for user attributes: {norm_user}")
        else:
            users_needing_query.append(norm_user)

    if not users_needing_query:
        debug(f"All {len(results)} user attribute lookups satisfied from cache")
        return results

    debug(f"Querying LDAP for {len(users_needing_query)} users (cached: {len(results)})")

    # Query LDAP for remaining users (get_ldap_connection handles DC discovery if dc_ip is None)
    try:
        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            aes_key=aes_key,
        )
    except LDAPConnectionError as e:
        warn(f"LDAP connection failed for user attribute lookup: {e}")
        return results

    # Build base DN
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Query users in batches using OR filter
    # LDAP has limits on filter size, so batch in groups of 20
    BATCH_SIZE = 20
    for i in range(0, len(users_needing_query), BATCH_SIZE):
        batch = users_needing_query[i:i + BATCH_SIZE]

        # Build OR filter for batch
        if len(batch) == 1:
            search_filter = f"(&(objectClass=user)(sAMAccountName={batch[0]}))"
        else:
            user_filters = "".join([f"(sAMAccountName={u})" for u in batch])
            search_filter = f"(&(objectClass=user)(|{user_filters}))"

        debug(f"LDAP batch query for {len(batch)} users")

        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=attributes,
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        entry_attrs = {}
                        sam_name = None

                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            attr_vals = [str(val) for val in attribute["vals"]]

                            if attr_name.lower() == "samaccountname":
                                sam_name = attr_vals[0].lower() if attr_vals else None
                            elif attr_name.lower() == "pwdlastset":
                                # Convert Windows FILETIME to Unix timestamp then datetime
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        # Windows FILETIME is 100-nanosecond intervals since 1601
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        from datetime import datetime, timezone
                                        # Use UTC timezone for consistency with task date parsing
                                        entry_attrs["pwdLastSet"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "lastlogon":
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        from datetime import datetime, timezone
                                        # Use UTC timezone for consistency
                                        entry_attrs["lastLogon"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "objectsid":
                                # Binary SID - convert to string
                                if attr_vals:
                                    try:
                                        binary_sid = attribute["vals"][0].asOctets()
                                        sid_str = binary_to_sid(binary_sid)
                                        if sid_str:
                                            entry_attrs["sid"] = sid_str
                                    except Exception:
                                        pass

                        if sam_name and entry_attrs:
                            results[sam_name] = entry_attrs
                            # Cache the result
                            if cache:
                                # Convert datetime to timestamp for JSON serialization
                                cache_entry = {}
                                for k, v in entry_attrs.items():
                                    if hasattr(v, 'timestamp'):
                                        cache_entry[k] = v.timestamp()
                                    else:
                                        cache_entry[k] = v
                                cache.set("user_attrs", sam_name, cache_entry)
                            debug(f"Got attributes for {sam_name}: pwdLastSet={entry_attrs.get('pwdLastSet')}")

        except Exception as e:
            warn(f"LDAP batch query error: {e}")
            continue

    info(f"Retrieved attributes for {len(results)} users via LDAP")
    return results


def get_user_pwd_last_set(
    username: str,
    domain: str,
    dc_ip: Optional[str] = None,
    auth_username: Optional[str] = None,
    auth_password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional["datetime"]:
    """
    Get pwdLastSet for a single user (with caching).

    Convenience wrapper around batch_get_user_attributes for single user lookup.

    Args:
        username: Username to look up (DOMAIN\\user or just user)
        domain: Domain name
        dc_ip: Domain controller IP
        auth_username: LDAP auth username
        auth_password: LDAP auth password
        hashes: NTLM hashes
        kerberos: Use Kerberos

    Returns:
        datetime of password last set, or None if not found
    """
    # Normalize username
    norm_user = username.split("\\")[-1].lower() if "\\" in username else username.lower()

    # Check cache first
    cache = get_cache()
    if cache:
        cached = cache.get("user_attrs", norm_user)
        if cached:
            pwd_ts = cached.get("pwdLastSet")
            if pwd_ts:
                from datetime import datetime
                if isinstance(pwd_ts, (int, float)):
                    return datetime.fromtimestamp(pwd_ts)
                return pwd_ts

    # Query LDAP
    results = batch_get_user_attributes(
        usernames=[username],
        domain=domain,
        dc_ip=dc_ip,
        username=auth_username,
        password=auth_password,
        hashes=hashes,
        kerberos=kerberos,
        attributes=["pwdLastSet", "sAMAccountName"],
    )

    if norm_user in results:
        return results[norm_user].get("pwdLastSet")

    return None


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
    local_domain_sid_prefix: Optional[str] = None,
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
        local_domain_sid_prefix: Known local domain SID prefix for foreign domain detection

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
            local_domain_sid_prefix,
        )
    else:
        # Regular username, return as-is
        return runas, None



# Well-known privileged group RIDs (relative to domain SID)
# These are the primary Tier-0 groups that grant domain-wide administrative access
TIER0_GROUP_RIDS = {
    512: "Domain Admins",
    519: "Enterprise Admins",
    518: "Schema Admins",
    516: "Domain Controllers",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

# Well-known privileged ACCOUNT RIDs (these are accounts, not groups)
# Users with these RIDs are inherently Tier-0
TIER0_ACCOUNT_RIDS = {
    500: "Domain Administrator",  # Built-in Administrator account
    502: "krbtgt",  # Kerberos TGT service account
}

# Well-known built-in privileged groups (fixed SIDs)
TIER0_BUILTIN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
}


# Type alias for Tier-0 cache: normalized_username -> (is_tier0, list_of_group_names)
Tier0Cache = Dict[str, Tuple[bool, List[str]]]


def fetch_tier0_members(
    domain: str,
    dc_ip: Optional[str] = None,
    auth_username: Optional[str] = None,
    auth_password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
) -> Tier0Cache:
    """
    Pre-flight fetch of all Tier-0 group members via LDAP.

    This queries each Tier-0 group once and collects all members,
    building a lookup cache. This is more efficient than querying
    per-user membership (O(G) queries vs O(U) queries).

    Uses LDAP_MATCHING_RULE_IN_CHAIN for transitive membership.

    Args:
        domain: Domain name (FQDN format, e.g., "domain.local")
        dc_ip: Domain controller IP address
        auth_username: LDAP authentication username
        auth_password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication (128 or 256 bit)

    Returns:
        Tier0Cache: Dict of normalized_username -> (is_tier0, list_of_group_names)
    """
    tier0_cache: Tier0Cache = {}

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for Tier-0 pre-flight - must be FQDN")
        return tier0_cache

    # Check persistent cache first
    cache = get_cache()
    cache_key = f"tier0_members@{domain.lower()}"
    if cache:
        cached = cache.get("tier0_preflight", cache_key)
        if cached is not None:
            debug(f"Tier-0 pre-flight: Using cached data for {domain}")
            return cached

    # Get LDAP connection (handles DC discovery if dc_ip is None)
    try:
        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=auth_username or "",
            password=auth_password,
            hashes=hashes,
            kerberos=kerberos,
            aes_key=aes_key,
        )
    except LDAPConnectionError as e:
        debug(f"LDAP connection failed for Tier-0 pre-flight: {e}")
        return tier0_cache

    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    try:
        # Step 1: Get domain SID by querying a domain controller
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"  # Domain Controllers
        search_results = conn.search(
            searchBase=base_dn,
            searchFilter=search_filter,
            attributes=["objectSid"],
            searchControls=None,
        )

        domain_sid = None
        if search_results:
            for entry in search_results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    for attribute in entry["attributes"]:
                        attr_name = str(attribute["type"])
                        if attr_name.lower() == "objectsid":
                            try:
                                binary_sid = attribute["vals"][0].asOctets()
                                sid_str = binary_to_sid(binary_sid)
                                if sid_str:
                                    domain_sid = "-".join(sid_str.split("-")[:-1])
                                    break
                            except Exception:
                                pass
                    if domain_sid:
                        break

        if not domain_sid:
            debug("Could not determine domain SID for Tier-0 pre-flight")
            return tier0_cache

        debug(f"Tier-0 pre-flight: Domain SID is {domain_sid}")

        # Step 2: Build list of privileged group DNs to query
        group_sids = []
        for rid, _name in TIER0_GROUP_RIDS.items():
            group_sids.append(f"(objectSid={domain_sid}-{rid})")

        # Add built-in groups
        for sid in TIER0_BUILTIN_SIDS:
            group_sids.append(f"(objectSid={sid})")

        search_filter = f"(|{''.join(group_sids)})"
        search_results = conn.search(
            searchBase=base_dn,
            searchFilter=search_filter,
            attributes=["distinguishedName", "sAMAccountName"],
            searchControls=None,
        )

        privileged_groups = []  # List of (dn, samAccountName)
        if search_results:
            for entry in search_results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    dn = None
                    sam = None
                    for attribute in entry["attributes"]:
                        attr_name = str(attribute["type"])
                        attr_vals = [str(val) for val in attribute["vals"]]
                        if attr_name.lower() == "distinguishedname" and attr_vals:
                            dn = attr_vals[0]
                        elif attr_name.lower() == "samaccountname" and attr_vals:
                            sam = attr_vals[0]
                    if dn:
                        privileged_groups.append((dn, sam or dn))

        if not privileged_groups:
            debug("Tier-0 pre-flight: No privileged groups found")
            return tier0_cache

        debug(f"Tier-0 pre-flight: Found {len(privileged_groups)} privileged groups")

        # Step 3: Query members of each privileged group (using transitive membership)
        # This gets all users who are members (direct or nested) of each group
        member_groups: Dict[str, List[str]] = {}  # normalized_username -> list of group names

        for group_dn, group_name in privileged_groups:
            # Escape DN for LDAP filter
            escaped_dn = group_dn.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")

            # Query all users who are (transitively) members of this group
            # LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) handles nested groups
            search_filter = f"(&(objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:={escaped_dn}))"

            try:
                search_results = conn.search(
                    searchBase=base_dn,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    searchControls=None,
                )

                member_count = 0
                if search_results:
                    for entry in search_results:
                        if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                            for attribute in entry["attributes"]:
                                attr_name = str(attribute["type"])
                                if attr_name.lower() == "samaccountname":
                                    for val in attribute["vals"]:
                                        username = str(val).lower()
                                        if username not in member_groups:
                                            member_groups[username] = []
                                        member_groups[username].append(group_name)
                                        member_count += 1

                debug(f"Tier-0 pre-flight: {group_name} has {member_count} members")

            except Exception as e:
                debug(f"Tier-0 pre-flight: Failed to query members of {group_name}: {e}")
                continue

        # Step 4: Also check for privileged accounts by RID (e.g., Administrator RID 500)
        # Query users and check if their RID matches a privileged account
        for rid, account_name in TIER0_ACCOUNT_RIDS.items():
            account_sid = f"{domain_sid}-{rid}"
            search_filter = f"(&(objectCategory=user)(objectSid={account_sid}))"

            try:
                search_results = conn.search(
                    searchBase=base_dn,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    searchControls=None,
                )

                if search_results:
                    for entry in search_results:
                        if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                            for attribute in entry["attributes"]:
                                attr_name = str(attribute["type"])
                                if attr_name.lower() == "samaccountname":
                                    for val in attribute["vals"]:
                                        username = str(val).lower()
                                        if username not in member_groups:
                                            member_groups[username] = []
                                        member_groups[username].append(account_name)
                                        debug(f"Tier-0 pre-flight: Found {account_name} account: {username}")
            except Exception as e:
                debug(f"Tier-0 pre-flight: Failed to query {account_name}: {e}")

        # Build final cache
        for username, groups in member_groups.items():
            tier0_cache[username] = (True, groups)

        debug(f"Tier-0 pre-flight: Found {len(tier0_cache)} unique Tier-0 users")

        # Save to persistent cache
        if cache and tier0_cache:
            cache.set("tier0_preflight", cache_key, tier0_cache)

        return tier0_cache

    except Exception as e:
        debug(f"Tier-0 pre-flight failed: {e}")
        return tier0_cache


def check_tier0_membership(
    username: str,
    tier0_cache: Tier0Cache,
) -> Tuple[bool, List[str]]:
    """
    Check if a user is Tier-0 using pre-fetched cache.

    This is the fast lookup function to use after fetch_tier0_members().

    Args:
        username: Username to check (can be DOMAIN\\user or just user)
        tier0_cache: Pre-fetched Tier0Cache from fetch_tier0_members()

    Returns:
        Tuple of (is_tier0, list_of_matching_groups)
    """
    if not username or not tier0_cache:
        return False, []

    # Normalize username - extract just the username part
    if "\\" in username:
        username = username.split("\\")[-1]
    elif "@" in username:
        username = username.split("@")[0]

    username_lower = username.lower()

    # Skip well-known system accounts
    if username_lower in ("system", "local service", "network service"):
        return False, []

    # Simple lookup
    return tier0_cache.get(username_lower, (False, []))


