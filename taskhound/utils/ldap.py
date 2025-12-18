# LDAP utilities for TaskHound
#
# This module provides shared LDAP connection and query utilities
# used across TaskHound modules (LAPS, SID resolver, etc.)

import socket
from typing import Optional, Tuple

from impacket.ldap import ldap as ldap_impacket

from .logging import debug


def parse_ntlm_hashes(hashes: Optional[str]) -> Tuple[str, str]:
    """
    Parse NTLM hashes from string format.

    Args:
        hashes: Hash string in "LM:NT" or "NT" format, or None

    Returns:
        Tuple of (lmhash, nthash) - empty strings if not provided
    """
    if not hashes:
        return "", ""

    if ":" in hashes:
        lmhash, nthash = hashes.split(":", 1)
        return lmhash, nthash
    else:
        return "", hashes


def resolve_dc_hostname(dc_ip: str, domain: str, use_tcp: bool = False) -> Optional[str]:
    """
    Resolve DC IP to hostname for Kerberos SPN construction.

    Tries multiple methods:
    1. DNS PTR lookup via DC itself (most reliable for AD environments)
    2. System reverse DNS lookup
    3. Construct from short name + domain

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (for constructing FQDN)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)

    Returns:
        DC hostname (FQDN) or None if resolution fails
    """
    # Method 1: Try DNS PTR lookup using the DC as nameserver
    # This is most reliable in AD environments
    try:
        import dns.resolver
        import dns.reversename

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dc_ip]
        resolver.timeout = 3
        resolver.lifetime = 3

        rev_name = dns.reversename.from_address(dc_ip)
        # Force TCP if requested (required for SOCKS/proxychains)
        answers = resolver.resolve(rev_name, "PTR", tcp=use_tcp)
        if answers:
            hostname = str(answers[0]).rstrip(".")
            # If we got a short name, append the domain
            if hostname and "." not in hostname:
                hostname = f"{hostname}.{domain}"
            # Verify it's not just the domain name
            if hostname and hostname.lower() != domain.lower():
                return hostname
    except ImportError:
        pass  # dnspython not available
    except Exception:
        pass  # DNS lookup failed

    # Method 2: System reverse DNS lookup
    try:
        hostname = socket.gethostbyaddr(dc_ip)[0]
        # Check if we got the domain name instead of the DC hostname
        if hostname and hostname.lower() != domain.lower():
            return hostname
    except socket.herror:
        pass

    # Method 3: Try socket.getfqdn
    try:
        hostname = socket.getfqdn(dc_ip)
        if hostname and hostname != dc_ip and hostname.lower() != domain.lower():
            return hostname
    except Exception:
        pass

    return None


def get_ldap_connection(
    dc_ip: Optional[str],
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    dc_host: Optional[str] = None,
    use_tcp: bool = False,
    nameserver: Optional[str] = None,
    timeout: int = 10,
) -> ldap_impacket.LDAPConnection:
    """
    Establish LDAP connection to domain controller.

    Tries LDAPS (port 636) first for secure connection, then falls back to
    LDAP (port 389) if LDAPS fails. This handles DCs that require channel
    binding or LDAP signing (strongerAuthRequired error).

    If dc_ip is not provided, attempts to discover DCs via DNS SRV records.

    Args:
        dc_ip: Domain controller IP address (optional - will auto-discover if not provided)
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos (128-bit or 256-bit hex string)
        dc_host: DC hostname for Kerberos SPN (optional, will try to resolve)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)
        nameserver: DNS server for lookups (defaults to dc_ip or system DNS)
        timeout: Timeout for DC discovery only (default: 10s). Note: actual LDAP
            connection uses OS-level TCP timeout (~75s on most systems) because
            impacket doesn't support per-connection timeouts.

    Returns:
        LDAPConnection object

    Raises:
        LDAPConnectionError: If connection fails
    """
    from .dns import DEFAULT_LDAP_TIMEOUT, get_working_dc

    # Use provided timeout or default
    effective_timeout = timeout if timeout else DEFAULT_LDAP_TIMEOUT

    # NOTE: The timeout parameter only applies to DC discovery, not the LDAP connection.
    # We cannot use socket.setdefaulttimeout() because it breaks SSL connections
    # (causes WantReadError during handshake). impacket's LDAPConnection doesn't
    # support per-connection timeouts, so we rely on OS-level TCP timeout (~75s)
    # for unreachable DCs. The DC discovery phase tests port connectivity with
    # proper timeouts, so unreachable DCs should be filtered out before we get here.

    # If no DC IP provided, try to discover one
    if not dc_ip:
        # Use nameserver if provided, otherwise let discovery use system DNS
        effective_ns = nameserver
        dc_ip = get_working_dc(
            domain=domain,
            nameserver=effective_ns,
            use_tcp=use_tcp,
            timeout=effective_timeout,
        )
        if not dc_ip:
            raise LDAPConnectionError(
                f"Could not discover DC for domain {domain}. "
                "Specify --dc-ip explicitly or check DNS configuration."
            )
        debug(f"LDAP: Auto-discovered DC: {dc_ip}")

    # Build base DN from domain
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Parse hashes
    lmhash, nthash = parse_ntlm_hashes(hashes)

    # For Kerberos (or AES key auth), we need the DC hostname for the SPN (ldap/dc01.domain.local)
    # If not provided, try to resolve
    kerberos_target = dc_host
    if (kerberos or aes_key) and not kerberos_target:
        kerberos_target = resolve_dc_hostname(dc_ip, domain, use_tcp=use_tcp)
        if kerberos_target:
            debug(f"LDAP: Resolved DC hostname for Kerberos SPN: {kerberos_target}")
        else:
            debug("LDAP: Could not resolve DC hostname, Kerberos may fail")
            kerberos_target = dc_ip

    # Try LDAPS first (port 636), then LDAP (port 389)
    # Modern DCs often require LDAP signing which plain LDAP doesn't provide
    connection_attempts = [
        ("ldaps", 636, True),  # LDAPS with SSL
        ("ldap", 389, False),  # Plain LDAP (may fail with strongerAuthRequired)
    ]

    last_error = None
    for protocol, port, use_ssl in connection_attempts:
        try:
            # For Kerberos (or AES key), use hostname in URL WITHOUT port (so SPN is ldap/hostname, not ldap/hostname:port)
            # The port is inferred from the protocol (ldaps=636, ldap=389)
            # Connect via dstIp for actual network connection
            if (kerberos or aes_key) and kerberos_target:
                ldap_url = f"{protocol}://{kerberos_target}"
            else:
                ldap_url = f"{protocol}://{dc_ip}:{port}"
            debug(f"LDAP: Attempting {protocol.upper()} connection to {ldap_url}")

            ldap_conn = ldap_impacket.LDAPConnection(
                ldap_url,
                baseDN=base_dn,
                dstIp=dc_ip,  # Always connect via IP
            )

            # Authenticate
            # AES key implies Kerberos authentication
            if kerberos or aes_key:
                # kdcHost is used for AS-REQ/TGS-REQ, not for SPN
                ldap_conn.kerberosLogin(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    aesKey=aes_key or "",
                    kdcHost=kerberos_target,
                )
            else:
                ldap_conn.login(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                )

            debug(f"LDAP: Successfully connected via {protocol.upper()}")
            return ldap_conn

        except Exception as e:
            error_str = str(e)
            debug(f"LDAP: {protocol.upper()} connection failed: {error_str}")
            last_error = e

            # If it's a certificate error on LDAPS, try plain LDAP
            if use_ssl and ("certificate" in error_str.lower() or "ssl" in error_str.lower()):
                debug("LDAP: SSL/certificate issue, trying plain LDAP...")
                continue

            # If strongerAuthRequired on plain LDAP, we already tried LDAPS
            if "strongerAuthRequired" in error_str:
                # LDAPS should have worked, but if we're here it didn't
                debug("LDAP: DC requires signing/encryption but LDAPS also failed")
                break

            # For other errors, try next protocol
            continue

    # All attempts failed
    raise LDAPConnectionError(f"LDAP connection failed: {last_error}")


def enumerate_domain_computers(
    dc_ip: Optional[str],
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    ldap_filter: Optional[str] = None,
    use_tcp: bool = False,
) -> list[str]:
    """
    Enumerate all computer objects from Active Directory via LDAP.

    Returns a list of computer hostnames (dNSHostName or sAMAccountName without $).

    Args:
        dc_ip: Domain controller IP address (optional - will auto-discover if not provided)
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        ldap_filter: Optional additional LDAP filter (e.g., "(operatingSystem=*Server*)")
        use_tcp: Force DNS queries over TCP

    Returns:
        List of computer hostnames

    Raises:
        LDAPConnectionError: If connection fails
    """
    from impacket.ldap.ldapasn1 import SearchResultEntry

    # Connect to LDAP
    ldap_conn = get_ldap_connection(
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        use_tcp=use_tcp,
    )

    # Build search filter
    # Base filter: all computer objects
    base_filter = "(objectClass=computer)"

    # Combine with custom filter if provided
    if ldap_filter:
        # Wrap user filter in AND with base filter
        search_filter = f"(&{base_filter}{ldap_filter})"
    else:
        search_filter = base_filter

    debug(f"LDAP: Enumerating computers with filter: {search_filter}")

    # Search for computers - request dNSHostName and sAMAccountName
    try:
        results = ldap_conn.search(
            searchFilter=search_filter,
            attributes=["dNSHostName", "sAMAccountName"],
            sizeLimit=0,  # No limit
        )
    except Exception as e:
        raise LDAPConnectionError(f"LDAP search failed: {e}") from e

    computers = []
    for result in results:
        if not isinstance(result, SearchResultEntry):
            continue

        # Extract attributes
        dns_hostname = None
        sam_name = None

        for attr in result["attributes"]:
            attr_type = str(attr["type"])
            if attr["vals"]:
                attr_value = str(attr["vals"][0])

                if attr_type.lower() == "dnshostname":
                    dns_hostname = attr_value
                elif attr_type.lower() == "samaccountname":
                    sam_name = attr_value

        # Prefer dNSHostName (FQDN), fall back to sAMAccountName (strip trailing $)
        if dns_hostname:
            computers.append(dns_hostname)
        elif sam_name:
            # Strip trailing $ from computer account name
            hostname = sam_name.rstrip("$")
            # Append domain to make it resolvable
            computers.append(f"{hostname}.{domain}")

    debug(f"LDAP: Found {len(computers)} computer objects")
    return computers


class LDAPConnectionError(Exception):
    """Failed to connect to domain controller via LDAP"""

    pass
