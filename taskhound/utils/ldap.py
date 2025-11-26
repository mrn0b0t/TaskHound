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


def resolve_dc_hostname(dc_ip: str, domain: str) -> Optional[str]:
    """
    Resolve DC IP to hostname for Kerberos SPN construction.

    Tries multiple methods:
    1. DNS PTR lookup via DC itself (most reliable for AD environments)
    2. System reverse DNS lookup
    3. Construct from short name + domain

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (for constructing FQDN)

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
        answers = resolver.resolve(rev_name, "PTR")
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
    dc_ip: str,
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    dc_host: Optional[str] = None,
) -> ldap_impacket.LDAPConnection:
    """
    Establish LDAP connection to domain controller.

    Tries LDAPS (port 636) first for secure connection, then falls back to
    LDAP (port 389) if LDAPS fails. This handles DCs that require channel
    binding or LDAP signing (strongerAuthRequired error).

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        dc_host: DC hostname for Kerberos SPN (optional, will try to resolve)

    Returns:
        LDAPConnection object

    Raises:
        LDAPConnectionError: If connection fails
    """
    # Build base DN from domain
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Parse hashes
    lmhash, nthash = parse_ntlm_hashes(hashes)

    # For Kerberos, we need the DC hostname for the SPN (ldap/dc01.domain.local)
    # If not provided, try to resolve
    kerberos_target = dc_host
    if kerberos and not kerberos_target:
        kerberos_target = resolve_dc_hostname(dc_ip, domain)
        if kerberos_target:
            debug(f"LDAP: Resolved DC hostname for Kerberos SPN: {kerberos_target}")
        else:
            debug(f"LDAP: Could not resolve DC hostname, Kerberos may fail")
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
            # For Kerberos, use hostname in URL WITHOUT port (so SPN is ldap/hostname, not ldap/hostname:port)
            # The port is inferred from the protocol (ldaps=636, ldap=389)
            # Connect via dstIp for actual network connection
            if kerberos and kerberos_target:
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
            if kerberos:
                # kdcHost is used for AS-REQ/TGS-REQ, not for SPN
                ldap_conn.kerberosLogin(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
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


class LDAPConnectionError(Exception):
    """Failed to connect to domain controller via LDAP"""

    pass
