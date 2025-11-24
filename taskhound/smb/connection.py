# SMB connection helpers.
#
# Small wrapper around Impacket's SMBConnection to handle cleartext
# passwords, NTLM hashes (LM:NT or NT-only), and optional Kerberos
# authentication. The intent is to keep calling code concise and
# centralize parsing of the different credential formats.
# This is horribly vibe-y but it works. Feel free to PR.

import socket
from typing import Optional

from impacket.smbconnection import SMBConnection


def _parse_hashes(password: str):
    # Parse a provided password or NTLM hash string.
    #
    # Accepts:
    #   - None/empty -> (None, '', '')
    #   - 'lm:nt' format -> (None, lm, nt)
    #   - 32-hex NT-only -> (None, '', nt)
    #   - cleartext -> (password, '', '')
    #
    # Returns a tuple suitable for passing into Impacket's login APIs.
    if not password:
        return None, "", ""

    if ":" in password:
        lm, nt = password.split(":", 1)
        return None, lm.strip(), nt.strip()

    # If it's hex length 32, treat as NT hash
    p = password.strip()
    if len(p) == 32 and all(c in "0123456789abcdefABCDEF" for c in p):
        return None, "", p

    # Otherwise treat as cleartext password
    return password, "", ""


def smb_connect(
    target: str, domain: str, username: str, password: str = None, kerberos: bool = False, dc_ip: str = None
) -> SMBConnection:
    # Create and authenticate an SMBConnection to `target`.
    #
    # This function prefers passing an explicit lm/nthash when provided and
    # falls back to a cleartext password. For Kerberos mode we delegate to
    # Impacket's kerberosLogin (which supports a KDC host if provided).
    smb = SMBConnection(remoteName=target, remoteHost=target, sess_port=445)

    pwd, lmhash, nthash = _parse_hashes(password)

    if kerberos:
        smb.kerberosLogin(
            user=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=None,
            TGT=None,
            TGS=None,
            kdcHost=dc_ip,
        )
    else:
        if lmhash or nthash:
            # When presenting hashes to SMB, the cleartext password is empty
            smb.login(username, "", domain, lmhash=lmhash, nthash=nthash)
        else:
            smb.login(username, pwd, domain)
    return smb


def get_server_sid(
    smb: SMBConnection,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Extract the server's machine account SID using SAMR RPC.

    This queries the machine account SID via SAMR protocol. While this requires
    an RPC call, it's more reliable than trying to extract it from SMB negotiation
    (which doesn't expose it in newer SMB versions).

    Args:
        smb: Established SMBConnection
        dc_ip: Domain controller IP (optional, for LDAP fallback)
        username: Username for LDAP fallback
        password: Password for LDAP fallback
        hashes: NTLM hashes for LDAP fallback
        kerberos: Use Kerberos for LDAP fallback

    Returns:
        SID string (e.g., "S-1-5-21-3570960105-1792075822-554663251-1002") or None

    Example:
        >>> smb = smb_connect("DC01.corp.local", "CORP", "user", "pass")
        >>> sid = get_server_sid(smb)
        >>> print(sid)
        S-1-5-21-3570960105-1792075822-554663251-1002
    """
    try:
        from impacket.dcerpc.v5 import samr, transport

        # Get computer name from SMB
        computer_name = smb.getServerName()
        if not computer_name:
            return None

        # Try SAMR RPC to get machine account SID
        try:
            rpctransport = transport.SMBTransport(
                smb.getRemoteName(), smb.getRemoteHost(), filename=r"\samr", smb_connection=smb
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Connect to SAMR
            resp = samr.hSamrConnect(dce)
            serverHandle = resp["ServerHandle"]

            # Enumerate domains
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp["Buffer"]["Buffer"]

            # Try each domain
            for domain in domains:
                try:
                    domain_name = domain["Name"]

                    # Skip Builtin domain
                    if domain_name.lower() == "builtin":
                        continue

                    # Open domain
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)
                    domain_sid = resp["DomainId"]

                    resp = samr.hSamrOpenDomain(dce, serverHandle, domainId=domain_sid)
                    domainHandle = resp["DomainHandle"]

                    # Look up machine account (computer accounts end with $)
                    machine_account = f"{computer_name}$"
                    resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [machine_account])

                    # Extract RID from NDRULONG object
                    rid_obj = resp["RelativeIds"]["Element"][0]
                    rid = rid_obj.fields["Data"]  # Integer value

                    # Build full SID
                    machine_sid = f"{domain_sid.formatCanonical()}-{rid}"
                    dce.disconnect()
                    return machine_sid

                except Exception:
                    # Try next domain
                    continue

            dce.disconnect()

        except Exception:
            # SAMR failed, fall back to LDAP if credentials available
            pass

        # Fallback: Use LDAP to lookup the computer account SID
        if dc_ip and username and (password or hashes):
            from ..utils.sid_resolver import resolve_name_to_sid_via_ldap

            # Get FQDN for LDAP lookup
            try:
                fqdn = smb.getServerDNSHostName()
                if not fqdn:
                    server_name = smb.getServerName()
                    server_domain = smb.getServerDNSDomainName()
                    if server_name and server_domain:
                        fqdn = f"{server_name}.{server_domain}"

                if fqdn:
                    domain = smb.getServerDNSDomainName()
                    if domain:
                        sid = resolve_name_to_sid_via_ldap(
                            name=fqdn,
                            domain=domain,
                            is_computer=True,
                            dc_ip=dc_ip,
                            username=username,
                            password=password,
                            hashes=hashes,
                            kerberos=kerberos,
                        )
                        return sid
            except Exception:
                pass

        return None

    except Exception:
        return None


def get_server_fqdn(smb: SMBConnection, target_ip: Optional[str] = None, dc_ip: Optional[str] = None) -> str:
    """
    Extract the server's FQDN from an established SMB connection.

    Attempts multiple resolution methods in order:
    1. SMB DNS hostname (most reliable)
    2. Constructed from SMB hostname + DNS domain
    3. DNS PTR lookup using DC as nameserver (if dc_ip provided)
    4. System DNS PTR lookup (fallback)

    Args:
        smb: Established SMBConnection
        target_ip: Original target IP address (used for DNS fallback)
        dc_ip: Domain Controller IP to use as DNS server

    Returns:
        FQDN string (e.g., "DC.badsuccessor.lab") or "UNKNOWN_HOST"
    """
    try:
        # Method 1: Try to get the full DNS hostname directly from SMB
        fqdn = smb.getServerDNSHostName()
        if fqdn:
            return fqdn

        # Method 2: Construct from hostname + DNS domain
        server_name = smb.getServerName()
        server_domain = smb.getServerDNSDomainName()

        if server_name and server_domain:
            return f"{server_name}.{server_domain}"
        elif server_name:
            # Have hostname but no domain from SMB, try DNS fallback
            pass
        else:
            # No SMB hostname info at all
            server_name = None
    except Exception:
        server_name = None

    # Method 3 & 4: DNS fallback - try to resolve via PTR record
    if target_ip and _is_ip_address(target_ip):
        # Method 3: Try using DC as DNS server (if provided)
        if dc_ip:
            fqdn = _dns_ptr_lookup(target_ip, nameserver=dc_ip)
            if fqdn:
                return fqdn

        # Method 4: Try system DNS
        fqdn = _dns_ptr_lookup(target_ip, nameserver=None)
        if fqdn:
            return fqdn

    # Final fallback: return just the hostname if we have it
    if server_name:
        return server_name

    return "UNKNOWN_HOST"


def _is_ip_address(hostname: str) -> bool:
    """Check if a string is an IPv4 address."""
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, TypeError):
            return False
    return False


def _dns_ptr_lookup(ip: str, nameserver: Optional[str] = None) -> Optional[str]:
    """
    Perform DNS PTR lookup to resolve IP to hostname.

    Args:
        ip: IP address to resolve
        nameserver: Optional DNS server to query (e.g., DC IP)

    Returns:
        FQDN if successful, None otherwise
    """
    try:
        # Try using dnspython if available (supports custom nameserver)
        if nameserver:
            try:
                import dns.resolver
                import dns.reversename

                # Create resolver with custom nameserver
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [nameserver]
                resolver.timeout = 3
                resolver.lifetime = 3

                # Perform PTR lookup
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR")

                if answers:
                    # Return first answer, strip trailing dot
                    fqdn = str(answers[0]).rstrip(".")
                    return fqdn
            except ImportError:
                # dnspython not available, fall through to socket method
                pass
            except Exception:
                # DNS query failed, fall through to socket method
                pass

        # Fallback: Use system resolver (socket.getfqdn)
        # This uses system DNS settings
        fqdn = socket.getfqdn(ip)

        # Validate we got an actual FQDN, not just the IP back
        if fqdn and fqdn != ip and "." in fqdn:
            return fqdn

        # Also try gethostbyaddr
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname

    except Exception:
        pass

    return None
