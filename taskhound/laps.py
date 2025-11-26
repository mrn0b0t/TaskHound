# LAPS (Local Administrator Password Solution) support for TaskHound
#
# This module handles querying LAPS passwords from Active Directory
# and provides credential lookup for SMB authentication.
#
# Supports:
#   - Windows LAPS (msLAPS-Password) - JSON format, plaintext only for MVP
#   - Legacy LAPS (ms-Mcs-AdmPwd) - plaintext
#   - Persistent caching via SQLite (respects LAPS expiration times)
#
# Author: TaskHound Contributors

import json
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from .utils.cache_manager import get_cache
from .utils.date_parser import parse_ad_timestamp, parse_filetime_hex
from .utils.ldap import (
    LDAPConnectionError as LAPSConnectionError_Base,
    get_ldap_connection,
    resolve_dc_hostname,
)
from .utils.logging import debug, good, info, warn


# Cache category for LAPS credentials
LAPS_CACHE_CATEGORY = "laps"


# =============================================================================
# Exceptions
# =============================================================================


class LAPSError(Exception):
    """Base exception for LAPS operations"""

    pass


class LAPSConnectionError(LAPSError):
    """Failed to connect to domain controller via LDAP"""

    pass


class LAPSPermissionError(LAPSError):
    """No permission to read LAPS attributes"""

    pass


class LAPSEmptyCacheError(LAPSError):
    """No LAPS passwords found in Active Directory"""

    pass


class LAPSParseError(LAPSError):
    """Failed to parse LAPS attribute data"""

    pass


# =============================================================================
# Error Messages
# =============================================================================

LAPS_ERRORS = {
    "ldap_connect": (
        "[!] LAPS: Failed to connect to domain controller via LDAP\n"
        "[!] Check: --dc-ip is correct, DC is reachable, credentials are valid"
    ),
    "no_permission": (
        "[!] LAPS: LDAP query succeeded but no LAPS attributes returned\n"
        "[!] Your account may not have permission to read LAPS passwords\n"
        "[!] Required: 'Read ms-Mcs-AdmPwd' or 'Read msLAPS-Password' on computer objects"
    ),
    "empty_cache": (
        "[!] LAPS: No computers with LAPS passwords found\n"
        "[!] Possible causes:\n"
        "[!]   - LAPS is not deployed in this environment\n"
        "[!]   - LAPS passwords have not been set yet\n"
        "[!]   - Your account lacks read permissions on LAPS attributes"
    ),
    "host_not_found": "[!] {hostname}: No LAPS password found in cache",
    "auth_failed": (
        "[!] {hostname}: LAPS authentication failed\n" "[!] Password may have rotated since LDAP query"
    ),
    "encrypted": (
        "[!] {hostname}: LAPS password is encrypted (Windows LAPS)\n"
        "[!] Encrypted LAPS decryption not yet supported"
    ),
    "remote_uac": (
        "[!] {hostname}: LAPS authentication succeeded but admin access denied\n"
        "[!] Likely cause: Remote UAC (LocalAccountTokenFilterPolicy=0)\n"
        "[!] \n"
        "[!] This is a Windows security feature that filters local admin tokens\n"
        "[!] for remote connections. The LAPS password is correct, but the\n"
        "[!] resulting session lacks administrative privileges.\n"
        "[!] \n"
        "[!] Solutions:\n"
        "[!]   1. GPO: Set LocalAccountTokenFilterPolicy=1 (DWORD) at\n"
        "[!]      HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
        "[!]   2. Use domain credentials with local admin rights instead\n"
        "[!]   3. Servers typically have this disabled by default (workstations don't)"
    ),
    "remote_uac_short": "[!] {hostname}: Remote UAC blocking LAPS admin access",
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class LAPSCredential:
    """Represents a LAPS credential for a single computer"""

    password: str
    username: str  # From msLAPS-Password JSON, --laps-user, or "Administrator"
    laps_type: str  # "legacy" or "mslaps"
    computer_name: str  # sAMAccountName (e.g., "WS01$")
    dns_hostname: Optional[str] = None  # FQDN if available
    expiration: Optional[datetime] = None  # Password expiration time
    encrypted: bool = False  # True if encrypted (not supported yet)

    def is_expired(self) -> bool:
        """Check if the LAPS password has expired"""
        if self.expiration is None:
            return False
        return datetime.now(timezone.utc) > self.expiration

    def to_cache_dict(self) -> Dict:
        """Serialize credential for persistent cache storage"""
        return {
            "password": self.password,
            "username": self.username,
            "laps_type": self.laps_type,
            "computer_name": self.computer_name,
            "dns_hostname": self.dns_hostname,
            "expiration": self.expiration.isoformat() if self.expiration else None,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_cache_dict(cls, data: Dict) -> "LAPSCredential":
        """Deserialize credential from persistent cache"""
        expiration = None
        if data.get("expiration"):
            try:
                expiration = datetime.fromisoformat(data["expiration"])
            except (ValueError, TypeError):
                pass
        
        return cls(
            password=data["password"],
            username=data["username"],
            laps_type=data["laps_type"],
            computer_name=data["computer_name"],
            dns_hostname=data.get("dns_hostname"),
            expiration=expiration,
            encrypted=data.get("encrypted", False),
        )


@dataclass
class LAPSCache:
    """In-memory cache for LAPS credentials"""

    _cache: Dict[str, LAPSCredential] = field(default_factory=dict)
    domain: Optional[str] = None  # Domain for scoping cache keys
    legacy_count: int = 0
    mslaps_count: int = 0
    encrypted_count: int = 0  # Skipped due to encryption
    from_persistent_cache: int = 0  # Count loaded from persistent cache

    def add(self, cred: LAPSCredential, persist: bool = True) -> None:
        """
        Add a credential to the cache, indexed by normalized hostname.
        
        Args:
            cred: LAPS credential to add
            persist: If True, also save to persistent SQLite cache
        """
        # Normalize: uppercase, without trailing $
        normalized_name = cred.computer_name.upper().rstrip("$")
        
        # Create cache key - include domain for multi-domain support
        # Format: "DOMAIN\COMPUTERNAME" or just "COMPUTERNAME" if no domain
        if self.domain:
            key = f"{self.domain.upper()}\\{normalized_name}"
        else:
            key = normalized_name
        
        self._cache[key] = cred

        # Update statistics
        if cred.encrypted:
            self.encrypted_count += 1
        elif cred.laps_type == "legacy":
            self.legacy_count += 1
        elif cred.laps_type == "mslaps":
            self.mslaps_count += 1

        # Persist to SQLite cache if enabled
        if persist:
            self._persist_credential(key, cred)

    @staticmethod
    def _normalize_key(hostname: str, domain: Optional[str] = None) -> str:
        """Normalize hostname to uppercase cache key, optionally with domain."""
        normalized = hostname.upper().rstrip("$")
        # Strip any existing domain prefix and re-add if domain specified
        if "\\" in normalized:
            normalized = normalized.split("\\")[-1]
        if "." in normalized:
            # Could be FQDN - extract short name
            normalized = normalized.split(".")[0]
        if domain:
            return f"{domain.upper()}\\{normalized}"
        return normalized

    def _persist_credential(self, key: str, cred: LAPSCredential) -> None:
        """Save credential to persistent SQLite cache"""
        cache = get_cache()
        if not cache or not cache.persistent_enabled:
            return

        # Calculate TTL based on LAPS expiration
        # Default to 8 hours if no expiration (typical LAPS rotation is 24h+)
        if cred.expiration:
            # Use actual expiration, but cap at 24 hours
            ttl_seconds = (cred.expiration - datetime.now(timezone.utc)).total_seconds()
            ttl_hours = min(max(ttl_seconds / 3600, 0.1), 24)  # Min 6 minutes, max 24 hours
        else:
            ttl_hours = 8  # Default for legacy LAPS without expiration info

        try:
            cache.set(LAPS_CACHE_CATEGORY, key, cred.to_cache_dict(), ttl_hours=ttl_hours)
            debug(f"LAPS: Cached {key} (TTL: {ttl_hours:.1f}h)")
        except Exception as e:
            debug(f"LAPS: Failed to persist {key}: {e}")

    def _load_from_persistent(self, key: str) -> Optional[LAPSCredential]:
        """Try to load credential from persistent SQLite cache"""
        cache = get_cache()
        if not cache or not cache.persistent_enabled:
            return None

        try:
            data = cache.get(LAPS_CACHE_CATEGORY, key)
            if data:
                cred = LAPSCredential.from_cache_dict(data)
                # Double-check expiration
                if not cred.is_expired():
                    debug(f"LAPS: Loaded {key} from persistent cache")
                    return cred
                else:
                    debug(f"LAPS: Cached {key} has expired, will re-query")
                    cache.delete(LAPS_CACHE_CATEGORY, key)
        except Exception as e:
            debug(f"LAPS: Failed to load {key} from cache: {e}")

        return None

    def get(self, hostname: str) -> Optional[LAPSCredential]:
        """
        Lookup LAPS credential by hostname.

        Checks in-memory cache first, then persistent cache.
        Lookups are case-insensitive. Uses self.domain for scoped lookups.

        Args:
            hostname: Computer name, FQDN, or IP-resolved name

        Returns:
            LAPSCredential if found, None otherwise
        """
        # Normalize hostname to uppercase, strip $ suffix
        normalized = hostname.upper().rstrip("$")
        
        # Extract short name from FQDN if present
        short_name = normalized.split(".")[0] if "." in normalized else normalized
        
        # Build list of keys to try (most specific to least specific)
        keys_to_try = []
        
        # If domain is set on cache, try domain-qualified key first
        if self.domain:
            keys_to_try.append(f"{self.domain.upper()}\\{short_name}")
        
        # Try unqualified short name (for backward compat and single-domain use)
        keys_to_try.append(short_name)
        
        # Also try the full normalized name if different from short name
        if normalized != short_name:
            if self.domain:
                keys_to_try.append(f"{self.domain.upper()}\\{normalized}")
            keys_to_try.append(normalized)
        
        # Check in-memory cache first
        for key in keys_to_try:
            if key in self._cache:
                return self._cache[key]
        
        # Check persistent cache
        for key in keys_to_try:
            cred = self._load_from_persistent(key)
            if cred:
                # Promote to in-memory cache (don't re-persist)
                self._cache[key] = cred
                self.from_persistent_cache += 1
                return cred

        return None

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, hostname: str) -> bool:
        return self.get(hostname) is not None

    @property
    def total_usable(self) -> int:
        """Count of non-encrypted credentials"""
        return self.legacy_count + self.mslaps_count

    def get_statistics(self) -> Dict[str, int]:
        """Return cache statistics for display"""
        return {
            "total": len(self._cache),
            "legacy": self.legacy_count,
            "mslaps": self.mslaps_count,
            "encrypted": self.encrypted_count,
            "usable": self.total_usable,
            "from_cache": self.from_persistent_cache,
        }

    @classmethod
    def load_from_persistent_cache(cls, domain: Optional[str] = None) -> Optional["LAPSCache"]:
        """
        Load all LAPS credentials from persistent SQLite cache.

        Args:
            domain: Domain name for filtering/scoping (optional, if provided only loads
                    credentials for that domain)

        Returns:
            LAPSCache populated with cached credentials, or None if cache is empty/disabled
        """
        sqlite_cache = get_cache()
        if not sqlite_cache or not sqlite_cache.persistent_enabled:
            debug("LAPS: Persistent cache not available")
            return None

        try:
            # Get all entries from LAPS category
            entries = sqlite_cache.get_all(LAPS_CACHE_CATEGORY)
            if not entries:
                debug("LAPS: No cached credentials found")
                return None

            # Create cache with domain set for future lookups
            cache = cls(domain=domain)
            loaded = 0
            expired = 0
            
            # Normalize domain for comparison
            domain_prefix = f"{domain.upper()}\\" if domain else None

            for key, data in entries.items():
                try:
                    # Normalize key to uppercase for consistent lookup
                    normalized_key = key.upper()
                    
                    # If domain specified, only load entries for that domain
                    if domain_prefix:
                        if not normalized_key.startswith(domain_prefix):
                            # Also check if it's an unqualified key that we should include
                            # (for backward compat with caches created before domain scoping)
                            if "\\" in normalized_key:
                                # Key belongs to a different domain, skip
                                continue
                    
                    cred = LAPSCredential.from_cache_dict(data)
                    if cred.is_expired():
                        expired += 1
                        # Clean up expired entry
                        sqlite_cache.delete(LAPS_CACHE_CATEGORY, key)
                        continue
                    
                    # Add to cache without re-persisting
                    cache._cache[normalized_key] = cred
                    if cred.encrypted:
                        cache.encrypted_count += 1
                    elif cred.laps_type == "legacy":
                        cache.legacy_count += 1
                    elif cred.laps_type == "mslaps":
                        cache.mslaps_count += 1
                    cache.from_persistent_cache += 1
                    loaded += 1
                except Exception as e:
                    debug(f"LAPS: Failed to load cached credential {key}: {e}")
                    continue

            if loaded > 0:
                debug(f"LAPS: Loaded {loaded} credentials from persistent cache ({expired} expired)")
                return cache
            else:
                debug("LAPS: All cached credentials were expired or invalid")
                return None

        except Exception as e:
            debug(f"LAPS: Failed to load from persistent cache: {e}")
            return None

    def save_to_persistent_cache(self) -> int:
        """
        Save all credentials to persistent cache.

        Returns:
            Number of credentials saved
        """
        sqlite_cache = get_cache()
        if not sqlite_cache or not sqlite_cache.persistent_enabled:
            return 0

        saved = 0
        for key, cred in self._cache.items():
            try:
                self._persist_credential(key, cred)
                saved += 1
            except Exception as e:
                debug(f"LAPS: Failed to save {key} to cache: {e}")

        return saved


@dataclass
class LAPSFailure:
    """Represents a LAPS-related failure for a target"""

    hostname: str
    failure_type: str  # "not_found", "auth_failed", "remote_uac", "encrypted"
    message: str
    laps_user_tried: Optional[str] = None
    laps_type_tried: Optional[str] = None


# =============================================================================
# Windows LAPS JSON Parsing
# =============================================================================


def parse_mslaps_password(json_data: str, default_username: Optional[str] = None) -> Tuple[str, str, bool]:
    """
    Parse Windows LAPS msLAPS-Password JSON attribute.

    The attribute contains JSON like:
    {
        "n": "Administrator",     # Account name
        "t": "1d9a2b3c...",       # Timestamp (hex, Windows FILETIME)
        "p": "MyP@ssw0rd123"      # Password (plaintext or encrypted blob)
    }

    Args:
        json_data: Raw JSON string from msLAPS-Password attribute
        default_username: Fallback username if not in JSON

    Returns:
        Tuple of (password, username, is_encrypted)

    Raises:
        LAPSParseError: If JSON parsing fails
    """
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise LAPSParseError(f"Invalid msLAPS-Password JSON: {e}")

    # Extract password
    password = data.get("p", "")
    if not password:
        raise LAPSParseError("msLAPS-Password JSON missing 'p' (password) field")

    # Extract username (Windows LAPS stores the managed account name)
    username = data.get("n", default_username or "Administrator")

    # Check if encrypted
    # Encrypted passwords are base64-encoded blobs, plaintext are readable strings
    # Heuristic: if it looks like base64 and is long, it's probably encrypted
    is_encrypted = False
    if len(password) > 50 and _looks_like_base64(password):
        is_encrypted = True

    return password, username, is_encrypted


def _looks_like_base64(s: str) -> bool:
    """Heuristic check if string looks like base64-encoded data"""
    import re

    # Base64 pattern: alphanumeric + /+ with optional = padding
    if re.match(r"^[A-Za-z0-9+/]+=*$", s):
        # Additional check: typical passwords have special chars that aren't in base64
        return True
    return False


# Alias for backward compatibility - parse_filetime_hex imported from utils.date_parser
parse_filetime = parse_filetime_hex


# =============================================================================
# LDAP Query Functions
# =============================================================================

# Note: _resolve_dc_hostname and _get_ldap_connection moved to utils/ldap.py
# Import them from there: resolve_dc_hostname, get_ldap_connection


def get_laps_passwords(
    dc_ip: str,
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    laps_user_override: Optional[str] = None,
    dc_host: Optional[str] = None,
    use_cache: bool = True,
) -> LAPSCache:
    """
    Get LAPS passwords, checking persistent cache first.

    This is the recommended entry point for LAPS queries. It will:
    1. Check the persistent SQLite cache for valid (non-expired) credentials
    2. If cache has valid credentials, return them without querying AD
    3. If cache is empty/expired, query AD
    4. Save new credentials to cache for future use

    Use --clear-cache to force a refresh from AD.

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format)
        username: Username for LDAP authentication
        password: Password for authentication
        hashes: NTLM hashes (alternative to password)
        kerberos: Use Kerberos authentication
        laps_user_override: Override username for all LAPS credentials
        dc_host: DC hostname for Kerberos SPN (optional, auto-resolved if not provided)
        use_cache: Whether to check persistent cache first (default: True)

    Returns:
        LAPSCache populated with discovered credentials

    Raises:
        LAPSConnectionError: If LDAP connection fails
        LAPSEmptyCacheError: If no LAPS passwords found
    """
    # Try loading from persistent cache first
    if use_cache:
        cached = LAPSCache.load_from_persistent_cache(domain)
        if cached and len(cached) > 0:
            stats = cached.get_statistics()
            good(f"LAPS: Loaded {stats['total']} credentials from cache")
            if stats["mslaps"] > 0:
                info(f"LAPS:   - Windows LAPS: {stats['mslaps']}")
            if stats["legacy"] > 0:
                info(f"LAPS:   - Legacy LAPS: {stats['legacy']}")
            return cached
        else:
            debug("LAPS: No valid cached credentials found, querying AD...")

    # Query AD for fresh credentials
    return query_laps_passwords(
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        laps_user_override=laps_user_override,
        dc_host=dc_host,
        save_to_cache=use_cache,
    )


def query_laps_passwords(
    dc_ip: str,
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    laps_user_override: Optional[str] = None,
    dc_host: Optional[str] = None,
    save_to_cache: bool = True,
) -> LAPSCache:
    """
    Query all LAPS passwords from Active Directory.

    Queries both Windows LAPS (msLAPS-Password) and Legacy LAPS (ms-Mcs-AdmPwd)
    attributes from all computer objects.

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format)
        username: Username for LDAP authentication
        password: Password for authentication
        hashes: NTLM hashes (alternative to password)
        kerberos: Use Kerberos authentication
        laps_user_override: Override username for all LAPS credentials
        dc_host: DC hostname for Kerberos SPN (optional, auto-resolved if not provided)
        save_to_cache: Whether to save results to persistent cache (default: True)

    Returns:
        LAPSCache populated with discovered credentials

    Raises:
        LAPSConnectionError: If LDAP connection fails
        LAPSEmptyCacheError: If no LAPS passwords found
    """
    cache = LAPSCache(domain=domain)

    info("LAPS: Connecting to domain controller via LDAP...")
    debug(f"LAPS: DC={dc_ip}, Domain={domain}, User={username}")

    try:
        ldap_conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            dc_host=dc_host,
        )
    except LAPSConnectionError_Base as e:
        # Re-raise with LAPS-specific exception for API consistency
        raise LAPSConnectionError(str(e))
    except Exception as e:
        raise LAPSConnectionError(f"Unexpected LDAP error: {e}")

    good("LAPS: LDAP connection established")
    info("LAPS: Querying computer objects for LAPS attributes...")

    # Build base DN
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # LDAP filter: computers with either LAPS attribute populated
    # Using (|(attr=*)(attr=*)) to match any computer with LAPS data
    ldap_filter = "(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)))"

    # Attributes to retrieve
    attributes = [
        "sAMAccountName",  # Computer name with $ (e.g., "WS01$")
        "dNSHostName",  # FQDN (e.g., "WS01.domain.local")
        "ms-Mcs-AdmPwd",  # Legacy LAPS password
        "ms-Mcs-AdmPwdExpirationTime",  # Legacy LAPS expiration
        "msLAPS-Password",  # Windows LAPS (JSON)
        "msLAPS-PasswordExpirationTime",  # Windows LAPS expiration
    ]

    try:
        # Perform search
        search_result = ldap_conn.search(
            searchBase=base_dn,
            searchFilter=ldap_filter,
            attributes=attributes,
            sizeLimit=0,  # No limit
        )

        # Process results
        for entry in search_result:
            # Skip search references
            if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                continue

            try:
                cred = _parse_ldap_entry(entry, laps_user_override)
                if cred:
                    cache.add(cred)
                    debug(f"LAPS: Found {cred.laps_type} password for {cred.computer_name}")
            except Exception as e:
                debug(f"LAPS: Failed to parse entry: {e}")
                continue

    except Exception as e:
        warn(f"LAPS: LDAP search failed: {e}")
        raise LAPSConnectionError(f"LDAP search failed: {e}")
    finally:
        # Close connection
        try:
            ldap_conn.close()
        except Exception:
            pass

    # Validate we found something
    if len(cache) == 0:
        raise LAPSEmptyCacheError("No LAPS passwords found in Active Directory")

    # Log statistics
    stats = cache.get_statistics()
    good(f"LAPS: Found {stats['total']} computers with LAPS passwords")
    if stats["mslaps"] > 0:
        info(f"LAPS:   - Windows LAPS: {stats['mslaps']}")
    if stats["legacy"] > 0:
        info(f"LAPS:   - Legacy LAPS: {stats['legacy']}")
    if stats["encrypted"] > 0:
        warn(f"LAPS:   - Encrypted (skipped): {stats['encrypted']}")

    # Save to persistent cache for future runs
    if save_to_cache:
        try:
            cache.save_to_persistent_cache()
            debug(f"LAPS: Saved {stats['total']} credentials to persistent cache")
        except Exception as e:
            debug(f"LAPS: Failed to save to persistent cache: {e}")

    return cache


def _parse_ldap_entry(entry: ldapasn1_impacket.SearchResultEntry, laps_user_override: Optional[str]) -> Optional[LAPSCredential]:
    """
    Parse a single LDAP search result entry into a LAPSCredential.

    Args:
        entry: LDAP search result entry
        laps_user_override: Override username if specified

    Returns:
        LAPSCredential or None if parsing fails
    """
    # Extract attributes from entry
    attrs = {}
    for attr in entry["attributes"]:
        attr_type = str(attr["type"])
        values = attr["vals"]
        if values:
            # Get first value (LAPS attributes are single-valued)
            attrs[attr_type.lower()] = str(values[0])

    # Get computer name (required)
    computer_name = attrs.get("samaccountname")
    if not computer_name:
        return None

    dns_hostname = attrs.get("dnshostname")

    # Try Windows LAPS first (preferred)
    mslaps_password = attrs.get("mslaps-password")
    if mslaps_password:
        try:
            password, username, is_encrypted = parse_mslaps_password(
                mslaps_password, default_username=laps_user_override
            )

            # Parse expiration if available
            expiration = None
            exp_time = attrs.get("mslaps-passwordexpirationtime")
            if exp_time:
                try:
                    expiration = parse_ad_timestamp(int(exp_time))
                except (ValueError, TypeError):
                    pass

            return LAPSCredential(
                password=password if not is_encrypted else "",
                username=laps_user_override or username,
                laps_type="mslaps",
                computer_name=computer_name,
                dns_hostname=dns_hostname,
                expiration=expiration,
                encrypted=is_encrypted,
            )
        except LAPSParseError as e:
            debug(f"LAPS: Failed to parse msLAPS-Password for {computer_name}: {e}")

    # Fall back to Legacy LAPS
    legacy_password = attrs.get("ms-mcs-admpwd")
    if legacy_password:
        # Parse expiration if available
        expiration = None
        exp_time = attrs.get("ms-mcs-admpwdexpirationtime")
        if exp_time:
            try:
                expiration = parse_ad_timestamp(int(exp_time))
            except (ValueError, TypeError):
                pass

        return LAPSCredential(
            password=legacy_password,
            username=laps_user_override or "Administrator",
            laps_type="legacy",
            computer_name=computer_name,
            dns_hostname=dns_hostname,
            expiration=expiration,
            encrypted=False,
        )

    return None


# =============================================================================
# Helper Functions
# =============================================================================


def get_laps_credential_for_host(
    cache: LAPSCache, hostname: str
) -> Tuple[Optional[LAPSCredential], Optional[LAPSFailure]]:
    """
    Lookup LAPS credential for a hostname with failure tracking.

    Args:
        cache: LAPSCache to search
        hostname: Target hostname (short name, FQDN, or resolved from IP)

    Returns:
        Tuple of (credential, failure) - one will be None
    """
    cred = cache.get(hostname)

    if cred is None:
        failure = LAPSFailure(
            hostname=hostname,
            failure_type="not_found",
            message=LAPS_ERRORS["host_not_found"].format(hostname=hostname),
        )
        return None, failure

    if cred.encrypted:
        failure = LAPSFailure(
            hostname=hostname,
            failure_type="encrypted",
            message=LAPS_ERRORS["encrypted"].format(hostname=hostname),
            laps_type_tried=cred.laps_type,
        )
        return None, failure

    if cred.is_expired():
        warn(f"LAPS: Password for {hostname} may be expired (expiration: {cred.expiration})")
        # Still return the credential - it might work if rotation hasn't happened yet

    return cred, None


def print_laps_summary(
    cache: LAPSCache,
    successes: int,
    failures: List[LAPSFailure],
) -> None:
    """
    Print LAPS authentication summary.

    Args:
        cache: LAPSCache that was used
        successes: Number of successful LAPS authentications
        failures: List of LAPS failures
    """
    stats = cache.get_statistics()

    print()
    print("─" * 60)
    print("LAPS STATISTICS")
    print("─" * 60)
    print(f"Total LAPS entries loaded : {stats['total']}")
    if stats["mslaps"] > 0:
        print(f"  - Windows LAPS          : {stats['mslaps']}")
    if stats["legacy"] > 0:
        print(f"  - Legacy LAPS           : {stats['legacy']}")
    if stats["encrypted"] > 0:
        print(f"  - Encrypted (skipped)   : {stats['encrypted']}")
    print()
    print("LAPS Auth Results:")
    print(f"  - Successful            : {successes}")

    # Group failures by type
    failure_counts: Dict[str, int] = {}
    for f in failures:
        failure_counts[f.failure_type] = failure_counts.get(f.failure_type, 0) + 1

    failure_labels = {
        "not_found": "No password in cache",
        "auth_failed": "Auth failed",
        "remote_uac": "Remote UAC blocked",
        "encrypted": "Encrypted (unsupported)",
    }

    for ftype, count in failure_counts.items():
        label = failure_labels.get(ftype, ftype)
        print(f"  - {label:21} : {count}")
