# LAPS Helper Functions
from typing import List, Optional, Tuple

from ..utils.logging import warn
from .exceptions import LAPS_ERRORS
from .models import LAPSCache, LAPSCredential, LAPSFailure

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
        warn(f"LAPS: Password for {hostname} may be expired (expiration: {cred.expiration})", verbose_only=True)
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
    failure_counts: dict[str, int] = {}
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
