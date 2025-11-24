# Small helpers used across the codebase.
#
# This module contains simple utilities for classifying RunAs values,
# normalizing target hostnames, and the ASCII banner used by the CLI.

import re
import uuid
from typing import List


def is_ipv4(host: str) -> bool:
    # Fast, permissive IPv4 string check (no regex).
    #
    # Accepts dotted-quad notation and ensures each octet is in 0-255.
    parts = host.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def normalize_targets(targets: List[str], domain: str) -> List[str]:
    # Normalize a list of targets: keep IPs, append domain for short hostnames.
    #
    # Empty lines are ignored. This mirrors the behavior expected by the CLI
    # where users may pass bare hostnames that need to be FQDN-ified.
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if is_ipv4(t):
            out.append(t)
        else:
            # append domain if it's a short host (no dot)
            if "." not in t:
                out.append(f"{t}.{domain}")
            else:
                out.append(t)
    return out


BANNER = r"""
TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD
  T   A   A S     K  K  H   H O   O U   U NN  N D   D
  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D
  T   A   A     S K  K  H   H O   O U   U N  NN D   D
  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD

                     by 0xr0BIT
"""


def sanitize_json_string(json_str: str) -> str:
    """
    Sanitize JSON string to handle unescaped backslashes that break JSON parsing.

    This commonly occurs in Active Directory Distinguished Names like:
    "CN=LASTNAME\\, FIRSTNAME,OU=..."

    Args:
        json_str: Raw JSON string that may contain unescaped backslashes

    Returns:
        Sanitized JSON string with properly escaped backslashes
    """
    # Replace single backslashes with double backslashes, but be careful not to
    # double-escape already escaped sequences

    # First, temporarily replace already properly escaped sequences
    placeholder = str(uuid.uuid4())

    # Protect already escaped sequences (\\, \", \n, \r, \t, \/, \b, \f, \u)
    protected = json_str.replace("\\\\", placeholder + "BACKSLASH")
    protected = protected.replace('\\"', placeholder + "QUOTE")
    protected = protected.replace("\\n", placeholder + "NEWLINE")
    protected = protected.replace("\\r", placeholder + "RETURN")
    protected = protected.replace("\\t", placeholder + "TAB")
    protected = protected.replace("\\/", placeholder + "SLASH")
    protected = protected.replace("\\b", placeholder + "BACKSPACE")
    protected = protected.replace("\\f", placeholder + "FORMFEED")

    # Protect unicode escapes (\uXXXX)
    unicode_pattern = r"\\u[0-9a-fA-F]{4}"
    unicode_matches = re.findall(unicode_pattern, protected)
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(match, f"{placeholder}UNICODE{i}")

    # Now escape any remaining single backslashes
    protected = protected.replace("\\", "\\\\")

    # Restore the protected sequences
    protected = protected.replace(placeholder + "BACKSLASH", "\\\\")
    protected = protected.replace(placeholder + "QUOTE", '\\"')
    protected = protected.replace(placeholder + "NEWLINE", "\\n")
    protected = protected.replace(placeholder + "RETURN", "\\r")
    protected = protected.replace(placeholder + "TAB", "\\t")
    protected = protected.replace(placeholder + "SLASH", "\\/")
    protected = protected.replace(placeholder + "BACKSPACE", "\\b")
    protected = protected.replace(placeholder + "FORMFEED", "\\f")

    # Restore unicode escapes
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(f"{placeholder}UNICODE{i}", match)

    return protected
