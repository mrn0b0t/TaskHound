# Logging utilities - delegates to rich console.
#
# This module maintains backwards compatibility for existing imports while
# delegating all output to the rich-based console module.

import os

from .console import (
    debug as _debug,
)
from .console import (
    error as _error,
)
from .console import (
    good as _good,
)
from .console import (
    info as _info,
)
from .console import (
    set_verbosity as _set_verbosity,
)
from .console import (
    status as _status,
)
from .console import (
    warn as _warn,
)

_VERBOSE = False
_DEBUG = False


def set_verbosity(verbose: bool, debug_flag: bool):
    """Set verbosity levels for both old and new systems."""
    global _VERBOSE, _DEBUG
    _VERBOSE = verbose
    _DEBUG = debug_flag
    _set_verbosity(verbose, debug_flag)

    # Also set env var for compatibility with other modules
    if debug_flag:
        os.environ["TASKHOUND_DEBUG"] = "1"


def status(msg: str):
    """Always print status message (concise output)."""
    _status(msg)


def good(msg: str, verbose_only: bool = False):
    """Print success message (verbose/debug only for backwards compat).

    Args:
        msg: Message to print
        verbose_only: If True, only print in verbose mode (default behavior anyway)
    """
    if _VERBOSE or _DEBUG:
        _good(msg)


def warn(msg: str, verbose_only: bool = False):
    """Print warning message.

    Args:
        msg: Message to print
        verbose_only: If True, only print in verbose mode
    """
    _warn(msg, verbose_only=verbose_only)


def error(msg: str):
    """Print error message."""
    _error(msg)


def info(msg: str, verbose_only: bool = False):
    """Print info message (verbose/debug only for backwards compat).

    Args:
        msg: Message to print
        verbose_only: If True, only print in verbose mode (same as default behavior)
    """
    # verbose_only parameter is kept for API consistency but info()
    # is already verbose-only by default
    if _VERBOSE or _DEBUG:
        _info(msg)


def debug(msg: str, exc_info: bool = False):
    """Debug logging - only prints if DEBUG flag is enabled."""
    if _DEBUG or os.getenv("DEBUG") or os.getenv("TASKHOUND_DEBUG"):
        _debug(msg, exc_info=exc_info)
