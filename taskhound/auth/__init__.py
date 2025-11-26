# Authentication context and utilities.
#
# This module provides a centralized AuthContext dataclass that bundles
# all authentication-related parameters, eliminating repeated parameter
# lists across the codebase.

from .context import AuthContext

__all__ = ["AuthContext"]
