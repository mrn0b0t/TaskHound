# Task classification logic for determining privilege levels.
#
# This module provides shared classification logic used by both online
# and offline processing modes. It determines whether a task is TIER-0,
# PRIV (high-value), or TASK (normal) based on the runas account.

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .utils.logging import warn
from .utils.sid_resolver import looks_like_domain_user


@dataclass
class ClassificationResult:
    """Result of task classification."""

    task_type: str  # "TIER-0", "PRIV", or "TASK"
    reason: Optional[str] = None
    password_analysis: Optional[str] = None
    should_include: bool = True  # Whether to include in output


def _get_task_date_for_analysis(meta: Dict) -> Tuple[Optional[str], bool]:
    """
    Get the best available date for password freshness analysis.
    Prefers RegistrationInfo/Date, falls back to StartBoundary from trigger.

    Args:
        meta: Task metadata dict containing date and start_boundary fields

    Returns:
        Tuple of (date_string, is_fallback) where:
        - date_string: ISO format date string or None if no date available
        - is_fallback: True if using StartBoundary fallback, False if using explicit date
    """
    # Prefer explicit registration date
    if meta.get("date"):
        return meta.get("date"), False

    # Fall back to start boundary (trigger time) as proxy for task creation
    # This is less accurate but better than no analysis at all
    if meta.get("start_boundary"):
        return meta.get("start_boundary"), True

    return None, False


def _analyze_password_age(
    hv: Any,
    runas: str,
    meta: Dict,
    rel_path: str,
) -> Optional[str]:
    """
    Analyze password age for DPAPI dump viability.

    Args:
        hv: HighValueLoader instance
        runas: The account the task runs as
        meta: Task metadata dict
        rel_path: Task path for warning messages

    Returns:
        Password analysis string or None if not applicable
    """
    if not hv or not hv.loaded:
        return None

    task_date, is_fallback = _get_task_date_for_analysis(meta)
    if is_fallback and task_date:
        warn(
            f"Task {rel_path} has no explicit creation date - "
            "using trigger StartBoundary for password analysis (may be inaccurate)"
        )

    risk_level, pwd_analysis = hv.analyze_password_age(runas, task_date)
    if risk_level != "UNKNOWN":
        return pwd_analysis

    return None


def classify_task(
    row: Dict[str, Any],
    meta: Dict[str, Any],
    runas: str,
    rel_path: str,
    hv: Optional[Any],
    show_unsaved_creds: bool,
    include_local: bool,
) -> ClassificationResult:
    """
    Classify a task as TIER-0, PRIV, or TASK based on the runas account.

    This is the single source of truth for task classification logic,
    used by both online and offline processing modes.

    Args:
        row: Task row dict (modified in place with type/reason/password_analysis)
        meta: Parsed task XML metadata
        runas: The account the task runs as
        rel_path: Task path for display/warnings
        hv: HighValueLoader instance (can be None)
        show_unsaved_creds: Whether to include tasks without saved credentials
        include_local: Whether to include local system accounts

    Returns:
        ClassificationResult with task_type, reason, password_analysis, should_include
    """
    has_no_saved_creds = row.get("credentials_hint") == "no_saved_credentials"
    has_stored_creds = row.get("credentials_hint") == "stored_credentials"

    # Skip tasks without saved credentials unless user explicitly requested them
    if has_no_saved_creds and not show_unsaved_creds:
        return ClassificationResult(
            task_type="TASK",
            should_include=False,
        )

    # Check for Tier 0 first, then high-value
    if hv and hv.loaded:
        # Check Tier 0 classification
        is_tier0, tier0_reasons = hv.check_tier0(runas)
        if is_tier0:
            reason = "; ".join(tier0_reasons)
            password_analysis = None

            if has_no_saved_creds:
                reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
            else:
                password_analysis = _analyze_password_age(hv, runas, meta, rel_path)

            # Update row in place
            row["type"] = "TIER-0"
            row["reason"] = reason
            row["password_analysis"] = password_analysis

            return ClassificationResult(
                task_type="TIER-0",
                reason=reason,
                password_analysis=password_analysis,
                should_include=True,
            )

        # Check high-value (PRIV)
        if hv.check_highvalue(runas):
            reason = "High Value match found (Check BloodHound Outbound Object Control for Details)"
            password_analysis = None

            if has_no_saved_creds:
                reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
            else:
                password_analysis = _analyze_password_age(hv, runas, meta, rel_path)

            # Update row in place
            row["type"] = "PRIV"
            row["reason"] = reason
            row["password_analysis"] = password_analysis

            return ClassificationResult(
                task_type="PRIV",
                reason=reason,
                password_analysis=password_analysis,
                should_include=True,
            )

    # Regular task - still analyze password age if credentials are stored
    password_analysis = None
    if hv and hv.loaded and has_stored_creds:
        password_analysis = _analyze_password_age(hv, runas, meta, rel_path)

    # Determine if we should include this regular task
    should_include = (
        looks_like_domain_user(runas)
        or has_stored_creds
        or (include_local and not looks_like_domain_user(runas))
    )

    if should_include:
        row["password_analysis"] = password_analysis

    return ClassificationResult(
        task_type="TASK",
        reason=None,
        password_analysis=password_analysis,
        should_include=should_include,
    )
