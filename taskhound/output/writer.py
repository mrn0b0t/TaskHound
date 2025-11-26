import csv
import json
import os
from typing import Any, Dict, List

from ..utils.logging import good


def _rows_to_dicts(rows: List[Any]) -> List[Dict]:
    """Convert TaskRow objects to dicts for serialization."""
    return [row.to_dict() if hasattr(row, "to_dict") else row for row in rows]


def write_plain(outdir: str, host: str, lines: List[str]):
    os.makedirs(outdir, exist_ok=True)
    safe = host.replace(":", "_")
    path = os.path.join(outdir, f"{safe}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    good(f"Wrote results to {path}")


def write_json(path: str, rows: List[Any]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_rows_to_dicts(rows), f, indent=2)
    good(f"Wrote JSON results to {path}")


def write_csv(path: str, rows: List[Any]):
    fieldnames = [
        "host",
        "target_ip",
        "computer_sid",
        "path",
        "type",
        "runas",
        "command",
        "arguments",
        "author",
        "date",
        "logon_type",
        "enabled",
        "trigger_type",
        "start_boundary",
        "interval",
        "duration",
        "days_interval",
        "reason",
        "credentials_hint",
        "credential_guard",
        "password_analysis",
        "cred_status",
        "cred_password_valid",
        "cred_hijackable",
        "cred_last_run",
        "cred_return_code",
        "cred_detail",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(_rows_to_dicts(rows))
    good(f"Wrote CSV results to {path}")
