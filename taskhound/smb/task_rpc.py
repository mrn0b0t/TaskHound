"""
Task Scheduler RPC client for credential validation.

Uses MS-TSCH protocol to query task execution history and determine
if stored credentials are valid based on return codes.

Requires RPC_C_AUTHN_LEVEL_PKT_PRIVACY authentication level.
"""

import contextlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from impacket.dcerpc.v5 import transport, tsch
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from taskhound.utils.logging import debug as log_debug
from taskhound.utils.logging import warn


class CredentialStatus(Enum):
    """Credential validation status based on task return codes."""

    VALID = "valid"  # Password correct, task ran successfully
    VALID_RESTRICTED = "valid_restricted"  # Password correct, but account restricted
    INVALID = "invalid"  # Wrong password or user not found
    BLOCKED = "blocked"  # Account disabled/locked/expired
    UNKNOWN = "unknown"  # Task never ran, cannot determine


@dataclass
class TaskRunInfo:
    """Information about a task's last execution and credential validation."""

    task_path: str
    last_run: Optional[datetime]
    return_code: int
    credential_status: CredentialStatus
    status_detail: str
    password_valid: bool  # Key field for DPAPI feasibility
    task_hijackable: bool  # Can we use this for execution?


# fmt: off
# Return codes indicating PASSWORD IS CORRECT (DPAPI feasible)
PASSWORD_VALID_CODES: set[int] = {
    # Task executed successfully - credentials definitely work
    0x00000000,  # SUCCESS
    0x00000001,  # ERROR_INVALID_FUNCTION
    0x00000002,  # ERROR_FILE_NOT_FOUND
    0x00000005,  # ERROR_ACCESS_DENIED (command-level, NOT auth)
    0x0000007B,  # ERROR_INVALID_NAME
    0x000000C1,  # ERROR_BAD_EXE_FORMAT
    0x800700C1,  # ERROR_BAD_EXE_FORMAT (HRESULT)
    0x80070002,  # ERROR_FILE_NOT_FOUND (HRESULT)
    0x80070005,  # E_ACCESSDENIED (HRESULT, command-level)

    # Account restrictions - password IS correct, just can't batch logon
    # These prove the password because Windows validates it before checking rights
    0x80070569,  # ERROR_LOGON_TYPE_NOT_GRANTED (no "batch logon" right)
    0xC000015B,  # STATUS_LOGON_TYPE_NOT_GRANTED (NTSTATUS)
    0x800704C3,  # ERROR_LOGON_NOT_GRANTED
    0xC000006E,  # STATUS_ACCOUNT_RESTRICTION
    0x80070533,  # ERROR_ACCOUNT_RESTRICTION
}

# Subset of PASSWORD_VALID_CODES: Task can actually run (hijackable)
TASK_RUNNABLE_CODES: set[int] = {
    0x00000000,  # SUCCESS
    0x00000001,  # ERROR_INVALID_FUNCTION
    0x00000002,  # ERROR_FILE_NOT_FOUND
    0x00000005,  # ERROR_ACCESS_DENIED
    0x0000007B,  # ERROR_INVALID_NAME
    0x000000C1,  # ERROR_BAD_EXE_FORMAT
    0x800700C1,  # ERROR_BAD_EXE_FORMAT (HRESULT)
    0x80070002,  # ERROR_FILE_NOT_FOUND (HRESULT)
    0x80070005,  # E_ACCESSDENIED (HRESULT)
}

# Password is WRONG or user doesn't exist
PASSWORD_INVALID_CODES: set[int] = {
    0x8007052E,  # ERROR_LOGON_FAILURE - wrong password
    0xC000006D,  # STATUS_LOGON_FAILURE (NTSTATUS)
    0x80070525,  # ERROR_NO_SUCH_USER
    0x8004130F,  # SCHED_E_ACCOUNT_INFORMATION_NOT_SET
    0x80041310,  # SCHED_E_ACCOUNT_NAME_NOT_FOUND
}

# Account blocked - password status unknown (may have been correct)
ACCOUNT_BLOCKED_CODES: set[int] = {
    0x8007056A,  # ERROR_PASSWORD_EXPIRED
    0x8007056B,  # ERROR_ACCOUNT_DISABLED
    0x80070775,  # ERROR_ACCOUNT_LOCKED_OUT
}

# Human-readable descriptions for common return codes
RETURN_CODE_DESCRIPTIONS: dict[int, str] = {
    0x00000000: "Task completed successfully",
    0x00000001: "Invalid function (command error)",
    0x00000002: "File not found",
    0x00000005: "Access denied (command-level)",
    0x0000007B: "Invalid name",
    0x000000C1: "Bad executable format",
    0x00041300: "Task is ready to run",
    0x00041301: "Task is currently running",
    0x00041302: "Task is disabled",
    0x00041303: "Task has not run",
    0x00041304: "No more runs scheduled",
    0x00041305: "Account information not set (not all properties valid)",
    0x00041306: "Task was terminated by user",
    0x00041307: "No valid triggers",
    0x00041308: "Event triggers don't have set run times",
    0x00041309: "Task trigger not found",
    0x0004130A: "One or more properties are invalid",
    0x0004130B: "No account specified for task",
    0x0004130C: "Task security context could not be set",
    0x0004130D: "Task registered, but not all triggers will start",
    0x0004130E: "Task registered, but may fail to start",
    0x0004130F: "Task is disabled",
    0x00041310: "Task has properties not compatible with earlier versions",
    0x00041311: "Task settings don't allow to start on demand",
    0x80070002: "File not found",
    0x80070005: "Access denied (command-level)",
    0x80070525: "User not found",
    0x80070533: "Account restriction",
    0x80070569: "Logon type not granted (no batch logon right)",
    0x8007052E: "Logon failure (wrong password)",
    0x8007056A: "Password expired",
    0x8007056B: "Account disabled",
    0x80070775: "Account locked out",
    0x800700C1: "Bad executable format",
    0x800704C3: "Logon not granted",
    0x800710E0: "Operation cancelled by user",
    0x8004130A: "Account name not found in the store",
    0x8004130B: "Task XML contains values incorrect or out of range",
    0x8004130C: "Task XML contains unexpected node",
    0x8004130D: "Task XML contains element/attribute from unexpected namespace",
    0x8004130E: "Task XML is malformed",
    0x8004130F: "Account information not set",
    0x80041310: "Account name not found",
    0x80041311: "Account information not set (XML)",
    0x80041312: "No security services available (orphaned task)",
    0x80041313: "Unable to establish connection to security services",
    0x80041314: "Unable to get object security descriptor",
    0x80041315: "Unable to query/set account information",
    0x80041316: "Unable to query/set password",
    0x80041317: "Not supported on this platform",
    0x80041318: "Access denied on remote machine",
    0x80041319: "Task object version mismatch",
    0x8004131A: "Task is already running",
    0x8004131B: "Task not running",
    0x8004131C: "Task service not running",
    0x8004131D: "S4U + Interactive tokens not supported (WinXP)",
    0x8004131E: "Network unavailable",
    0x8004131F: "S4U option requires password",
    0xC000006D: "Logon failure (NTSTATUS)",
    0xC000006E: "Account restriction (NTSTATUS)",
    0xC000015B: "Logon type not granted (NTSTATUS)",
}
# fmt: on


def get_return_code_description(code: int) -> str:
    """Get human-readable description for a return code."""
    return RETURN_CODE_DESCRIPTIONS.get(code, f"Unknown code 0x{code:08X}")


class TaskSchedulerRPC:
    """
    Task Scheduler RPC client for querying task execution history.

    Uses MS-TSCH protocol over named pipe \\pipe\\atsvc.
    Requires PKT_PRIVACY authentication level for access.
    """

    def __init__(
        self,
        target: str,
        domain: str,
        username: str,
        password: str,
        lm_hash: str = "",
        nt_hash: str = "",
        aes_key: str = "",
        kerberos: bool = False,
        dc_ip: str = "",
    ):
        """
        Initialize Task Scheduler RPC client.

        Args:
            target: Target hostname or IP
            domain: Domain name
            username: Username for authentication
            password: Password (or empty if using hash/aesKey)
            lm_hash: LM hash (optional)
            nt_hash: NT hash (optional)
            aes_key: Kerberos AES key (optional, 128 or 256-bit)
            kerberos: Use Kerberos authentication
            dc_ip: Domain Controller IP for KDC (optional)
        """
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aes_key = aes_key
        self.kerberos = kerberos
        self.dc_ip = dc_ip
        self._dce = None
        self._connection_lost = False

    def connect(self) -> bool:
        """
        Establish RPC connection to Task Scheduler service.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            binding = f"ncacn_np:{self.target}[\\pipe\\atsvc]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_credentials(
                self.username,
                self.password,
                self.domain,
                self.lm_hash,
                self.nt_hash,
                self.aes_key,
            )

            # Enable Kerberos if requested (needed for AES key auth)
            if self.kerberos or self.aes_key:
                kdc_host = self.dc_ip or self.target
                rpc_transport.set_kerberos(True, kdcHost=kdc_host)
                log_debug(f"Using Kerberos authentication for RPC (KDC: {kdc_host})")

            self._dce = rpc_transport.get_dce_rpc()
            # PKT_PRIVACY is REQUIRED - lower auth levels get access denied
            self._dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            # For Kerberos, must set GSS_NEGOTIATE auth type BEFORE connect()
            if self.kerberos or self.aes_key:
                self._dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            self._dce.connect()
            self._dce.bind(tsch.MSRPC_UUID_TSCHS)
            self._connection_lost = False

            log_debug(f"Connected to Task Scheduler RPC on {self.target}")
            return True

        except Exception as e:
            log_debug(f"Failed to connect to Task Scheduler RPC: {e}")
            return False

    def disconnect(self) -> None:
        """Close RPC connection."""
        if self._dce:
            with contextlib.suppress(Exception):
                self._dce.disconnect()
            self._dce = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

    def get_task_run_info(self, task_path: str) -> Optional[TaskRunInfo]:
        """
        Query last run information for a specific task.

        Args:
            task_path: Full path to task (e.g., "\\MyTask" or
                      "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag")

        Returns:
            TaskRunInfo with credential validation results, or None on error
        """
        if not self._dce:
            warn("Not connected to Task Scheduler RPC")
            return None

        try:
            resp = tsch.hSchRpcGetLastRunInfo(self._dce, task_path)
            last_run_time = resp["pLastRuntime"]
            return_code = resp["pLastReturnCode"]

            # Parse last run time
            if last_run_time["wYear"] == 0:
                last_run = None
            else:
                last_run = datetime(
                    year=last_run_time["wYear"],
                    month=last_run_time["wMonth"],
                    day=last_run_time["wDay"],
                    hour=last_run_time["wHour"],
                    minute=last_run_time["wMinute"],
                    second=last_run_time["wSecond"],
                )

            # Determine credential status
            cred_status, password_valid, hijackable, detail = (
                self._interpret_return_code(return_code, last_run)
            )

            return TaskRunInfo(
                task_path=task_path,
                last_run=last_run,
                return_code=return_code,
                credential_status=cred_status,
                status_detail=detail,
                password_valid=password_valid,
                task_hijackable=hijackable,
            )

        except Exception as e:
            error_str = str(e)
            if "SCHED_S_TASK_HAS_NOT_RUN" in error_str:
                return TaskRunInfo(
                    task_path=task_path,
                    last_run=None,
                    return_code=0x00041303,
                    credential_status=CredentialStatus.UNKNOWN,
                    status_detail="Task has never run",
                    password_valid=False,  # Can't determine
                    task_hijackable=False,  # Can't determine
                )
            log_debug(f"Failed to get run info for {task_path}: {e}")
            # Check if connection was lost (need to reconnect)
            if "PIPE_DISCONNECTED" in error_str or "rpc_s_access_denied" in error_str:
                self._connection_lost = True
            return None

    def _interpret_return_code(
        self, code: int, last_run: Optional[datetime]
    ) -> tuple[CredentialStatus, bool, bool, str]:
        """
        Interpret return code for credential validation.

        Args:
            code: Task return code
            last_run: Last run datetime (None if never ran)

        Returns:
            Tuple of (status, password_valid, task_hijackable, detail_message)
        """
        detail = get_return_code_description(code)

        if last_run is None:
            return (CredentialStatus.UNKNOWN, False, False, "Task never executed")

        if code in PASSWORD_VALID_CODES:
            hijackable = code in TASK_RUNNABLE_CODES
            if hijackable:
                return (CredentialStatus.VALID, True, True, detail)
            else:
                return (
                    CredentialStatus.VALID_RESTRICTED,
                    True,
                    False,
                    f"{detail} (password valid, account restricted)",
                )

        elif code in PASSWORD_INVALID_CODES:
            return (CredentialStatus.INVALID, False, False, detail)

        elif code in ACCOUNT_BLOCKED_CODES:
            return (CredentialStatus.BLOCKED, False, False, detail)

        else:
            # Unknown code but task ran - likely valid
            return (
                CredentialStatus.VALID,
                True,
                True,
                f"{detail} (task executed, assuming valid)",
            )

    def validate_specific_tasks(
        self, task_paths: list[str]
    ) -> dict[str, TaskRunInfo]:
        """
        Validate credentials for specific task paths.

        Use this when you already have the list of password-authenticated
        tasks from SMB crawling - avoids redundant RPC enumeration.

        Args:
            task_paths: List of task paths to validate.
                        Accepts SMB paths like "Windows\\System32\\Tasks\\MyTask"
                        or RPC paths like "\\MyTask"

        Returns:
            Dictionary mapping ORIGINAL task path to TaskRunInfo
            (preserves the SMB path format for correlation)
        """
        results = {}

        # Task root prefix from SMB crawling
        SMB_TASK_PREFIX = "Windows\\System32\\Tasks\\"
        SMB_TASK_PREFIX_ALT = "Windows/System32/Tasks/"

        # Track if we need to reconnect (Kerberos connections can drop after errors)
        for original_path in task_paths:
            # Reconnect if connection was lost (common with Kerberos after RPC errors)
            if self._connection_lost:
                log_debug("Reconnecting to Task Scheduler RPC (connection lost)...")
                self.disconnect()
                if not self.connect():
                    log_debug("Failed to reconnect to Task Scheduler RPC")
                    break

            # Convert SMB path to RPC path
            # SMB: "Windows\System32\Tasks\HIGH_PRIV_CREDS"
            # RPC: "\HIGH_PRIV_CREDS"
            rpc_path = original_path

            # Strip SMB task root prefix
            if rpc_path.startswith(SMB_TASK_PREFIX):
                rpc_path = rpc_path[len(SMB_TASK_PREFIX):]
            elif rpc_path.startswith(SMB_TASK_PREFIX_ALT):
                rpc_path = rpc_path[len(SMB_TASK_PREFIX_ALT):]

            # Ensure path starts with backslash for RPC
            if not rpc_path.startswith("\\"):
                rpc_path = "\\" + rpc_path

            # Normalize path separators (SMB uses \, RPC uses \)
            rpc_path = rpc_path.replace("/", "\\")

            log_debug(f"Validating credentials for task: {rpc_path} (SMB: {original_path})")
            run_info = self.get_task_run_info(rpc_path)
            if run_info:
                # Store with original SMB path for correlation with crawled tasks
                results[original_path] = run_info
            else:
                log_debug(f"Could not get run info for {rpc_path}")

        return results
