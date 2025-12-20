# Remote registry helpers for Credential Guard detection
#
# This module provides a function to remotely check if Credential Guard is enabled on a Windows host
# via the SYSTEM\CurrentControlSet\Control\Lsa registry keys. Uses Impacket's RemoteOperations and
# RemoteRegistry classes. Returns True if Credential Guard is detected, False otherwise.

import logging

from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

logger = logging.getLogger(__name__)


def check_credential_guard(smb_conn, host):
    # Returns True if Credential Guard is enabled, False otherwise.
    #
    # Checks HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags == 1
    # and/or HKLM\SYSTEM\CurrentControlSet\Control\Lsa\IsolatedUserMode == 1
    #
    # Returns True if either key is set to 1, False otherwise or on error.
    try:
        logger.debug(f"{host}: CredGuard check - connecting to remote registry (\\pipe\\winreg)")
        stringBinding = rf"ncacn_np:{host}[\pipe\winreg]"
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_smb_connection(smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        logger.debug(f"{host}: CredGuard check - RRP bind successful")

        # Open HKLM
        reg_handle = rrp.hOpenLocalMachine(dce)["phKey"]
        logger.debug(f"{host}: CredGuard check - opened HKLM")

        # Open LSA key
        lsa_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
        ans = rrp.hBaseRegOpenKey(dce, reg_handle, lsa_path, samDesired=rrp.KEY_READ)
        lsa_handle = ans["phkResult"]
        logger.debug(f"{host}: CredGuard check - opened {lsa_path}")

        # Check LsaCfgFlags
        lsa_cfg_flags = None
        try:
            val = rrp.hBaseRegQueryValue(dce, lsa_handle, "LsaCfgFlags")
            lsa_cfg_flags = int.from_bytes(val["lpData"], "little")
            logger.debug(f"{host}: CredGuard check - LsaCfgFlags = {lsa_cfg_flags}")
            if lsa_cfg_flags == 1:
                logger.debug(f"{host}: CredGuard check - DETECTED via LsaCfgFlags=1")
                return True
        except DCERPCException:
            logger.debug(f"{host}: CredGuard check - LsaCfgFlags not present")

        # Check IsolatedUserMode
        isolated_user_mode = None
        try:
            val = rrp.hBaseRegQueryValue(dce, lsa_handle, "IsolatedUserMode")
            isolated_user_mode = int.from_bytes(val["lpData"], "little")
            logger.debug(f"{host}: CredGuard check - IsolatedUserMode = {isolated_user_mode}")
            if isolated_user_mode == 1:
                logger.debug(f"{host}: CredGuard check - DETECTED via IsolatedUserMode=1")
                return True
        except DCERPCException:
            logger.debug(f"{host}: CredGuard check - IsolatedUserMode not present")

        logger.debug(f"{host}: CredGuard check - NOT detected (LsaCfgFlags={lsa_cfg_flags}, IsolatedUserMode={isolated_user_mode})")
        return False
    except Exception as e:
        logger.debug(f"{host}: CredGuard check failed: {type(e).__name__}: {e}")
        return False
