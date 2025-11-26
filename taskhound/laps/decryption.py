# LAPS Encrypted Password Decryption (Windows LAPS / DPAPI-NG)
import json
from dataclasses import dataclass, field
from typing import Any

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import (
    EncryptedPasswordBlob,
    KeyIdentifier,
    compute_kek,
    create_sd,
    decrypt_plaintext,
    unwrap_cek,
)
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652

from ..utils.logging import debug
from .exceptions import LAPSError

# =============================================================================
# Decryption Context
# =============================================================================


@dataclass
class LAPSDecryptionContext:
    """
    Context for LAPS encrypted password decryption via MS-GKDI.

    Holds authentication credentials and connection parameters needed
    to establish the RPC connection to the Group Key Distribution Service.
    """

    domain: str
    username: str
    password: str | None = None
    lmhash: str = ""
    nthash: str = ""
    kerberos: bool = False
    kdc_host: str | None = None
    dns_server: str | None = None

    # Cache for Group Key Envelopes to avoid repeated RPC calls
    _gke_cache: dict[bytes, Any] = field(default_factory=dict)

    @classmethod
    def from_credentials(
        cls,
        domain: str,
        username: str,
        password: str | None = None,
        hashes: str | None = None,
        kerberos: bool = False,
        kdc_host: str | None = None,
        dns_server: str | None = None,
    ) -> "LAPSDecryptionContext":
        """Create context from standard authentication parameters."""
        lmhash = ""
        nthash = ""
        if hashes:
            if ":" in hashes:
                lmhash, nthash = hashes.split(":")
            else:
                nthash = hashes

        return cls(
            domain=domain,
            username=username,
            password=password,
            lmhash=lmhash,
            nthash=nthash,
            kerberos=kerberos,
            kdc_host=kdc_host,
            dns_server=dns_server,
        )


# =============================================================================
# Decryption Functions
# =============================================================================


def decrypt_laps_password(
    encrypted_blob: bytes,
    ctx: LAPSDecryptionContext,
) -> tuple[str, str]:
    """
    Decrypt an msLAPS-EncryptedPassword blob using MS-GKDI.

    Windows LAPS encrypts passwords using DPAPI-NG (also known as CNG DPAPI).
    Decryption requires:
    1. Parsing the encrypted blob structure
    2. Extracting the Key Identifier and SID protection descriptor
    3. Connecting to MS-GKDI (Group Key Distribution Interface) on the DC
    4. Calling GetKey to retrieve the Group Key Envelope
    5. Computing the KEK (Key Encryption Key)
    6. Unwrapping the CEK (Content Encryption Key)
    7. Decrypting the password JSON

    Args:
        encrypted_blob: Raw bytes from msLAPS-EncryptedPassword attribute
        ctx: Decryption context with authentication credentials

    Returns:
        Tuple of (password, username) from the decrypted JSON

    Raises:
        LAPSError: If decryption fails
    """
    debug("LAPS: Unpacking encrypted password blob...")

    try:
        # Parse the encrypted blob structure
        encrypted_laps = EncryptedPasswordBlob(encrypted_blob)
        cms_blob = encrypted_laps["Blob"]

        # Decode the CMS (PKCS#7) structure
        parsed_cms, remaining = decoder.decode(cms_blob, asn1Spec=rfc5652.ContentInfo())
        enveloped_data_blob = parsed_cms["content"]
        parsed_enveloped, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())

        # Extract recipient info (contains the encrypted key)
        recipient_infos = parsed_enveloped["recipientInfos"]
        kek_recipient_info = recipient_infos[0]["kekri"]
        kek_identifier = kek_recipient_info["kekid"]

        # Parse the Key Identifier
        key_id = KeyIdentifier(bytes(kek_identifier["keyIdentifier"]))

        # Extract the SID from the protection descriptor
        tmp, _ = decoder.decode(kek_identifier["other"]["keyAttr"])
        sid = tmp["field-1"][0][0][1].asOctets().decode("utf-8")
        target_sd = create_sd(sid)

        debug(f"LAPS: Key ID root: {key_id['RootKeyId']}, SID: {sid}")

    except Exception as e:
        raise LAPSError(f"Failed to parse encrypted LAPS blob: {e}") from e

    # Check cache for Group Key Envelope
    root_key_id = key_id["RootKeyId"]
    gke = ctx._gke_cache.get(root_key_id)

    if not gke:
        debug("LAPS: Connecting to MS-GKDI for key retrieval...")
        gke = _get_group_key_envelope(ctx, target_sd, key_id)
        ctx._gke_cache[root_key_id] = gke
    else:
        debug("LAPS: Using cached Group Key Envelope")

    try:
        # Compute the Key Encryption Key (KEK)
        kek = compute_kek(gke, key_id)
        debug(f"LAPS: Computed KEK: {kek.hex()[:32]}...")

        # Extract IV from content encryption parameters
        enc_content_param = bytes(
            parsed_enveloped["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"]
        )
        iv, _ = decoder.decode(enc_content_param)
        iv = bytes(iv[0])

        # Unwrap the Content Encryption Key (CEK)
        cek = unwrap_cek(kek, bytes(kek_recipient_info["encryptedKey"]))
        debug(f"LAPS: Unwrapped CEK: {cek.hex()[:32]}...")

        # Decrypt the password
        # The 'remaining' data contains the encrypted content (not in PKCS#7 structure)
        plaintext = decrypt_plaintext(cek, iv, remaining)

        # Remove padding (last 18 bytes are padding/signature)
        json_data = plaintext[:-18].decode("utf-16-le")
        debug(f"LAPS: Decrypted JSON: {json_data}")

        # Parse the JSON to extract password and username
        data = json.loads(json_data)
        password = data.get("p", "")
        username = data.get("n", "Administrator")

        return password, username

    except Exception as e:
        raise LAPSError(f"Failed to decrypt LAPS password: {e}") from e


def _get_group_key_envelope(
    ctx: LAPSDecryptionContext,
    target_sd: bytes,
    key_id: KeyIdentifier,
) -> GroupKeyEnvelope:
    """
    Connect to MS-GKDI RPC service and retrieve the Group Key Envelope.

    Args:
        ctx: Decryption context with authentication credentials
        target_sd: Security descriptor bytes for the target SID
        key_id: Key identifier from the encrypted blob

    Returns:
        GroupKeyEnvelope containing the key material

    Raises:
        LAPSError: If RPC connection or GetKey call fails
    """
    try:
        # Resolve the MS-GKDI endpoint
        dest_host = ctx.dns_server if ctx.dns_server else ctx.domain
        string_binding = hept_map(
            destHost=dest_host,
            remoteIf=MSRPC_UUID_GKDI,
            protocol="ncacn_ip_tcp",
        )

        debug(f"LAPS: MS-GKDI binding: {string_binding}")

        # Create RPC transport
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if hasattr(rpc_transport, "set_credentials"):
            rpc_transport.set_credentials(
                username=ctx.username,
                password=ctx.password or "",
                domain=ctx.domain,
                lmhash=ctx.lmhash,
                nthash=ctx.nthash,
            )

        if ctx.kerberos:
            rpc_transport.set_kerberos(True, kdcHost=ctx.kdc_host)

        # Connect and bind
        dce = rpc_transport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        debug("LAPS: Connecting to MS-GKDI...")
        dce.connect()

        debug("LAPS: Binding to MS-GKDI interface...")
        dce.bind(MSRPC_UUID_GKDI)

        # Call GetKey
        debug("LAPS: Calling GetKey...")
        resp = GkdiGetKey(
            dce,
            target_sd=target_sd,
            l0=key_id["L0Index"],
            l1=key_id["L1Index"],
            l2=key_id["L2Index"],
            root_key_id=key_id["RootKeyId"],
        )

        # Parse response into GroupKeyEnvelope
        gke = GroupKeyEnvelope(b"".join(resp["pbbOut"]))

        debug(f"LAPS: Got Group Key Envelope (Root Key: {gke['RootKeyId']})")

        return gke

    except Exception as e:
        raise LAPSError(f"MS-GKDI GetKey failed: {e}") from e
