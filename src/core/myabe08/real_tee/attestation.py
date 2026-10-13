"""Gramine 1.8 quote diagnostic and canonical proposed RA binding.

This module cannot verify a quote and must never authorize provisioning.
"""
import hashlib

from ..channel import x25519_private_new, x25519_public_bytes
from ..encoding import UInt32, encode, require_bytes
from ..errors import ContractError

QUOTE_PROBE_PROFILE = 'SGX_DEBUG_GRAMINE_V1'
MAX_QUOTE_BYTES = 8192  # Gramine sgx_attest.h: SGX_QUOTE_MAX_SIZE.


def attestation_binding(sys_id, challenge, channel_public):
    """SHA256(Encode(domain, SysID, profile, UInt32(1), challenge, X25519 pub))."""
    require_bytes(sys_id, 'RA SysID')
    require_bytes(challenge, 'RA challenge', 32)
    require_bytes(channel_public, 'RA X25519 public key', 32)
    if not sys_id:
        raise ContractError('RA SysID required')
    digest = hashlib.sha256(encode(('MYABE-RA-BIND', sys_id,
        QUOTE_PROBE_PROFILE, UInt32(1), challenge, channel_public))).digest()
    return digest + b'\x00' * 32


def gramine_quote_probe(sys_id, challenge):
    """Inside SGX only: request real quote via Gramine attestation pseudo-files.

    Returns public quote and public ephemeral key for diagnostics. The private
    key is discarded; no channel or provisioning is established by this call.
    """
    private = x25519_private_new()
    public = x25519_public_bytes(private)
    report_data, quote = quote_for_public(sys_id, challenge, public)
    return public, report_data, quote


def quote_for_public(sys_id, challenge, public):
    """Inside SGX: quote the caller's already-created session public key."""
    report_data = attestation_binding(sys_id, challenge, public)
    with open('/dev/attestation/user_report_data', 'wb') as stream:
        stream.write(report_data)
    with open('/dev/attestation/quote', 'rb') as stream:
        quote = stream.read(MAX_QUOTE_BYTES + 1)
    if not 432 < len(quote) <= MAX_QUOTE_BYTES:
        raise ContractError('Gramine quote size rejected')
    return report_data, quote
