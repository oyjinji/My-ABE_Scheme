"""Host Intel QVL evaluation with disjoint strict and DEBUG feasibility types."""
import ctypes as C
from dataclasses import dataclass
import hashlib
import os
import re
import subprocess
import tempfile
import time
from typing import Optional

from ..encoding import require_bytes
from ..errors import AuthenticationError, ContractError
from ..profile import SGX_DEBUG_GRAMINE_V1
from .attestation import attestation_binding, MAX_QUOTE_BYTES

QVL_OK = 0
QV_OK = 0
QV_OUT_OF_DATE = 0xA002
FEASIBILITY_LABEL = 'QVL_VERIFIED_OUTDATED_TCB_DEBUG_FEASIBILITY_V1'
_MINT = object()


@dataclass(frozen=True)
class QvlEvaluation:
    api_return: int
    collateral_expiration_status: Optional[int]
    qv_result: Optional[int]
    supplemental_version: Optional[tuple]
    supplemental_size: int
    quote_digest: bytes


@dataclass(frozen=True)
class AttestationPolicyDecision:
    strict_accepted: bool
    feasibility_accepted: bool
    reason: str


@dataclass(frozen=True)
class QuoteFields:
    mrenclave: bytes
    mrsigner: bytes
    product_id: int
    svn: int
    debug: bool
    report_data: bytes
    quote_version: int
    att_key_type: int


class _QvlCheckedQuote:
    def __init__(self, token, quote, evaluation, fields):
        if token is not _MINT:
            raise ContractError('QVL quote type must come from real verification')
        self._quote = quote
        self.evaluation = evaluation
        self.fields = fields

    @property
    def quote_digest(self):
        return self.evaluation.quote_digest

    def check_identity(self, policy):
        return policy.check_authenticated_fields(profile_id=SGX_DEBUG_GRAMINE_V1,
            mrenclave=self.fields.mrenclave, mrsigner=self.fields.mrsigner,
            product_id=self.fields.product_id, svn=self.fields.svn,
            debug=self.fields.debug)

    def check_binding(self, sys_id, challenge, enclave_public):
        expected = attestation_binding(sys_id, challenge, enclave_public)
        if self.fields.report_data != expected:
            raise AuthenticationError('quote report_data binding rejected')


class StrictVerifiedSgxQuote(_QvlCheckedQuote):
    """Minted only for API success, current collateral, QV_RESULT_OK."""


class QvlCheckedNonTerminalQuote(_QvlCheckedQuote):
    """QVL-completed OUT_OF_DATE DEBUG evidence; never strict verified."""


def decide_policy(evaluation, *, allow_outdated_debug_feasibility=False,
                  enclave_debug=False):
    if type(evaluation) is not QvlEvaluation:
        raise ContractError('QVL evaluation required')
    if type(allow_outdated_debug_feasibility) is not bool or type(enclave_debug) is not bool:
        raise ContractError('attestation policy flags must be boolean')
    if evaluation.api_return != QVL_OK:
        return AttestationPolicyDecision(False, False, 'QVL_API_ERROR')
    if evaluation.collateral_expiration_status != 0:
        return AttestationPolicyDecision(False, False, 'COLLATERAL_EXPIRED')
    if evaluation.qv_result == QV_OK:
        return AttestationPolicyDecision(True, False, 'STRICT_CURRENT_TCB')
    if evaluation.qv_result == QV_OUT_OF_DATE:
        if allow_outdated_debug_feasibility and enclave_debug:
            return AttestationPolicyDecision(False, True,
                                             'INSECURE_TEST_OVERRIDE_USED')
        return AttestationPolicyDecision(False, False, 'BLOCKED_BY_TCB_POLICY')
    return AttestationPolicyDecision(False, False, 'TERMINAL_OR_UNKNOWN_QV_RESULT')


def _quote_fields(quote):
    """Use Gramine's installed quote parser after QVL, not guessed offsets."""
    fd, path = tempfile.mkstemp(prefix='myabe-ra-quote-', suffix='.bin')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(quote)
        viewed = subprocess.run(('gramine-sgx-quote-view', path),
            capture_output=True, text=True, check=True).stderr
    finally:
        os.unlink(path)
    def field(name):
        match = re.search(r'^\s*' + re.escape(name) + r'\s*:\s*([0-9a-f]+)',
                          viewed, re.MULTILINE)
        if match is None:
            raise ContractError('quote metadata unavailable')
        return bytes.fromhex(match.group(1))
    return QuoteFields(field('mr_enclave'), field('mr_signer'),
        int.from_bytes(field('isv_prod_id'), 'little'),
        int.from_bytes(field('isv_svn'), 'little'),
        bool(int.from_bytes(field('attributes.flags'), 'little') & 2),
        field('report_data'), int.from_bytes(field('version'), 'little'),
        int.from_bytes(field('sign_type'), 'little'))


def verify_real_quote(quote):
    """Call installed Intel QVL; return a checked type only for nonterminal QV."""
    require_bytes(quote, 'SGX quote')
    if not 432 < len(quote) <= MAX_QUOTE_BYTES:
        raise ContractError('SGX quote size rejected')
    lib = C.CDLL('libsgx_dcap_quoteverify.so.1')
    C.CDLL('/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1')
    lib.sgx_qv_set_path.argtypes = [C.c_int, C.c_char_p]
    lib.sgx_qv_set_path.restype = C.c_uint32
    path_result = lib.sgx_qv_set_path(1,
        b'/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1')
    if path_result != 0:
        raise ContractError('QVL provider path failed')
    lib.sgx_qv_get_quote_supplemental_data_size.argtypes = [C.POINTER(C.c_uint32)]
    lib.sgx_qv_get_quote_supplemental_data_size.restype = C.c_uint32
    size = C.c_uint32()
    if lib.sgx_qv_get_quote_supplemental_data_size(C.byref(size)) != 0 or size.value < 4:
        raise ContractError('QVL supplemental size failed')
    qbuf = (C.c_ubyte * len(quote)).from_buffer_copy(quote)
    supplemental = (C.c_ubyte * size.value)()
    expiration = C.c_uint32(0xffffffff)
    result = C.c_uint32(0xffffffff)
    lib.sgx_qv_verify_quote.argtypes = [C.POINTER(C.c_ubyte), C.c_uint32,
        C.c_void_p, C.c_long, C.POINTER(C.c_uint32), C.POINTER(C.c_uint32),
        C.c_void_p, C.c_uint32, C.POINTER(C.c_ubyte)]
    lib.sgx_qv_verify_quote.restype = C.c_uint32
    api = lib.sgx_qv_verify_quote(qbuf, len(quote), None, int(time.time()),
        C.byref(expiration), C.byref(result), None, size.value, supplemental)
    version = ((supplemental[1] << 8) | supplemental[0],
               (supplemental[3] << 8) | supplemental[2]) if api == 0 else None
    evaluation = QvlEvaluation(api, expiration.value if api == 0 else None,
        result.value if api == 0 else None, version, size.value,
        hashlib.sha256(quote).digest())
    checked = None
    if api == 0 and expiration.value == 0 and result.value in (QV_OK, QV_OUT_OF_DATE):
        fields = _quote_fields(quote)
        kind = StrictVerifiedSgxQuote if result.value == QV_OK else QvlCheckedNonTerminalQuote
        checked = kind(_MINT, quote, evaluation, fields)
    return evaluation, checked
