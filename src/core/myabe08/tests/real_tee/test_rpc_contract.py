"""Transport validation independent of SGX availability."""
import socket

import pytest

from core.myabe08.crypto import BLS12381Backend
from core.myabe08.encoding import encode
from core.myabe08.errors import ContractError
from core.myabe08.real_tee.messages import (decode_public_parameters,
    encode_public_parameters)
from core.myabe08.real_tee.rpc import (frame, read_request, HEADER, HEALTH,
    LIMITS, MAGIC, VERSION)
from core.myabe08.algebra import setup_algebra_core

REQUEST_ID = b'R'*16
BODY = encode(('MYABE08-HEALTH-V1',))


def _read(raw):
    left, right = socket.socketpair()
    try:
        left.sendall(raw)
        left.shutdown(socket.SHUT_WR)
        return read_request(right)
    finally:
        left.close()
        right.close()


def test_rpc_frame_strict_rejection():
    valid = frame(HEALTH, REQUEST_ID, BODY)
    assert _read(valid) == (HEALTH, REQUEST_ID, ('MYABE08-HEALTH-V1',))
    for raw in (valid[:-1], valid+b'x',
                HEADER.pack(MAGIC, VERSION+1, HEALTH, REQUEST_ID, len(BODY))+BODY,
                HEADER.pack(MAGIC, VERSION, 100, REQUEST_ID, len(BODY))+BODY,
                HEADER.pack(MAGIC, VERSION, HEALTH, REQUEST_ID,
                            LIMITS[HEALTH]+1),
                HEADER.pack(MAGIC, VERSION, HEALTH, REQUEST_ID, 1)+b'\xff'):
        with pytest.raises(ContractError):
            _read(raw)
    with pytest.raises(ContractError):
        frame(HEALTH, REQUEST_ID, b'not canonical')


def test_public_parameters_wrong_sysid_and_group_encoding():
    backend = BLS12381Backend(b'RPC-TEST-A')
    pp, _ = setup_algebra_core(backend, 2)
    raw = encode_public_parameters(pp, backend)
    assert decode_public_parameters(raw, backend) == pp
    with pytest.raises(ContractError):
        decode_public_parameters(raw, BLS12381Backend(b'RPC-TEST-B'))
    from core.myabe08.encoding import decode
    fields = list(decode(raw))
    fields[2] = b'\x00' * len(fields[2])
    with pytest.raises(ContractError):
        decode_public_parameters(encode(tuple(fields)), backend)
