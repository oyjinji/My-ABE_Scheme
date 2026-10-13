"""Canonical binding unit tests; these do not authenticate a quote."""
import pytest

from core.myabe08.errors import ContractError
from core.myabe08.real_tee.attestation import attestation_binding


def test_binding_is_exact_and_domain_separated():
    one=attestation_binding(b'SYS',b'A'*32,b'P'*32)
    assert len(one)==64 and one[32:]==b'\x00'*32
    assert one==attestation_binding(b'SYS',b'A'*32,b'P'*32)
    for args in ((b'OTHER',b'A'*32,b'P'*32),
                 (b'SYS',b'B'*32,b'P'*32),
                 (b'SYS',b'A'*32,b'Q'*32)):
        assert attestation_binding(*args)!=one
    with pytest.raises(ContractError):
        attestation_binding(b'SYS',b'short',b'P'*32)
