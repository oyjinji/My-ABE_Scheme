"""The public eight-algorithm facade also has an explicit EMULATED TEST path."""
import pytest

from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.errors import ContractError, Unauthorized, UnsupportedProfileError
from core.myabe08.profile import EMULATED_TEE_PROFILE
from core.myabe08.public import EMULATED_TEST_MODE, PublicMyABE08
from core.myabe08.revocation import ACTIVATE, REVOKE
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.types import Attribute, PolicyContext, PolicyInput, Validity

SYS_ID = b'MYABE08-4EF-EMULATED-TEST'


class Clock:
    def now(self):
        return 1000


def label(x):
    return Attribute('ns', 'label', x)


def context(x):
    context_id = bytes([x])*32
    return PolicyContext(SYS_ID, context_id, 1,
                         compute_ctx_priv(SYS_ID, context_id, 1))


def test_emulated_public_eight_algorithms_and_no_implicit_sgx(tmp_path):
    with pytest.raises(UnsupportedProfileError):
        PublicMyABE08(sys_id=SYS_ID, namespace='ns', backend=EMULATED_TEE_PROFILE,
            experiment_trust_mode='STRICT_CURRENT_TCB', state_path=tmp_path/'bad',
            clock=Clock())
    scheme = PublicMyABE08(sys_id=SYS_ID, namespace='ns',
        backend=EMULATED_TEE_PROFILE, experiment_trust_mode=EMULATED_TEST_MODE,
        state_path=tmp_path/'kgc', clock=Clock())
    setup = scheme.Setup(c_max=3, validity=Validity(100, 2000))
    assert setup.metadata['TEEProfile'] == EMULATED_TEE_PROFILE
    assert setup.metadata['RemoteAttestation'] == 'NOT_APPLICABLE'
    holder = new_private_key()
    user = scheme.KeyGen(uid='PRIVATE-EMULATED-UID',
        attributes=(label('A'), label('B')),
        auth_public_key=public_key_bytes(holder), validity=Validity(100, 2000))
    with pytest.raises(ContractError, match='UnsupportedMessage'):
        scheme.Encrypt(message=b'', policy=None, context=None, data_id=b'x')
    ct = scheme.Encrypt(message=b'public emulated',
        policy=PolicyInput(((1,1),(0,-1)), (label('A'), label('B'))),
        context=context(1), data_id=b'test')
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
        auth_private_key=holder, expiry=1500)
    partial = scheme.Transform(ciphertext=ct, public_auth=auth)
    assert scheme.FinalDec(partial=partial,
                           recovery_key=user.recovery_key) == b'public emulated'
    assert (auth.tee_pairings, partial.csp_pairings) == (1, 2)
    assert scheme.workload_metadata(partial, policy_shape='AND')['tI'] == 1
    update = scheme.Rev(uid='PRIVATE-EMULATED-UID', operation=REVOKE)
    assert scheme.RevStateUpt(update).version == 1
    with pytest.raises(Exception, match='revoked|REVOKED'):
        scheme.TEEAuthorize(user=user, ciphertext=ct,
                            auth_private_key=holder, expiry=1500)
    update = scheme.Rev(uid='PRIVATE-EMULATED-UID', operation=ACTIVATE)
    assert scheme.RevStateUpt(update).version == 2
    auth = scheme.TEEAuthorize(user=user, ciphertext=ct,
        auth_private_key=holder, expiry=1500)
    assert scheme.FinalDec(partial=scheme.Transform(ciphertext=ct, public_auth=auth),
                           recovery_key=user.recovery_key) == b'public emulated'
