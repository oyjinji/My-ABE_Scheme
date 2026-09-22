'''
Smoke tests for DACP Ed25519 row signatures and lightweight certificates.
'''

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.dacp import DACPCPABE
from Code.dacp.components import (
    BlindPairingOPRF,
    Ed25519Signature,
    PrototypeCertificateAuthority,
)


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<48} OK'.format(name))


def make_ed_scheme(group, oprf=None):
    return DACPCPABE(
        group,
        oprf=oprf,
        signature=Ed25519Signature(),
        certificate=PrototypeCertificateAuthority(signature=Ed25519Signature()),
    )


def test_signature_adapter():
    signature = Ed25519Signature()
    sk, pk = signature.keygen()
    message = {'cid': 'cid', 'row_index': 7, 'token_id': 'tok', 'row_hash': 'hash'}
    sig = signature.sign(sk, message)
    assert_true('Ed25519 sign/verify', signature.verify(pk, message, sig))
    assert_true('Ed25519 rejects wrong message', not signature.verify(pk, dict(message, row_hash='bad'), sig))
    _other_sk, other_pk = signature.keygen()
    assert_true('Ed25519 rejects wrong public key', not signature.verify(other_pk, message, sig))


def test_certificate_adapter():
    signature = Ed25519Signature()
    ca = PrototypeCertificateAuthority(signature=Ed25519Signature())
    _sk, pk = signature.keygen()
    cert = ca.issue_cert('DO', pk)
    assert_true('Prototype CA issues cert', isinstance(cert, dict))
    assert_true('Prototype CA verifies cert', ca.verify_cert(cert, public_key=pk))

    expired = ca.issue_cert(
        'DO',
        pk,
        not_before=time.time() - 10.0,
        not_after=time.time() - 1.0,
    )
    assert_true('Prototype CA rejects expired cert', not ca.verify_cert(expired, public_key=pk))

    _other_sk, other_pk = signature.keygen()
    assert_true('Prototype CA rejects public-key mismatch', not ca.verify_cert(cert, public_key=other_pk))


def test_dacp_ed25519_encrypt_decrypt():
    group = PairingGroup('MNT224')
    scheme = make_ed_scheme(group)
    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, ['1', '2', '3'], user_id='DU')
    msg = group.random(GT)
    do_sk, do_pk = scheme.signature.keygen()
    do_pk_ref = scheme.signature.serialize_public_key(do_pk).hex()
    cert = scheme.certificate.issue_cert('DO', do_pk)
    ct = scheme.encrypt(
        pk,
        msg,
        '((1 and 3) and (2 OR 4))',
        sk_DO_sig=do_sk,
        pk_DO_sig=do_pk_ref,
        cert_DO=cert,
    )
    recovered = scheme.decrypt(pk, ct, key)
    assert_true('DACP Ed25519 decrypt succeeds', recovered == msg)


def test_tamper_detection():
    group = PairingGroup('MNT224')
    scheme = make_ed_scheme(group)
    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, ['1'], user_id='DU')
    msg = group.random(GT)
    do_sk, do_pk = scheme.signature.keygen()
    do_pk_ref = scheme.signature.serialize_public_key(do_pk).hex()
    cert = scheme.certificate.issue_cert('DO', do_pk)
    ct = scheme.encrypt(
        pk,
        msg,
        '1',
        sk_DO_sig=do_sk,
        pk_DO_sig=do_pk_ref,
        cert_DO=cert,
    )

    tampered_ct = dict(ct)
    tampered_ct['rows'] = [dict(row) for row in ct['rows']]
    tampered_ct['rows'][0]['C_i_1'] = pk['g1']
    tampered_partial = scheme.transform(pk, tampered_ct, key['TK_id'])
    assert_true(
        'DACP rejects tampered row component',
        scheme.final_decrypt(pk, tampered_partial, key['RK_id']) is None,
    )

    partial = scheme.transform(pk, ct, key['TK_id'])
    partial['candidates'] = [dict(item) for item in partial['candidates']]
    partial['candidates'][0]['tau_i'] = group.random(GT)
    assert_true(
        'DACP rejects tampered tau candidate',
        scheme.final_decrypt(pk, partial, key['RK_id']) is None,
    )


def test_protocol_script():
    output = subprocess.check_output(
        [
            sys.executable,
            str(ROOT / 'Benchmark' / 'run_dacp_protocol.py'),
            '--oprf',
            'blind',
            '--sig',
            'ed25519',
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    assert_true('Protocol blind+Ed25519 succeeds', 'satisfied_success: True' in output)
    assert_true('Protocol reports Ed25519 mode', 'signature_mode: ed25519' in output)
    assert_true('Protocol verifies certificate', 'cert_verified: True' in output)


def main():
    try:
        Ed25519Signature()
    except RuntimeError as exc:
        print('Ed25519 tests skipped: {0}'.format(exc))
        return

    test_signature_adapter()
    test_certificate_adapter()
    test_dacp_ed25519_encrypt_decrypt()
    test_tamper_detection()
    test_protocol_script()
    print('=' * 72)
    print('DACP Ed25519 signature tests passed.')


if __name__ == '__main__':
    main()
