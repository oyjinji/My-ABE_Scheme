'''
Smoke tests for DACP AES-GCM bytes envelope.
'''

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.dacp import DACPCPABE
from Code.dacp.components import (
    AESGCMEnvelope,
    BlindPairingOPRF,
    Ed25519Signature,
    PrototypeCertificateAuthority,
)


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<48} OK'.format(name))


def make_ed_aes_scheme(group):
    return DACPCPABE(
        group,
        oprf=BlindPairingOPRF(group),
        symmetric=AESGCMEnvelope(),
        signature=Ed25519Signature(),
        certificate=PrototypeCertificateAuthority(signature=Ed25519Signature()),
    )


def test_aesgcm_envelope():
    group = PairingGroup('MNT224')
    envelope = AESGCMEnvelope(group=group)
    shared_secret = group.random(GT)
    plaintext = b'hello dacp secure data sharing'
    aad = b'dacp aad'
    sealed = envelope.seal(plaintext, shared_secret, aad=aad)
    assert_true('AESGCM seal/open', envelope.open(sealed, shared_secret, aad=aad) == plaintext)
    assert_true('AESGCM rejects wrong aad', envelope.open(sealed, shared_secret, aad=b'bad aad') is None)

    bad_nonce = dict(sealed)
    bad_nonce['nonce'] = ('00' * 12)
    bad_nonce['nonce_AEAD'] = bad_nonce['nonce']
    assert_true('AESGCM rejects wrong nonce', envelope.open(bad_nonce, shared_secret, aad=aad) is None)

    bad_ct = dict(sealed)
    raw_ct = bytearray(bytes.fromhex(bad_ct['ciphertext']))
    raw_ct[0] ^= 1
    bad_ct['ciphertext'] = bytes(raw_ct).hex()
    bad_ct['C_sym'] = bad_ct['ciphertext']
    assert_true('AESGCM rejects tampered ciphertext', envelope.open(bad_ct, shared_secret, aad=aad) is None)

    try:
        envelope.seal('not bytes', shared_secret, aad=aad)
    except TypeError:
        assert_true('AESGCM rejects non-bytes msg', True)
    else:
        raise AssertionError('AESGCM rejects non-bytes msg')


def test_dacp_aesgcm_bytes():
    group = PairingGroup('MNT224')
    scheme = make_ed_aes_scheme(group)
    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, ['1'], user_id='DU')
    plaintext = b'hello dacp secure data sharing'
    do_sk, do_pk = scheme.signature.keygen()
    do_pk_ref = scheme.signature.serialize_public_key(do_pk).hex()
    cert = scheme.certificate.issue_cert('DO', do_pk)
    ct = scheme.encrypt(
        pk,
        plaintext,
        '1',
        sk_DO_sig=do_sk,
        pk_DO_sig=do_pk_ref,
        cert_DO=cert,
    )
    assert_true('DACP ciphertext marks AESGCM', ct.get('symmetric_mode') == 'AESGCM')
    recovered = scheme.decrypt(pk, ct, key)
    assert_true('DACP AESGCM bytes decrypt', recovered == plaintext)

    partial = scheme.transform(pk, ct, key['TK_id'])
    tampered_cid = dict(partial)
    tampered_cid['cid'] = 'bad-' + partial['cid']
    assert_true(
        'DACP rejects tampered cid',
        scheme.final_decrypt(pk, tampered_cid, key['RK_id']) is None,
    )

    partial = scheme.transform(pk, ct, key['TK_id'])
    tampered_digest = dict(partial)
    tampered_digest['BF_digest'] = 'bad-' + partial['BF_digest']
    assert_true(
        'DACP rejects tampered ABF digest',
        scheme.final_decrypt(pk, tampered_digest, key['RK_id']) is None,
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
            '--symmetric',
            'aesgcm',
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    assert_true('Protocol AESGCM succeeds', 'satisfied_success: True' in output)
    assert_true('Protocol reports AESGCM mode', 'symmetric_mode: aesgcm' in output)
    assert_true('Protocol reports bytes success', 'bytes_plaintext_success: True' in output)
    assert_true('Protocol reports AEAD auth', 'aead_authenticated: True' in output)


def main():
    try:
        AESGCMEnvelope()
        Ed25519Signature()
    except RuntimeError as exc:
        print('AESGCM tests skipped: {0}'.format(exc))
        return

    test_aesgcm_envelope()
    test_dacp_aesgcm_bytes()
    test_protocol_script()
    print('=' * 72)
    print('DACP AESGCM tests passed.')


if __name__ == '__main__':
    main()
