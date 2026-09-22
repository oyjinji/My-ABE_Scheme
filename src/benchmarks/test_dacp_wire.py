'''
Smoke tests for DACP stable JSON wire encoding.
'''

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR

from Code.dacp import DACPCPABE
from Code.dacp.components import (
    AESGCMEnvelope,
    BlindPairingOPRF,
    Ed25519Signature,
    PrototypeCertificateAuthority,
)
from Code.dacp.protocol import MessageEnvelope, WireCodec, make_message
from Code.dacp.protocol.messages import OPRF_REQUEST, OPRF_RESPONSE


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<52} OK'.format(name))


def round_trip(codec, obj):
    data = json.dumps(
        codec.encode_obj(obj),
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')
    return codec.decode_obj(json.loads(data.decode('utf-8')))


def make_scheme(group):
    return DACPCPABE(
        group,
        oprf=BlindPairingOPRF(group),
        symmetric=AESGCMEnvelope(),
        signature=Ed25519Signature(),
        certificate=PrototypeCertificateAuthority(signature=Ed25519Signature()),
    )


def test_basic_types(codec):
    value = {
        'bytes': b'abc',
        'str': 'abc',
        'int': 7,
        'list': [1, 'x', b'y'],
        'dict': {'nested': b'z'},
    }
    decoded = round_trip(codec, value)
    assert_true('Wire basic bytes', decoded['bytes'] == b'abc')
    assert_true('Wire basic str/int/list/dict', decoded['list'][2] == b'y' and decoded['dict']['nested'] == b'z')


def test_group_elements(group, codec):
    for name, group_type in (('G1', G1), ('G2', G2), ('GT', GT), ('ZR', ZR)):
        element = group.random(group_type)
        decoded = round_trip(codec, element)
        assert_true('Wire group element {0}'.format(name), decoded == element)


def test_message_and_oprf(group, codec):
    oprf = BlindPairingOPRF(group)
    blinded, blind_state = oprf.blind(['A', 'B'])
    req = make_message(
        OPRF_REQUEST,
        'DO',
        'KGC',
        {
            'batch_id': 'batch',
            'nonce_oprf': 'nonce',
            'blinded_items': blinded,
            'num_items': len(blinded),
            'epoch': None,
        },
    )
    req2 = codec.decode_message(codec.encode_message(req))
    assert_true('Wire MessageEnvelope type', isinstance(req2, MessageEnvelope))
    assert_true('Wire OPRF_REQUEST B_i', req2.payload['blinded_items'][0]['B_i'] == blinded[0]['B_i'])
    assert_true('Wire OPRF_REQUEST hides attrs', 'attr' not in req2.payload['blinded_items'][0])

    kappa = group.random(ZR)
    evaluated = oprf.evaluate(req2.payload['blinded_items'], kappa)
    resp = make_message(
        OPRF_RESPONSE,
        'KGC',
        'DO',
        {
            'batch_id': 'batch',
            'nonce_oprf': 'nonce',
            'evaluated_items': evaluated,
        },
    )
    resp2 = codec.decode_message(codec.encode_message(resp))
    assert_true('Wire OPRF_RESPONSE R_i', resp2.payload['evaluated_items'][0]['R_i'] == evaluated[0]['R_i'])
    tokens = oprf.unblind(resp2.payload['evaluated_items'], blind_state)
    assert_true('Wire OPRF tokens recover', len(tokens) == 2)


def test_signature_cert_aes(group, codec):
    signature = Ed25519Signature()
    sk, pk = signature.keygen()
    pk_bytes = signature.serialize_public_key(pk)
    message = {'row': 1, 'digest': 'abc'}
    sig = signature.sign(sk, message)
    decoded_pk = round_trip(codec, pk_bytes)
    decoded_sig = round_trip(codec, sig)
    assert_true('Wire Ed25519 public key bytes', decoded_pk == pk_bytes)
    assert_true('Wire Ed25519 signature hex', signature.verify(decoded_pk, message, decoded_sig))

    ca = PrototypeCertificateAuthority(signature=Ed25519Signature())
    cert = ca.issue_cert('DO', pk_bytes)
    cert2 = round_trip(codec, cert)
    assert_true('Wire certificate verifies', ca.verify_cert(cert2, public_key=pk_bytes))

    envelope = AESGCMEnvelope(group=group)
    shared_secret = group.random(GT)
    sealed = envelope.seal(b'wire plaintext', shared_secret, aad=b'aad')
    sealed2 = round_trip(codec, sealed)
    assert_true('Wire AESGCM ciphertext/nonce', envelope.open(sealed2, shared_secret, aad=b'aad') == b'wire plaintext')


def test_ct_and_ct_prime(group, codec):
    scheme = make_scheme(group)
    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, ['1'], user_id='DU')
    plaintext = b'wire dacp bytes plaintext'
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
    ct2 = round_trip(codec, ct)
    tk2 = round_trip(codec, key['TK_id'])
    partial = scheme.transform(pk, ct2, tk2)
    rk2 = round_trip(codec, key['RK_id'])
    assert_true('Wire CT transform/final', scheme.final_decrypt(pk, partial, rk2) == plaintext)

    partial2 = round_trip(codec, partial)
    assert_true('Wire CT_prime final_decrypt', scheme.final_decrypt(pk, partial2, rk2) == plaintext)


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
            '--wire',
            'json',
        ],
        cwd=str(ROOT),
        universal_newlines=True,
    )
    assert_true('Protocol wire JSON succeeds', 'satisfied_success: True' in output)
    assert_true('Protocol wire mode reported', 'wire_mode: json' in output)
    assert_true('Protocol wire bytes reported', 'wire_total_bytes: 0' not in output)


def main():
    try:
        AESGCMEnvelope()
        Ed25519Signature()
    except RuntimeError as exc:
        print('Wire tests skipped: {0}'.format(exc))
        return

    group = PairingGroup('MNT224')
    codec = WireCodec(group)
    test_basic_types(codec)
    test_group_elements(group, codec)
    test_message_and_oprf(group, codec)
    test_signature_cert_aes(group, codec)
    test_ct_and_ct_prime(group, codec)
    test_protocol_script()
    print('=' * 72)
    print('DACP wire codec tests passed.')


if __name__ == '__main__':
    main()
