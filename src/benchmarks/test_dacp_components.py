'''
Smoke tests for DACP prototype components.
'''

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT, ZR

from Code.dacp import DACPCPABE
from Code.dacp.components import (
    BlindPairingOPRF,
    PrototypeABF,
    PrototypeCertificateAuthority,
    PrototypeGTEnvelope,
    PrototypeHashSignature,
    PrototypeOPRF,
)


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<36} OK'.format(name))


def main():
    group = PairingGroup('MNT224')

    oprf = PrototypeOPRF(group)
    attrs = ['1', '2', '3']
    kappa = group.random(ZR)
    blinded_items, blind_state = oprf.blind(attrs, nonce='component-test')
    evaluated_items = oprf.evaluate(blinded_items, kappa)
    unblinded = oprf.unblind(evaluated_items, blind_state)
    token = oprf.token_from_attr('1', kappa)
    token_id = oprf.token_id(token)
    assert_true('PrototypeOPRF blind count', len(blinded_items) == len(attrs))
    assert_true('PrototypeOPRF no attr leakage', all('prototype_attr' not in item for item in blinded_items))
    assert_true('PrototypeOPRF evaluate count', len(evaluated_items) == len(attrs))
    assert_true('PrototypeOPRF unblind shape', 'evaluated_items' in unblinded)
    assert_true('PrototypeOPRF token_id', isinstance(token_id, str) and len(token_id) == 64)

    blind_oprf = BlindPairingOPRF(group)
    blind_attrs = ['A', 'B', 'C']
    blind_kappa = group.random(ZR)
    blind_items, blind_state = blind_oprf.blind(blind_attrs)
    blind_evaluated = blind_oprf.evaluate(blind_items, blind_kappa)
    blind_tokens = blind_oprf.unblind(blind_evaluated, blind_state)
    assert_true('BlindPairingOPRF blind count', len(blind_items) == len(blind_attrs))
    assert_true('BlindPairingOPRF no attr leakage', all('attr' not in item for item in blind_items))
    assert_true('BlindPairingOPRF evaluate count', len(blind_evaluated) == len(blind_attrs))
    assert_true('BlindPairingOPRF unblind count', len(blind_tokens) == len(blind_attrs))
    for token_entry in blind_tokens:
        index = token_entry['item_index']
        expected_tau = blind_oprf._hash_attr(blind_attrs[index]) ** blind_kappa
        assert_true('BlindPairingOPRF tau {0}'.format(index), token_entry['tau_i'] == expected_tau)
        assert_true(
            'BlindPairingOPRF stable token_id {0}'.format(index),
            token_entry['token_id'] == blind_oprf.token_id(token_entry['tau_i']),
        )

    abf = PrototypeABF(m=128, k=3, beta=16)
    token_rows = {'token-a': [0, 2], 'token-b': [1]}
    bf = abf.build(token_rows, params={'row_count': 3})
    assert_true('PrototypeABF query token-a', abf.query(bf, 'token-a') == [0, 2])
    assert_true('PrototypeABF query token-b', abf.query(bf, 'token-b') == [1])
    assert_true('PrototypeABF miss', abf.query(bf, 'token-c') == [])

    symmetric = PrototypeGTEnvelope(group)
    msg = group.random(GT)
    shared_secret = group.random(GT)
    aad = b'component-test-aad'
    sealed = symmetric.seal(msg, shared_secret, aad=aad)
    opened = symmetric.open(sealed, shared_secret, aad=aad)
    assert_true('PrototypeGTEnvelope open', opened == msg)

    signature = PrototypeHashSignature()
    row_message = {'cid': 'cid', 'row_index': 1, 'token_id': 'tok', 'row_hash': 'h'}
    sig = signature.sign('do-key', row_message)
    assert_true('PrototypeHashSignature verify', signature.verify('do-key', row_message, sig))
    assert_true('PrototypeHashSignature reject', not signature.verify('other-key', row_message, sig))

    ca = PrototypeCertificateAuthority()
    cert = ca.issue_cert('DO', 'do-key')
    assert_true('PrototypeCertificate issue', isinstance(cert, dict))
    assert_true('PrototypeCertificate verify', ca.verify_cert(cert))

    default_scheme = DACPCPABE(group)
    assert_true('DACP default oprf', isinstance(default_scheme.oprf, PrototypeOPRF))
    assert_true('DACP default abf', isinstance(default_scheme.abf, PrototypeABF))
    assert_true('DACP default symmetric', isinstance(default_scheme.symmetric, PrototypeGTEnvelope))
    assert_true('DACP default signature', isinstance(default_scheme.signature, PrototypeHashSignature))
    assert_true('DACP default certificate', isinstance(default_scheme.certificate, PrototypeCertificateAuthority))

    custom_scheme = DACPCPABE(
        group,
        oprf=blind_oprf,
        abf=abf,
        symmetric=symmetric,
        signature=signature,
        certificate=ca,
    )
    assert_true('DACP custom oprf', custom_scheme.oprf is blind_oprf)
    assert_true('DACP custom abf', custom_scheme.abf is abf)
    assert_true('DACP custom symmetric', custom_scheme.symmetric is symmetric)
    assert_true('DACP custom signature', custom_scheme.signature is signature)
    assert_true('DACP custom certificate', custom_scheme.certificate is ca)

    print('=' * 72)
    print('DACP component tests passed.')


if __name__ == "__main__":
    main()
