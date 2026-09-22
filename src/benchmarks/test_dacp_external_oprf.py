'''
Tests for feeding protocol OPRF tokens into DACPCPABE.encrypt().
'''

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.dacp import DACPCPABE
from Code.dacp.components import BlindPairingOPRF


def assert_true(name, condition):
    if not condition:
        raise AssertionError(name)
    print('{:<44} OK'.format(name))


def assert_raises(name, fn):
    try:
        fn()
    except ValueError as exc:
        print('{:<44} OK ({})'.format(name, exc))
        return
    raise AssertionError(name)


def policy_row_attrs(scheme, policy_str):
    policy = scheme.util.createPolicy(policy_str)
    msp = scheme.util.convert_policy_to_msp(policy)
    return [scheme.util.strip_index(attr) for attr in msp.keys()]


def external_tokens_for_policy(scheme, msk, policy_str):
    row_attrs = policy_row_attrs(scheme, policy_str)
    blinded_items, blind_state = scheme.oprf.blind(row_attrs)
    evaluated_items = scheme.oprf.evaluate(blinded_items, msk['kappa'])
    tokens = scheme.oprf.unblind(evaluated_items, blind_state)
    return tokens


def main():
    group = PairingGroup('MNT224')
    scheme = DACPCPABE(group, oprf=BlindPairingOPRF(group))
    attrs = ['1', '2', '3']
    policy_str = '((1 and 3) and (2 OR 4))'
    msg = group.random(GT)

    pk, msk = scheme.setup()
    key = scheme.keygen(pk, msk, attrs, user_id='du-external-oprf')
    tokens = external_tokens_for_policy(scheme, msk, policy_str)

    ctxt = scheme.encrypt(
        pk,
        msg,
        policy_str,
        oprf_tokens=tokens,
        require_external_oprf=True,
        pk_DO_sig='external-oprf-do',
        sk_DO_sig='external-oprf-do',
        cert_DO='prototype-cert-for-external-oprf-do',
    )
    recovered = scheme.decrypt(pk, ctxt, key)
    assert_true('external OPRF encrypt succeeds', recovered == msg)
    assert_true('encrypt reports external token use', ctxt['external_oprf_tokens_used'] is True)

    assert_raises(
        'missing token fails',
        lambda: scheme.encrypt(pk, msg, policy_str, oprf_tokens=tokens[:-1], require_external_oprf=True),
    )
    assert_raises(
        'no token fails',
        lambda: scheme.encrypt(pk, msg, policy_str, oprf_tokens=None, require_external_oprf=True),
    )

    wrong_index_tokens = [dict(token) for token in tokens]
    wrong_index_tokens[0]['item_index'] = len(tokens) + 10
    assert_raises(
        'wrong item_index fails',
        lambda: scheme.encrypt(
            pk,
            msg,
            policy_str,
            oprf_tokens=wrong_index_tokens,
            require_external_oprf=True,
        ),
    )

    print('=' * 72)
    print('DACP external OPRF tests passed.')


if __name__ == "__main__":
    main()
