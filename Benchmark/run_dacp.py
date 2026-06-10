'''
Minimal runnable DACP example.
'''

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.dacp import DACPCPABE


def main():
    group = PairingGroup('MNT224')
    abe = DACPCPABE(group)

    attr_list = ['1', '2', '3']
    bad_attr_list = ['1', '4']
    policy_str = '((1 and 3) and (2 OR 4))'
    msg = group.random(GT)

    pk, msk = abe.setup()
    key = abe.keygen(pk, msk, attr_list, user_id='du-001')
    ctxt = abe.encrypt(
        pk,
        msg,
        policy_str,
        pk_DO_sig='do-demo-key',
        sk_DO_sig='do-demo-key',
        cert_DO='prototype-cert-for-do-demo-key',
    )

    rec_msg = abe.decrypt(pk, ctxt, key)
    partial = abe.transform(pk, ctxt, key['TK_id'])
    final_msg = abe.final_decrypt(pk, partial, key['RK_id'])

    bad_key = abe.keygen(pk, msk, bad_attr_list, user_id='du-bad')
    bad_msg = abe.decrypt(pk, ctxt, bad_key)

    print('DACP run')
    print('=' * 72)
    print('decrypt_success: {0}'.format(rec_msg == msg))
    print('outsourced_success: {0}'.format(final_msg == msg))
    print('unsatisfied_returns_none: {0}'.format(bad_msg is None))
    print('pk_fields: {0}'.format(sorted(['PP', 'g1', 'g2', 'g1_a', 'e_g1g2_alpha'])))
    print('key_fields: {0}'.format(sorted(key.keys())))
    print('tk_fields: {0}'.format(sorted(key['TK_id'].keys())))
    print('rk_fields: {0}'.format(sorted(key['RK_id'].keys())))
    print('ctxt_fields: {0}'.format(sorted(ctxt.keys())))
    print('anonymous_fields_present: {0}'.format(
        all(name in ctxt for name in ('BF', 'A_star', 'policy_tag', 'attribute_tag_root', 'cid'))
    ))
    print('real_attrs: {0}'.format(len(key['real_attr_list'])))
    print('dummy_attrs: {0}'.format(len(key['dummy_attr_list'])))
    print('bf_slots: {0}'.format(ctxt['BF']['m']))
    print('transform_candidates: {0}'.format(len(partial['candidates'])))
    print('transform_stats: {0}'.format(partial['stats']))


if __name__ == "__main__":
    main()
