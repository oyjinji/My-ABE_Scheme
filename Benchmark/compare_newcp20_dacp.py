'''
Coarse benchmark comparison for legacy NewCP2.0 and DACP.
'''

import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.dacp import DACPCPABE


def load_newcp20_class():
    module_path = ROOT / 'Code' / 'newcp2.0' / '__init__.py'
    spec = importlib.util.spec_from_file_location(
        'Code.newcp20_dynamic',
        str(module_path),
        submodule_search_locations=[str(module_path.parent)],
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.NewCP20CPABE


def estimate_value_size(group, value):
    if value is None:
        return 0
    if isinstance(value, dict):
        return sum(estimate_value_size(group, item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return sum(estimate_value_size(group, item) for item in value)
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode('utf-8'))
    if isinstance(value, int):
        return max(1, (value.bit_length() + 7) // 8)
    try:
        return len(group.serialize(value))
    except Exception:
        return len(repr(value).encode('utf-8'))


def measure_scheme(abe, group, attr_list, policy_str, iterations=3):
    totals = {
        'setup': 0.0,
        'keygen': 0.0,
        'encrypt': 0.0,
        'transform': 0.0,
        'final': 0.0,
        'decrypt': 0.0,
    }
    snapshot = None

    for _ in range(iterations):
        msg = group.random(GT)

        start = time.time()
        pk, msk = abe.setup()
        totals['setup'] += time.time() - start

        start = time.time()
        key = abe.keygen(pk, msk, attr_list, user_id='bench-du')
        totals['keygen'] += time.time() - start

        start = time.time()
        ctxt = abe.encrypt(
            pk,
            msg,
            policy_str,
            pk_DO_sig='bench-do-key',
            sk_DO_sig='bench-do-key',
            cert_DO='prototype-cert-for-bench-do-key',
        )
        totals['encrypt'] += time.time() - start

        start = time.time()
        partial = abe.transform(pk, ctxt, key['TK_id'])
        totals['transform'] += time.time() - start

        start = time.time()
        rec_msg = abe.final_decrypt(pk, partial, key['RK_id'])
        totals['final'] += time.time() - start

        start = time.time()
        rec_msg_2 = abe.decrypt(pk, ctxt, key)
        totals['decrypt'] += time.time() - start

        if rec_msg != msg or rec_msg_2 != msg:
            raise RuntimeError('Decryption failed for {0}'.format(abe.name))

        snapshot = {'pk': pk, 'key': key, 'ctxt': ctxt, 'partial': partial}

    key = snapshot['key']
    ctxt = snapshot['ctxt']
    partial = snapshot['partial']

    return {
        'T_Setup_ms': totals['setup'] * 1000.0 / iterations,
        'T_KeyGen_ms': totals['keygen'] * 1000.0 / iterations,
        'T_Enc_ms': totals['encrypt'] * 1000.0 / iterations,
        'T_Transform_ms': totals['transform'] * 1000.0 / iterations,
        'T_FinalDec_ms': totals['final'] * 1000.0 / iterations,
        'T_DecryptTotal_ms': totals['decrypt'] * 1000.0 / iterations,
        'CT_fields': len(ctxt),
        'Key_fields': len(key),
        'CT_bytes': estimate_value_size(group, ctxt),
        'Key_bytes': estimate_value_size(group, key),
        'candidates': len(partial['candidates']),
        'abf_queries': partial['stats']['abf_queries'],
    }


def fmt_ms(value):
    return '{0:.3f} ms'.format(value)


def fmt_bytes(value):
    return '{0} B'.format(value)


def print_row(name, left, right):
    print('{:<20} {:>20} {:>20}'.format(name, left, right))


def main():
    group = PairingGroup('MNT224')
    attr_list = ['1', '2', '3', '5', '6', '9']
    policy_str = '(((1 and 3) and (2 OR 4)) and ((5 and 6) OR (7 and 8)) and (9 OR 10))'

    NewCP20CPABE = load_newcp20_class()
    newcp20 = NewCP20CPABE(group)
    dacp = DACPCPABE(group)

    newcp_stats = measure_scheme(newcp20, group, attr_list, policy_str)
    dacp_stats = measure_scheme(dacp, group, attr_list, policy_str)

    print('=' * 86)
    print('NewCP2.0 legacy vs DACP')
    print('=' * 86)
    print('{:<20} {:>20} {:>20}'.format('Metric', 'NewCP2.0', 'DACP'))
    print_row('T_Setup', fmt_ms(newcp_stats['T_Setup_ms']), fmt_ms(dacp_stats['T_Setup_ms']))
    print_row('T_KeyGen', fmt_ms(newcp_stats['T_KeyGen_ms']), fmt_ms(dacp_stats['T_KeyGen_ms']))
    print_row('T_Enc', fmt_ms(newcp_stats['T_Enc_ms']), fmt_ms(dacp_stats['T_Enc_ms']))
    print_row('T_Transform', fmt_ms(newcp_stats['T_Transform_ms']), fmt_ms(dacp_stats['T_Transform_ms']))
    print_row('T_FinalDec', fmt_ms(newcp_stats['T_FinalDec_ms']), fmt_ms(dacp_stats['T_FinalDec_ms']))
    print_row('T_DecryptTotal', fmt_ms(newcp_stats['T_DecryptTotal_ms']), fmt_ms(dacp_stats['T_DecryptTotal_ms']))
    print_row('CT_fields', str(newcp_stats['CT_fields']), str(dacp_stats['CT_fields']))
    print_row('Key_fields', str(newcp_stats['Key_fields']), str(dacp_stats['Key_fields']))
    print_row('CT_bytes', fmt_bytes(newcp_stats['CT_bytes']), fmt_bytes(dacp_stats['CT_bytes']))
    print_row('Key_bytes', fmt_bytes(newcp_stats['Key_bytes']), fmt_bytes(dacp_stats['Key_bytes']))
    print_row('candidates', str(newcp_stats['candidates']), str(dacp_stats['candidates']))
    print_row('abf_queries', str(newcp_stats['abf_queries']), str(dacp_stats['abf_queries']))


if __name__ == "__main__":
    main()
