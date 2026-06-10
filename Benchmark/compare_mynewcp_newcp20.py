'''
:Date:            4/2026
'''

import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.mynewcp import MyNewCPABE
from Code.msp import MSP


def load_newcp20_class():
    # The requested directory name "newcp2.0" is not a normal Python package
    # import path, so this sample loads it explicitly from its file location.
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
        total = 0
        for item in value.values():
            total += estimate_value_size(group, item)
        return total
    if isinstance(value, (list, tuple, set)):
        total = 0
        for item in value:
            total += estimate_value_size(group, item)
        return total
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


def get_policy_stats(group, policy_str):
    util = MSP(group)
    policy = util.createPolicy(policy_str)
    mono_span_prog = util.convert_policy_to_msp(policy)

    unique_attrs = set()
    for attr in mono_span_prog.keys():
        unique_attrs.add(util.strip_index(attr))

    return {
        'ell': len(mono_span_prog),
        'n': util.len_longest_row,
        'u': len(unique_attrs),
    }


def measure_scheme(abe, group, attr_list, policy_str, iterations=3):
    totals = {
        'keygen': 0.0,
        'encrypt': 0.0,
        'transform': 0.0,
        'final': 0.0,
    }
    snapshot = None

    for _ in range(iterations):
        msg = group.random(GT)
        pk, msk = abe.setup()

        start = time.time()
        key = abe.keygen(pk, msk, attr_list)
        totals['keygen'] += time.time() - start

        start = time.time()
        ctxt = abe.encrypt(pk, msg, policy_str)
        totals['encrypt'] += time.time() - start

        start = time.time()
        partial = abe.transform(pk, ctxt, key)
        totals['transform'] += time.time() - start

        start = time.time()
        rec_msg = abe.final_decrypt(pk, partial, key)
        totals['final'] += time.time() - start

        if rec_msg != msg:
            raise RuntimeError('Decryption failed for {0}'.format(abe.name))

        snapshot = {
            'key': key,
            'ctxt': ctxt,
            'partial': partial,
        }

    key = snapshot['key']
    ctxt = snapshot['ctxt']
    partial = snapshot['partial']

    tk_payload = {
        'K_0': key['K_0'],
        'K_1': key['K_1'],
        'TK': key['TK'],
    }
    rk_payload = {
        'RK': key['RK'],
    }
    local_payload = {
        'RK': key['RK'],
        'Map': key['Map'],
    }

    stats = {
        'T_KeyGen_ms': totals['keygen'] * 1000.0 / iterations,
        'T_Enc_ms': totals['encrypt'] * 1000.0 / iterations,
        'T_Transform_ms': totals['transform'] * 1000.0 / iterations,
        'T_FinalDec_ms': totals['final'] * 1000.0 / iterations,
        'CT_bytes': estimate_value_size(group, ctxt),
        'TK_bytes': estimate_value_size(group, tk_payload),
        'RK_bytes': estimate_value_size(group, rk_payload),
        'LocalState_bytes': estimate_value_size(group, local_payload),
        'dummy_count': len(key['dummy_attr_list']),
        'mixed_count': len(key['mixed_attr_list']),
        'candidate_count': len(partial['candidates']),
        'transform_tests': extract_transform_tests(key, partial),
    }

    return stats


def extract_transform_tests(key, partial):
    if 'stats' in partial and 'ipe_tests' in partial['stats']:
        return partial['stats']['ipe_tests']
    if 'stats' in partial and 'abf_queries' in partial['stats']:
        return partial['stats']['abf_queries']
    return len(key['TK'])


def print_header(title):
    print('=' * 86)
    print(title)
    print('=' * 86)


def print_row(name, left, right):
    print('{:<20} {:>20} {:>20}'.format(name, left, right))


def fmt_ms(value):
    return '{0:.3f} ms'.format(value)


def fmt_bytes(value):
    return '{0} B'.format(value)


def main():
    group = PairingGroup('MNT224')
    attr_list = ['1', '2', '3', '5', '6', '9']
    policy_str = '(((1 and 3) and (2 OR 4)) and ((5 and 6) OR (7 and 8)) and (9 OR 10))'

    policy_stats = get_policy_stats(group, policy_str)

    NewCP20CPABE = load_newcp20_class()
    mynew = MyNewCPABE(group)
    newcp20 = NewCP20CPABE(group)

    mynew_stats = measure_scheme(mynew, group, attr_list, policy_str)
    newcp20_stats = measure_scheme(newcp20, group, attr_list, policy_str)

    print_header('Policy Parameters')
    print('ell={0}  n={1}  u={2}  s={3}'.format(
        policy_stats['ell'],
        policy_stats['n'],
        policy_stats['u'],
        len(attr_list),
    ))
    print('dummy_count(mynew)={0}  mixed_count(mynew)={1}'.format(
        mynew_stats['dummy_count'],
        mynew_stats['mixed_count'],
    ))
    print('dummy_count(newcp2.0)={0}  mixed_count(newcp2.0)={1}'.format(
        newcp20_stats['dummy_count'],
        newcp20_stats['mixed_count'],
    ))

    print_header('Timing Comparison')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'NewCP2.0 CP-ABE'))
    print_row('T_KeyGen', fmt_ms(mynew_stats['T_KeyGen_ms']), fmt_ms(newcp20_stats['T_KeyGen_ms']))
    print_row('T_Enc', fmt_ms(mynew_stats['T_Enc_ms']), fmt_ms(newcp20_stats['T_Enc_ms']))
    print_row('T_Transform', fmt_ms(mynew_stats['T_Transform_ms']), fmt_ms(newcp20_stats['T_Transform_ms']))
    print_row('T_FinalDec', fmt_ms(mynew_stats['T_FinalDec_ms']), fmt_ms(newcp20_stats['T_FinalDec_ms']))

    print_header('Size Comparison')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'NewCP2.0 CP-ABE'))
    print_row('|CT|', fmt_bytes(mynew_stats['CT_bytes']), fmt_bytes(newcp20_stats['CT_bytes']))
    print_row('|TK|', fmt_bytes(mynew_stats['TK_bytes']), fmt_bytes(newcp20_stats['TK_bytes']))
    print_row('|RK|', fmt_bytes(mynew_stats['RK_bytes']), fmt_bytes(newcp20_stats['RK_bytes']))
    print_row('|LocalState|', fmt_bytes(mynew_stats['LocalState_bytes']), fmt_bytes(newcp20_stats['LocalState_bytes']))

    print_header('Transform Workload')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'NewCP2.0 CP-ABE'))
    print_row('transform_tests', str(mynew_stats['transform_tests']), str(newcp20_stats['transform_tests']))
    print_row('candidate_count', str(mynew_stats['candidate_count']), str(newcp20_stats['candidate_count']))

    print_header('Reference Reading')
    print('FABEO.md motivates NewCP2.0 by moving linear-size components into G1,')
    print('keeping G2 terms constant-size, and aggregating pairings during final recovery.')


if __name__ == "__main__":
    main()
