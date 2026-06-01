'''
:Date:            4/2026
'''

import sys
import time

sys.path.append("/home/jinji_o/ABE-Test/Git/FABEO")

from charm.toolbox.pairinggroup import PairingGroup, GT

from FABEO.ipecp import IPECPABE
from FABEO.mynewcp import MyNewCPABE
from FABEO.msp import MSP


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
        'transform_tests': extract_transform_tests(abe, key, partial),
    }

    return stats


def extract_transform_tests(abe, key, partial):
    if 'stats' in partial and 'ipe_tests' in partial['stats']:
        return partial['stats']['ipe_tests']
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
    attr_list = ['1', '2', '3']
    policy_str = '((1 and 3) and (2 OR 4))'

    policy_stats = get_policy_stats(group, policy_str)

    mynew = MyNewCPABE(group)
    ipecp = IPECPABE(group)

    mynew_stats = measure_scheme(mynew, group, attr_list, policy_str)
    ipecp_stats = measure_scheme(ipecp, group, attr_list, policy_str)

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
    print('dummy_count(ipecp)={0}  mixed_count(ipecp)={1}'.format(
        ipecp_stats['dummy_count'],
        ipecp_stats['mixed_count'],
    ))

    print_header('Timing Comparison')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'IPE CP-ABE'))
    print_row('T_KeyGen', fmt_ms(mynew_stats['T_KeyGen_ms']), fmt_ms(ipecp_stats['T_KeyGen_ms']))
    print_row('T_Enc', fmt_ms(mynew_stats['T_Enc_ms']), fmt_ms(ipecp_stats['T_Enc_ms']))
    print_row('T_Transform', fmt_ms(mynew_stats['T_Transform_ms']), fmt_ms(ipecp_stats['T_Transform_ms']))
    print_row('T_FinalDec', fmt_ms(mynew_stats['T_FinalDec_ms']), fmt_ms(ipecp_stats['T_FinalDec_ms']))

    print_header('Size Comparison')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'IPE CP-ABE'))
    print_row('|CT|', fmt_bytes(mynew_stats['CT_bytes']), fmt_bytes(ipecp_stats['CT_bytes']))
    print_row('|TK|', fmt_bytes(mynew_stats['TK_bytes']), fmt_bytes(ipecp_stats['TK_bytes']))
    print_row('|RK|', fmt_bytes(mynew_stats['RK_bytes']), fmt_bytes(ipecp_stats['RK_bytes']))
    print_row('|LocalState|', fmt_bytes(mynew_stats['LocalState_bytes']), fmt_bytes(ipecp_stats['LocalState_bytes']))

    print_header('Transform Workload')
    print('{:<20} {:>20} {:>20}'.format('Metric', 'MyNew CP-ABE', 'IPE CP-ABE'))
    print_row('transform_tests', str(mynew_stats['transform_tests']), str(ipecp_stats['transform_tests']))
    print_row('candidate_count', str(mynew_stats['candidate_count']), str(ipecp_stats['candidate_count']))

    print_header('Reference Reading')
    print('IPE-Compare.md predicts that MyNew should dominate IPE CP-ABE on')
    print('T_KeyGen, T_Enc, T_Transform, |CT|, and |TK|, while |RK| stays close.')


if __name__ == "__main__":
    main()
