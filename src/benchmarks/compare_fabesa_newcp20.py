'''
:Date:            5/2026
'''

import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import PairingGroup, GT

from Code.fabesa import FABESACPABE
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


def measure_fabesa(abe, group, attr_list, policy_str, iterations=3):
    totals = {
        'setup': 0.0,
        'keygen': 0.0,
        'encrypt': 0.0,
        'match': 0.0,
        'decrypt': 0.0,
    }
    snapshot = None

    for _ in range(iterations):
        msg = group.random(GT)

        start = time.time()
        pk, msk = abe.setup()
        totals['setup'] += time.time() - start

        start = time.time()
        key = abe.keygen(pk, msk, attr_list)
        totals['keygen'] += time.time() - start

        start = time.time()
        ctxt = abe.encrypt(pk, msg, policy_str)
        totals['encrypt'] += time.time() - start

        start = time.time()
        match = abe.match(ctxt, key)
        totals['match'] += time.time() - start

        start = time.time()
        rec_msg = abe.decrypt_with_match(pk, ctxt, key, match)
        totals['decrypt'] += time.time() - start

        if rec_msg != msg:
            raise RuntimeError('Decryption failed for {0}'.format(abe.name))

        snapshot = {
            'pk': pk,
            'key': key,
            'ctxt': ctxt,
            'match': match,
        }

    key = snapshot['key']
    ctxt = snapshot['ctxt']
    match = snapshot['match']

    return {
        'T_Setup_ms': totals['setup'] * 1000.0 / iterations,
        'T_KeyGen_ms': totals['keygen'] * 1000.0 / iterations,
        'T_Enc_ms': totals['encrypt'] * 1000.0 / iterations,
        'T_Match_ms': totals['match'] * 1000.0 / iterations,
        'T_Transform_ms': 0.0,
        'T_FinalDec_ms': totals['decrypt'] * 1000.0 / iterations,
        'T_TotalDec_ms': (totals['match'] + totals['decrypt']) * 1000.0 / iterations,
        'T_DULocal_ms': (totals['match'] + totals['decrypt']) * 1000.0 / iterations,
        'CT_bytes': estimate_value_size(group, ctxt),
        'SK_bytes': estimate_value_size(group, key),
        'matched_subsets': match['stats']['matched_subsets'],
        'matched_attributes': match['stats']['matched_attributes'],
        'name_tests': match['stats']['name_tests'],
    }


def measure_newcp20(abe, group, attr_list, policy_str, iterations=3):
    totals = {
        'setup': 0.0,
        'keygen': 0.0,
        'encrypt': 0.0,
        'transform': 0.0,
        'final': 0.0,
    }
    snapshot = None

    for _ in range(iterations):
        msg = group.random(GT)

        start = time.time()
        pk, msk = abe.setup()
        totals['setup'] += time.time() - start

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
            'pk': pk,
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
    local_payload = {
        'RK': key['RK'],
        'Map': key['Map'],
    }

    return {
        'T_Setup_ms': totals['setup'] * 1000.0 / iterations,
        'T_KeyGen_ms': totals['keygen'] * 1000.0 / iterations,
        'T_Enc_ms': totals['encrypt'] * 1000.0 / iterations,
        'T_Match_ms': 0.0,
        'T_Transform_ms': totals['transform'] * 1000.0 / iterations,
        'T_FinalDec_ms': totals['final'] * 1000.0 / iterations,
        'T_TotalDec_ms': (totals['transform'] + totals['final']) * 1000.0 / iterations,
        'T_DULocal_ms': totals['final'] * 1000.0 / iterations,
        'CT_bytes': estimate_value_size(group, ctxt),
        'SK_bytes': estimate_value_size(group, tk_payload) + estimate_value_size(group, local_payload),
        'matched_subsets': 0,
        'matched_attributes': len(partial['candidates']),
        'name_tests': extract_transform_tests(key, partial),
    }


def extract_transform_tests(key, partial):
    if 'stats' in partial and 'abf_queries' in partial['stats']:
        return partial['stats']['abf_queries']
    return len(key['TK'])


def print_header(title):
    print('=' * 92)
    print(title)
    print('=' * 92)


def print_row(name, left, right):
    print('{:<22} {:>22} {:>22}'.format(name, left, right))


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
    fabesa = FABESACPABE(group)
    newcp20 = NewCP20CPABE(group)

    fabesa_stats = measure_fabesa(fabesa, group, attr_list, policy_str)
    newcp_stats = measure_newcp20(newcp20, group, attr_list, policy_str)

    print_header('Policy Parameters')
    print('ell={0}  n={1}  u={2}  s={3}'.format(
        policy_stats['ell'],
        policy_stats['n'],
        policy_stats['u'],
        len(attr_list),
    ))
    print('matched_subsets(fabesa)={0}  matched_attributes(fabesa)={1}'.format(
        fabesa_stats['matched_subsets'],
        fabesa_stats['matched_attributes'],
    ))

    print_header('Timing Comparison')
    print('{:<22} {:>22} {:>22}'.format('Metric', 'FABESA CP-A2BE', 'NewCP2.0 CP-ABE'))
    print_row('T_Setup', fmt_ms(fabesa_stats['T_Setup_ms']), fmt_ms(newcp_stats['T_Setup_ms']))
    print_row('T_KeyGen', fmt_ms(fabesa_stats['T_KeyGen_ms']), fmt_ms(newcp_stats['T_KeyGen_ms']))
    print_row('T_Enc', fmt_ms(fabesa_stats['T_Enc_ms']), fmt_ms(newcp_stats['T_Enc_ms']))
    print_row('T_Match', fmt_ms(fabesa_stats['T_Match_ms']), 'included in Transform')
    print_row('T_Transform', '-', fmt_ms(newcp_stats['T_Transform_ms']))
    print_row('T_FinalDec', fmt_ms(fabesa_stats['T_FinalDec_ms']), fmt_ms(newcp_stats['T_FinalDec_ms']))
    print_row('T_TotalDec', fmt_ms(fabesa_stats['T_TotalDec_ms']), fmt_ms(newcp_stats['T_TotalDec_ms']))
    print_row('T_DU_Local', fmt_ms(fabesa_stats['T_DULocal_ms']), fmt_ms(newcp_stats['T_DULocal_ms']))

    print_header('Size Comparison')
    print('{:<22} {:>22} {:>22}'.format('Metric', 'FABESA CP-A2BE', 'NewCP2.0 CP-ABE'))
    print_row('|CT|', fmt_bytes(fabesa_stats['CT_bytes']), fmt_bytes(newcp_stats['CT_bytes']))
    print_row('|SK/TK+Local|', fmt_bytes(fabesa_stats['SK_bytes']), fmt_bytes(newcp_stats['SK_bytes']))

    print_header('Matching And Decryption Workload')
    print('{:<22} {:>22} {:>22}'.format('Metric', 'FABESA CP-A2BE', 'NewCP2.0 CP-ABE'))
    print_row('name/token tests', str(fabesa_stats['name_tests']), str(newcp_stats['name_tests']))
    print_row('matched candidates', str(fabesa_stats['matched_attributes']), str(newcp_stats['matched_attributes']))

    print_header('Reference Reading')
    print('Compare_fabesa.md asks for Setup, KeyGen, Enc, Match, Transform,')
    print('FinalDec, TotalDec, and DU-local costs. FABESA CP-A2BE has no CSP Transform;')
    print('NewCP2.0 moves most decryption work into Transform and leaves FinalDec local.')


if __name__ == "__main__":
    main()
