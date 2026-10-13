"""Read-only TEST scalar and canonical group regression vectors."""
import hashlib
import json
from pathlib import Path

from core.myabe08.tests.test_algebra_core import fixed_case

VECTOR=Path(__file__).parent/'vectors'/'profile_v1.json'
PREVIOUS_PROJECTION_SHA256='665852875cf5693ef716b07179c828d105d2c904f2b79661fb9e1967861370bf'


def test_phase2a_phase2b_fields_remain_frozen():
    data=json.loads(VECTOR.read_text())
    previous={k:v for k,v in data.items() if k not in ('phase3a','phase3b','phase3c')}
    digest=hashlib.sha256(json.dumps(previous,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    assert digest==PREVIOUS_PROJECTION_SHA256


def test_deterministic_algebra_bytes_and_pair_count():
    v=json.loads(VECTOR.read_text())['phase3a']
    assert 'NOT PRODUCTION SECRET' in v['notice']
    assert v['scalar_inputs']=={'alpha':7,'a':11,'z':13,'mu':17,'s':19,
                                'y':[5],'r_j':[23,29],'delta_q':37}
    x=fixed_case();b=x['backend'];pp=x['pp'];base=x['base'];rk=x['recovery']
    ct=x['ct'];bundle=x['bundle'];tr=x['tr']
    actual={
        'g1_a_hex':b.serialize_g1(pp.g1_a).hex(),
        'g2_a_hex':b.serialize_g2(pp.g2_a).hex(),
        'gt_alpha_hex':b.serialize_gt(pp.gt_alpha).hex(),
        'k0_hex':b.serialize_g2(base.k0).hex(),
        'rk_hex':b.serialize_scalar(rk.rk).hex(),
        'c_i_hex':[b.serialize_g1(z).hex() for z in ct.c_i],
        'd_j_hex':[b.serialize_g2(z).hex() for z in ct.d_j],
        'c_hex':b.serialize_g1(ct.c).hex(),
        'e_hex':b.serialize_gt(ct.e).hex(),
        'k1_q_hex':b.serialize_g2(bundle.k1_q).hex(),
        'k_tau_q_hex':[b.serialize_g1(z).hex() for z in bundle.k_tau_q],
        't0_q_hex':b.serialize_gt(bundle.t0_q).hex(),
        'x_hex':b.serialize_g1(tr.x).hex(),
        'y_by_slot_hex':[[slot,b.serialize_g1(y).hex()] for slot,y in tr.y_by_slot],
        't_a_hex':b.serialize_gt(tr.t_a).hex(),
        'e_hat_hex':b.serialize_gt(x['quotient']).hex(),
        'e_recovered_hex':b.serialize_gt(x['recovered']).hex(),
        'pair_terms':{'tee':x['tee_counts'].pairing_terms,
                      'csp':x['csp_counts'].pairing_terms,
                      'system':x['tee_counts'].pairing_terms+x['csp_counts'].pairing_terms},
    }
    for key,value in actual.items(): assert v[key]==value,key
    assert v['policy']['tokens_hex']==[t.hex() for t in x['tokens']]
    assert v['e_recovered_hex']==v['e_hex']
