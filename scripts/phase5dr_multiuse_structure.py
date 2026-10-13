"""Local BLS12-381 repeated-policy component comparison, without timings."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from core.myabe08.algebra import encrypt_algebra_core, setup_algebra_core
from core.myabe08.baselines import fabeo
from core.myabe08.crypto import BLS12381Backend
from core.myabe08.experiments.provenance import code_manifest, file_sha256, spec_manifest
from core.myabe08.lsss import LSSSMatrix


CASES=(
    ('A',('A',),((1,),)),
    ('A,A AND',('A','A'),((1,1),(0,-1))),
    ('A,B,A OR',('A','B','A'),((1,),(1,),(1,))),
    ('A,B,A,C,A OR',('A','B','A','C','A'),((1,),)*5),
    ('A x4 OR',('A',)*4,((1,),)*4),
)


def one_case(backend,name,labels,rows):
    matrix=LSSSMatrix(rows,backend.scalar_order,len(rows),len(rows[0]))
    seen={}
    for label in labels:seen[label]=seen.get(label,0)+1
    cmax=max(seen.values())
    tokens=tuple(hashlib.sha256(b'PHASE5DR-MULTIUSE-TEST\x00'+x.encode()).digest()
                 for x in labels)
    pp,_=setup_algebra_core(backend,cmax)
    myabe=encrypt_algebra_core(pp,matrix,tokens,backend)
    fpp,alpha=fabeo.setup(backend)
    message=backend.pair(fpp.g1,fpp.g2)
    ct=fabeo.encrypt(fpp,matrix,labels,message)
    key=fabeo.keygen(fpp,alpha,tuple(sorted(set(labels))))
    if fabeo.decrypt(fpp,ct,key)!=message:
        raise AssertionError('FABEO multi-use access failed')
    if len(myabe.d_j)!=cmax or len(ct.g2_sprime)!=cmax:
        raise AssertionError('multi-use component count mismatch')
    myabe_bytes=(sum(len(x.encoded) for x in myabe.c_i)+
                 sum(len(x.encoded) for x in myabe.d_j)+len(myabe.c.encoded))
    fabeo_bytes=(sum(len(backend.serialize_g1(x)) for x in ct.rows)+
                 len(backend.serialize_g2(ct.g2_s))+
                 sum(len(backend.serialize_g2(x)) for x in ct.g2_sprime)+
                 len(backend.serialize_gt(ct.masked)))
    return [dict(policy=name,ell=len(labels),actual_tau=cmax,scheme=scheme,
        g1_count=g1,g2_count=g2,gt_count=gt,core_group_bytes=size,
        measurement_origin='LOCAL_CONSTRUCTED_SINGLE',
        comparison_scope='STRUCTURAL_ONLY_DIFFERENT_FEATURE_SETS')
        for scheme,g1,g2,gt,size in (
            ('MYABE08_BLS12381_CORE',len(myabe.c_i)+1,len(myabe.d_j),0,myabe_bytes),
            ('FABEO22_PAPER_MULTIUSE_BLS12381_V1',len(ct.rows),
             1+len(ct.g2_sprime),1,fabeo_bytes))]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    spec=spec_manifest()
    args.output.mkdir(parents=True,exist_ok=False)
    backend=BLS12381Backend(b'PHASE5DR-MULTIUSE-STRUCTURE')
    rows=[]
    for case in CASES:rows.extend(one_case(backend,*case))
    with (args.output/'REPEATED_POLICY_MYABE_VS_FABEO.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=tuple(rows[0]))
        writer.writeheader();writer.writerows(rows)
    names=[case[0] for case in CASES]
    mine=[next(r['core_group_bytes'] for r in rows if r['policy']==name and
               r['scheme']=='MYABE08_BLS12381_CORE') for name in names]
    theirs=[next(r['core_group_bytes'] for r in rows if r['policy']==name and
               r['scheme'].startswith('FABEO')) for name in names]
    fig,ax=plt.subplots(figsize=(8,4.8),layout='constrained')
    xs=range(len(names))
    ax.bar([x-.2 for x in xs],mine,width=.4,label='MyABE core')
    ax.bar([x+.2 for x in xs],theirs,width=.4,label='FABEO paper multi-use BLS')
    ax.set_xticks(list(xs),names,rotation=15,ha='right')
    ax.set_ylabel('Encoded ABE core group bytes (bytes)')
    ax.set_title('Repeated-policy component structure (no timings)')
    ax.legend(frameon=False)
    ax.grid(axis='y',alpha=.25)
    ax.set_axisbelow(True)
    fig.savefig(args.output/'REPEATED_POLICY_MYABE_VS_FABEO.png',dpi=300)
    fig.savefig(args.output/'REPEATED_POLICY_MYABE_VS_FABEO.pdf')
    plt.close(fig)
    (args.output/'REPEATED_POLICY_MYABE_VS_FABEO.json').write_text(json.dumps(dict(
        title='Repeated-policy BLS12-381 component structure',
        specification=spec,source_code_manifest=code_manifest(),
        source_script_sha256=file_sha256(Path(__file__)),
        source_data='REPEATED_POLICY_MYABE_VS_FABEO.csv',
        sample_policy='one locally constructed ciphertext per scheme/configuration',
        timing_samples=0,comparability='STRUCTURAL_ONLY',
        caveat='Different feature sets; FABEO multi-use is a paper reimplementation, '
               'not an oracle-verified native tau>1 port.'),sort_keys=True,indent=2)+'\n')


if __name__=='__main__':main()
