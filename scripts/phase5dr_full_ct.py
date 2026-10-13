"""One-construction public CT size check for the EMULATED row ablation.

This is deterministic-size structural evidence, not a timing benchmark. It
must run only after the separately versioned public row-ablation profile passes
its E2E tests. It never invokes SGX or changes the formal core sample runs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from core.myabe08.crypto import compute_ctx_priv
from core.myabe08.experiments.provenance import code_manifest, file_sha256, spec_manifest
from core.myabe08.profile import EMULATED_TEE_PROFILE
from core.myabe08.public import EMULATED_TEST_MODE, PublicMyABE08, serialize_ciphertext
from core.myabe08.signing import new_private_key, public_key_bytes
from core.myabe08.types import Attribute, PolicyContext, PolicyInput, Validity


class FixedTestClock:
    def now(self): return 1000


def construct(config, mode, state_dir):
    sys_id=b'MYABE08-PHASE5DR-FULL-CT-TEST'
    labels=tuple(config['labels'])
    context_id=hashlib.sha256(('phase5dr-%s-%s'%(
        config['ell'],config['cmax'])).encode()).digest()
    context=PolicyContext(sys_id,context_id,1,
        compute_ctx_priv(sys_id,context_id,1))
    scheme=PublicMyABE08(sys_id=sys_id,namespace='bench',
        backend=EMULATED_TEE_PROFILE,experiment_trust_mode=EMULATED_TEST_MODE,
        state_path=state_dir/'state',clock=FixedTestClock(),
        component_allocation=mode)
    scheme.Setup(c_max=config['cmax'],validity=Validity(100,2000))
    holder=new_private_key()
    user=scheme.KeyGen(uid='PHASE5DR-SYNTHETIC-USER',
        attributes=(Attribute('bench','label',labels[0]),),
        auth_public_key=public_key_bytes(holder),validity=Validity(100,2000))
    policy=PolicyInput(((1,),)*config['ell'],
        tuple(Attribute('bench','label',label) for label in labels))
    ct=scheme.Encrypt(message=b'phase5dr-size-only',policy=policy,
        context=context,data_id=b'phase5dr-size-only')
    auth=scheme.TEEAuthorize(user=user,ciphertext=ct,
        auth_private_key=holder,expiry=1500)
    partial=scheme.Transform(ciphertext=ct,public_auth=auth)
    if scheme.FinalDec(partial=partial,recovery_key=user.recovery_key)!=b'phase5dr-size-only':
        raise AssertionError('public row ablation failed E2E')
    wire=serialize_ciphertext(ct,scheme.crypto)
    core_bytes=(sum(len(c.encoded) for c in ct.row_components)+
                sum(len(d.encoded) for d in ct.occurrence_components)+
                len(ct.header.c.encoded))
    af=ct.anonymous_filter
    return dict(ell=config['ell'],distinct=config['distinct'],
        actual_cmax=config['cmax'],mode=mode,full_ct_wire_bytes=len(wire),
        core_group_bytes=core_bytes,g1_count=len(ct.row_components)+1,
        g2_count=len(ct.occurrence_components),
        af_slot_count=len(af.slots),
        af_slot_bytes=sum(len(slot) for slot in af.slots),
        public_e2e='PASS',n_constructions=1,
        measurement_origin='LOCAL_CONSTRUCTED_SINGLE',
        tee_profile=EMULATED_TEE_PROFILE,
        security_claim='INTERNAL_ABLATION_TEST_ONLY')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('ablation_run',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    run=args.ablation_run
    manifest=json.loads((run/'MANIFEST.json').read_text())
    plan=json.loads((run/'PHASE5D_R_PLAN.json').read_text())
    if (manifest['status']!='COMPLETE' or manifest['track']!='ablation' or
        manifest['raw_sha256']!=file_sha256(run/'raw.jsonl')):
        raise ValueError('complete validated ablation run required')
    spec=spec_manifest()
    configs=[c for c in plan['configurations'] if c['track']=='ablation']
    if len(configs)!=20: raise ValueError('complete 20-configuration plan required')
    expected_core={}
    with (run/'raw.jsonl').open() as stream:
        for line in stream:
            sample=json.loads(line)
            key=(sample['config']['ell'],sample['config']['cmax'],sample['scheme'])
            value=sample['core_ct_bytes']
            if key in expected_core and expected_core[key]!=value:
                raise ValueError('nonconstant formal core group size')
            expected_core[key]=value
    args.output.mkdir(parents=True,exist_ok=False)
    rows=[]
    with TemporaryDirectory(prefix='phase5dr-full-ct-') as tmp:
        root=Path(tmp)
        for index,config in enumerate(configs):
            for mode in ('OCCURRENCE','ROW'):
                state_dir=root/('%02d-%s'%(index,mode))
                state_dir.mkdir()
                result=construct(config,mode,state_dir)
                if result['core_group_bytes']!=expected_core[(
                    config['ell'],config['cmax'],mode)]:
                    raise ValueError('public/core group size mismatch')
                rows.append(result)
            print(config['ell'],config['cmax'],'public CT complete',flush=True)
    with (args.output/'full_ct_size.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=tuple(rows[0]))
        writer.writeheader();writer.writerows(rows)
    paired=[]
    for config in configs:
        chosen=[r for r in rows if r['ell']==config['ell'] and
                r['actual_cmax']==config['cmax']]
        if len(chosen)!=2:raise ValueError('missing construction pair')
        occ=next(r for r in chosen if r['mode']=='OCCURRENCE')
        row=next(r for r in chosen if r['mode']=='ROW')
        if (occ['af_slot_count']!=row['af_slot_count'] or
            occ['af_slot_bytes']!=row['af_slot_bytes']):
            status='AF_SHAPE_DIFFERED_NO_DIRECT_FULL_CT_ATTRIBUTION'
        else: status='PAIRED_AF_SHAPE_MATCH'
        paired.append(dict(ell=config['ell'],distinct=config['distinct'],
            actual_cmax=config['cmax'],occurrence_full_ct_bytes=occ['full_ct_wire_bytes'],
            row_full_ct_bytes=row['full_ct_wire_bytes'],
            reduction_percent=(row['full_ct_wire_bytes']-occ['full_ct_wire_bytes'])/
                              row['full_ct_wire_bytes']*100,
            comparability=status,n_constructions_per_arm=1))
    with (args.output/'full_ct_paired.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=tuple(paired[0]))
        writer.writeheader();writer.writerows(paired)
    fig,axes=plt.subplots(2,2,figsize=(10,7),constrained_layout=True)
    for ax,ell in zip(axes.flat,(20,40,80,160)):
        selected=sorted((r for r in paired if r['ell']==ell),
                        key=lambda r:r['actual_cmax'])
        ax.plot([r['actual_cmax'] for r in selected],
                [r['occurrence_full_ct_bytes'] for r in selected],
                marker='o',label='MyABE occurrence-aware')
        ax.plot([r['actual_cmax'] for r in selected],
                [r['row_full_ct_bytes'] for r in selected],
                marker='o',label='NoOccurrenceReuse TEST ablation')
        ax.set(title='ell = %d'%ell,xlabel='Actual cmax',
               ylabel='Canonical CT wire bytes (bytes)')
        ax.grid(alpha=.25)
    handles,labels=axes.flat[0].get_legend_handles_labels()
    fig.legend(handles,labels,loc='upper center',ncol=2,
               bbox_to_anchor=(.5,1.06),frameon=False)
    fig.suptitle('Occurrence reuse: complete signed CT size',y=1.02)
    fig.savefig(args.output/'OCCURRENCE_CT_REDUCTION.png',dpi=300,bbox_inches='tight')
    fig.savefig(args.output/'OCCURRENCE_CT_REDUCTION.pdf',bbox_inches='tight')
    plt.close(fig)
    (args.output/'OCCURRENCE_CT_REDUCTION.json').write_text(json.dumps(dict(
        title='Complete signed public CT size, EMULATED TEST profile',
        source_data='full_ct_paired.csv',x='actual cmax',
        y='canonical signed CT wire bytes',unit='bytes',
        aggregation='one correctness-checked construction per arm/configuration',
        trust='EMULATED TEST only; NoOccurrenceReuse internal ablation',
        caveat='Check per-configuration AF-shape comparability in full_ct_paired.csv; '
               'one construction is size evidence, not a latency distribution',
        timing_claim='NONE'),sort_keys=True,indent=2)+'\n')
    (args.output/'PROVENANCE.json').write_text(json.dumps(dict(
        status='COMPLETE_SINGLE_CONSTRUCTION_SIZE_ONLY',
        ablation_raw_sha256=manifest['raw_sha256'],
        specification=spec,code_manifest=code_manifest(),
        source_script_sha256=file_sha256(Path(__file__)),
        configurations=len(configs),constructions=len(rows),
        timing_samples=0,backend=EMULATED_TEE_PROFILE),
        sort_keys=True,indent=2)+'\n')


if __name__=='__main__':
    main()
