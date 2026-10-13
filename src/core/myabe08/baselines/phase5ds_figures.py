"""Matplotlib-only comparative figures from frozen 5D-R and validated 5D-S."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from ..experiments.provenance import file_sha256
from .phase5ds import ROOT, design
from .phase5ds_report import paired_summary, sources

BLUE='#1f77b4'; GRAY='#7f7f7f'; ORANGE='#ff7f0e'
DARK='#164a7b'; TEAL='#1b9e89'; PURPLE='#7653a5'
COLORS={'OCCURRENCE':BLUE,'ROW':GRAY,
    'MYABE08_BLS12381_CORE':BLUE,
    'FABEO22_CP_BLS12381_TAU1':ORANGE,
    'CORE':DARK,'FULL_EMULATED':TEAL,'FULL_REAL_SGX':PURPLE}
SGX_FOOT='SGX_DEBUG_GRAMINE_V1 · QVL OUT_OF_DATE · strict RA2 BLOCKED · feasibility only'


def _save(out, name, fig, rows, metadata):
    (out/'data').mkdir(parents=True,exist_ok=True)
    (out/'meta').mkdir(parents=True,exist_ok=True)
    if rows:
        keys=list(dict.fromkeys(key for row in rows for key in row))
        with (out/'data'/f'{name}.csv').open('x',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=keys)
            writer.writeheader(); writer.writerows(rows)
    else:
        (out/'data'/f'{name}.csv').write_text('note\nstructural diagram\n')
    fig.savefig(out/f'{name}.png',dpi=300,bbox_inches='tight')
    fig.savefig(out/f'{name}.pdf',bbox_inches='tight')
    plt.close(fig)
    metadata=dict(metadata,figure=name,
                  renderer_sha256=file_sha256(Path(__file__)),
                  analysis_sha256=file_sha256(Path(__file__).with_name('phase5ds_report.py')),
                  data_sha256=file_sha256(out/'data'/f'{name}.csv'),
                  png_sha256=file_sha256(out/f'{name}.png'),
                  pdf_sha256=file_sha256(out/f'{name}.pdf'))
    (out/'meta'/f'{name}.json').write_text(json.dumps(metadata,indent=2,sort_keys=True)+'\n')


def _axis(ax,x,y,title,unit=None):
    ax.set(xlabel=x,ylabel=y,title=title)
    ax.grid(alpha=.25)
    ax.spines[['top','right']].set_visible(False)
    if unit:
        ax.ticklabel_format(axis='y',style='plain',useOffset=False)


def _meta(source_hashes,experiment,x,y,interpretation,sgx=False):
    return dict(experiment=experiment,x_variable=x,y_variable=y,
        aggregation='canonical median unless structural',source_hashes=source_hashes,
        interpretation=interpretation,trust_cohort=SGX_FOOT if sgx else
        'COMMON_BACKEND_OR_INTERNAL_EMULATED_ABLATION')


def _old_rows(old,source):
    return [dict(ell=r['config']['ell'],cmax=r['config'].get('cmax',1),
        scheme=r['scheme'],metric=r['metric'],median=r['median'],
        p95=r['p95'],n=r['n']) for r in old[source]]


def occurrence_figures(out,old):
    hashes=old['hashes']; rows=_old_rows(old,'ablation')
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    repeated=design()[4][1]
    labels=[chr(64+code) for code in repeated.row_codes]
    ranks=list(repeated.occurrence_ranks)
    for ax,mode in zip(axes,('ROW','OCCURRENCE')):
        ax.axis('off'); ax.set_xlim(0,1);ax.set_ylim(0,6)
        ax.set_title('NoOccurrenceReuse' if mode=='ROW' else 'MyABE occurrence-aware')
        for i,(label,rank) in enumerate(zip(labels,ranks)):
            dest=f'D{i+1}' if mode=='ROW' else f'D{rank}'
            ax.text(.1,5-i,f'row {i+1}: {label}',va='center')
            ax.annotate(dest,xy=(.82,5-i),xytext=(.52,5-i),va='center',
                arrowprops=dict(arrowstyle='->',lw=1.2))
        ax.text(.1,.1,(f'#D = ell = {repeated.ell}' if mode=='ROW' else
                        f'#D = cmax = {max(ranks)}'),weight='bold')
    fig.text(.5,-.03,'Rows share a random component by occurrence rank rather than carrying one independent D component per policy row.',ha='center',fontsize=9)
    _save(out,'FIG_OCCURRENCE_MECHANISM_EXPLAINED',fig,
        [dict(row=i+1,attribute=labels[i],rank=ranks[i],no_occurrence_d=i+1,
              myabe_d=ranks[i]) for i in range(5)],
        _meta(hashes,'5D-R internal ablation','policy row','D component','structural mechanism'))

    component=[r for r in rows if r['metric']=='g2_count']
    fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
    for cmax in sorted(set(r['cmax'] for r in component)):
        for scheme,style in (('OCCURRENCE','-'),('ROW','--')):
            subset=sorted((r for r in component if r['cmax']==cmax and r['scheme']==scheme),key=lambda r:r['ell'])
            ax.plot([r['ell'] for r in subset],[r['median'] for r in subset],style,
                color=COLORS[scheme],alpha=.55+.07*cmax/8,marker='o',ms=3,
                label=f"{'MyABE' if scheme=='OCCURRENCE' else 'NoOccurrenceReuse'} cmax={cmax}")
    _axis(ax,'Policy rows ell','G2 D components','Shared occurrence slots vs per-row components')
    ax.legend(fontsize=7,ncol=2)
    _save(out,'FIG_OCCURRENCE_COMPONENT_SAVING',fig,component,
        _meta(hashes,'5D-R internal ablation','ell','G2 count','MyABE #D=cmax; ablation #D=ell'))

    ct=[{key:float(value) if key not in ('ell','distinct','actual_cmax','comparability','n_constructions_per_arm') else value
         for key,value in r.items()} for r in old['full_ct']]
    for r in ct:
        for key in ('ell','distinct','actual_cmax','n_constructions_per_arm'):
            r[key]=int(r[key])
    fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
    for c in sorted(set(r['actual_cmax'] for r in ct)):
        subset=sorted((r for r in ct if r['actual_cmax']==c),key=lambda r:r['ell'])
        ax.plot([r['ell'] for r in subset],[r['reduction_percent'] for r in subset],
                marker='o',label=f'cmax={c}')
    _axis(ax,'Policy rows ell','Canonical full CT reduction (%)','Full signed CT size reduction vs ablation')
    ax.legend(fontsize=8)
    _save(out,'FIG_OCCURRENCE_CT_SAVING_PERCENT',fig,ct,
        _meta(hashes,'5D-R size-only matched constructions','ell','CT reduction %',
            'One paired construction per arm; separate TEST encoding markers '
            'also contribute to wire bytes; no timing inference'))

    for metric,name,title in (('encrypt_ns','FIG_OCCURRENCE_ENCRYPT_RATIO','Encrypt'),
        ('transform_ns','FIG_OCCURRENCE_TRANSFORM_RATIO','Transform')):
        values={}
        for r in rows:
            if r['metric']==metric:
                values[(r['ell'],r['cmax'],r['scheme'])]=r['median']
        ratio=[dict(ell=ell,cmax=c,ratio=values[(ell,c,'OCCURRENCE')]/
                values[(ell,c,'ROW')],myabe_ns=values[(ell,c,'OCCURRENCE')],
                ablation_ns=values[(ell,c,'ROW')])
            for ell,c,_ in sorted(set((e,k,s) for e,k,s in values))
            if (ell,c,'OCCURRENCE') in values and (ell,c,'ROW') in values]
        # De-duplicate because both scheme keys are traversed above.
        ratio=list({(r['ell'],r['cmax']):r for r in ratio}.values())
        fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
        for c in sorted(set(r['cmax'] for r in ratio)):
            subset=sorted((r for r in ratio if r['cmax']==c),key=lambda r:r['ell'])
            ax.plot([r['ell'] for r in subset],[r['ratio'] for r in subset],marker='o',label=f'cmax={c}')
        ax.axhline(1,color='black',lw=1,ls=':')
        _axis(ax,'Policy rows ell','MyABE / NoOccurrence median',f'{title} ratio (<1: MyABE lower)')
        ax.legend(fontsize=8)
        _save(out,name,fig,ratio,_meta(hashes,'5D-R internal ablation','ell','median ratio',
            'Values above and below one retained'))

    fig,ax=plt.subplots(figsize=(6,2.5),layout='constrained');ax.axis('off')
    ax.text(.05,.70,'MyABE: #D = cmax',fontsize=17,color=BLUE)
    ax.text(.05,.40,'NoOccurrenceReuse: #D = ell',fontsize=17,color=GRAY)
    ax.text(.05,.10,'Even cmax=1 shares one global D slot across all rows.',fontsize=10)
    _save(out,'FIG_OCCURRENCE_STRUCTURE_CARD',fig,
        [dict(configuration='ABACA',ell=repeated.ell,cmax=max(ranks),
              myabe_d=max(ranks),ablation_d=repeated.ell)],
        _meta(hashes,'5D-R structural ablation','ell','D count','global rank-slot sharing'))


def fabeo_figures(out,old):
    hashes=old['hashes']; rows=_old_rows(old,'core')
    metrics=[('keygen_ns','KeyGen','FIG_CORE_KEYGEN_ABSOLUTE','ms',1e6),
        ('encrypt_ns','Encrypt','FIG_CORE_ENCRYPT_ABSOLUTE','ms',1e6),
        ('access_ns','Authorized access','FIG_CORE_ACCESS_ABSOLUTE','ms',1e6),
        ('ct_group_bytes','Core CT group','FIG_CORE_STORAGE_ABSOLUTE','bytes',1)]
    pairs={}
    for r in rows:
        pairs[(r['ell'],r['metric'],r['scheme'])]=r
    for metric,title,name,unit,scale in metrics:
        subset=[r for r in rows if r['metric']==metric]
        fig,ax=plt.subplots(figsize=(7,4),layout='constrained')
        for scheme,label in (('MYABE08_BLS12381_CORE','MyABE core'),
                             ('FABEO22_CP_BLS12381_TAU1','FABEO tau=1')):
            s=sorted((r for r in subset if r['scheme']==scheme),key=lambda r:r['ell'])
            ax.plot([r['ell'] for r in s],[r['median']/scale for r in s],
                marker='o',color=COLORS[scheme],label=label)
        _axis(ax,'Policy rows ell',f'Median ({unit})',title+' · common BLS12-381')
        ax.legend()
        _save(out,name,fig,subset,_meta(hashes,'5D-R common-backend tau=1','ell',
            f'{metric} ({unit})','ABE core only; no full-system inference'))
    ratio=[]
    for ell in sorted(set(r['ell'] for r in rows)):
        for metric in ('keygen_ns','encrypt_ns','access_ns','ct_group_bytes',
                       'du_core_key_bytes'):
            mine=pairs[(ell,metric,'MYABE08_BLS12381_CORE')]['median']
            base=pairs[(ell,metric,'FABEO22_CP_BLS12381_TAU1')]['median']
            ratio.append(dict(ell=ell,metric=metric,myabe=mine,fabeo=base,
                              ratio=mine/base))
    fig,axes=plt.subplots(2,3,figsize=(11,6),layout='constrained')
    for ax,metric in zip(axes.flat,('keygen_ns','encrypt_ns','access_ns',
                                   'ct_group_bytes','du_core_key_bytes')):
        s=[r for r in ratio if r['metric']==metric]
        ax.plot([r['ell'] for r in s],[r['ratio'] for r in s],marker='o',color=BLUE)
        ax.axhline(1,ls=':',color='black',lw=1)
        _axis(ax,'ell','MyABE / FABEO',metric.replace('_',' '))
        if metric == 'encrypt_ns':
            ax.set_ylim(0.8, 1.2)
            ax.set_yticks([0.8, 0.9, 1.0, 1.1, 1.2])
    axes.flat[-1].axis('off')
    fig.suptitle('Common-backend tau=1 ratios · <1 means lower measured cost/size')
    _save(out,'FIG_MYABE_FABEO_RATIO',fig,ratio,
        _meta(hashes,'5D-R common-backend tau=1','ell','MyABE/FABEO ratio',
            'Core access disadvantage visible; DU key is placement trade-off'))
    placement=[r for r in rows if r['ell']==100 and r['metric'] in
               ('du_core_key_bytes','tee_core_key_bytes')]
    fig,ax=plt.subplots(figsize=(6,4),layout='constrained')
    for i,scheme in enumerate(('MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1')):
        du=next(r['median'] for r in placement if r['scheme']==scheme and r['metric']=='du_core_key_bytes')
        tee=next(r['median'] for r in placement if r['scheme']==scheme and r['metric']=='tee_core_key_bytes')
        ax.bar(i-.18,du,width=.35,color=COLORS[scheme],label='DU' if i==0 else None)
        ax.bar(i+.18,tee,width=.35,color=GRAY,label='TEE' if i==0 else None)
    ax.set_xticks((0,1),('MyABE','FABEO'))
    _axis(ax,'Scheme','Core key/state bytes','Key placement at ell=100')
    ax.legend()
    _save(out,'FIG_KEY_PLACEMENT',fig,placement,
        _meta(hashes,'5D-R common-backend tau=1','role','bytes',
            'MyABE DU 32-byte scalar coexists with 128-byte TEE-side core state'))


def paired_figures(out,run,summary):
    source={str(run/name):file_sha256(run/name) for name in
            ('raw.jsonl','PHASE5D_S_PLAN.json','COMPLETION.json',
             'CODE_MANIFEST.json','SOURCE_MANIFEST.json')}
    sgx=True
    configs=sorted(set((r['configuration_id'],r['workload_name'],r['ell'])
                       for r in summary),key=lambda x:(x[2],x[1]))
    names=[name for _,name,_ in configs]
    lookup={(r['configuration_id'],r['profile'],r['metric']):r
            for r in summary}
    for metric,name,title in (('encrypt_ns','FIG_MYABE_CORE_FULL_ENCRYPT',
                               'Core to full Encrypt'),
        ('request_e2e_ns','FIG_MYABE_CORE_FULL_ACCESS','Core to full access')):
        plotted=[]; fig,ax=plt.subplots(figsize=(11,4.4),layout='constrained')
        for i,profile in enumerate(('CORE','FULL_EMULATED','FULL_REAL_SGX')):
            values=[]
            for config_id,workload,ell in configs:
                actual_metric='access_ns' if profile=='CORE' and metric=='request_e2e_ns' else metric
                row=lookup[(config_id,profile,actual_metric)]
                values.append(row['median']/1e6)
                plotted.append(dict(configuration_id=config_id,workload=workload,
                    ell=ell,profile=profile,metric=actual_metric,
                    median_ns=row['median'],p95_ns=row['p95'],
                    boundary=('exclusive stage sum; not contiguous wall clock'
                        if profile=='CORE' and metric=='request_e2e_ns'
                        else 'public wall-clock span')))
            x=np.arange(len(configs))+.22*(i-1)
            ax.bar(x,values,width=.21,label=profile.replace('_',' '),
                   color=COLORS[profile])
        ax.set_xticks(np.arange(len(configs)),names,rotation=30,ha='right')
        _axis(ax,'Matched structural workload','Median latency (ms)',title)
        ax.legend(fontsize=8)
        if metric=='request_e2e_ns':
            fig.text(.5,-.04,'CORE is an exclusive stage sum; it is not a contiguous E2E wall-clock ratio.',ha='center',fontsize=9)
        fig.text(.5,-.10,SGX_FOOT,ha='center',fontsize=8,color=PURPLE)
        _save(out,name,fig,plotted,_meta(source,'5D-S paired workload','workload',
            'median latency (ms)','Matched structure; access timing boundaries differ',sgx))

    # Cost placement uses actual measured spans as grouped, non-additive observations.
    placement=[]
    for config_id,workload,ell in configs:
        if ell not in (10,40,80): continue
        for profile in ('FULL_EMULATED','FULL_REAL_SGX'):
            for role,metric in (('DO/Encrypt','encrypt_ns'),('Authorize path','teeauthorize_ns'),
                                ('CSP/Transform','transform_ns'),('DU/FinalDec','finaldec_ns')):
                row=lookup[(config_id,profile,metric)]
                placement.append(dict(workload=workload,ell=ell,profile=profile,
                    role=role,metric=metric,median_ns=row['median'],
                    scope='HOST_SPAN_INCLUDES_RPC_AND_ENCLAVE' if
                        role=='Authorize path' else 'PUBLIC_ALGORITHM_SPAN'))
    fig,axes=plt.subplots(1,3,figsize=(12,4),layout='constrained')
    for ax,ell in zip(axes,(10,40,80)):
        subset=[r for r in placement if r['ell']==ell]
        roles=['DO/Encrypt','Authorize path','CSP/Transform','DU/FinalDec']
        for i,profile in enumerate(('FULL_EMULATED','FULL_REAL_SGX')):
            s=[next(r['median_ns']/1e6 for r in subset if r['role']==role and
                    r['profile']==profile) for role in roles]
            ax.bar(np.arange(4)+.36*(i-.5),s,width=.34,color=COLORS[profile],
                   label=profile.replace('_',' ') if ell==10 else None)
        ax.set_xticks(np.arange(4),('DO','Auth','CSP','DU'))
        _axis(ax,'Execution role','Median span (ms)',f'ell={ell}')
    axes[0].legend(fontsize=7)
    fig.suptitle('Observed role costs · grouped, not stacked')
    fig.text(.5,-.04,'Authorize is a host span including RPC and enclave; not pure TEE time. '+SGX_FOOT,
             ha='center',fontsize=8,color=PURPLE)
    _save(out,'FIG_MYABE_COST_PLACEMENT',fig,placement,
        _meta(source,'5D-S paired workload','role','median ms',
            'Role spans are non-additive observations',sgx))

    # A single representative workload makes the component semantics legible.
    config_id,workload,ell=next(x for x in configs if x[2]==10)
    buckets=(('ABE core','encrypt_encrypt_core_ns'),
        ('Anon tokenization','encrypt_policy_token_ns'),
        ('AF build','encrypt_af_build_ns'),
        ('Capability/publication','encrypt_publication_sign_ns'),
        ('Publication other','encrypt_publication_other_ns'),
        ('DEM','encrypt_dem_encrypt_ns'),
        ('Revocation check','authorize_revset_lookup_ns'),
        ('TEE credential','authorize_credential_verify_ns'),
        ('TEE tokenization','authorize_tokenization_ns'),
        ('TEE rerandomization','authorize_rerandomization_ns'),
        ('TEE T0 pairing','authorize_t0_pairing_ns'),
        ('TEE cap sign','authorize_cap_sign_ns'),
        ('AF query','transform_af_query_ns'),
        ('CSP T_A','transform_t_a_ns'),
        ('DU crypto','finaldec_finaldec_crypto_ns'),
        ('DU DEM','finaldec_dem_decrypt_ns'),
        ('RPC send','authorize_rpc_send_ns'),
        ('RPC receive','authorize_rpc_receive_ns'))
    breakdown=[]
    for profile in ('FULL_EMULATED','FULL_REAL_SGX'):
        for label,metric in buckets:
            record=lookup.get((config_id,profile,metric))
            if record:
                breakdown.append(dict(workload=workload,profile=profile,
                    bucket=label,metric=metric,median_ns=record['median'],
                    additivity='NON_ADDITIVE_OBSERVATION' if 'rpc_' in metric else
                    'EXCLUSIVE_NESTED_STAGE'))
    fig,ax=plt.subplots(figsize=(10,6),layout='constrained')
    labels=list(dict.fromkeys(r['bucket'] for r in breakdown))
    for i,profile in enumerate(('FULL_EMULATED','FULL_REAL_SGX')):
        s=[next((r['median_ns']/1e6 for r in breakdown if r['profile']==profile and
                 r['bucket']==label),0) for label in labels]
        ax.barh(np.arange(len(labels))+.36*(i-.5),s,height=.34,
            color=COLORS[profile],label=profile.replace('_',' '))
    ax.set_yticks(np.arange(len(labels)),labels)
    _axis(ax,'Median stage latency (ms)','Stage','Feature cost observations · ell=10')
    ax.legend(fontsize=8)
    fig.text(.5,-.04,'RPC receive overlaps enclave work; bars must not be summed. '+SGX_FOOT,
             ha='center',fontsize=8,color=PURPLE)
    _save(out,'FIG_FEATURE_COST_BREAKDOWN',fig,breakdown,
        _meta(source,'5D-S paired workload','stage','median ns',
            'Stage observations; RPC receive and enclave execution overlap',sgx))

    # Byte scopes are explicit. CORE algebra group bytes are not a full wire CT.
    storage=[]
    for config_id,workload,ell in configs:
        for profile in ('CORE','FULL_EMULATED','FULL_REAL_SGX'):
            for metric in (('core_group_bytes',) if profile=='CORE' else
                ('ct_total_bytes','auth_bytes','ctprime_bytes')):
                row=lookup[(config_id,profile,metric)]
                storage.append(dict(workload=workload,ell=ell,profile=profile,
                    metric=metric,median_bytes=row['median'],
                    scope='ALGEBRA_GROUP_COMPONENTS' if profile=='CORE' else
                    'CANONICAL_PUBLIC_WIRE'))
    fig,axes=plt.subplots(1,2,figsize=(12,4),layout='constrained')
    core=[r for r in storage if r['metric']=='core_group_bytes']
    axes[0].bar(range(len(core)),[r['median_bytes'] for r in core],color=DARK)
    axes[0].set_xticks(range(len(core)),[r['workload'] for r in core],rotation=35,ha='right')
    _axis(axes[0],'Workload','Group bytes','Core algebra components')
    for profile in ('FULL_EMULATED','FULL_REAL_SGX'):
        s=[next(r['median_bytes'] for r in storage if r['workload']==w and
                r['profile']==profile and r['metric']=='ct_total_bytes')
           for w in names]
        axes[1].plot(range(len(names)),s,marker='o',color=COLORS[profile],
                     label=profile.replace('_',' '))
    axes[1].set_xticks(range(len(names)),names,rotation=35,ha='right')
    _axis(axes[1],'Workload','Wire bytes','Full signed CT')
    axes[1].legend(fontsize=8)
    fig.text(.5,-.04,'Different byte scopes: do not divide Core group bytes by full signed CT bytes. '+SGX_FOOT,
             ha='center',fontsize=8,color=PURPLE)
    _save(out,'FIG_MYABE_PAIRED_STORAGE',fig,storage,
        _meta(source,'5D-S paired workload','workload','bytes',
            'Core group vs full wire is not a same-scope storage ratio',sgx))

    communication=[]
    for config_id,workload,ell in configs:
        for metric in ('authorize_rpc_send_bytes','authorize_rpc_receive_bytes'):
            row=lookup.get((config_id,'FULL_REAL_SGX',metric))
            if row:
                communication.append(dict(workload=workload,ell=ell,
                    profile='FULL_REAL_SGX',metric=metric,
                    median_bytes=row['median']))
    if communication:
        fig,ax=plt.subplots(figsize=(10,4),layout='constrained')
        for i,metric in enumerate(('authorize_rpc_send_bytes',
                                   'authorize_rpc_receive_bytes')):
            values=[next(r['median_bytes'] for r in communication if
                         r['workload']==name and r['metric']==metric)
                    for name in names]
            ax.bar(np.arange(len(names))+.36*(i-.5),values,width=.34,
                label='request frame' if i==0 else 'response frame',
                color=PURPLE if i==0 else TEAL)
        ax.set_xticks(np.arange(len(names)),names,rotation=35,ha='right')
        _axis(ax,'Workload','RPC frame bytes','SGX TEEAuthorize communication')
        ax.legend(fontsize=8)
        fig.text(.5,-.04,'No Core/Emulated RPC byte counterpart; no communication-overhead ratio. '+SGX_FOOT,
                 ha='center',fontsize=8,color=PURPLE)
        _save(out,'FIG_MYABE_COMMUNICATION_PROFILE',fig,communication,
            _meta(source,'5D-S real SGX feasibility','workload','RPC frame bytes',
                'Observed TEEAuthorize frame size only',sgx))


def matrix_and_dashboard(out,old,summary,run):
    hashes=dict(old['hashes'])
    for name in ('raw.jsonl','PHASE5D_S_PLAN.json','COMPLETION.json'):
        hashes[str(run/name)]=file_sha256(run/name)
    abl=old['ablation']; core=old['core']
    def val(records,scheme,metric,ell,cmax=1):
        return next(r['median'] for r in records if r['scheme']==scheme and
                    r['metric']==metric and r['config']['ell']==ell and
                    r['config']['cmax']==cmax)
    ct160=next(r for r in old['full_ct'] if int(r['ell'])==160 and
               int(r['actual_cmax'])==1)
    paired_lookup={(r['workload_name'],r['profile'],r['metric']):r['median']
                    for r in summary}
    w1_core=paired_lookup[('W1-AND-10','CORE','encrypt_ns')]
    w1_full=paired_lookup[('W1-AND-10','FULL_EMULATED','encrypt_ns')]
    def item(metric,comparison,mine,reference,interpretation):
        return dict(metric=metric,comparison=comparison,myabe_result=mine,
                    reference=reference,interpretation=interpretation)
    rows=[
        item('Occurrence D','ablation ell=160',
            val(abl,'OCCURRENCE','g2_count',160),
            val(abl,'ROW','g2_count',160),'STRUCTURAL_ADVANTAGE'),
        item('Full CT bytes','ablation ell=160',
            int(ct160['occurrence_full_ct_bytes']),
            int(ct160['row_full_ct_bytes']),'SUPPORTED_ADVANTAGE'),
        item('Encrypt median ms','ablation ell=160',
            round(val(abl,'OCCURRENCE','encrypt_ns',160)/1e6,3),
            round(val(abl,'ROW','encrypt_ns',160)/1e6,3),'SUPPORTED_ADVANTAGE'),
        item('Transform median ms','ablation ell=160',
            round(val(abl,'OCCURRENCE','transform_ns',160)/1e6,3),
            round(val(abl,'ROW','transform_ns',160)/1e6,3),'SUPPORTED_ADVANTAGE'),
        item('KeyGen median ms','FABEO ell=100',
            round(val(core,'MYABE08_BLS12381_CORE','keygen_ns',100)/1e6,3),
            round(val(core,'FABEO22_CP_BLS12381_TAU1','keygen_ns',100)/1e6,3),
            'SUPPORTED_ADVANTAGE'),
        item('Encrypt median ms','FABEO ell=100',
            round(val(core,'MYABE08_BLS12381_CORE','encrypt_ns',100)/1e6,3),
            round(val(core,'FABEO22_CP_BLS12381_TAU1','encrypt_ns',100)/1e6,3),
            'ROUGHLY_COMPARABLE'),
        item('Access median ms','FABEO ell=100',
            round(val(core,'MYABE08_BLS12381_CORE','access_ns',100)/1e6,3),
            round(val(core,'FABEO22_CP_BLS12381_TAU1','access_ns',100)/1e6,3),
            'SUPPORTED_TRADEOFF'),
        item('Core CT group B','FABEO ell=100',
            val(core,'MYABE08_BLS12381_CORE','ct_group_bytes',100),
            val(core,'FABEO22_CP_BLS12381_TAU1','ct_group_bytes',100),
            'STRUCTURAL_ADVANTAGE'),
        item('DU local core B','FABEO ell=100',
            val(core,'MYABE08_BLS12381_CORE','du_core_key_bytes',100),
            val(core,'FABEO22_CP_BLS12381_TAU1','du_core_key_bytes',100),
            'STRUCTURAL_ADVANTAGE (TEE state +%d B)' %
            val(core,'MYABE08_BLS12381_CORE','tee_core_key_bytes',100)),
        item('Full Encrypt ms','Core W1-AND-10',
            round(w1_full/1e6,3),round(w1_core/1e6,3),
            ('SUPPORTED_TRADEOFF' if w1_full>w1_core else 'ROUGHLY_COMPARABLE')+
            ' (feature boundary)'),
        item('Full access ratio','Core stage sum',
            'undefined','undefined','NOT_DIRECTLY_COMPARABLE')]
    fig,ax=plt.subplots(figsize=(13,6),layout='constrained');ax.axis('off')
    table=ax.table(cellText=[[r['metric'],r['comparison'],r['myabe_result'],
                              r['reference'],r['interpretation']] for r in rows],
        colLabels=('Metric','Comparison','MyABE result','Reference','Interpretation'),
        loc='center',cellLoc='left',colWidths=(.19,.18,.15,.15,.33))
    table.auto_set_font_size(False);table.set_fontsize(7);table.scale(1,1.6)
    ax.set_title('Measured advantages and trade-offs · no overall score',pad=15)
    fig.text(.5,-.04,SGX_FOOT,ha='center',fontsize=8,color=PURPLE)
    _save(out,'FIG_ADVANTAGE_TRADEOFF_MATRIX',fig,rows,
        _meta(hashes,'5D-R + 5D-S','metric','category','comparability categories',True))

    paper=Path(__file__).with_name('BASELINE_PAPER_AUDIT.md')
    architecture=[
        dict(scheme='MyABE-08',role='TEE',stage='Credential, RevSet, T0, cap'),
        dict(scheme='MyABE-08',role='CSP',stage='AF.Query, LSSS, T_A'),
        dict(scheme='MyABE-08',role='DU',stage='FinalDec, DEM'),
        dict(scheme='HR-ABE paper',role='CSP',stage='Transform1'),
        dict(scheme='HR-ABE paper',role='TEE',stage='Signed state, RK open, Transform2'),
        dict(scheme='HR-ABE paper',role='DU',stage='Final decrypt')]
    fig,ax=plt.subplots(figsize=(10,3.3),layout='constrained')
    ax.set_xlim(0,3);ax.set_ylim(-.5,1.7);ax.axis('off')
    for y,scheme,color in ((1,'MyABE-08',BLUE),(0,'HR-ABE paper',GRAY)):
        ax.text(-.05,y+.38,scheme,ha='right',fontsize=10,weight='bold')
        roles=('TEE','CSP','DU') if scheme=='MyABE-08' else ('CSP','TEE','DU')
        for x,role in enumerate(roles):
            stage=next(r['stage'] for r in architecture if r['scheme']==scheme and
                       r['role']==role)
            ax.text(x+.48,y+.1,f'{role}\n{stage}',ha='center',va='center',
                fontsize=8,bbox=dict(boxstyle='round,pad=.4',facecolor=color,
                                     alpha=.15,edgecolor=color))
            if x<2: ax.annotate('',xy=(x+.90,y+.1),xytext=(x+.78,y+.1),
                                 arrowprops=dict(arrowstyle='->',lw=1))
    ax.set_title('TEE revocable architecture reference · stages only, no timing')
    _save(out,'FIG_TEE_REVOCABLE_ARCHITECTURE_REFERENCE',fig,architecture,
        _meta(dict(hashes,**{str(paper):file_sha256(paper)}),
            '5D-R paper architecture reference','role','stage',
            'HR-ABE is BLOCKED_TYPE_MAPPING; no local latency comparison'))

    fig,axes=plt.subplots(2,3,figsize=(13,8),layout='constrained')
    ax=axes[0,0];ax.bar(('MyABE','NoOccurrence'),(
        val(abl,'OCCURRENCE','g2_count',80),
        val(abl,'ROW','g2_count',80)),color=(BLUE,GRAY))
    _axis(ax,'Scheme','D components','A · ell=80, cmax=1')
    ax=axes[0,1];ct=[r for r in old['full_ct'] if int(r['actual_cmax'])==1]
    ax.plot([int(r['ell']) for r in ct],[float(r['reduction_percent']) for r in ct],marker='o',color=BLUE)
    _axis(ax,'ell','CT reduction (%)','B · Canonical full CT')
    ax=axes[0,2];x=(10,40,80,160)
    for metric,label in (('encrypt_ns','Encrypt'),('transform_ns','Transform')):
        ax.plot(x,[val(abl,'OCCURRENCE',metric,e)/val(abl,'ROW',metric,e)
                   for e in x],marker='o',label=label)
    ax.axhline(1,color='black',ls=':');ax.legend(fontsize=8)
    _axis(ax,'ell','MyABE / ablation','C · Occurrence timing ratio')
    ax=axes[1,0]
    for metric,label in (('keygen_ns','KeyGen'),('encrypt_ns','Encrypt'),
                         ('access_ns','Access')):
        ax.plot((10,40,80,100),[val(core,'MYABE08_BLS12381_CORE',metric,e)/
            val(core,'FABEO22_CP_BLS12381_TAU1',metric,e) for e in (10,40,80,100)],
            marker='o',label=label)
    ax.axhline(1,color='black',ls=':');ax.legend(fontsize=8)
    _axis(ax,'ell','MyABE / FABEO','D · Common-backend core')
    ax=axes[1,1];lookup={(r['workload_name'],r['profile'],r['metric']):r['median']
                           for r in summary}
    workloads=[r['workload_name'] for r in summary if r['profile']=='CORE'
               and r['metric']=='encrypt_ns']
    workloads=list(dict.fromkeys(workloads))
    for profile in ('CORE','FULL_EMULATED','FULL_REAL_SGX'):
        ax.plot(np.arange(len(workloads)),[lookup[(w,profile,'encrypt_ns')]/1e6
            for w in workloads],marker='o',label=profile.replace('_',' '),
            color=COLORS[profile])
    ax.set_xticks(np.arange(len(workloads)),
                  [w.split('-',1)[1] for w in workloads],rotation=35,ha='right')
    ax.legend(fontsize=6)
    _axis(ax,'Workload','Encrypt median (ms)','E · Paired core-to-full')
    ax=axes[1,2];du=(val(core,'MYABE08_BLS12381_CORE','du_core_key_bytes',100),
        val(core,'FABEO22_CP_BLS12381_TAU1','du_core_key_bytes',100))
    tee=(val(core,'MYABE08_BLS12381_CORE','tee_core_key_bytes',100),0)
    x=np.arange(2);ax.bar(x-.18,du,width=.35,label='DU',color=BLUE)
    ax.bar(x+.18,tee,width=.35,label='TEE',color=GRAY)
    ax.set_xticks(x,('MyABE','FABEO'));ax.legend(fontsize=8)
    _axis(ax,'Scheme','Core key/state bytes','F · Key placement')
    fig.suptitle('My-ABE: Measured Benefits and Costs',fontsize=16)
    fig.text(.5,-.02,'Same-backend ablation and FABEO core comparison; paired full-system feature measurements. '+SGX_FOOT,
             ha='center',fontsize=8)
    _save(out,'MYABE_ADVANTAGE_TRADEOFF_DASHBOARD_V2',fig,
        [dict(panel=x) for x in ('occurrence_components','CT_reduction',
        'ablation_ratio','FABEO_core_ratio','paired_encrypt','key_placement')],
        _meta(hashes,'5D-R + 5D-S','multiple','multiple','descriptive dashboard',True))


def generate(run: Path, output: Path):
    checked,raw,summary=paired_summary(run)
    old=sources()
    output.mkdir(parents=True,exist_ok=False)
    with (output/'paired_statistics.csv').open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(summary[0]))
        writer.writeheader();writer.writerows(summary)
    (output/'VALIDATION.json').write_text(json.dumps(dict(checked,
        old_ablation=old['validation']['ablation'],
        old_core=old['validation']['core'],
        paired_statistics_sha256=file_sha256(output/'paired_statistics.csv')),
        sort_keys=True,indent=2)+'\n')
    occurrence_figures(output,old)
    fabeo_figures(output,old)
    paired_figures(output,run,summary)
    matrix_and_dashboard(output,old,summary,run)
    index=[]
    for meta_path in sorted((output/'meta').glob('*.json')):
        metadata=json.loads(meta_path.read_text())
        name=metadata['figure']
        png=output/(name+'.png');pdf=output/(name+'.pdf')
        if (png.read_bytes()[:8]!=b'\x89PNG\r\n\x1a\n' or
            pdf.read_bytes()[:4]!=b'%PDF' or
            file_sha256(output/'data'/(name+'.csv'))!=metadata['data_sha256']):
            raise ValueError('figure format/source hash validation failed: '+name)
        index.append(dict(figure=name,experiment=metadata['experiment'],
            png=png.name,pdf=pdf.name,source_data='data/'+name+'.csv',
            metadata='meta/'+name+'.json',interpretation=metadata['interpretation']))
    (output/'FIGURE_INDEX.json').write_text(json.dumps(index,sort_keys=True,indent=2)+'\n')
    lines=['# Phase 5D-S comparative figure index','',
        'All figures are descriptive. Real SGX means DEBUG/QVL OUT_OF_DATE/',
        'strict RA2 BLOCKED feasibility measurements.','',
        '| Figure | Experiment | Reading boundary |','|---|---|---|']
    for row in index:
        lines.append(f"| [{row['figure']}]({row['png']}) | {row['experiment']} | {row['interpretation']} |")
    (output/'README_FIGURES.md').write_text('\n'.join(lines)+'\n')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    print(generate(args.run,args.output))


if __name__=='__main__':
    main()
