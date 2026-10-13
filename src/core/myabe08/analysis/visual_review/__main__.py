"""Generate researcher-facing plots from validated, frozen analysis bundles."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from ..core import REPO, load_frozen, sha256_file
from ..report import verify_bundle
from ...experiments.phase5c import validate_run
from ...experiments.phase5c_report import verify as verify_phase5c


ROOT = REPO / 'artifacts/myabe08'
B5 = ROOT / 'analysis/phase5b/20260926T061408Z-8bb066fbcd25'
C5 = ROOT / 'analysis/phase5c/20260926T134453Z-97db85981604'
A5 = ROOT / 'benchmarks/phase5a/revalidated-v2'
RUNS = {
    'Exp6': ROOT / 'benchmarks/phase5c/Exp6/SGX_DEBUG_GRAMINE_V1/20260926T094728Z-ba7e4c08e76c',
    'Exp7': ROOT / 'benchmarks/phase5c/Exp7/SGX_DEBUG_GRAMINE_V1/20260926T133402Z-d874ac0fa211',
}
FROZEN_CODE = '5de747a41d1dc01ee7ffac8cd7cac4d80beb3d70c1ce7aa0848de8fe6819912d'
FOOT = ('SGX_DEBUG_GRAMINE_V1  |  QVL: OUT_OF_DATE  |  Strict RA2: BLOCKED  |  '
        'Feasibility measurements only')
EXPERIMENTS = {'00':'Overview','01':'Overview','02':'Exp1','03':'Exp1','04':'Exp1',
               '05':'Exp3','06':'Exp3','07':'Exp4','08':'Exp4','09':'Exp4',
               '10':'Exp5','11':'Exp5','12':'Exp5','13':'Exp6','14':'Exp6',
               '15':'Exp6','16':'Exp6','17':'Exp6','18':'Exp7','19':'Exp7',
               '20':'Exp7','21':'Exp2'}
TITLES = {
    '00':'EXPERIMENT_OVERVIEW','01':'EXPERIMENT_PIPELINE',
    '02':'EXP1_ENCRYPT_SCALING','03':'EXP1_TRANSFORM_SCALING','04':'EXP1_PAIRING_STRUCTURE',
    '05':'EXP3_STORAGE_SCALING','06':'EXP3_STORAGE_BREAKDOWN',
    '07':'EXP4_TOKENIZATION_PROFILE_COMPARISON','08':'EXP4_BATCH_SCALING',
    '09':'EXP4_SGX_BREAKDOWN','10':'EXP5_E2E_SCALING',
    '11':'EXP5_CANDIDATE_SCALING','12':'EXP5_TI_SCALING',
    '13':'EXP6_REVSET_LOOKUP','14':'EXP6_UPDATE_SCALING','15':'EXP6_STATE_SIZE',
    '16':'EXP6_REQUEST_RATE','17':'EXP6_LOAD_LATENCY',
    '18':'EXP7_EVIDENCE_MATRIX','19':'EXP7_FRESH_COMPONENTS',
    '20':'EXP7_EQUALITY_LINKABILITY','21':'EXP2_BLOCKED',
}
CATEGORIES = {x:'CORE' for x in ('00','02','05','07','10','13','14','16','18')}
CATEGORIES.update({x:'DIAGNOSTIC' for x in ('01','04','09','21')})
CATEGORIES.update({x:'APPENDIX' for x in ('12','15','17','19')})
SGX = {'00','01','02','03','04','07','08','09','10','11','12','13','14','15','16','17','18','19','20'}
COLORS = plt.get_cmap('tab10').colors


def read_csv(path):
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def finite(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return float('nan')


def validate_inputs():
    """Validate exact frozen cohorts/bundles; never discover runs by glob."""
    for path in (A5, B5, C5, *RUNS.values()):
        if not path.is_dir():
            raise FileNotFoundError(path)
    loaded = load_frozen(A5)
    b = verify_bundle(B5)
    signatures = []
    for exp, path in RUNS.items():
        validate_run(path, require_current_code=False)
        m = read_json(path / 'manifest.json')
        if m['experiment'] != exp or m['status'] != 'COMPLETE' or m['code_tree_sha256'] != FROZEN_CODE:
            raise ValueError('noncanonical Phase 5C run')
        signatures.append(tuple(m[k] for k in ('code_tree_sha256','environment_fingerprint',
                                                'spec_sha256','plan_sha256')))
    if signatures[0] != signatures[1]:
        raise ValueError('Phase 5C run provenance mismatch')
    c = verify_phase5c(C5)
    return {'phase5a_cohorts':len(loaded['cohorts']), 'phase5b':b,
            'phase5c_runs':{k:v.name for k,v in RUNS.items()}, 'phase5c':c,
            'phase5c_provenance':signatures[0]}


def source_data():
    paths = {
        'e1': B5/'tables/table_exp1_results_data.csv',
        'e3': B5/'tables/table_exp3_storage_data.csv',
        'e4': B5/'tables/table_exp4_token_af_data.csv',
        'e4stage': B5/'figures/figure_Fig_Exp4_H_Enclave_Stages_data.csv',
        'e5': B5/'tables/table_exp5_scaling_data.csv',
        'e6': C5/'tables/table_exp6_revocation_scaling_data.csv',
        'e6load': C5/'tables/table_exp6_request_load_data.csv',
        'e6state': C5/'summary/EXP6_STATE_MEMORY.json',
        'e7fresh': C5/'tables/table_exp7_freshness_observations_data.csv',
        'e7eq': C5/'tables/table_exp7_equality_linkability_data.csv',
        'e7obs': C5/'summary/EXP7_OBSERVATIONS.json',
        'bmanifest': B5/'analysis_manifest.json',
        'cmanifest': C5/'analysis_manifest.json',
        'blimits': B5/'paper/LIMITATIONS_FOR_RESULTS.md',
        'e1paper': B5/'paper/RESULTS_EXP1.md',
    }
    data = {k:(read_json(p) if p.suffix=='.json' else
               p.read_text(encoding='utf-8') if p.suffix=='.md' else read_csv(p))
            for k,p in paths.items()}
    if 'Exp2 remains BLOCKED_COMMON_BACKEND' not in data['blimits']:
        raise ValueError('canonical Exp2 blocked status unavailable')
    return paths, data


def rows_for(fid, d):
    """Return precisely the plotted/labelled values, not new estimates."""
    if fid in ('00','21'):
        entries = [('Exp1','COMPLETE','ell / cmax / tI'),('Exp2','BLOCKED','audited common backend unavailable'),
                   ('Exp3','COMPLETE','ell / cmax / bytes'),('Exp4','COMPLETE','N / batch / L_hit'),
                   ('Exp5','COMPLETE','|J| / tI / N'),('Exp6','COMPLETE','|RL| / n_reg / request rate'),
                   ('Exp7','COMPLETE','transcript / equality / W')]
        return [dict(experiment=e,status=s,variables=v) for e,s,v in entries] if fid=='00' else [
            dict(experiment='Exp2',status='BLOCKED',reason='Common audited pairing/runtime backend unavailable',
                 comparison='No cross-curve timing comparison performed')]
    if fid=='01':
        return [dict(stage=a,phase=b) for a,b in [('Implementation','Phase 4E/F'),
            ('Correctness','Phase 4E/F'),('Benchmark','Phase 5A'),('Analysis','Phase 5B'),
            ('Revocation / privacy evidence','Phase 5C')]]
    if fid in ('02','03'):
        return [dict(r) for r in d['e1']]
    if fid=='04':
        if 'FinalDec pairings equal 0' not in d['e1paper']:
            raise ValueError('canonical FinalDec pairing statement unavailable')
        return [dict(r,FinalDec_pairings=0) for r in d['e1']]
    if fid in ('05','06'):
        if fid=='05':return [dict(r) for r in d['e3']]
        chosen = {(5,1),(40,1),(80,3),(160,1),(160,5)}
        return [dict(r) for r in d['e3'] if (int(r['ell']),int(r['cmax'])) in chosen]
    if fid=='07':
        return [dict(r) for r in d['e4'] if (int(r['ell']),int(r['N']),int(r['cmax']),
            int(r['actual_L_hit']))==(20,20,2,10)]
    if fid=='08':return [dict(r) for r in d['e4']]
    if fid=='09':return [dict(r) for r in d['e4stage']]
    if fid in ('10','11','12'):return [dict(r) for r in d['e5']]
    if fid in ('13','14'):return [dict(r) for r in d['e6']]
    if fid=='15':
        return [dict(kind='revset',**r) for r in d['e6']]+[
            dict(kind='registration',**r) for r in d['e6state']['registration']]
    if fid in ('16','17'):return [dict(r) for r in d['e6load']]
    if fid=='18':
        obs=d['e7obs']; audit=obs['canary_audit']
        if audit['status']!='PASS' or audit['forbidden_value_hits']!=0:
            raise ValueError('Exp7 canary audit not clean')
        equality=obs['equality']; leak=obs['known_leakage']
        af=next(r for r in d['e7eq'] if r['relation']=='AF same-context matching')
        return [dict(surface=s,expected=e,observed=o) for s,e,o in [
            ('UID visible?','No','Not observed'),('rh_id visible?','No','Not observed'),
            ('K0 / mu visible?','No','Not observed'),('Stable Blob digest visible?','No','Not observed'),
            ('Same-context token equal?','Yes',f"{equality['same_context_equal_count']}/{equality['same_context_checks']} equal"),
            ('Cross-context direct equality?','No',f"{equality['direct_cross_context_equal_count']}/{equality['cross_context_checks']} equal"),
            ('Same-user same-CT W stable?','Known leakage',f"{leak['equality_count']}/{leak['same_user_same_ct_w_requests']} equal"),
            ('AF same-context hit?','Yes',f"{equality['same_context_af_success_count']}/{af['sample_count']} success")]]
    if fid=='19':return [dict(r) for r in d['e7fresh']]
    if fid=='20':return [dict(r) for r in d['e7eq'] if r['relation'] in (
        'same attribute/same context token','same attribute/different context token',
        'same user/same CT W','AF same-context matching')]
    raise KeyError(fid)


def sources_for(fid, p):
    keys = {'00':['bmanifest','cmanifest','blimits'],'01':['bmanifest','cmanifest'],
        '02':['e1'],'03':['e1'],'04':['e1','e1paper'],'05':['e3'],'06':['e3'],
        '07':['e4'],'08':['e4'],'09':['e4stage'],'10':['e5'],'11':['e5'],'12':['e5'],
        '13':['e6'],'14':['e6'],'15':['e6','e6state'],'16':['e6load'],'17':['e6load'],
        '18':['e7obs','e7eq'],'19':['e7fresh'],'20':['e7eq','e7obs'],
        '21':['blimits']}[fid]
    return [p[k] for k in keys]


def style_axis(ax, xlabel='', ylabel=''):
    ax.set_xlabel(xlabel); ax.set_ylabel(ylabel)
    ax.grid(axis='y', alpha=.23, linewidth=.7)
    ax.set_axisbelow(True)
    ax.tick_params(labelsize=9)


def plot(fid, rows):
    """Plot only rows returned by rows_for; no smoothing/interpolation."""
    fig, ax = plt.subplots(figsize=(9,5.2), constrained_layout=True)
    if fid=='00':
        y=np.arange(len(rows)); colors=['#bf5353' if r['status']=='BLOCKED' else '#4477aa' for r in rows]
        ax.barh(y,[1]*len(rows),color=colors,height=.65)
        ax.set_yticks(y,[r['experiment'] for r in rows]);ax.invert_yaxis();ax.set_xlim(0,1.6)
        ax.set_xticks([]);ax.set_xlabel('Experiment status and core variables')
        for i,r in enumerate(rows):ax.text(.03,i,r['status'],va='center',color='white',weight='bold',fontsize=9);ax.text(1.05,i,r['variables'],va='center',fontsize=9)
        ax.spines[['top','right','bottom']].set_visible(False)
    elif fid=='01':
        ax.set_xlim(-.5,4.5);ax.set_ylim(-.35,1.25);ax.axis('off')
        for i,r in enumerate(rows):
            ax.scatter(i,.65,s=1300,color='#4477aa',zorder=2)
            ax.text(i,.65,str(i+1),ha='center',va='center',color='white',weight='bold')
            ax.text(i,.28,r['stage'],ha='center',va='top',fontsize=9)
            ax.text(i,.05,r['phase'],ha='center',va='top',fontsize=8,color='#555555')
            if i<4:ax.annotate('',xy=(i+.75,.65),xytext=(i+.25,.65),arrowprops={'arrowstyle':'->','lw':1.5})
    elif fid in ('02','03'):
        field='Encrypt_median_ms' if fid=='02' else 'Transform_median_ms'
        for j,reg in enumerate(dict.fromkeys(r['repeat_regime'] for r in rows)):
            rr=sorted((r for r in rows if r['repeat_regime']==reg),key=lambda r:int(r['ell']))
            ax.plot([int(r['ell']) for r in rr],[finite(r[field]) for r in rr],marker='o',lw=1.8,label=reg.replace('_',' ').title(),color=COLORS[j])
        style_axis(ax,'Policy rows ell','Median latency (ms)');ax.legend(frameon=False,ncol=2,fontsize=8)
    elif fid=='04':
        by={int(r['tI']):r for r in rows}
        x=sorted(by)
        for j,(label,key) in enumerate([('TEE','TEE_pairings'),('CSP','CSP_pairings'),('System','system_pairings')]):
            ax.plot(x,[int(by[t][key]) for t in x],marker='o',lw=1.8,label=label,color=COLORS[j])
        ax.plot(x,[int(by[t]['FinalDec_pairings']) for t in x],marker='o',lw=1.5,label='FinalDec',color=COLORS[3])
        style_axis(ax,'Actual tI (attributes used)','Pairing operations (count)');ax.set_xticks(x);ax.legend(frameon=False)
    elif fid=='05':
        for j,c in enumerate(sorted({int(r['cmax']) for r in rows})):
            rr=sorted((r for r in rows if int(r['cmax'])==c),key=lambda r:int(r['ell']))
            ax.plot([int(r['ell']) for r in rr],[int(r['CT_total_bytes'])/1024 for r in rr],marker='o',lw=1.7,label=f'cmax={c}',color=COLORS[j])
        style_axis(ax,'Policy rows ell','Canonical CT size (KiB)');ax.legend(frameon=False,ncol=3,fontsize=8)
    elif fid=='06':
        rr=sorted(rows,key=lambda r:(int(r['ell']),int(r['cmax'])));x=np.arange(len(rr));bottom=np.zeros(len(rr))
        for j,(key,label) in enumerate([('CT_core_bytes','CT core'),('AF_bytes','AF'),('header_bytes','Header'),('DEM_bytes','DEM'),('publication_bytes','Publication')]):
            vals=np.array([int(r[key])/1024 for r in rr]);ax.bar(x,vals,bottom=bottom,label=label,color=COLORS[j]);bottom+=vals
        ax.set_xticks(x,[f"ell={r['ell']}\ncmax={r['cmax']}" for r in rr]);style_axis(ax,'Measured configuration','Canonical CT size (KiB)');ax.legend(frameon=False,ncol=5,fontsize=8,loc='upper center')
    elif fid=='07':
        rr=sorted(rows,key=lambda r:r['backend']);x=np.arange(len(rr));y=[finite(r['policy_token_median_ms']) for r in rr]
        ax.bar(x,y,color=[COLORS[0],COLORS[1]],width=.52)
        for i,r in enumerate(rr):ax.scatter(i,finite(r['policy_token_p95_ms']),marker='_',s=140,color='black',zorder=3)
        ax.set_xticks(x,['EMULATED' if 'EMULATED' in r['backend'] else 'REAL SGX DEBUG' for r in rr]);style_axis(ax,'Deployment profile','Policy tokenization latency (ms)')
        ax.text(.02,.97,'ell=N=20; cmax=2; actual L_hit=10\nBlack tick: p95',transform=ax.transAxes,va='top',fontsize=8)
    elif fid=='08':
        for panel,(key,title) in enumerate([('policy_token_median_ms','Policy-side'),('user_token_median_ms','User-side')]):
            a=ax if panel==0 else fig.add_subplot(122)
            if panel==0:ax.remove();a=fig.add_subplot(121)
            for j,backend in enumerate(['EMULATED_TEE_PROFILE','SGX_DEBUG_GRAMINE_V1']):
                rr=sorted((r for r in rows if r['backend']==backend),key=lambda r:int(r['batch_policy']))
                a.scatter([int(r['batch_policy'] if panel==0 else r['batch_user']) for r in rr],
                          [finite(r[key]) for r in rr],label='EMULATED' if j==0 else 'REAL SGX DEBUG',color=COLORS[j],s=38)
            style_axis(a,'Batch size (tokens)','Median latency (ms)');a.set_title(title,fontsize=10)
            if panel==0:a.legend(frameon=False,fontsize=8)
    elif fid=='09':
        rr=[r for r in rows if r['component']!='unattributed overhead']+[r for r in rows if r['component']=='unattributed overhead']
        left=0
        for j,r in enumerate(rr):
            val=finite(r['mean_ms']);ax.barh([0],[val],left=left,label=r['component'],height=.4,color=COLORS[j]);left+=val
        ax.set_yticks([0],['Enclave total']);ax.set_xlabel('Mean duration (ms)');ax.set_xlim(0,left*1.03)
        ax.legend(frameon=False,ncol=2,fontsize=8,loc='upper center',bbox_to_anchor=(.5,1.25))
        ax.grid(axis='x',alpha=.2);ax.set_axisbelow(True)
    elif fid in ('10','11'):
        xkey='N' if fid=='10' else 'actual_J';ykey='E2E_median_ms' if fid=='10' else 'Transform_median_ms'
        for j,shape in enumerate(dict.fromkeys(r['policy_shape'] for r in rows)):
            rr=[r for r in rows if r['policy_shape']==shape]
            ax.scatter([int(r[xkey]) for r in rr],[finite(r[ykey]) for r in rr],label=shape,marker=['o','s','^'][j],s=55,color=COLORS[j])
        style_axis(ax,'N (attributes)' if fid=='10' else 'Actual candidate |J|',
                   'Request E2E median (ms)' if fid=='10' else 'Transform median (ms)')
        ax.legend(frameon=False)
    elif fid=='12':
        fig.clear();a,b=fig.subplots(1,2)
        x=[int(r['tI']) for r in rows];a.scatter(x,[finite(r['Transform_median_ms']) for r in rows],alpha=.8)
        b.scatter(x,[int(r['CSP_pairings']) for r in rows],alpha=.8,color=COLORS[1])
        style_axis(a,'Actual tI','Transform median (ms)');style_axis(b,'Actual tI','CSP pairings (count)')
        a.set_xticks(sorted(set(x)));b.set_xticks(sorted(set(x)))
    elif fid in ('13','14'):
        x=[int(r['rl_size']) for r in rows]
        pairs=[('active_lookup_median_ms','Active user'),('revoked_lookup_median_ms','Revoked user')] if fid=='13' else [('insert_median_ms','Insert / revoke'),('delete_median_ms','Delete / activate')]
        for j,(key,label) in enumerate(pairs):
            xx=[v for v,r in zip(x,rows) if np.isfinite(finite(r[key]))];yy=[finite(r[key]) for r in rows if np.isfinite(finite(r[key]))]
            ax.plot(xx,yy,marker='o',lw=1.8,label=label,color=COLORS[j])
        ax.set_xscale('symlog',linthresh=10);ax.set_xticks(x,[str(v) for v in x]);
        style_axis(ax,'RevSet size |RL|','Median latency (ms)');ax.legend(frameon=False)
    elif fid=='15':
        fig.clear();a,b=fig.subplots(1,2)
        rev=[r for r in rows if r['kind']=='revset'];reg=[r for r in rows if r['kind']=='registration']
        x=[int(r['rl_size']) for r in rev]
        a.plot(x,[int(r['revset_logical_bytes'])/1024 for r in rev],marker='o')
        a.set_xscale('symlog',linthresh=10);a.set_xticks(x,[str(v) for v in x]);style_axis(a,'RevSet size |RL|','Canonical logical size (KiB)')
        b.plot([int(r['n_reg']) for r in reg],[int(r['registration_state_logical_bytes'])/1024 for r in reg],marker='o',color=COLORS[1])
        style_axis(b,'Registered users n_reg','Registration logical size (KiB)')
    elif fid=='16':
        for j,kind in enumerate(dict.fromkeys(r['request_class'] for r in rows)):
            rr=[r for r in rows if r['request_class']==kind]
            ax.plot([finite(r['target_request_rate_hz']) for r in rr],[finite(r['actual_request_rate_hz']) for r in rr],marker='o',label=kind.replace('_',' ').title(),color=COLORS[j])
        maxv=max(finite(r['target_request_rate_hz']) for r in rows);ax.plot([0,maxv],[0,maxv],ls='--',color='#666666',label='Ideal y=x')
        style_axis(ax,'Target rate (requests/s)','Achieved rate (requests/s)');ax.legend(frameon=False)
    elif fid=='17':
        for j,kind in enumerate(dict.fromkeys(r['request_class'] for r in rows)):
            rr=sorted((r for r in rows if r['request_class']==kind),key=lambda r:finite(r['target_fraction']))
            xx=[100*finite(r['target_fraction']) for r in rr]
            for k,(metric,ls) in enumerate([('request_median_ms','-'),('request_p95_ms','--')]):
                ax.plot(xx,[finite(r[metric]) for r in rr],marker='o',ls=ls,color=COLORS[j],label=kind.replace('_',' ').title()+(' median' if k==0 else ' p95'))
        style_axis(ax,'Target load level (%)','Request latency (ms)');ax.legend(frameon=False,fontsize=8,ncol=2)
        worst=next(r for r in rows if r['request_class']=='REVOKED_REJECT' and finite(r['target_fraction'])==1)
        ax.text(.02,.25,f"Revoked 100% queue-delay p95: {finite(worst['queue_delay_p95_ms']):,.0f} ms (separate from request latency)",transform=ax.transAxes,fontsize=8)
    elif fid=='18':
        ax.axis('off');ax.set_xlim(0,3);ax.set_ylim(-.5,len(rows)+.5)
        for i,h in enumerate(['Evidence','Expected','Observed']):ax.text([.03,1.9,2.38][i],len(rows),h,weight='bold',fontsize=9)
        for j,r in enumerate(rows):
            y=len(rows)-1-j
            if j%2==0:ax.axhspan(y-.38,y+.38,color='#f3f6f8',zorder=-1)
            ax.text(.03,y,r['surface'],va='center',fontsize=9)
            ax.text(1.9,y,r['expected'],va='center',fontsize=9,color='#95502a' if 'leakage' in r['expected'] else '#333333')
            ax.text(2.38,y,r['observed'],va='center',fontsize=9)
    elif fid=='19':
        rr=rows;x=np.arange(len(rr));ax.bar(x,[int(r['unique_count']) for r in rr],color=COLORS[0])
        ax.set_xticks(x,[r['component'].replace('request_','') for r in rr]);ax.set_ylim(0,55)
        style_axis(ax,'Fresh component','Unique observations (count)')
        if len({r['sample_count'] for r in rr})!=1 or any(int(r['collision_count'])!=0 for r in rr):
            raise ValueError('freshness summary differs from zero-collision sample')
        ax.text(.02,.97,f"n={rr[0]['sample_count']} each; zero collisions observed",transform=ax.transAxes,va='top',fontsize=9)
    elif fid=='20':
        labelmap={'same attribute/same context token':'Same-context token\nexpected equality',
            'same attribute/different context token':'Cross-context token\nno direct equality',
            'same user/same CT W':'Same-user same-CT W\nknown linkability',
            'AF same-context matching':'Same-context AF\nexpected match'}
        x=np.arange(len(rows));ax.bar(x,[int(r['equality_count']) for r in rows],color=[COLORS[0],COLORS[1],COLORS[3],COLORS[2]])
        ax.set_xticks(x,[labelmap[r['relation']] for r in rows]);style_axis(ax,'Observed relation (distinct semantics)','Equal / successful observations (count)')
        for i,r in enumerate(rows):ax.text(i,int(r['equality_count'])+2,f"{r['equality_count']}/{r['sample_count']}",ha='center',fontsize=9)
        ax.set_ylim(0,115)
    elif fid=='21':
        ax.axis('off');ax.text(.5,.7,'Fair FABEO comparison: NOT EXECUTED',ha='center',va='center',fontsize=17,weight='bold',color='#a14848',transform=ax.transAxes)
        ax.text(.5,.43,'Common audited pairing/runtime backend unavailable',ha='center',fontsize=11,transform=ax.transAxes)
        ax.text(.5,.29,'No cross-curve timing comparison performed',ha='center',fontsize=11,transform=ax.transAxes)
    if fid not in ('00','01','21'):
        ax=fig.axes[0]
    fig.suptitle(TITLES[fid].replace('_',' ').title(),fontsize=13,weight='semibold')
    if fid in SGX:
        # supxlabel participates in constrained layout and reserves footer space.
        fig.supxlabel(FOOT,fontsize=7,color='#555555')
    return fig


def save_csv(path, rows):
    if not rows:raise ValueError('no figure data')
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('x',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def meta_for(fid, paths, rows):
    x,y,unit={
        '02':('ell','Encrypt median','ms'),'03':('ell','Transform median','ms'),
        '04':('actual tI','pairing operations','count'),'05':('ell','CT size','KiB'),
        '06':('configuration','mutually exclusive CT components','KiB'),
        '07':('backend','policy token median/p95','ms'),
        '08':('batch size','policy/user token median','ms'),
        '09':('enclave stage','mean duration','ms'),
        '10':('N','request E2E median','ms'),'11':('actual |J|','Transform median','ms'),
        '12':('actual tI','Transform median / CSP pairings','ms / count'),
        '13':('|RL|','RevSet lookup median','ms'),'14':('|RL|','RevStateUpt median','ms'),
        '15':('|RL|','RevSet logical size','KiB'),
        '16':('target request rate','achieved rate','requests/s'),
        '17':('load level','request median/p95','ms'),
        '18':('evidence item','expected / observed','discrete'),
        '19':('component','unique count','count'),
        '20':('relation','equality/success count','count'),
    }.get(fid,('experiment / stage','status','categorical'))
    special_filters={
        '04':'All frozen Exp1 configurations; FinalDec zero pairing from canonical RESULTS_EXP1.md',
        '06':'Representative (ell,cmax): (5,1), (40,1), (80,3), (160,1), (160,5)',
        '07':'Exact match ell=N=20, cmax=2, actual_L_hit=10; both backend profiles',
        '08':'All Exp4 configurations; cmax and L_hit vary with batch size',
        '09':'Representative canonical Exp4 enclave-stage configuration; mean components only',
        '15':'All Exp6 RevSet sizes plus all canonical registration sizes; separate panels',
        '18':'Exp7 canary audit PASS and zero forbidden hits; observed equality counts',
        '21':'Canonical Phase 5B limitation: BLOCKED_COMMON_BACKEND',
    }
    trust=('MIXED_STATUS_WITH_REAL_SGX_DEBUG_FEASIBILITY' if fid in ('00','01') else
           'MATCHED_EMULATED_AND_REAL_SGX_DEBUG_FEASIBILITY' if fid in ('07','08') else
           'EMULATED_TEE_PROFILE' if fid in ('05','06') else
           'STATUS_ONLY' if fid=='21' else 'REAL_SGX_DEBUG_FEASIBILITY')
    return dict(figure_id=fid,title=TITLES[fid],experiment=EXPERIMENTS[fid],
        input_artifact=[str(p.relative_to(REPO)) for p in paths],
        source_hash={str(p.relative_to(REPO)):sha256_file(p) for p in paths},
        filters=special_filters.get(fid,'Exact frozen canonical rows; no outlier deletion or smoothing'),
        x_variable=x,y_variable=y,aggregation='frozen median/p95, mean stages, or direct count as labelled',
        unit=unit,trust_cohort=trust,
        sgx_footnote=FOOT if fid in SGX else None,category=CATEGORIES.get(fid,'USEFUL'),
        row_count=len(rows),visual_review_only=True,phase6_executed=False)


def docs(out, figures, p, d, validation):
    names=[(fid,TITLES[fid]) for fid in figures if fid!='dashboard']
    e1=d['e1'];e3=d['e3'];e4=d['e4'];e5=d['e5'];e6=d['e6'];eq=d['e7eq']
    def one(rows, **matches):
        found=[r for r in rows if all(str(r[k])==str(v) for k,v in matches.items())]
        if len(found)!=1:raise ValueError(f'cross-check selection not unique: {matches}, {len(found)}')
        return found[0]
    a=one(e1,ell=5,repeat_regime='UNIQUE');b=one(e1,ell=40,repeat_regime='UNIQUE')
    c=one(e3,ell=5,cmax=1);d3=one(e3,ell=160,cmax=1)
    m=[r for r in e4 if all(str(r[k])==str(v) for k,v in dict(ell=20,N=20,cmax=2,actual_L_hit=10).items())]
    if len(m)!=2:raise ValueError('Exp4 matched pair unavailable')
    em=one(m,backend='EMULATED_TEE_PROFILE');sg=one(m,backend='SGX_DEBUG_GRAMINE_V1')
    f=one(e5,configuration_id='CFG-0b9aaf5887e119e78573');g=one(e5,policy_shape='threshold',N=40,actual_J=10)
    h=one(e6,rl_size=10);i=one(e6,rl_size=5000)
    q={r['relation']:r for r in eq}
    key=("# MYABE-08 关键数字（Visual Review）\n\n所有值由冻结 canonical 表重新读取。仅描述观察，不作性能归因或形式证明。\n\n"
        f"- Exp1 UNIQUE，ell 5→40：Encrypt median {a['Encrypt_median_ms']}→{b['Encrypt_median_ms']} ms。\n"
        f"- Exp3 cmax=1，ell 5→160：CT {c['CT_total_bytes']}→{d3['CT_total_bytes']} bytes。\n"
        f"- Exp4 匹配 ell=N=20、cmax=2、L_hit=10：EMULATED {em['policy_token_median_ms']} ms，REAL SGX DEBUG {sg['policy_token_median_ms']} ms，观察比值 {finite(sg['policy_token_median_ms'])/finite(em['policy_token_median_ms']):.2f}×；部署 profile 对比，并非纯 SGX 开销。\n"
        f"- Exp5 threshold：N=5、actual J=2、配置 {f['configuration_id']} 的 E2E {f['E2E_median_ms']} ms；N=40、actual J=10 的 E2E {g['E2E_median_ms']} ms。N=5、J=2 还有另一配置，不能合并成一条单变量曲线。\n"
        f"- Exp6 RL 10→5000：active lookup {h['active_lookup_median_ms']}→{i['active_lookup_median_ms']} ms；insert/revoke {h['insert_median_ms']}→{i['insert_median_ms']} ms。\n"
        f"- Exp7 同 context token {q['same attribute/same context token']['equality_count']}/{q['same attribute/same context token']['sample_count']} 相等；跨 context 直接相等 {q['same attribute/different context token']['equality_count']}/{q['same attribute/different context token']['sample_count']}；同用户同 CT 的 W {q['same user/same CT W']['equality_count']}/{q['same user/same CT W']['sample_count']} 相等。W 稳定性是已知可链接性。\n\n"
        f"SGX_DEBUG_GRAMINE_V1；QVL: OUT_OF_DATE；Strict RA2: BLOCKED；Feasibility measurements only。\n\nVisual review only. No Phase 6 execution.\n")
    (out/'KEY_RESULTS.md').write_text(key,encoding='utf-8')
    index=['# Figure Index','','| Figure ID | Experiment | Title | Filename | Core message | Category | Input source |',
           '|---|---|---|---|---|---|---|']
    review=['# MYABE-08 Visual Review','','仅使用冻结且重新校验的 canonical 工件；图用于理解趋势和筛选未来论文图，不替代最终论文图。没有删除 outlier、平滑或补点。','',
            'SGX 图统一表示 `SGX_DEBUG_GRAMINE_V1`、QVL `OUT_OF_DATE`、strict RA2 `BLOCKED`，仅属 feasibility measurements。','',
            'Visual review only. No Phase 6 execution.','']
    notes={
      '00':('实验地图；横向顺序是 Exp1–Exp7，Exp2 为 BLOCKED。','可直接定位每个实验的核心变量。','比较完整性与覆盖面。','不表示各实验质量或速度排序。'),
      '01':('研究工作阶段及对应 Phase。','已到 benchmark、analysis、revocation/privacy evidence。','项目流程位置。','不表示生产可信或 Phase 6 启动。'),
      '02':('ell 对 Encrypt median，按重复 regime 分组。','观察加密时间随所测 ell 增长。','发生策略行处理成本。','不证明渐近复杂度或跨配置因果。'),
      '03':('ell 对 Transform median，按重复 regime 分组。','不同重复 regime 的观测曲线不同。','Transform 工作量与策略结构相关。','不证明重复本身是唯一原因。'),
      '04':('actual tI 对 TEE/CSP/System/FinalDec pairing 次数。','TEE=1，CSP=1+tI，System=2+tI，FinalDec=0。','结构性 operation count。','不是 wall-clock speedup。'),
      '05':('ell 对 canonical CT KiB，按 cmax 分组。','所测 CT 尺寸随 ell 增加。','canonical wire storage 的配置差异。','不代表进程 RSS。'),
      '06':('五个代表配置的互斥 CT core/AF/header/DEM/publication 分解。','各部分对总字节数的贡献可辨。','Phase 5B 的互斥 accounting。','不能把这些配置外推为全部工作负载。'),
      '07':('结构匹配配置的 EMULATED 与 REAL SGX DEBUG policy token median 和 p95。','SGX profile 的所测 latency 较高。','观察到的部署 profile 对比。','不是纯 SGX overhead 因果估计。'),
      '08':('policy/user token batch size 与 median latency。','不同配置和 backend 有不同观测值。','batch sweep 的样本分布。','cmax 与 L_hit 同时变化；不是独立 batch 效应。'),
      '09':('代表性 SGX enclave stage mean 与未归因 overhead。','rerandomization/pairing/signing 与未归因部分可见。','只在 enclave total 内拆分。','不能与 RPC receive 相加，也不证明每阶段因果占比。'),
      '10':('N 对 request E2E median，按 policy shape。','threshold 各实际配置有不同观测值。','E2E 所测扩展趋势。','重复 N 的不同配置不能合并为单变量曲线。'),
      '11':('actual |J| 对 Transform median，按 policy shape。','点散布显示候选集与 Transform 的共同变化。','使用实际候选数而非 requested J。','不证明 |J| 单独决定 latency。'),
      '12':('actual tI 对 Transform median 和 CSP pairing count 两个 panel。','pairing count 跟随 tI，latency 仍有离散。','计数结构与时间分开看。','不证明单次 pairing 的固定时间。'),
      '13':('|RL| 对 active/revoked RevSet lookup median。','所测 lookup 随 RL 增大明显上升。','exact-set SGX 实现的观测成本。','不证明形式渐近复杂度。'),
      '14':('|RL| 对 insert/revoke、delete/activate median。','所测更新成本随 RL 增加。','状态更新的观测扩展。','不证明任意负载下的吞吐。'),
      '15':('|RL| 对 canonical RevSet logical KiB。','逻辑状态随成员数增大。','精确集编码大小。','不是 RSS，也不含所有进程内存。'),
      '16':('target 对 achieved requests/s，含 y=x 参考。','高负载 revoked 组出现 achieved 低于 target。','可检查饱和迹象。','有限样本不能推断长期容量。'),
      '17':('25–100% load 对 active/revoked request median/p95。','两类请求 latency 不同；高负载 revoked queue p95 单独注释。','请求服务时间和排队须分辨。','不应把 queue delay 直接加到 request latency。'),
      '18':('Exp7 预期语义与观察到的离散证据。','未观察到审计禁止值；同-context 等值和 W 稳定可见。','隐私边界与已知泄露同时展示。','不是隐私分数或匿名性证明。'),
      '19':('五种 fresh component 的 unique count，均为 50 样本。','每种 50/50 唯一、0 observed collisions。','有限样本中未见碰撞。','No observed collisions in this finite sample do not prove cryptographic randomness.'),
      '20':('四种不同语义的 equality/matching 计数。','100/100、0/100、50/50、50/50。','区分预期等值、无直接跨-context 等值与 W 可链接性。','不是统一的 privacy success rate。'),
      '21':('Exp2 fair FABEO comparison 状态卡。','未执行可比性实验。','缺共同已审计 pairing/runtime backend。','没有任何跨曲线性能结论。'),
    }
    for fid,title in names:
        src=', '.join(str(x.relative_to(REPO)) for x in sources_for(fid,p))
        axes=meta_for(fid,sources_for(fid,p),rows_for(fid,d))
        index.append(f'| {fid} | {EXPERIMENTS[fid]} | {title} | figure_{fid}.png / .pdf | {notes[fid][1]} | {CATEGORIES.get(fid,"USEFUL")} | `{src}` |')
        review += [f'## Figure {fid} — {title} [{CATEGORIES.get(fid,"USEFUL")}]','',
            f'1. What it shows：{notes[fid][0]} 横轴：{axes["x_variable"]}；纵轴：{axes["y_variable"]}（{axes["unit"]}）。',
            f'2. Main visual observation：{notes[fid][1]}',f'3. What it means technically：{notes[fid][2]}',
            f'4. What it does NOT prove：{notes[fid][3]}','']
    if 'dashboard' in figures:
        index.append('| Dashboard | Exp1/3/4/5/6/7 | My-ABE Experimental Overview | MYABE_EXPERIMENT_DASHBOARD.png / .pdf | 六组证据速览 | CORE | 同各 panel 源表 |')
        review += ['## Dashboard [CORE]','','六组精选 panel 帮助定位趋势；每 panel 的单位与对应独立 Figure 一致。它不证明性能优势或生产可信。','']
    (out/'FIGURE_INDEX.md').write_text('\n'.join(index)+'\n',encoding='utf-8')
    (out/'VISUAL_REVIEW.md').write_text('\n'.join(review)+'\n',encoding='utf-8')
    readme=['# MYABE-08 Visual Review Pack','','## What experiments have been completed?','',
        '| Experiment | Focus | Status |','|---|---|---|',
        '| Exp1 | Occurrence optimization | COMPLETE |','| Exp2 | Fair FABEO comparison | BLOCKED |',
        '| Exp3 | Storage | COMPLETE |','| Exp4 | Contextual tokenization / AF | COMPLETE |',
        '| Exp5 | Transform scaling | COMPLETE |','| Exp6 | Revocation scaling | COMPLETE |',
        '| Exp7 | Transcript/privacy evidence | COMPLETE |','','## What are the most important things visible in the data?','',
        'Encrypt、CT storage、exact RevSet lookup/update 在已测配置中随规模增大；匹配的 SGX DEBUG 与 EMULATED profile 有不同 tokenization latency。Exp7 同时显示预期的同-context 等值与稳定 W 可链接性。Exp2 缺可比 backend，未做公平性能比较。','',
        '每图有 `data/figure_XX.csv` 与 `meta/figure_XX.json`；详见 `FIGURE_INDEX.md`、`VISUAL_REVIEW.md` 和 `KEY_RESULTS.md`。',
        '',FOOT,'','Visual review only. No Phase 6 execution.','']
    (out/'README_VISUAL_REVIEW.md').write_text('\n'.join(readme),encoding='utf-8')
    (out/'validation.json').write_text(json.dumps(validation,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')


def dashboard(out, p, d):
    panels=[('02','Occurrence cost'),('05','Ciphertext storage'),('07','TEE deployment profile'),
            ('10','Request E2E scaling'),('13','Revocation lookup'),('20','Privacy / linkability evidence')]
    fig,axs=plt.subplots(2,3,figsize=(15,9),constrained_layout=True)
    combined=[];allpaths=[]
    for ax,(fid,title) in zip(axs.flat,panels):
        rows=rows_for(fid,d)
        for row in rows:combined.append(dict(panel=fid,**row))
        allpaths.extend(sources_for(fid,p))
        if fid=='02':
            rr=sorted((r for r in rows if r['repeat_regime']=='UNIQUE'),key=lambda r:int(r['ell']))
            ax.plot([int(r['ell']) for r in rr],[finite(r['Encrypt_median_ms']) for r in rr],marker='o');style_axis(ax,'ell','Median (ms)')
        elif fid=='05':
            for c in (1,5):
                rr=sorted((r for r in rows if int(r['cmax'])==c),key=lambda r:int(r['ell']))
                ax.plot([int(r['ell']) for r in rr],[int(r['CT_total_bytes'])/1024 for r in rr],marker='o',label=f'cmax={c}')
            style_axis(ax,'ell','CT size (KiB)');ax.legend(frameon=False,fontsize=8)
        elif fid=='07':
            rr=sorted(rows,key=lambda r:r['backend']);ax.bar(['EMU','SGX DEBUG'],[finite(r['policy_token_median_ms']) for r in rr],color=COLORS[:2]);style_axis(ax,'Profile','Token median (ms)')
        elif fid=='10':
            for j,shape in enumerate(dict.fromkeys(r['policy_shape'] for r in rows)):
                rr=[r for r in rows if r['policy_shape']==shape]
                ax.scatter([int(r['N']) for r in rr],[finite(r['E2E_median_ms']) for r in rr],label=shape,color=COLORS[j])
            style_axis(ax,'N','E2E median (ms)');ax.legend(frameon=False,fontsize=7)
        elif fid=='13':
            ax.plot([int(r['rl_size']) for r in rows],[finite(r['active_lookup_median_ms']) for r in rows],marker='o');ax.set_xscale('symlog',linthresh=10);style_axis(ax,'|RL|','Lookup median (ms)')
        else:
            rr=rows;ax.bar(range(len(rr)),[int(r['equality_count']) for r in rr],color=[COLORS[0],COLORS[1],COLORS[3],COLORS[2]])
            ax.set_xticks(range(len(rr)),['same ctx','cross ctx','stable W','AF hit'],rotation=20);style_axis(ax,'Relation','Count')
        ax.set_title(title,fontsize=11)
    fig.suptitle('My-ABE Experimental Overview\nValidated Exp1/3/4/5/6/7 evidence; Exp2 fair comparison remains blocked.',fontsize=14)
    fig.supxlabel(FOOT,fontsize=7,color='#555555')
    stem='MYABE_EXPERIMENT_DASHBOARD';fig.savefig(out/(stem+'.png'),dpi=300);fig.savefig(out/(stem+'.pdf'));plt.close(fig)
    save_csv(out/'data/dashboard.csv',combined)
    meta=dict(title='My-ABE Experimental Overview',experiment='Exp1/3/4/5/6/7',panels=[x[0] for x in panels],
              input_artifact=[str(v.relative_to(REPO)) for v in dict.fromkeys(allpaths)],
              source_hash={str(v.relative_to(REPO)):sha256_file(v) for v in dict.fromkeys(allpaths)},
              filters='Exact canonical rows; panel-specific display filters stated in chart',
              x_variable='panel-specific',y_variable='panel-specific',aggregation='canonical median or observed count',
              unit='panel-specific',trust_cohort='MIXED_EMULATED_AND_REAL_SGX_DEBUG_FEASIBILITY',sgx_footnote=FOOT)
    (out/'meta/dashboard.json').write_text(json.dumps(meta,indent=2)+'\n')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group()
    choice.add_argument('--all',action='store_true')
    choice.add_argument('--dashboard',action='store_true')
    choice.add_argument('--exp',choices=['Exp1','Exp2','Exp3','Exp4','Exp5','Exp6','Exp7'])
    parser.add_argument('--output',type=Path,default=ROOT/'visual_review',help='parent for a new unique visual ID directory')
    parser.add_argument('--validate-only',action='store_true')
    args=parser.parse_args(argv)
    validation=validate_inputs()
    p,d=source_data()
    if args.validate_only:
        print(json.dumps(validation,indent=2));return 0
    if args.dashboard:ids=[]
    elif args.exp:ids=[fid for fid,exp in EXPERIMENTS.items() if exp==args.exp]
    else:ids=list(TITLES)
    visual_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
    out=args.output.resolve()/visual_id
    out.mkdir(parents=True,exist_ok=False);(out/'data').mkdir();(out/'meta').mkdir()
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
                         'axes.spines.right':False,'pdf.fonttype':42})
    for fid in ids:
        rows=rows_for(fid,d);paths=sources_for(fid,p)
        fig=plot(fid,rows);stem=f'figure_{fid}'
        fig.savefig(out/(stem+'.png'),dpi=300);fig.savefig(out/(stem+'.pdf'));plt.close(fig)
        save_csv(out/'data'/(stem+'.csv'),rows)
        (out/'meta'/(stem+'.json')).write_text(json.dumps(meta_for(fid,paths,rows),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    if args.dashboard or args.all or not args.exp:dashboard(out,p,d)
    docs(out,ids+(['dashboard'] if (args.dashboard or args.all or not args.exp) else []),p,d,validation)
    print(out)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
