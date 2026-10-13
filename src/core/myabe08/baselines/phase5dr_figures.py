"""Plot only validated, locally measured Phase 5D-R core-only datasets."""
import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from ..experiments.provenance import file_sha256


COLORS = {'OCCURRENCE':'#1f77b4', 'ROW':'#7f7f7f',
          'MYABE08_BLS12381_CORE':'#1f77b4',
          'FABEO22_CP_BLS12381_TAU1':'#ff7f0e'}
LABELS = {'OCCURRENCE':'MyABE occurrence-aware',
          'ROW':'NoOccurrenceReuse (internal ablation)',
          'MYABE08_BLS12381_CORE':'MyABE ABE core',
          'FABEO22_CP_BLS12381_TAU1':'FABEO tau=1 common BLS'}


def _load(path):
    validation=json.loads((path/'VALIDATION.json').read_text())
    if validation['status']!='PASS' or validation['outliers_removed']!=0:
        raise ValueError('validated all-sample analysis required')
    statistics_path=path/'statistics.json'
    return json.loads(statistics_path.read_text()),file_sha256(statistics_path)


def _save(fig,output,name,rows,source_hash,title,x,y,cohort):
    output.mkdir(parents=True,exist_ok=True)
    fig.savefig(output/(name+'.png'),dpi=300,bbox_inches='tight')
    fig.savefig(output/(name+'.pdf'),bbox_inches='tight')
    plt.close(fig)
    with (output/(name+'.csv')).open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=('ell','cmax','scheme','median',
                                                  'p95','n','unit'))
        writer.writeheader()
        writer.writerows(rows)
    (output/(name+'.json')).write_text(json.dumps(dict(title=title,x=x,y=y,
        trust_cohort=cohort,source_statistics_sha256=source_hash,
        filters='complete validated Phase 5D-R core-only local samples; no exclusions',
        aggregation='30 samples/configuration; median and p95; 3 blocks'),
        indent=2,sort_keys=True)+'\n')


def _selected(stats,metric,unit):
    scale=1e6 if unit=='ms' else 1
    return [dict(ell=r['config']['ell'],cmax=r['config']['cmax'],
                 scheme=r['scheme'],median=r['median']/scale,
                 p95=r['p95']/scale,n=r['n'],unit=unit)
            for r in stats if r['metric']==metric]


def ablation(analysis,output):
    stats,source_hash=_load(analysis)
    specs=(('OCCURRENCE_CORE_GROUP_BYTES','core_ct_bytes','bytes',
            'Core ciphertext group bytes','Canonical group bytes (bytes)'),
           ('OCCURRENCE_COMPONENT_REDUCTION','g2_count','elements',
            'D component count','G2 elements'),
           ('OCCURRENCE_ENCRYPT_COST','encrypt_ns','ms',
            'Encrypt algebra latency','Median latency (ms)'),
           ('OCCURRENCE_TRANSFORM_COST','transform_ns','ms',
            'Transform algebra latency','Median latency (ms)'))
    for name,metric,unit,title,ylabel in specs:
        data=_selected(stats,metric,unit)
        fig,axes=plt.subplots(2,2,figsize=(10,7),constrained_layout=True)
        for ax,ell in zip(axes.flat,(20,40,80,160)):
            for scheme in ('OCCURRENCE','ROW'):
                sub=sorted((r for r in data if r['ell']==ell and
                            r['scheme']==scheme),key=lambda r:r['cmax'])
                ax.plot([r['cmax'] for r in sub],
                        [r['median'] for r in sub],marker='o',linewidth=1.7,
                        color=COLORS[scheme],label=LABELS[scheme])
            ax.set(title='ell = '+str(ell),xlabel='Actual cmax',ylabel=ylabel)
            ax.grid(alpha=.25)
        handles,labels=axes.flat[0].get_legend_handles_labels()
        fig.legend(handles,labels,loc='upper center',ncol=2,
                   bbox_to_anchor=(.5,1.06),frameon=False)
        fig.suptitle(title,y=1.02)
        _save(fig,output,name,data,source_hash,title,'Actual cmax',ylabel,
              'BLS12-381 py_ecc; algebra-core only; no SGX')


def core(analysis,output):
    stats,source_hash=_load(analysis)
    specs=(('CORE_KEYGEN_COMPARISON','keygen_ns','ms','KeyGen','Median latency (ms)'),
           ('CORE_ENCRYPT_COMPARISON','encrypt_ns','ms','Encrypt','Median latency (ms)'),
           ('CORE_AUTHORIZED_ACCESS_COMPARISON','access_ns','ms',
            'Authorized cryptographic access','Median latency (ms)'),
           ('CORE_CIPHERTEXT_GROUP_BYTES','ct_group_bytes','bytes',
            'Ciphertext group payload','Group bytes (bytes)'),
           ('CORE_KEY_MATERIAL_BYTES','total_core_key_bytes','bytes',
            'Total ABE core key material','Encoded key bytes (bytes)'),
           ('CORE_PAIRINGS','access_pairings','operations',
            'Authorized access pairings','Pairing calls'))
    for name,metric,unit,title,ylabel in specs:
        data=_selected(stats,metric,unit)
        fig,ax=plt.subplots(figsize=(6.6,4.3),layout='constrained')
        for scheme in ('MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1'):
            sub=sorted((r for r in data if r['scheme']==scheme),
                       key=lambda r:r['ell'])
            ax.plot([r['ell'] for r in sub],[r['median'] for r in sub],
                    marker='o',linewidth=1.8,color=COLORS[scheme],
                    label=LABELS[scheme])
        ax.set(title=title,xlabel='Policy rows (ell)',ylabel=ylabel)
        ax.grid(alpha=.25)
        ax.legend(frameon=False)
        _save(fig,output,name,data,source_hash,title,'Policy rows (ell)',ylabel,
              'BLS12-381 py_ecc; AND unique attributes; no SGX')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--track',choices=('ablation','core'),required=True)
    parser.add_argument('--analysis',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    (ablation if args.track=='ablation' else core)(args.analysis,args.output)


if __name__=='__main__':
    main()
