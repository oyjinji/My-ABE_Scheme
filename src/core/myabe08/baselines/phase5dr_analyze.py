"""Validate immutable Phase 5D-R core-only sample runs before statistics."""
import argparse
import csv
import json
from pathlib import Path
import statistics

from ..experiments.provenance import code_manifest, file_sha256, spec_manifest
from .phase5dr_bench import _sha, plan


def _percentile(values, fraction):
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    left = int(pos)
    right = min(left + 1, len(values) - 1)
    return values[left] + (values[right] - values[left]) * (pos - left)


def validate(run: Path):
    manifest = json.loads((run/'MANIFEST.json').read_text())
    frozen = json.loads((run/'PHASE5D_R_PLAN.json').read_text())
    source = json.loads((run/'BASELINE_SOURCE_MANIFEST.json').read_text())
    code = json.loads((run/'PHASE5D_R_CODE_MANIFEST.json').read_text())
    spec = spec_manifest()
    if (manifest['status'] != 'COMPLETE' or
        manifest['plan_sha256'] != plan()['plan_sha256'] or
        frozen['plan_sha256'] != _sha({k:v for k,v in frozen.items()
                                       if k != 'plan_sha256'}) or
        code['tree_sha256'] != code_manifest()['tree_sha256'] or
        source['specification'] != spec or
        source['myabe_algebra_sha256'] != file_sha256(
            Path(code['source_root'])/'algebra.py') or
        source['fabeo_port_sha256'] != file_sha256(
            Path(code['source_root'])/'baselines/fabeo.py') or
        file_sha256(run/'raw.jsonl') != manifest['raw_sha256']):
        raise ValueError('run manifest/spec/hash mismatch or incomplete run')
    track = manifest['track']
    configs = [c for c in frozen['configurations'] if c['track'] == track]
    if len(configs) != manifest['configurations']:
        raise ValueError('configuration count mismatch')
    rows = [json.loads(line) for line in (run/'raw.jsonl').read_text().splitlines()]
    if len(rows) != manifest['samples'] or len(rows) != len(configs)*2*30:
        raise ValueError('sample count mismatch')
    expected = {(_sha(c)[:20], scheme, block, rep)
                for c in configs
                for scheme in (('OCCURRENCE','ROW') if track == 'ablation' else
                               ('MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1'))
                for block in range(3) for rep in range(10)}
    actual = {(r['config_id'],r['scheme'],r['block'],r['repetition']) for r in rows}
    if actual != expected or len(actual) != len(rows):
        raise ValueError('missing/duplicate/unexpected samples')
    for row in rows:
        if (row['config_id'] != _sha(row['config'])[:20] or
            row['measurement_origin'] != 'LOCAL_MEASURED' or
            row['security_profile'] != 'SECURITY_PROFILE_BLS12_381' or
            row['tee_profile'] != 'NO_TEE_ALGEBRA_CORE_ONLY'):
            raise ValueError('configuration digest mismatch')
        for key, value in row.items():
            if key.endswith('_ns') and (type(value) is not int or value < 0):
                raise ValueError('invalid duration')
    return manifest, rows


def analyze(run: Path, output: Path):
    manifest, rows = validate(run)
    output.mkdir(parents=True, exist_ok=False)
    metrics = ('encrypt_ns','transform_ns','core_ct_bytes','g2_count',
               'd_component_bytes','csp_pairings') if manifest['track']=='ablation' else (
               'setup_ns','keygen_ns','encrypt_ns','access_ns',
               'ct_group_bytes','du_core_key_bytes','tee_core_key_bytes',
               'total_core_key_bytes','access_pairings')
    groups = {}
    for row in rows:
        groups.setdefault((row['config_id'],row['scheme']), []).append(row)
    summary = []
    for (config_id,scheme), values in sorted(groups.items()):
        for metric in metrics:
            sample = [r[metric] for r in values]
            summary.append(dict(config_id=config_id,config=values[0]['config'],
                scheme=scheme,metric=metric,n=len(sample),minimum=min(sample),
                q1=_percentile(sample,.25),median=statistics.median(sample),
                q3=_percentile(sample,.75),mean=statistics.mean(sample),
                std=statistics.stdev(sample),p90=_percentile(sample,.90),
                p95=_percentile(sample,.95),maximum=max(sample)))
    (output/'statistics.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    with (output/'statistics.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=('config_id','config','scheme','metric',
            'n','minimum','q1','median','q3','mean','std','p90','p95','maximum'))
        writer.writeheader()
        for row in summary:
            writer.writerow({**row,'config':json.dumps(row['config'],sort_keys=True)})
    (output/'VALIDATION.json').write_text(json.dumps(dict(status='PASS',
        source_run=str(run),raw_sha256=manifest['raw_sha256'],
        samples=len(rows),outliers_removed=0),sort_keys=True,indent=2)+'\n')
    return summary


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('run',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    result=analyze(args.run,args.output)
    print('validated_rows',len(result))


if __name__=='__main__':
    main()
