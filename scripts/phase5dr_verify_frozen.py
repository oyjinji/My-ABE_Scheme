"""Independently revalidate a Phase 5D-R run against its frozen source archive.

Useful after later source changes: verification never substitutes the current
checkout for the exact code bytes recorded when the benchmark was sampled.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import tarfile


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_file(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            h.update(block)
    return h.hexdigest()


def digest_json(value):
    return digest(json.dumps(value,sort_keys=True,separators=(',',':'),
                             ensure_ascii=False).encode())


def verify(run, analysis=None):
    frozen=json.loads((run/'PHASE5D_R_PLAN.json').read_text())
    code=json.loads((run/'PHASE5D_R_CODE_MANIFEST.json').read_text())
    source=json.loads((run/'BASELINE_SOURCE_MANIFEST.json').read_text())
    manifest=json.loads((run/'MANIFEST.json').read_text())
    archive_info=json.loads((run/'SOURCE_SNAPSHOT.json').read_text())
    archive=run/archive_info['archive']
    if (manifest['status']!='COMPLETE' or
        frozen['plan_sha256']!=digest_json({k:v for k,v in frozen.items()
                                           if k!='plan_sha256'}) or
        manifest['plan_sha256']!=frozen['plan_sha256'] or
        code['tree_sha256']!=digest_json(code['files']) or
        archive_info['archive_sha256']!=digest_file(archive) or
        archive_info['source_tree_sha256']!=code['tree_sha256']):
        raise ValueError('frozen manifest/plan/archive mismatch')
    expected={f['path']:(f['sha256'],f['size_bytes']) for f in code['files']}
    with tarfile.open(archive,'r:gz') as stream:
        actual={}
        for member in stream:
            if not member.isfile(): continue
            prefix='myabe08/'
            if not member.name.startswith(prefix):
                raise ValueError('source archive contains unexpected path')
            name=member.name[len(prefix):]
            if name.startswith('/') or '..' in Path(name).parts:
                raise ValueError('unsafe source archive member')
            raw=stream.extractfile(member).read()
            actual[name]=(digest(raw),len(raw))
    if actual!=expected:
        raise ValueError('source snapshot differs from code manifest')
    if (source['myabe_algebra_sha256']!=expected['algebra.py'][0] or
        source['fabeo_port_sha256']!=expected['baselines/fabeo.py'][0] or
        source['fabeo_native_sha256']!=digest_file(run/'FABEO_NATIVE_REFERENCE.py') or
        source['specification']['sha256']!=
            'd52daf431bfececa4b1b8bf0f77fe34634710c9502d372f405b75b806812df85'):
        raise ValueError('source/spec lineage mismatch')
    if digest_file(run/'raw.jsonl')!=manifest['raw_sha256']:
        raise ValueError('raw sample hash mismatch')
    track=manifest['track']
    if track not in ('ablation','core'):
        raise ValueError('unknown track')
    configs=[c for c in frozen['configurations'] if c['track']==track]
    if len(configs)!=manifest['configurations'] or len(configs)!=(20 if track=='ablation' else 6):
        raise ValueError('incomplete configuration set')
    schemes=('OCCURRENCE','ROW') if track=='ablation' else (
        'MYABE08_BLS12381_CORE','FABEO22_CP_BLS12381_TAU1')
    expected_grid={(digest_json(c)[:20],scheme,block,rep)
                   for c in configs for scheme in schemes
                   for block in range(3) for rep in range(10)}
    rows=[]
    with (run/'raw.jsonl').open() as stream:
        for line in stream: rows.append(json.loads(line))
    actual_grid={(r['config_id'],r['scheme'],r['block'],r['repetition']) for r in rows}
    if (len(rows)!=len(expected_grid) or len(rows)!=manifest['samples'] or
            actual_grid!=expected_grid):
        raise ValueError('missing, duplicate or unexpected sample')
    for r in rows:
        if (r['config_id']!=digest_json(r['config'])[:20] or
            r['measurement_origin']!='LOCAL_MEASURED' or
            r['security_profile']!='SECURITY_PROFILE_BLS12_381' or
            r['tee_profile']!='NO_TEE_ALGEBRA_CORE_ONLY'):
            raise ValueError('sample provenance mismatch')
        if any(type(value) is not int or value<0 for name,value in r.items()
               if name.endswith('_ns')):
            raise ValueError('negative or malformed duration')
    result=dict(status='PASS',track=track,run=str(run),
                samples=len(rows),configurations=len(configs),
                source_files=len(actual),source_tree_sha256=code['tree_sha256'],
                snapshot_sha256=digest_file(archive),raw_sha256=manifest['raw_sha256'],
                outliers_removed=0)
    if analysis is not None:
        validation=json.loads((analysis/'VALIDATION.json').read_text())
        stats=json.loads((analysis/'statistics.json').read_text())
        if (validation['status']!='PASS' or validation['raw_sha256']!=manifest['raw_sha256']
                or validation['samples']!=len(rows) or
                validation['outliers_removed']!=0):
            raise ValueError('analysis lineage mismatch')
        grouped=defaultdict(list)
        for row in rows: grouped[row['config_id'],row['scheme']].append(row)
        for item in stats:
            values=[r[item['metric']] for r in grouped[item['config_id'],item['scheme']]]
            if (len(values)!=item['n'] or item['n']!=30 or
                    statistics.median(values)!=item['median'] or
                    min(values)!=item['minimum'] or max(values)!=item['maximum']):
                raise ValueError('statistics/raw mismatch')
        result['analysis']=str(analysis)
        result['statistics_rows']=len(stats)
        result['statistics_sha256']=digest_file(analysis/'statistics.json')
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('run',type=Path)
    parser.add_argument('--analysis',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=verify(args.run,args.analysis)
    rendered=json.dumps(result,sort_keys=True,indent=2)+'\n'
    if args.output:
        args.output.write_text(rendered)
    print(rendered,end='')


if __name__=='__main__':
    main()
