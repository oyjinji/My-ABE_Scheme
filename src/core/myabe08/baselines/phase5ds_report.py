"""Phase 5D-S descriptive analysis; never acquires benchmark observations."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import statistics

from ..experiments.provenance import file_sha256, spec_manifest
from .phase5ds import (R_ABLATION, R_ABLATION_ANALYSIS, R_CORE,
    R_CORE_ANALYSIS, R_RUN, validate, verify_5dr)

PUBLIC_CT = R_RUN/'public_ct/20260927T165759Z'


def percentile(values, fraction):
    ordered = sorted(values)
    pos = (len(ordered)-1)*fraction
    lo = int(pos)
    hi = min(lo+1, len(ordered)-1)
    return ordered[lo]+(ordered[hi]-ordered[lo])*(pos-lo)


def _read_old(path):
    with path.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row['config'] = json.loads(row['config'])
        for name in ('median','q1','q3','p95','n'):
            row[name] = float(row[name])
    return rows


def sources():
    old = verify_5dr()
    provenance = json.loads((PUBLIC_CT/'PROVENANCE.json').read_text())
    if (provenance['status'] != 'COMPLETE_SINGLE_CONSTRUCTION_SIZE_ONLY' or
        provenance['configurations'] != 20 or
        provenance['constructions'] != 40 or
        provenance['timing_samples'] != 0 or
        provenance['backend'] != 'EMULATED_TEE_PROFILE' or
        provenance['source_script_sha256'] != file_sha256(
            Path(__file__).parents[4]/'scripts/phase5dr_full_ct.py') or
        provenance['ablation_raw_sha256'] != file_sha256(R_ABLATION/'raw.jsonl') or
        provenance['specification'] != spec_manifest()):
        raise ValueError('Phase 5D-R CT size provenance mismatch')
    ablation = R_ABLATION_ANALYSIS/'statistics.csv'
    core = R_CORE_ANALYSIS/'statistics.csv'
    ct = PUBLIC_CT/'full_ct_paired.csv'
    full_ct=list(csv.DictReader(ct.open(newline='')))
    with (PUBLIC_CT/'full_ct_size.csv').open(newline='') as stream:
        constructions=list(csv.DictReader(stream))
    by_key={(int(r['ell']),int(r['actual_cmax']),r['mode']):r
            for r in constructions}
    if len(full_ct)!=20 or len(constructions)!=40 or len(by_key)!=40:
        raise ValueError('Phase 5D-R public CT size table incomplete')
    for row in full_ct:
        ell,cmax=int(row['ell']),int(row['actual_cmax'])
        a=by_key[(ell,cmax,'OCCURRENCE')]
        b=by_key[(ell,cmax,'ROW')]
        aa,bb=int(a['full_ct_wire_bytes']),int(b['full_ct_wire_bytes'])
        if (row['comparability']!='PAIRED_AF_SHAPE_MATCH' or
            a['af_slot_count']!=b['af_slot_count'] or
            a['af_slot_bytes']!=b['af_slot_bytes'] or
            int(row['occurrence_full_ct_bytes'])!=aa or
            int(row['row_full_ct_bytes'])!=bb or
            abs(float(row['reduction_percent'])-(bb-aa)/bb*100)>1e-9):
            raise ValueError('Phase 5D-R public CT size pair mismatch')
    return dict(validation=old, ablation=_read_old(ablation),
        core=_read_old(core), full_ct=full_ct,
        hashes={str(path): file_sha256(path) for path in (ablation, core, ct,
            PUBLIC_CT/'full_ct_size.csv', PUBLIC_CT/'PROVENANCE.json',
            R_ABLATION/'raw.jsonl',
            R_CORE/'raw.jsonl')})


def paired_summary(run: Path):
    checked = validate(run)
    frozen_code=json.loads((run/'CODE_MANIFEST.json').read_text())
    source_root=Path(frozen_code['source_root'])
    non_runtime={'baselines/phase5ds_report.py','baselines/phase5ds_figures.py'}
    for entry in frozen_code['files']:
        relative=entry['path']
        if (relative.endswith('.py') and not relative.startswith('tests/') and
            relative not in non_runtime and
            file_sha256(source_root/relative)!=entry['sha256']):
            raise ValueError('runtime Python source drift since paired acquisition: '+relative)
    rows = [json.loads(line) for line in (run/'raw.jsonl').read_text().splitlines()]
    forbidden={'uid','rh_id','mu','k0','k0q','delta_q','k_tok','k_rev',
        'sk_cap','rk','blob','stable_blob_digest','plaintext_rho',
        'plaintext_attribute'}
    def audit(value):
        if isinstance(value,dict):
            if forbidden.intersection(k.lower() for k in value):
                raise ValueError('paired artifact contains forbidden private field')
            for child in value.values(): audit(child)
        elif isinstance(value,list):
            for child in value: audit(child)
        elif isinstance(value,str) and ('SYNTHETIC-UID-' in value or
            'SYNTHETIC-OUTSIDER-' in value):
            raise ValueError('paired artifact contains user identifier')
    for row in rows: audit(row)
    matched={}
    for row in rows:
        metric=row['metrics']
        ti=metric['actual_tI']
        if (metric['tee_pairings']!=1 or metric['csp_pairings']!=1+ti or
            metric['tee_pairings']+metric['csp_pairings']!=2+ti or
            metric['finaldec_pairings']!=0):
            raise ValueError('paired pairing invariant mismatch')
        key=(row['configuration_id'],row['block'],row['sample'])
        matched.setdefault(key,[]).append(row)
    for group in matched.values():
        if (len(group)!=3 or
            any(len({r['metrics'][field] for r in group})!=1 for field in
                ('actual_tI','candidate_count','reconstruction_count')) or
            len({json.dumps(r['structural'],sort_keys=True) for r in group})!=1):
            raise ValueError('paired structure/witness cardinality drift across profiles')
    grouped = {}
    for row in rows:
        for metric, value in row['metrics'].items():
            if type(value) in (int,float):
                grouped.setdefault((row['configuration_id'], row['profile'],
                                    metric), []).append(value)
    summary = []
    config = {item['configuration_id']: item for item in
        json.loads((run/'PHASE5D_S_PLAN.json').read_text())['configurations']}
    for (config_id, profile, metric), values in sorted(grouped.items()):
        summary.append(dict(configuration_id=config_id,
            workload_id=config[config_id]['workload']['workload_id'],
            workload_name=config[config_id]['name'],
            ell=config[config_id]['workload']['ell'],
            d=config[config_id]['workload']['d'],
            cmax=config[config_id]['workload']['cmax'],
            shape=config[config_id]['workload']['policy_shape'], profile=profile,
            metric=metric, n=len(values), median=statistics.median(values),
            q1=percentile(values,.25), q3=percentile(values,.75),
            p95=percentile(values,.95)))
    return checked, rows, summary


def _claim(claim_id, metric, comparison, workload, configuration,
           mine, baseline, artifact, figure, allowed_wording,
           comparability='DIRECTLY_COMPARABLE'):
    return dict(claim_id=claim_id, metric=metric, comparison=comparison,
        workload=workload, configuration=configuration,
        myabe_value=mine, baseline_value=baseline,
        ratio=mine/baseline if baseline else None,
        absolute_delta=mine-baseline,
        comparability=comparability, artifact=str(artifact), figure=figure,
        allowed_wording=allowed_wording)


def claims(old, paired=None, paired_run=None):
    result = []
    abl = old['ablation']
    core = old['core']
    for ell, cmax in ((160,1),(160,4),(160,8)):
        for metric, fig in (('encrypt_ns','FIG_OCCURRENCE_ENCRYPT_RATIO'),
                            ('transform_ns','FIG_OCCURRENCE_TRANSFORM_RATIO'),
                            ('core_ct_bytes','FIG_OCCURRENCE_COMPONENT_SAVING')):
            select = lambda scheme: next(r['median'] for r in abl if
                r['config']['ell']==ell and r['config']['cmax']==cmax and
                r['scheme']==scheme and r['metric']==metric)
            mine, base = select('OCCURRENCE'), select('ROW')
            result.append(_claim(f'ABL-{ell}-{cmax}-{metric}', metric,
                'MyABE vs NoOccurrenceReuse internal ablation',
                'OR', f'ell={ell}; cmax={cmax}', mine, base,
                R_ABLATION_ANALYSIS/'statistics.csv', fig,
                'Same-backend internal ablation; lower measured '+metric+
                (' for MyABE.' if mine < base else ' for NoOccurrenceReuse.')))
    for row in old['full_ct']:
        ell,cmax=int(row['ell']),int(row['actual_cmax'])
        result.append(_claim(f'FULLCT-{ell}-{cmax}', 'canonical_full_ct_bytes',
            'MyABE vs NoOccurrenceReuse internal ablation', 'OR',
            f'ell={ell}; cmax={cmax}',
            int(row['occurrence_full_ct_bytes']),int(row['row_full_ct_bytes']),
            PUBLIC_CT/'full_ct_paired.csv','FIG_OCCURRENCE_CT_SAVING_PERCENT',
            'One paired EMULATED TEST construction per arm; full signed CT '
            'bytes include separate ablation encoding markers. No timing claim.',
            'STRUCTURAL_ONLY'))
    for ell in (10,40,80,100):
        for metric, fig in (('keygen_ns','FIG_CORE_KEYGEN_ABSOLUTE'),
            ('encrypt_ns','FIG_CORE_ENCRYPT_ABSOLUTE'),
            ('access_ns','FIG_CORE_ACCESS_ABSOLUTE'),
            ('ct_group_bytes','FIG_CORE_STORAGE_ABSOLUTE'),
            ('du_core_key_bytes','FIG_KEY_PLACEMENT'),
            ('access_pairings','FIG_MYABE_FABEO_RATIO')):
            select = lambda scheme: next(r['median'] for r in core if
                r['config']['ell']==ell and r['scheme']==scheme and
                r['metric']==metric)
            mine, base = select('MYABE08_BLS12381_CORE'),\
                         select('FABEO22_CP_BLS12381_TAU1')
            result.append(_claim(f'FABEO-{ell}-{metric}', metric,
                'MyABE core vs FABEO22 tau=1 common BLS', 'AND',
                f'ell={ell}; cmax=1', mine, base,
                R_CORE_ANALYSIS/'statistics.csv', fig,
                ('DU-local core key placement only; MyABE also holds TEE-side '
                 'state.' if metric=='du_core_key_bytes' else
                 'Common-backend tau=1 ABE core comparison only; '+
                 ('MyABE lower.' if mine < base else
                  'FABEO lower.' if mine > base else 'Equal recorded value.')),
                ('KEY_PLACEMENT_TRADEOFF' if metric=='du_core_key_bytes' else
                 'STRUCTURAL_ONLY' if metric in ('ct_group_bytes','access_pairings') else
                 'DIRECTLY_COMPARABLE')))
    if paired:
        lookup = {(r['configuration_id'],r['profile'],r['metric']): r
                  for r in paired}
        for r in paired:
            if r['profile']!='CORE' or r['metric']!='encrypt_ns':
                continue
            full = lookup[(r['configuration_id'],'FULL_EMULATED','encrypt_ns')]
            result.append(_claim('FEATURE-ENCRYPT-'+r['configuration_id'],
                'encrypt_ns','Full Emulated vs Core matched workload',
                r['workload_id'],f"ell={r['ell']}; cmax={r['cmax']}",
                full['median'],r['median'],
                paired_run/'raw.jsonl' if paired_run else 'PHASE5D_S_PAIRED',
                'FIG_MYABE_CORE_FULL_ENCRYPT',
                'Observed full-emulated Encrypt versus algebra-core Encrypt; '
                'includes additional protocol features.',
                'PAIRED_DIFFERENT_FEATURE_BOUNDARY'))
        for r in paired:
            if r['profile']!='FULL_EMULATED' or r['metric'] not in (
                    'encrypt_ns','request_e2e_ns'):
                continue
            real=lookup[(r['configuration_id'],'FULL_REAL_SGX',r['metric'])]
            result.append(_claim('DEPLOYMENT-'+r['metric']+'-'+r['configuration_id'],
                r['metric'],'Full SGX DEBUG feasibility vs Full Emulated',
                r['workload_id'],f"ell={r['ell']}; cmax={r['cmax']}",
                real['median'],r['median'],
                paired_run/'raw.jsonl' if paired_run else 'PHASE5D_S_PAIRED',
                'FIG_MYABE_CORE_FULL_ENCRYPT' if r['metric']=='encrypt_ns'
                else 'FIG_MYABE_CORE_FULL_ACCESS',
                'Observed deployment-profile delta; not pure SGX hardware overhead.',
                'OBSERVED_DEPLOYMENT_PROFILE_DELTA'))
    return result


def overheads(summary):
    """Only valid same-boundary ratios receive a numeric value."""
    lookup={(r['configuration_id'],r['profile'],r['metric']):r for r in summary}
    configurations={r['configuration_id']:(r['workload_id'],r['workload_name'],
                                          r['ell'],r['cmax'])
                    for r in summary}
    result=[]
    for config_id,(workload,workload_name,ell,cmax) in sorted(configurations.items()):
        for metric,first,second,classification in (
            ('encrypt_ns','CORE','FULL_EMULATED',
                'PAIRED_DIFFERENT_FEATURE_BOUNDARY'),
            ('encrypt_ns','FULL_EMULATED','FULL_REAL_SGX',
                'OBSERVED_DEPLOYMENT_PROFILE_DELTA'),
            ('request_e2e_ns','FULL_EMULATED','FULL_REAL_SGX',
                'OBSERVED_DEPLOYMENT_PROFILE_DELTA')):
            a,b=lookup[(config_id,first,metric)],lookup[(config_id,second,metric)]
            result.append(dict(configuration_id=config_id,workload_id=workload,
                workload_name=workload_name,
                ell=ell,cmax=cmax,metric=metric,reference_profile=first,
                comparison_profile=second,comparison_class=classification,
                reference_median_ns=a['median'],comparison_median_ns=b['median'],
                absolute_delta_ns=b['median']-a['median'],
                median_ratio=b['median']/a['median'],
                p95_ratio=b['p95']/a['p95'],
                ratio_name='feature_overhead_ratio' if first=='CORE'
                    else 'deployment_profile_ratio'))
        a=lookup[(config_id,'CORE','access_ns')]
        b=lookup[(config_id,'FULL_EMULATED','request_e2e_ns')]
        result.append(dict(configuration_id=config_id,workload_id=workload,
            workload_name=workload_name,
            ell=ell,cmax=cmax,metric='access',reference_profile='CORE',
            comparison_profile='FULL_EMULATED',
            comparison_class='NOT_DIRECTLY_COMPARABLE_STAGE_SUM_VS_WALLCLOCK',
            reference_median_ns=a['median'],comparison_median_ns=b['median'],
            absolute_delta_ns=None,median_ratio=None,p95_ratio=None,
            ratio_name='UNDEFINED'))
    return result


def _table(path,rows):
    with path.open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader();writer.writerows(rows)


def report(run: Path, output: Path):
    checked, raw, summary=paired_summary(run)
    old=sources()
    output.mkdir(parents=True,exist_ok=False)
    values=claims(old,summary,run)
    _table(output/'COMPARATIVE_CLAIMS_V1.csv',values)
    (output/'COMPARATIVE_CLAIMS_V1.json').write_text(
        json.dumps(values,sort_keys=True,indent=2)+'\n')
    over=overheads(summary)
    _table(output/'PAIRED_OVERHEADS.csv',over)
    (output/'PAIRED_OVERHEADS.json').write_text(
        json.dumps(over,sort_keys=True,indent=2)+'\n')
    counts={profile:sum(r['profile']==profile for r in raw) for profile in
            ('CORE','FULL_EMULATED','FULL_REAL_SGX')}
    validation_text=['# Phase 5D-S paired dataset validation','',
        f"- Run: `{run}`",
        f"- Raw SHA-256: `{checked['raw_sha256']}`",
        f"- Complete measured rows: {checked['rows']}",
        f"- Per-profile rows: {counts}",
        '- Per-configuration design: 5 warmups/profile, 20 measured/profile, 3 interleaved blocks (7/7/6).',
        '- All planned tuples present exactly once and in deterministic shuffled order.',
        '- Same SysID, PolicyContextID, matrix, row codes, attributes and message length per paired configuration.',
        '- All correctness, witness-cardinality and 2+tI pairing checks passed.',
        '- Runtime Python sources match the acquisition code manifest; existing 5D-R raw files revalidated.',
        '- Paired raw-artifact private-field/canary audit passed; outliers removed: 0.',
        '- Real SGX: DEBUG; QVL OUT_OF_DATE; strict RA2 BLOCKED; TEST current head.',
        '- The earlier mismatched-SysID pilot has ABORTED status and is excluded.','']
    (output/'DATASET_VALIDATION.md').write_text('\n'.join(validation_text)+'\n')
    claim={r['claim_id']:r for r in values}
    abl=claim['ABL-160-1-encrypt_ns']
    tr=claim['ABL-160-1-transform_ns']
    kg=claim['FABEO-100-keygen_ns']
    enc=claim['FABEO-100-encrypt_ns']
    acc=claim['FABEO-100-access_ns']
    ct=claim['FABEO-100-ct_group_bytes']
    full_ct=claim['FULLCT-160-1']
    exemplar=next(r for r in over if r['workload_name']=='W1-AND-10' and
                  r['ratio_name']=='feature_overhead_ratio')
    deployment=next(r for r in over if r['workload_name']=='W1-AND-10' and
                    r['ratio_name']=='deployment_profile_ratio' and
                    r['metric']=='encrypt_ns')
    conclusion=f"""# What does My-ABE gain? — Phase 5D-S

**CANDIDATE — FORMAL PROOF OPEN.** All numbers below come from the linked
canonical artifacts and `COMPARATIVE_CLAIMS_V1.csv`; no outlier was removed.

## 1. Directly measured advantages

- Same-backend internal ablation, OR, ell=160, cmax=1: global occurrence slots
  need 1 D component rather than 160 per-row D components. The core group
  encoding is {claim['ABL-160-1-core_ct_bytes']['myabe_value']:.0f} vs
  {claim['ABL-160-1-core_ct_bytes']['baseline_value']:.0f} bytes. This is an
  internal ablation, not an external scheme comparison.
- One paired EMULATED TEST public construction at ell=160,cmax=1 has full
  signed CT wire sizes {full_ct['myabe_value']:.0f} vs
  {full_ct['baseline_value']:.0f} bytes ({(1-full_ct['ratio'])*100:.2f}% lower).
  The ablation uses a separate TEST
  encoding marker, so the wire difference is not solely D payload bytes;
  there is no CT timing distribution in this size artifact.
- The same configuration's Encrypt median is {abl['myabe_value']/1e6:.3f} vs
  {abl['baseline_value']/1e6:.3f} ms (ratio {abl['ratio']:.3f}); Transform median
  is {tr['myabe_value']/1e6:.3f} vs {tr['baseline_value']/1e6:.3f} ms
  (ratio {tr['ratio']:.3f}). Its CSP pairing count is two in both arms;
  the difference cannot be attributed to fewer pairings.
- Common BLS12-381 tau=1 AND core at ell=100: MyABE KeyGen median
  {kg['myabe_value']/1e6:.3f} vs FABEO {kg['baseline_value']/1e6:.3f} ms.
  Core group bytes are {ct['myabe_value']:.0f} vs {ct['baseline_value']:.0f};
  this is a structural core encoding count, not a complete CT ratio.

## 2. Measured trade-offs

- At ell=100 the common-backend Encrypt medians are
  {enc['myabe_value']/1e6:.3f} vs {enc['baseline_value']/1e6:.3f} ms; the
  lower observed median belongs to {'MyABE' if enc['ratio']<1 else 'FABEO'}.
- FABEO authorized access is lower at ell=100: MyABE
  {acc['myabe_value']/1e6:.3f} vs FABEO {acc['baseline_value']/1e6:.3f} ms.
  This core comparison does not assert comparable full-system semantics.
- A matched W1-AND-10 Full Emulated Encrypt takes
  {exemplar['comparison_median_ns']/1e6:.3f} ms versus core Encrypt
  {exemplar['reference_median_ns']/1e6:.3f} ms, ratio
  {exemplar['median_ratio']:.3f}. The full path includes policy tokenization,
  AF, publication and DEM. This is a paired *different-feature-boundary*
  comparison. Core access is an exclusive stage sum, so its ratio to a
  continuous Full request is intentionally undefined.
- On the same W1-AND-10 public Encrypt boundary, real SGX feasibility versus
  Emulated has median ratio {deployment['median_ratio']:.3f}. This is an
  **observed deployment-profile delta**, not pure SGX hardware overhead.
  Setup/QVL preflight is excluded from these per-request measurements.
- MyABE's 32-byte DU local core scalar is accompanied by 128 bytes of
  TEE-side core state. It is a placement choice, not a claim that all
  per-user credentials, sealed blobs and public envelopes are smaller.

## 3. Still unproven or blocked

- HR-ABE local wall-clock comparison remains `BLOCKED_TYPE_MAPPING`.
- LUAR local wall-clock comparison remains `BLOCKED_CORRECTNESS` and
  `LITERATURE_REFERENCE_ONLY`.
- A production SGX comparison, current-TCB strict RA2, stable provisioning,
  persistent rollback-protected state, trusted time and a formal proof remain open.
- The same-user/same-CT stable W linkability disclosed in Phase 5C remains.
"""
    (output/'WHAT_DOES_MYABE_GAIN.md').write_text(conclusion)
    buckets="""# MYABE cost-bucket definition — Phase 5D-S

Timers use `perf_counter_ns`. Bucket labels are logical observations, not an
assertion that every stage forms a partition of a wall-clock interval.

| Bucket | Direct timer fields | Rule |
|---|---|---|
| ABE_CORE | `encrypt_encrypt_core_ns`, `authorize_rerandomization_ns`, `authorize_t0_pairing_ns`, `transform_authorized_subset_ns`, `transform_t_a_ns`, `finaldec_finaldec_crypto_ns` | Algebra stage hooks; the Core access metric is the sum of the latter five and excludes AF.Query. |
| ANON_TOKENIZATION | `encrypt_policy_token_ns`, `authorize_tokenization_ns` | Policy/user contextual tokenization. Policy timing includes channel/request work at the public boundary. |
| AF | `encrypt_af_build_ns`, `transform_af_query_ns` | AF Build/Query. |
| REVOCATION_AUTHORIZATION | `authorize_credential_verify_ns`, `authorize_state_coordination_ns`, `authorize_revset_lookup_ns` | Nested enclave stages; success path only. |
| CAP_PUBLICATION | `encrypt_publication_sign_ns`, `authorize_cap_sign_ns` | Publication and capability signatures. |
| RPC_TRANSPORT | `authorize_rpc_send_ns`, `authorize_rpc_receive_ns` | `rpc_receive_ns` overlaps enclave computation: **NON_ADDITIVE_OBSERVATION**. Emulated transport timings are unavailable, not zero. |
| DEM_FINAL | `encrypt_dem_encrypt_ns`, `finaldec_dem_decrypt_ns` | Byte-message wrapper. |
| UNATTRIBUTED_OVERHEAD | `encrypt_publication_other_ns` and residual public spans | Validation, serialization, dispatch and uninstrumented work. `publication_other_ns` is recorded as `max(0, publication_total - DEM - sign)`; it must not be treated as an exact additive partition if timing noise would make the raw residual negative. |

The full `request_e2e_ns` is a contiguous TEEAuthorize→Transform→FinalDec
host span. Core `access_ns` is an **EXCLUSIVE_ABE_STAGE_SUM_NOT_CONTIGUOUS_WALLCLOCK**;
its difference or ratio to `request_e2e_ns` is not a causal feature-overhead
estimate. Full Emulated / Full Real SGX is an observed deployment-profile
delta, not pure SGX hardware overhead. Figure bars are grouped, never stacked
across overlapping timers. `PAIRED_OVERHEADS.csv` defines median ratio as
the ratio of arm medians and p95 ratio as the ratio of arm p95 values; neither
is a paired-sample ratio percentile or a confidence interval.

The Core profile records the same structural message length but performs only
ABE KEM/recovery, not byte-message DEM. Its AF witness index is prepared
outside timed Core work; AF.Query executes inside the unchanged algebra helper
but its measured duration is excluded from `access_ns`. This is why Core
access is a stage sum and cannot be relabeled a continuous wall-clock request.

In `FIG_MYABE_COST_PLACEMENT`, the authorization bar is the public host-side
TEEAuthorize span including request preparation, RPC and enclave execution;
it is labeled "Auth", not a pure TEE execution cost. The individual SGX
enclave stages in `FIG_FEATURE_COST_BREAKDOWN` are measured in the Gramine
service. Canonical serialization is separately observed after construction
and is not added to the Encrypt wall-clock span.

QVL attestation preflight runs in Setup. Per-request `encrypt_ns` and
`request_e2e_ns` exclude that setup/preflight cost; therefore the deployment
ratio is not a complete lifecycle-cost comparison. No QVL preflight latency
is inferred from these per-request rows.
"""
    (output/'MYABE_COST_BUCKET_DEFINITION.md').write_text(buckets)
    table="""# System properties — scoped evidence, no score

`Blocked` means this Phase has no verified local claim. HR-ABE and LUAR cells
are architecture references only; paper claims are not imported as MYABE proofs.

| Property | MyABE-08 | FABEO22 tau=1 | HR-ABE paper | LUAR paper |
|---|---|---|---|---|
| CP-ABE | Yes | Yes | Yes | Yes |
| LSSS | Yes | Yes | Yes | Yes |
| Multi-use attributes | Yes | Partial (tau=1 measured) | Blocked | Blocked |
| Outsourced decrypt | Yes | Different model | Yes | Different model |
| TEE | Yes (DEBUG feasibility) | No | Yes (paper) | Different model |
| User revocation | Yes (exact TEST set) | No | Yes (paper) | Different model |
| Attribute revocation | No | No | Blocked | Yes (paper) |
| Access-time revoke | Yes (TEST current head) | No | Blocked | Different model |
| Periodic CT update | No | No | Blocked | Yes (paper) |
| Periodic DU key update | No | No | Blocked | Yes (paper) |
| Policy/attribute anonymization | Partial (contextual token equality leaks) | No | Blocked | Blocked |
| CSP sees stable user ID? | No in tested transcript | Different model | Blocked | Blocked |
| Trusted time | No | Different model | Assumed (paper) | Blocked |
| Rollback mechanism | No production mechanism | Different model | Assumed (paper) | Blocked |
| Formal proof | Open | Paper proof; local port not proved | Paper model only | Paper model only |
| Local fair benchmark | Paired TEST, core/ablation | Common BLS tau=1 core | Blocked | Blocked |
"""
    (output/'TABLE_SYSTEM_PROPERTIES.md').write_text(table)
    readme=f"""# Comparative story — Phase 5D-S

**What is My-ABE's measured advantage?** The same-backend internal ablation
shows that occurrence-rank slots reduce D components and the measured core
CT/Encrypt/Transform cost on the tested OR grid. A common-BLS tau=1 FABEO
comparison shows lower MyABE KeyGen and core group bytes at the cited AND
points. FABEO's authorized access is lower and remains visible in the figures.

## Occurrence-aware advantage

Global rank-slot sharing means `#D=cmax`, including cmax=1 on unique rows;
per-row NoOccurrenceReuse has `#D=ell`. See the component, ratio and full-CT
figures. The latter is a single-construction size observation.

## FABEO core comparison

Only BLS12-381 / py_ecc tau=1 AND core timings are directly compared.
MyABE/FABEO at ell=100: KeyGen {kg['ratio']:.3f}, Encrypt
{enc['ratio']:.3f}, authorized access {acc['ratio']:.3f}. Values above one
favor FABEO on that metric. MyABE DU-local key size and TEE-side state must
be read together. No cross-curve or full-system FABEO ratio is inferred.

## Cost of anonymity and revocation

The new Phase 5D-S rows use identical structural workloads across Core,
Full Emulated and Full SGX DEBUG feasibility profiles. Full Encrypt includes
tokenization, AF, publication and DEM; stage timings show where observed work
lands. Access Core is a non-contiguous stage sum, so no Core/Full access
feature-overhead ratio is issued. Full SGX vs Emulated is a deployment-profile
observation (W1-AND-10 Encrypt median ratio {deployment['median_ratio']:.3f}),
never pure SGX hardware overhead.

## Remaining external-baseline gap

HR-ABE `BLOCKED_TYPE_MAPPING`; LUAR `LITERATURE_REFERENCE_ONLY` after
`BLOCKED_CORRECTNESS`. The real SGX cohort is DEBUG, QVL OUT_OF_DATE and
strict RA2 BLOCKED. `CANDIDATE — FORMAL PROOF OPEN`; stable W linkability is
known. No Phase 6 work was performed.

Read `WHAT_DOES_MYABE_GAIN.md`, `COMPARATIVE_CLAIMS_V1.csv`,
`MYABE_COST_BUCKET_DEFINITION.md`, `TABLE_SYSTEM_PROPERTIES.md`, and the
figure source CSV/JSON before reusing a quantitative statement.

The run's `MANIFEST.json` is the immutable acquisition-start record;
`COMPLETION.json` is the authoritative final status and raw SHA-256.
"""
    (output/'README_COMPARATIVE_STORY.md').write_text(readme)
    (output/'VALIDATION.json').write_text(json.dumps(dict(status='PASS',
        paired=checked,phase5dr=old['validation'],outliers_removed=0,
        claims=len(values),overhead_rows=len(over),
        source_hashes=old['hashes']),sort_keys=True,indent=2)+'\n')
    return output


def write_claims(path: Path, values):
    path.mkdir(parents=True, exist_ok=False)
    with (path/'COMPARATIVE_CLAIMS_V1.csv').open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(values[0]))
        writer.writeheader(); writer.writerows(values)
    (path/'COMPARATIVE_CLAIMS_V1.json').write_text(
        json.dumps(values,sort_keys=True,indent=2)+'\n')


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    print(report(args.run,args.output))


if __name__=='__main__':
    main()
