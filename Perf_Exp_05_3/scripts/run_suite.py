#!/usr/bin/env python3
"""Run EXP-00..11 on the FABEO-defined MNT224/Charm profile."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from charm.toolbox.pairinggroup import G1, G2, GT, ZR, PairingGroup, pair  # noqa: E402

from Code.fxabe_05_3_exp import (  # noqa: E402
    FXABE053, NoOccurrenceFXABE, OperationCounts, TransformMetrics,
)
from Code.fxabe_05_3_exp.fx import FXIndex  # noqa: E402
from Code.fxabe_05_3_exp.storage import fxabe_ciphertext_bytes, recursive_group_bytes  # noqa: E402
from Perf_Exp_05_3.adapters import FABEOAdapter  # noqa: E402
from Perf_Exp_05_3.scripts.common import (  # noqa: E402
    base_row, derive_seed, dump_json, environment, load_yaml, timed, write_csv,
)
from Perf_Exp_05_3.workloads import (  # noqa: E402
    and_workload, duplicate_workload, or_workload, threshold_workload,
)


def _write(raw_dir, stem, rows):
    write_csv(raw_dir / (stem + ".csv"), rows)
    return rows


def _ops(row, ops):
    row.update(ops.as_dict())
    return row


def _prepare_fx(group, cls, workload, c_max, seed, message=b"FXABE-05.3 benchmark"):
    scheme = cls(group, user_capacity=2048, c_max=c_max, seed=seed)
    pp, msk = scheme.setup()
    static, private, recovery = scheme.keygen(
        pp, msk, "user-0", workload.user_attributes, "p1"
    )
    ku = scheme.rev_key_upt(pp, 1)
    sid = scheme.open_policy_session("owner", "p1", len(workload.policy["rho"]))
    metrics, ops = {}, OperationCounts()
    ct = scheme.encrypt(pp, msk, message, workload.policy, "p1", ku, sid,
                        ops=ops, metrics=metrics, fx_seed=derive_seed(seed, "fx"))
    return scheme, pp, msk, static, private, recovery, ku, ct, metrics, ops


def run_exp00(config, group, run_id, raw):
    rows = []
    repeats, warmups = int(config["exp00_repeats"]), int(config["warmup"])
    g1, g2, gt, scalar = group.random(G1), group.random(G2), group.random(GT), group.random(ZR)
    operations = [
        ("G1 exponentiation", lambda: g1 ** scalar, OperationCounts(G1_exp=1)),
        ("G2 exponentiation", lambda: g2 ** scalar, OperationCounts(G2_exp=1)),
        ("GT exponentiation", lambda: gt ** scalar, OperationCounts(GT_exp=1)),
        ("pairing", lambda: pair(g1, g2), OperationCounts(pair_count=1)),
        ("G1 multiplication", lambda: g1 * g1, OperationCounts()),
        ("G2 multiplication", lambda: g2 * g2, OperationCounts()),
        ("G1 serialization", lambda: group.serialize(g1), OperationCounts()),
        ("G2 serialization", lambda: group.serialize(g2), OperationCounts()),
        ("hash-to-G1", lambda: group.hash("FX53-micro-hash", G1), OperationCounts(G1_exp=0)),
    ]
    for name, fn, counts in operations:
        for _ in range(warmups):
            fn()
        for replicate in range(repeats):
            result, elapsed = timed(fn)
            size = len(result) if isinstance(result, bytes) else ""
            row = base_row(run_id, "EXP-00", "COMMON-PRIMITIVE", config["master_seed"],
                           replicate, phase=name, time_ns=elapsed,
                           serialized_bytes=size, component=name, notes="single real operation")
            rows.append(_ops(row, counts))
    return _write(raw, "exp00_group_ops", rows)


def run_exp01(config, group, run_id, raw):
    rows = []
    for ell in map(int, config["ell"]):
        workload = or_workload(group, ell, matched=1)
        cmax = min(8, max(1, ell))
        for scheme_name, cls in (("FXABE-05.3 Core", FXABE053),
                                 ("FXABE-NoOccurrence Core", NoOccurrenceFXABE)):
            seed = derive_seed(config["master_seed"], "EXP-01", scheme_name, ell)
            scheme = cls(group, user_capacity=8, c_max=cmax, seed=seed)
            pp, msk = scheme.setup()
            ku = scheme.rev_key_upt(pp, 1)
            for index in range(int(config["warmup"]) + int(config["repeats"])):
                sid = scheme.open_policy_session("owner", "p1", ell)
                metrics, ops = {}, OperationCounts()
                ct = scheme.encrypt(pp, msk, b"encrypt", workload.policy, "p1", ku, sid,
                                    metrics=metrics, ops=ops, fx_seed=derive_seed(seed, index))
                if index < int(config["warmup"]):
                    continue
                replicate = index - int(config["warmup"])
                core_ops = OperationCounts(G1_exp=2 * ell + 1,
                                           G2_exp=(cmax if cls is FXABE053 else ell),
                                           GT_exp=1)
                row = base_row(run_id, "EXP-01", scheme_name, seed, replicate, "OR",
                               ell=ell, u=ell, c_max=cmax, actual_c_star=1,
                               phase="Encrypt Core", time_ns=metrics["encrypt_core_ns"],
                               component="ABE Core", notes="D_count=%d" % len(ct["D"]))
                rows.append(_ops(row, core_ops))
                if cls is FXABE053:
                    components = [
                        ("Policy OPRF", metrics["policy_oprf_ns"]),
                        ("FX Build", metrics["fx_build_ns"]),
                        ("PStore Build", metrics["pstore_build_ns"]),
                        ("ABE Encrypt Core", metrics["encrypt_core_ns"]),
                        ("Revocation Encrypt", metrics["revocation_encrypt_ns"]),
                        ("Full Encrypt", metrics["encrypt_total_ns"]),
                    ]
                    for phase, elapsed in components:
                        rows.append(base_row(
                            run_id, "EXP-01", "FXABE-05.3 Full", seed, replicate, "OR",
                            ell=ell, u=ell, c_max=cmax, actual_c_star=1,
                            phase=phase, time_ns=elapsed, component=phase,
                            notes="offline/index-build" if phase != "Full Encrypt" else "total",
                        ))
        adapter = FABEOAdapter(group)
        (pk, msk), _ = adapter.setup()
        msg = group.random(GT)
        for _ in range(int(config["warmup"])):
            adapter.encrypt(pk, msg, workload.policy_string)
        for replicate in range(int(config["repeats"])):
            (ct, counts), elapsed = timed(lambda: adapter.encrypt(pk, msg, workload.policy_string))
            row = base_row(run_id, "EXP-01", "FABEO", config["master_seed"], replicate,
                           "OR", ell=ell, phase="Encrypt Core", time_ns=elapsed,
                           component="ABE Core", notes="official encrypt")
            rows.append(_ops(row, counts))
    return _write(raw, "exp01_encrypt", rows)


def run_exp02(config, group, run_id, raw):
    rows = []
    for ell in map(int, config["ell"]):
        workload = or_workload(group, ell, matched=1)
        cmax = min(8, ell)
        for name, cls in (("FXABE-05.3", FXABE053), ("FXABE-NoOccurrence", NoOccurrenceFXABE)):
            prepared = _prepare_fx(group, cls, workload, cmax,
                                   derive_seed(config["master_seed"], "EXP-02", name, ell))
            breakdown = fxabe_ciphertext_bytes(group, prepared[7])
            for component, size in breakdown.items():
                rows.append(base_row(run_id, "EXP-02", name, config["master_seed"], 0,
                                     "OR", ell=ell, u=ell, c_max=cmax, actual_c_star=1,
                                     phase="Storage", serialized_bytes=size, component=component,
                                     notes="canonical serialization"))
        adapter = FABEOAdapter(group)
        (pk, msk), _ = adapter.setup()
        ct, _ = adapter.encrypt(pk, group.random(GT), workload.policy_string)
        for component, size in adapter.ciphertext_bytes(ct).items():
            rows.append(base_row(run_id, "EXP-02", "FABEO", config["master_seed"], 0,
                                 "OR", ell=ell, phase="Storage", serialized_bytes=size,
                                 component=component, notes="group.serialize + canonical metadata"))
    return _write(raw, "exp02_storage", rows)


def run_exp03(config, group, run_id, raw):
    rows = []
    ell = max(map(int, config["transform_J"]))
    for J in map(int, config["transform_J"]):
        workload = or_workload(group, ell, matched=J)
        prepared = _prepare_fx(group, FXABE053, workload, 1,
                               derive_seed(config["master_seed"], "EXP-03", J))
        scheme, pp, _, static, private, recovery, ku, ct = prepared[:8]
        for _ in range(int(config["warmup"])):
            scheme.transform(pp, ct, static, private, ku, TransformMetrics())
        for replicate in range(int(config["repeats"])):
            metrics = TransformMetrics()
            transformed = scheme.transform(pp, ct, static, private, ku, metrics)
            if scheme.final_dec(pp, transformed, recovery) != b"FXABE-05.3 benchmark":
                raise AssertionError("EXP-03 decrypt")
            components = [
                ("FX Query", metrics.fx_query_ns),
                ("AuthorizedSubset", metrics.authorized_subset_ns),
                ("Transform Attribute", metrics.transform_attribute_ns),
                ("Transform Revocation", metrics.transform_revocation_ns),
                ("Transform Total", metrics.transform_total_ns),
            ]
            for phase, elapsed in components:
                row = base_row(run_id, "EXP-03", "FXABE-05.3", config["master_seed"],
                               replicate, "OR", ell=ell, u=ell, N=J, J=metrics.J,
                               k=metrics.k, t_I=metrics.t_I, c_max=1,
                               actual_c_star=1, phase=phase, time_ns=elapsed,
                               component=phase, notes="pair_count invariant")
                if phase == "Transform Total":
                    row = _ops(row, metrics.ops)
                rows.append(row)
    return _write(raw, "exp03_transform_vs_J", rows)


def run_exp04(config, group, run_id, raw):
    rows = []
    ell, cmax = 8, 8
    for target in map(int, config["t_I"]):
        workload = duplicate_workload(group, ell, target)
        prepared = _prepare_fx(group, FXABE053, workload, cmax,
                               derive_seed(config["master_seed"], "EXP-04", target))
        scheme, pp, _, static, private, recovery, ku, ct = prepared[:8]
        for _ in range(int(config["warmup"])):
            scheme.transform(pp, ct, static, private, ku, TransformMetrics())
        for replicate in range(int(config["repeats"])):
            metrics = TransformMetrics()
            transformed = scheme.transform(pp, ct, static, private, ku, metrics)
            if metrics.t_I != target or scheme.final_dec(pp, transformed, recovery) is None:
                raise AssertionError("EXP-04 t_I construction")
            row = base_row(run_id, "EXP-04", "FXABE-05.3", config["master_seed"],
                           replicate, "Duplicate-AND", ell=ell, u=ell // target,
                           N=ell // target, J=metrics.J, k=metrics.k, t_I=metrics.t_I,
                           c_max=cmax, actual_c_star=target, phase="Transform Total",
                           time_ns=metrics.transform_total_ns, component="Transform",
                           notes="fixed ell=J=k=c_max=8")
            rows.append(_ops(row, metrics.ops))
    return _write(raw, "exp04_transform_vs_tI", rows)


def run_exp05(config, group, run_id, raw):
    rows = []
    ell = 40
    workload = or_workload(group, ell, matched=1)
    for cmax in map(int, config["c_max"]):
        seed = derive_seed(config["master_seed"], "EXP-05", cmax)
        scheme = FXABE053(group, user_capacity=8, c_max=cmax, seed=seed)
        pp, msk = scheme.setup(); static, private, recovery = scheme.keygen(pp, msk, "u", [workload.policy["rho"][0]], "p1")
        ku = scheme.rev_key_upt(pp, 1)
        for index in range(int(config["warmup"]) + int(config["repeats"])):
            sid = scheme.open_policy_session("owner", "p1", ell)
            metrics, ops = {}, OperationCounts()
            ct = scheme.encrypt(pp, msk, b"cmax", workload.policy, "p1", ku, sid,
                                metrics=metrics, ops=ops, fx_seed=derive_seed(seed, index))
            tm = TransformMetrics(); tr = scheme.transform(pp, ct, static, private, ku, tm)
            if scheme.final_dec(pp, tr, recovery) != b"cmax": raise AssertionError("EXP-05")
            if index < int(config["warmup"]): continue
            replicate = index - int(config["warmup"])
            sizes = fxabe_ciphertext_bytes(group, ct)
            for phase, elapsed, size in (
                ("Encrypt Core", metrics["encrypt_core_ns"], ""),
                ("Storage", 0, sizes["total_CT_bytes"]),
                ("Transform Total", tm.transform_total_ns, ""),
            ):
                row = base_row(run_id, "EXP-05", "FXABE-05.3", seed, replicate, "OR",
                               ell=ell, u=ell, N=1, J=1, k=1, t_I=1, c_max=cmax,
                               actual_c_star=1, phase=phase, time_ns=elapsed,
                               serialized_bytes=size, component=phase,
                               notes="G2_D_count=%d" % len(ct["D"]))
                if phase == "Encrypt Core": row.update(G1_exp=2*ell+1, G2_exp=cmax, GT_exp=1, pair_count=0)
                if phase == "Transform Total": row = _ops(row, tm.ops)
                rows.append(row)
    return _write(raw, "exp05_cmax", rows)


def _fx_entries(u, posting_len=1):
    entries = {}
    row = 1
    for i in range(int(u)):
        token = ("token-%08d" % i).encode()
        entries[token] = tuple(range(row, row + posting_len))
        row += posting_len
    return entries, row - 1


def run_exp06(config, _group, run_id, raw):
    rows = []
    for u in map(int, config["fx_u"]):
        entries, ell = _fx_entries(u)
        ctx = ("EXP06-%d" % u).encode()
        for _ in range(int(config["warmup"])):
            FXIndex.build(entries, ctx, ell, seed=derive_seed(config["master_seed"], u, "w"))
        for replicate in range(int(config["repeats"])):
            index = FXIndex.build(entries, ctx, ell,
                                  seed=derive_seed(config["master_seed"], "EXP-06", u, replicate))
            m = index.build_metrics
            accounting = index.accounting()
            for phase, elapsed, size in (
                ("FX Build", m["total_ns"] - m["pstore_build_ns"], accounting["FX_slot_bytes"] + accounting["FX_metadata_bytes"]),
                ("PStore Build", m["pstore_build_ns"], accounting["PStore_ciphertext_bytes"] + accounting["PStore_nonce_bytes"]),
                ("FX+PStore Build", m["total_ns"], accounting["FX_PStore_serialized_bytes"]),
            ):
                rows.append(base_row(run_id, "EXP-06", "FXABE-05.3", config["master_seed"],
                                     replicate, "Distinct tokens", ell=ell, u=u,
                                     phase=phase, time_ns=elapsed, serialized_bytes=size,
                                     component=phase, notes=json.dumps({
                                         "retry": m["retry"], "slot_count": m["slot_count"],
                                         "load_factor": m["load_factor"],
                                     }, sort_keys=True)))
    return _write(raw, "exp06_fx_build", rows)


def run_exp07(config, _group, run_id, raw):
    rows = []
    u, posting_len = 64, 4
    entries, ell = _fx_entries(u, posting_len)
    ctx = b"EXP07-query-context"
    index = FXIndex.build(entries, ctx, ell, seed=config["master_seed"])
    tokens = list(entries)
    for N in map(int, config["query_N"]):
        chosen = tokens[:N]
        for _ in range(int(config["warmup"])):
            for token in chosen: index.query(token, ctx)
        for replicate in range(int(config["repeats"])):
            totals = {key: 0 for key in ("retrieval_ns", "short_check_ns", "pstore_aead_ns", "posting_decode_ns", "total_ns")}
            for token in chosen:
                result = index.query(token, ctx)
                if not result.hit: raise AssertionError("EXP-07 hit")
                for key in totals: totals[key] += result.metrics[key]
            phases = [
                ("FX Retrieval", totals["retrieval_ns"]),
                ("Short Check", totals["short_check_ns"]),
                ("PStore AEAD", totals["pstore_aead_ns"]),
                ("Posting Decode", totals["posting_decode_ns"]),
                ("Query Total", totals["total_ns"]),
            ]
            for phase, elapsed in phases:
                rows.append(base_row(run_id, "EXP-07", "FXABE-05.3", config["master_seed"],
                                     replicate, "all-hit", ell=ell, u=u, N=N,
                                     J=N*posting_len, phase=phase, time_ns=elapsed,
                                     component=phase, notes="L_hit=%d" % (N*posting_len)))
    return _write(raw, "exp07_fx_query", rows)


def run_exp08_09(config, group, run_id, raw):
    e2e, anonymity = [], []
    for ell in map(int, config["e2e_ell"]):
        matched = min(16, ell)
        workload = or_workload(group, ell, matched=matched)
        cmax = min(8, ell)
        seed = derive_seed(config["master_seed"], "EXP-08", ell)
        for index in range(int(config["warmup"]) + int(config["repeats"])):
            scheme = FXABE053(group, user_capacity=8, c_max=cmax, seed=derive_seed(seed, index))
            setup_started = perf_counter_ns(); pp, msk = scheme.setup(); setup_ns = perf_counter_ns()-setup_started
            key_started = perf_counter_ns(); static, private, recovery = scheme.keygen(pp, msk, "u", workload.user_attributes, "p1"); key_ns=perf_counter_ns()-key_started
            rev_t = {}; ku = scheme.rev_key_upt(pp, 1, timings=rev_t)
            sid = scheme.open_policy_session("owner", "p1", ell)
            em = {}; ct = scheme.encrypt(pp, msk, b"e2e", workload.policy, "p1", ku, sid,
                                         metrics=em, fx_seed=derive_seed(seed,index,"fx"))
            tm=TransformMetrics(); tr=scheme.transform(pp,ct,static,private,ku,tm)
            ft={}; out=scheme.final_dec(pp,tr,recovery,timings=ft)
            if out != b"e2e": raise AssertionError("EXP-08")
            if index < int(config["warmup"]): continue
            replicate=index-int(config["warmup"])
            phases = [
                ("Setup", setup_ns, "offline"), ("KeyGen Crypto + User OPRF", key_ns, "offline/epoch-bound"),
                ("RevKeyUpt", rev_t["total_ns"], "epoch-bound"),
                ("Policy OPRF", em["policy_oprf_ns"], "encrypt/index-build"),
                ("FX Build", em["fx_build_ns"], "encrypt/index-build"),
                ("PStore Build", em["pstore_build_ns"], "encrypt/index-build"),
                ("ABE Encrypt Core", em["encrypt_core_ns"], "encrypt"),
                ("FX Query", tm.fx_query_ns, "online"),
                ("AuthorizedSubset", tm.authorized_subset_ns, "online"),
                ("Transform Attribute", tm.transform_attribute_ns, "online"),
                ("Transform Revocation", tm.transform_revocation_ns, "online"),
                ("FinalDec", ft["total_ns"], "online/client"),
            ]
            for phase, elapsed, lifecycle in phases:
                e2e.append(base_row(run_id,"EXP-08","FXABE-05.3 Full",seed,replicate,"OR",
                                    ell=ell,u=ell,N=matched,J=tm.J,k=tm.k,t_I=tm.t_I,c_max=cmax,
                                    actual_c_star=1,phase=phase,time_ns=elapsed,component=phase,
                                    notes=lifecycle))
            extra = em["policy_oprf_ns"] + em["fx_build_ns"] + em["pstore_build_ns"]
            full = em["encrypt_core_ns"] + extra
            for phase, elapsed in (("FXABE Core", em["encrypt_core_ns"]),
                                   ("OPRF + FX/PStore", extra), ("FXABE Full", full)):
                anonymity.append(base_row(run_id,"EXP-09","FXABE-05.3",seed,replicate,"OR",
                                          ell=ell,u=ell,N=matched,J=tm.J,k=tm.k,t_I=tm.t_I,
                                          c_max=cmax,actual_c_star=1,phase=phase,time_ns=elapsed,
                                          component=phase,notes="overhead_pct=%.6f" % (100.0*extra/em["encrypt_core_ns"])))
    # Representative non-OR full-lifecycle workloads. These are not folded
    # into the FABEO fair-comparison figure because its official API accepts
    # Boolean AND/OR policies, not an externally injected threshold MSP.
    representative_ell = min(map(int, config["e2e_ell"]))
    representatives = [
        and_workload(group, representative_ell),
        threshold_workload(group, representative_ell, representative_ell // 2),
    ]
    for workload in representatives:
        seed = derive_seed(config["master_seed"], "EXP-08", workload.name, representative_ell)
        cmax = min(8, representative_ell)
        for index in range(int(config["warmup"]) + int(config["repeats"])):
            prepared = _prepare_fx(group, FXABE053, workload, cmax,
                                   derive_seed(seed, index), message=b"e2e-non-or")
            scheme, pp, _, static, private, recovery, ku, ct, em = prepared[:9]
            tm = TransformMetrics(); tr = scheme.transform(pp, ct, static, private, ku, tm)
            ft = {}; out = scheme.final_dec(pp, tr, recovery, timings=ft)
            if out != b"e2e-non-or": raise AssertionError("EXP-08 non-OR")
            if index < int(config["warmup"]): continue
            replicate = index - int(config["warmup"])
            phases = [
                ("Policy OPRF", em["policy_oprf_ns"], "encrypt/index-build"),
                ("FX Build", em["fx_build_ns"], "encrypt/index-build"),
                ("PStore Build", em["pstore_build_ns"], "encrypt/index-build"),
                ("ABE Encrypt Core", em["encrypt_core_ns"], "encrypt"),
                ("FX Query", tm.fx_query_ns, "online"),
                ("AuthorizedSubset", tm.authorized_subset_ns, "online"),
                ("Transform Attribute", tm.transform_attribute_ns, "online"),
                ("Transform Revocation", tm.transform_revocation_ns, "online"),
                ("FinalDec", ft["total_ns"], "online/client"),
            ]
            for phase, elapsed, lifecycle in phases:
                e2e.append(base_row(
                    run_id, "EXP-08", "FXABE-05.3 Full", seed, replicate, workload.name,
                    ell=representative_ell, u=len(set(workload.policy["rho"])),
                    N=len(workload.user_attributes), J=tm.J, k=tm.k, t_I=tm.t_I,
                    c_max=cmax, actual_c_star=1, phase=phase, time_ns=elapsed,
                    component=phase, notes=lifecycle + "; representative non-OR",
                ))
    _write(raw,"exp08_e2e_breakdown",e2e)
    _write(raw,"exp09_anonymity_overhead",anonymity)
    return e2e, anonymity


def _register_tree_users(scheme, n):
    for i in range(int(n)):
        scheme.state["tree"].register("u-%d" % i)


def _rev_sample(group, n, revoked, seed):
    scheme=FXABE053(group,user_capacity=n,c_max=1,seed=seed); pp,msk=scheme.setup()
    _register_tree_users(scheme,n)
    for i in range(revoked): scheme.rev("u-%d" % i,1)
    metrics={}; ops=OperationCounts(); ku=scheme.rev_key_upt(pp,1,ops=ops,timings=metrics)
    return scheme,pp,msk,ku,metrics,ops


def run_exp10(config, group, run_id, raw):
    rows=[]; repeats=int(config["repeats"]); warm=int(config["warmup"])
    for n in map(int,config["rev_n"]):
        revoked=max(1,int(round(n*0.05)))
        for index in range(warm+repeats):
            sample=_rev_sample(group,n,revoked,derive_seed(config["master_seed"],"EXP-10-n",n,index))
            if index<warm: continue
            _,_,_,ku,m,ops=sample; rep=index-warm
            ku_bytes=recursive_group_bytes(group,ku)
            for phase,elapsed,size in (("RevKeyUpt vs n",m["total_ns"],""),("Cover size",0,m["cover_size"]),("KU serialized bytes",0,ku_bytes)):
                row=base_row(run_id,"EXP-10","FXABE-05.3",config["master_seed"],rep,"Revocation",
                             n_users=n,n_revoked=revoked,phase=phase,time_ns=elapsed,
                             serialized_bytes=size,component=phase,notes="cover_size=%d"%m["cover_size"])
                if phase=="RevKeyUpt vs n": row=_ops(row,ops)
                rows.append(row)
    fixed_n=max(map(int,config["rev_n"]))
    for revoked in map(int,config["revoked"]):
        if revoked>=fixed_n: continue
        for index in range(warm+repeats):
            sample=_rev_sample(group,fixed_n,revoked,derive_seed(config["master_seed"],"EXP-10-r",revoked,index))
            if index<warm: continue
            _,_,_,ku,m,ops=sample; rep=index-warm
            for phase,elapsed,size in (("RevKeyUpt vs revoked",m["total_ns"],""),("Cover size vs revoked",0,m["cover_size"]),("KU bytes vs revoked",0,recursive_group_bytes(group,ku))):
                row=base_row(run_id,"EXP-10","FXABE-05.3",config["master_seed"],rep,"Revocation",
                             n_users=fixed_n,n_revoked=revoked,phase=phase,time_ns=elapsed,
                             serialized_bytes=size,component=phase,notes="cover_size=%d"%m["cover_size"])
                if phase.startswith("RevKeyUpt"): row=_ops(row,ops)
                rows.append(row)
    # Real Transform with a fixed active user; only cover lookup changes.
    n=min(128,fixed_n); workload=or_workload(group,20,matched=1)
    for revoked in [x for x in map(int,config["revoked"]) if x<n]:
        seed=derive_seed(config["master_seed"],"EXP-10-transform",revoked)
        scheme=FXABE053(group,user_capacity=n,c_max=1,seed=seed); pp,msk=scheme.setup()
        static,private,recovery=scheme.keygen(pp,msk,"active",workload.user_attributes,"p1")
        for i in range(1,n): scheme.state["tree"].register("u-%d"%i)
        for i in range(1,revoked+1): scheme.rev("u-%d"%i,1)
        ku=scheme.rev_key_upt(pp,1); sid=scheme.open_policy_session("owner","p1",20)
        ct=scheme.encrypt(pp,msk,b"rev",workload.policy,"p1",ku,sid,fx_seed=seed)
        for _ in range(warm): scheme.transform(pp,ct,static,private,ku,TransformMetrics())
        for rep in range(repeats):
            tm=TransformMetrics(); tr=scheme.transform(pp,ct,static,private,ku,tm)
            if scheme.final_dec(pp,tr,recovery)!=b"rev": raise AssertionError("EXP-10 transform")
            row=base_row(run_id,"EXP-10","FXABE-05.3",seed,rep,"OR",ell=20,u=20,N=1,J=1,k=1,t_I=1,c_max=1,
                         actual_c_star=1,n_users=n,n_revoked=revoked,phase="Transform vs revoked",
                         time_ns=tm.transform_total_ns,component="Transform",notes="active user excluded")
            rows.append(_ops(row,tm.ops))
    # PrivacyKeyUpt real scaling; token issuance is epoch-bound and not charged to Transform.
    for S in map(int,config["privacy_S"]):
        attrs=["S%04d"%i for i in range(S)]
        scheme=FXABE053(group,user_capacity=4,c_max=1,seed=derive_seed(config["master_seed"],"privacy",S)); pp,msk=scheme.setup()
        scheme.keygen(pp,msk,"u",attrs,"p1")
        for _ in range(warm): scheme.privacy_key_upt(pp,msk,"u","warm")
        for rep in range(repeats):
            ops=OperationCounts(); _,elapsed=timed(lambda:scheme.privacy_key_upt(pp,msk,"u","p%d"%rep,ops=ops))
            row=base_row(run_id,"EXP-10","FXABE-05.3",config["master_seed"],rep,"Privacy update",
                         N=S,phase="PrivacyKeyUpt vs |S|",time_ns=elapsed,component="PrivacyKeyUpt",
                         notes="offline epoch-bound")
            rows.append(_ops(row,ops))
    # Dual vs coupled, both executed: coupled additionally refreshes all active users.
    n=32; revoked=4; attrs=["A0","A1","A2","A3"]
    for sample_index in range(warm + repeats):
        rep = sample_index - warm
        for model in ("Dual-Epoch","Coupled-Epoch"):
            seed=derive_seed(config["master_seed"],"epoch-model",model,sample_index)
            scheme=FXABE053(group,user_capacity=n,c_max=1,seed=seed); pp,msk=scheme.setup()
            for i in range(n): scheme.keygen(pp,msk,"u-%d"%i,attrs,"p1")
            for i in range(revoked): scheme.rev("u-%d"%i,1)
            started=perf_counter_ns(); scheme.rev_key_upt(pp,1)
            if model=="Coupled-Epoch":
                for i in range(revoked,n): scheme.privacy_key_upt(pp,msk,"u-%d"%i,"p2")
            elapsed=perf_counter_ns()-started
            if sample_index < warm:
                continue
            rows.append(base_row(run_id,"EXP-10","FXABE-05.3",seed,rep,"Epoch model",
                                 n_users=n,n_revoked=revoked,phase=model,time_ns=elapsed,
                                 component="Dual vs Coupled",notes="real active-user refresh"))
    return _write(raw,"exp10_revocation",rows)


def run_exp11(config, group, run_id, raw):
    rows=[]
    warm=int(config["warmup"]); repeats=int(config["repeats"])
    for ell in map(int,config["core_ell"]):
        workload=or_workload(group,ell,matched=1); cmax=min(8,ell)
        for name,cls in (("FXABE-05.3 Core",FXABE053),("FXABE-NoOccurrence Core",NoOccurrenceFXABE)):
            seed=derive_seed(config["master_seed"],"EXP-11",name,ell)
            for sample_index in range(warm+repeats):
                rep=sample_index-warm
                scheme=cls(group,user_capacity=8,c_max=cmax,seed=derive_seed(seed,sample_index))
                so=OperationCounts(); (pp,msk),setup_ns=timed(lambda:scheme.setup(ops=so))
                ko=OperationCounts(); (static,private,recovery),key_ns=timed(lambda:scheme.keygen(pp,msk,"u",workload.user_attributes,"p1",ops=ko))
                ku=scheme.rev_key_upt(pp,1); sid=scheme.open_policy_session("owner","p1",ell)
                em={}; eo=OperationCounts(); ct=scheme.encrypt(pp,msk,b"core",workload.policy,"p1",ku,sid,ops=eo,metrics=em,fx_seed=derive_seed(seed,rep,"fx"))
                tm=TransformMetrics(); tr=scheme.transform(pp,ct,static,private,ku,tm)
                fo=OperationCounts(); ft={}; out=scheme.final_dec(pp,tr,recovery,ops=fo,timings=ft)
                if out!=b"core": raise AssertionError("EXP-11 FX")
                if sample_index < warm: continue
                sizes=fxabe_ciphertext_bytes(group,ct)
                key_bytes=recursive_group_bytes(group,{"static":static,"private":private,"recovery":recovery})
                transform_crypto_ns=tm.transform_attribute_ns+tm.transform_revocation_ns
                phases=[("Setup",setup_ns,so,""),("KeyGen",key_ns,ko,key_bytes),
                        ("Encrypt",em["encrypt_core_ns"],OperationCounts(G1_exp=2*ell+1,G2_exp=cmax if cls is FXABE053 else ell,GT_exp=1),sizes["total_CT_bytes"]),
                        ("Transform Crypto",transform_crypto_ns,tm.ops,""),
                        ("Transform",tm.transform_total_ns,tm.ops,""),("FinalDec",ft["total_ns"],fo,""),
                        ("Transform+FinalDec",tm.transform_total_ns+ft["total_ns"],OperationCounts(G1_exp=tm.ops.G1_exp,GT_exp=1,pair_count=tm.pair_count),"" )]
                for phase,elapsed,ops,size in phases:
                    row=base_row(run_id,"EXP-11",name,seed,rep,"OR",ell=ell,u=ell,N=1,J=tm.J,k=tm.k,t_I=tm.t_I,c_max=cmax,
                                 actual_c_star=1,phase=phase,time_ns=elapsed,serialized_bytes=size,component=phase,
                                 notes="key_bytes" if phase=="KeyGen" else "")
                    rows.append(_ops(row,ops))
        adapter=FABEOAdapter(group); msg=group.random(GT)
        for sample_index in range(warm+repeats):
            rep=sample_index-warm
            ((pk,msk),so),setup_ns=timed(adapter.setup)
            (key,ko),key_ns=timed(lambda:adapter.keygen(pk,msk,workload.user_attributes))
            (ct,eo),enc_ns=timed(lambda:adapter.encrypt(pk,msg,workload.policy_string))
            (out,do),dec_ns=timed(lambda:adapter.decrypt(pk,ct,key))
            if out!=msg: raise AssertionError("EXP-11 FABEO")
            if sample_index < warm: continue
            sizes=adapter.ciphertext_bytes(ct); key_bytes=adapter.key_bytes(key)
            for phase,elapsed,ops,size in (("Setup",setup_ns,so,""),("KeyGen",key_ns,ko,key_bytes),
                                           ("Encrypt",enc_ns,eo,sizes["total_CT_bytes"]),("Decrypt",dec_ns,do,"")):
                row=base_row(run_id,"EXP-11","FABEO",config["master_seed"],rep,"OR",ell=ell,
                             phase=phase,time_ns=elapsed,serialized_bytes=size,component=phase,
                             notes="official lifecycle")
                rows.append(_ops(row,ops))
    return _write(raw,"exp11_fabeo_core",rows)


def write_feature_table(root):
    rows=[
        {"scheme":"FABEO","policy-label semantic hiding":"No","user-attribute semantic hiding":"No","FX anonymous lookup":"No","outsourced decryption":"No","DU lightweight finalization":"No","user revocation":"No","dual epoch":"No","ciphertext G1 elements":"ell","ciphertext G2 elements":"2","pairings":"3 (official decrypt)","token lifecycle":"N/A"},
        {"scheme":"FXABE-05.3","policy-label semantic hiding":"Yes (stated boundary)","user-attribute semantic hiding":"Yes (stated boundary)","FX anonymous lookup":"Yes","outsourced decryption":"Yes","DU lightweight finalization":"Yes","user revocation":"Yes","dual epoch":"Yes","ciphertext G1 elements":"ell+2","ciphertext G2 elements":"c_max","pairings":"3+t_I","token lifecycle":"user offline epoch-bound; policy at Encrypt"},
    ]
    import csv
    with open(root/"feature_comparison.csv","w",newline="",encoding="utf-8") as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


RUNNERS=[run_exp00,run_exp01,run_exp02,run_exp03,run_exp04,run_exp05,run_exp06,run_exp07,run_exp08_09,run_exp10,run_exp11]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",required=True); parser.add_argument("--run-id",required=True)
    parser.add_argument("--resume",action="store_true",help="continue a partial run without overwriting completed raw CSVs")
    args=parser.parse_args(); config=load_yaml(args.config)
    if config["mode"]=="full":
        raise SystemExit("Full is gated and intentionally not run automatically; use the explicit full runner only after FULL_READY=YES")
    run_root=ROOT/"Perf_Exp_05_3"/"results"/args.run_id
    if run_root.exists() and not args.resume: raise SystemExit("result directory exists: %s"%run_root)
    raw=run_root/"raw"
    for directory in (raw,run_root/"aggregated",run_root/"plots",run_root/"logs"):
        directory.mkdir(parents=True,exist_ok=args.resume)
    group=PairingGroup(config["curve"])
    if group.groupType()!="MNT224" or config["backend"]!="Charm-Crypto/PBC":
        raise SystemExit("COMMON_BENCHMARK_PROFILE mismatch")
    if not args.resume or not (run_root/"correctness.json").exists():
        dump_json(run_root/"environment.json",environment(group,args.config))
        shutil.copy2(args.config,run_root/"config_snapshot.yaml")
        gate=subprocess.run([sys.executable,"-m","pytest","-q","Perf_Exp_05_3/tests/test_correctness.py"],cwd=str(ROOT),text=True,capture_output=True)
        correctness={"success":gate.returncode==0,"stdout":gate.stdout,"stderr":gate.stderr}
        dump_json(run_root/"correctness.json",correctness)
        if gate.returncode: raise SystemExit("correctness gate failed")
    timings={}
    outputs={
        "run_exp00":["exp00_group_ops.csv"],"run_exp01":["exp01_encrypt.csv"],
        "run_exp02":["exp02_storage.csv"],"run_exp03":["exp03_transform_vs_J.csv"],
        "run_exp04":["exp04_transform_vs_tI.csv"],"run_exp05":["exp05_cmax.csv"],
        "run_exp06":["exp06_fx_build.csv"],"run_exp07":["exp07_fx_query.csv"],
        "run_exp08_09":["exp08_e2e_breakdown.csv","exp09_anonymity_overhead.csv"],
        "run_exp10":["exp10_revocation.csv"],"run_exp11":["exp11_fabeo_core.csv"],
    }
    for runner in RUNNERS:
        if args.resume and all((raw/name).exists() for name in outputs[runner.__name__]):
            print("%s SKIP completed raw"%runner.__name__,flush=True);continue
        started=perf_counter_ns(); runner(config,group,args.run_id,raw); timings[runner.__name__]=perf_counter_ns()-started
        print("%s PASS %.3fs"%(runner.__name__,timings[runner.__name__]/1e9),flush=True)
    write_feature_table(run_root)
    dump_json(run_root/"logs"/"timings.json",timings)
    dump_json(run_root/"metadata.json",{"run_id":args.run_id,"mode":config["mode"],"experiments":"EXP-00..11","full_run":False})
    print("RAW_COMPLETE",run_root,flush=True)


if __name__=="__main__": main()
