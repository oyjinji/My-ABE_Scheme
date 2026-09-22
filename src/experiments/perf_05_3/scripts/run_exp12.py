#!/usr/bin/env python3
"""Run the isolated EXP-12 policy-OPRF distinct-token sensitivity experiment."""

import argparse
import json
import math
import shutil
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from charm.toolbox.pairinggroup import PairingGroup

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from Code.fxabe_05_3_exp import FXABE053, OperationCounts, TransformMetrics  # noqa: E402
from Code.fxabe_05_3_exp.storage import fxabe_ciphertext_bytes  # noqa: E402
from Perf_Exp_05_3.scripts.aggregate import aggregate_file  # noqa: E402
from Perf_Exp_05_3.scripts.common import (base_row, derive_seed, dump_json, environment,
                                          load_yaml, write_csv)  # noqa: E402
from Perf_Exp_05_3.workloads import distinct_token_workload  # noqa: E402


def op_row(row, counts):
    row.update(counts.as_dict())
    return row


def legal_points(config):
    ell, cmax = int(config["ell"]), int(config["c_max"])
    requested = [int(x) for x in config["requested_u"]]
    legal = [u for u in requested if 1 <= u <= ell and math.ceil(ell / u) <= cmax]
    excluded = [u for u in requested if u not in legal]
    if not legal:
        raise ValueError("no legal u satisfies ceil(ell/u) <= c_max")
    return legal, excluded


def run(config_path, run_id):
    config = load_yaml(config_path)
    run_root = ROOT / "Perf_Exp_05_3/results" / run_id
    if run_root.exists():
        raise SystemExit(f"result directory exists: {run_root}")
    for child in ("raw", "aggregated", "plots", "logs"):
        (run_root / child).mkdir(parents=True)
    group = PairingGroup(config["curve"])
    if group.groupType() != "MNT224" or config["backend"] != "Charm-Crypto/PBC":
        raise SystemExit("COMMON_BENCHMARK_PROFILE mismatch")
    dump_json(run_root / "environment.json", environment(group, config_path))
    shutil.copy2(config_path, run_root / "config_snapshot.yaml")
    legal, excluded = legal_points(config)
    ell, cmax = int(config["ell"]), int(config["c_max"])
    warm, repeats = int(config["warmup"]), int(config["repeats"])
    message = b"X" * int(config["message_bytes"])
    raw_rows, gate = [], []
    for u in legal:
        workload = distinct_token_workload(group, ell, u)
        multiplicities = Counter(workload.policy["rho"])
        actual = max(multiplicities.values())
        if actual > cmax:
            raise AssertionError("invalid occurrence multiplicity")
        seed = derive_seed(config["master_seed"], "EXP-12", ell, u)
        scheme = FXABE053(group, user_capacity=8, c_max=cmax, seed=seed)
        pp, msk = scheme.setup()
        static, private, recovery = scheme.keygen(pp, msk, "exp12-user", workload.user_attributes, "p1")
        ku = scheme.rev_key_upt(pp, 1)
        last = None
        for index in range(warm + repeats):
            sid = scheme.open_policy_session("exp12-owner", "p1", ell)
            metrics, ops = {}, OperationCounts()
            ct = scheme.encrypt(pp, msk, message, workload.policy, "p1", ku, sid,
                                metrics=metrics, ops=ops,
                                fx_seed=derive_seed(seed, "fx", index))
            sizes = fxabe_ciphertext_bytes(group, ct)
            if metrics["actual_c_star"] != actual or len(ct["D"]) != cmax or ct["index"].has_exact_locator():
                raise AssertionError("EXP-12 invariant")
            last = ct
            if index < warm:
                continue
            replicate = index - warm
            common = dict(ell=ell, u=u, k=1, c_max=cmax, actual_c_star=actual,
                          posting_min=min(multiplicities.values()),
                          posting_max=max(multiplicities.values()),
                          posting_mean=ell / u,
                          FX_bytes=sizes["FX_slot_bytes"] + sizes["FX_metadata_bytes"],
                          PStore_bytes=sizes["PStore_ciphertext_bytes"] + sizes["PStore_nonce_bytes"],
                          posting_payload_bytes=sizes["posting_payload_bytes"],
                          total_ciphertext_bytes=sizes["total_CT_bytes"])
            phases = (
                ("Policy OPRF", metrics["policy_oprf_ns"], OperationCounts(G1_exp=3 * u)),
                ("FX Build", metrics["fx_build_ns"], OperationCounts()),
                ("PStore Build", metrics["pstore_build_ns"], OperationCounts()),
                ("ABE Encrypt Core", metrics["encrypt_core_ns"],
                 OperationCounts(G1_exp=2 * ell + 1, G2_exp=cmax, GT_exp=1)),
                ("Encrypt Full", metrics["encrypt_total_ns"], ops),
            )
            for phase, elapsed, counts in phases:
                row = base_row(run_id, "EXP-12", "FXABE-05.3", seed, replicate,
                               "OR-Duplicate", phase=phase, time_ns=elapsed,
                               component=phase, notes="fixed ell; real occurrence ranks", **common)
                raw_rows.append(op_row(row, counts))
            for component, size in (("FX-ABF bytes", common["FX_bytes"]),
                                    ("PStore bytes", common["PStore_bytes"]),
                                    ("total ciphertext bytes", common["total_ciphertext_bytes"])):
                raw_rows.append(base_row(run_id, "EXP-12", "FXABE-05.3", seed, replicate,
                                         "OR-Duplicate", phase="Storage", serialized_bytes=size,
                                         component=component, notes="canonical serialization", **common))
        tm = TransformMetrics()
        transformed = scheme.transform(pp, last, static, private, ku, tm)
        recovered = scheme.final_dec(pp, transformed, recovery)
        gate.append({"u": u, "actual_c_star": actual, "D_count": len(last["D"]),
                     "pair_count": tm.pair_count, "t_I": tm.t_I,
                     "decrypt": recovered == message, "no_exact_locator": not last["index"].has_exact_locator()})
    raw_path = run_root / "raw/exp12_policy_u_raw.csv"
    write_csv(raw_path, raw_rows)
    aggregate_file(raw_path, run_root / "aggregated/exp12_policy_u_aggregated.csv")
    validation = {
        "status": "PASS" if all(x["decrypt"] and x["no_exact_locator"] and
                                  x["D_count"] == cmax and x["pair_count"] == 3 + x["t_I"]
                                  for x in gate) else "FAIL",
        "curve": "MNT224", "backend": "Charm-Crypto/PBC", "ell": ell,
        "c_max": cmax, "requested_u": config["requested_u"], "legal_u": legal,
        "excluded_illegal_u": excluded, "warmup": warm, "repeats": repeats,
        "raw_rows": len(raw_rows), "failed_rows": sum(r["success"] != True for r in raw_rows),
        "gates": gate,
    }
    dump_json(run_root / "validation.json", validation)
    dump_json(run_root / "metadata.json", {"experiment": "EXP-12", "supplemental": True,
                                            "standard_raw_modified": False,
                                            "legality_rule": "ceil(ell/u) <= c_max"})
    plots(run_root, raw_rows)
    analysis(run_root, raw_rows, validation)
    if validation["status"] != "PASS":
        raise SystemExit("EXP12_VALIDATION_FAIL")
    print(f"EXP12_PASS run={run_id} legal_u={legal} excluded={excluded} raw_rows={len(raw_rows)}")
    return run_root


def series(rows, phase, value="time_ns"):
    groups = defaultdict(list)
    for row in rows:
        if row["phase"] == phase and row.get(value) != "":
            groups[int(row["u"])].append(float(row[value]))
    return sorted((u, statistics.median(values)) for u, values in groups.items())


def plots(run_root, rows):
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    for phase in ("Policy OPRF", "FX Build", "PStore Build"):
        points = series(rows, phase)
        ax.plot([x for x, _ in points], [y / 1e6 for _, y in points], marker="o", label=phase)
    ax.set(xlabel="Distinct policy tokens u (ell=640)", ylabel="Median time (ms)",
           title="Policy OPRF and Anonymous Index Build vs u")
    ax.grid(alpha=.25); ax.legend(); fig.tight_layout()
    fig.savefig(run_root / "plots/12a_policy_oprf_vs_u.png", dpi=180); plt.close(fig)
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    for phase in ("Policy OPRF", "ABE Encrypt Core", "Encrypt Full"):
        points = series(rows, phase)
        ax.plot([x for x, _ in points], [y / 1e6 for _, y in points], marker="o", label=phase)
    ax.set(xlabel="Distinct policy tokens u (ell=640)", ylabel="Median time (ms)",
           title="Full Encryption Sensitivity to Distinct Tokens")
    ax.grid(alpha=.25); ax.legend(); fig.tight_layout()
    fig.savefig(run_root / "plots/12b_full_encrypt_vs_u.png", dpi=180); plt.close(fig)


def linear_r2(points):
    xs, ys = zip(*points); xm, ym = statistics.mean(xs), statistics.mean(ys)
    denom = sum((x - xm) ** 2 for x in xs)
    slope = sum((x - xm) * (y - ym) for x, y in points) / denom
    intercept = ym - slope * xm
    residual = sum((y - (intercept + slope * x)) ** 2 for x, y in points)
    total = sum((y - ym) ** 2 for y in ys)
    return slope, 1 - residual / total if total else 1.0


def analysis(run_root, rows, validation):
    phases = ("Policy OPRF", "FX Build", "PStore Build", "ABE Encrypt Core", "Encrypt Full")
    data = {phase: [(u, t / 1e6) for u, t in series(rows, phase)] for phase in phases}
    slope, r2 = linear_r2(data["Policy OPRF"])
    first, last = data["Policy OPRF"][0], data["Policy OPRF"][-1]
    driver = "u" if last[1] > first[1] * 4 and r2 >= .90 else "MIXED/INCONCLUSIVE"
    lines = ["# EXP-12 Policy OPRF vs Distinct Tokens", "",
             f"Validation: **{validation['status']}**. Fixed ell={validation['ell']}, c_max={validation['c_max']}; "
             f"legal u={validation['legal_u']}; excluded u={validation['excluded_illegal_u']} because "
             "`ceil(ell/u) > c_max`.", "",
             "| u | actual c* | Policy OPRF ms | FX Build ms | PStore Build ms | ABE Core ms | Full Encrypt ms | FX bytes | PStore bytes | total CT bytes |",
             "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for u in validation["legal_u"]:
        sample = next(r for r in rows if int(r["u"]) == u)
        vals = {phase: dict(data[phase])[u] for phase in phases}
        lines.append(f"| {u} | {sample['actual_c_star']} | {vals['Policy OPRF']:.3f} | {vals['FX Build']:.3f} | "
                     f"{vals['PStore Build']:.3f} | {vals['ABE Encrypt Core']:.3f} | {vals['Encrypt Full']:.3f} | "
                     f"{sample['FX_bytes']} | {sample['PStore_bytes']} | {sample['total_ciphertext_bytes']} |")
    lines += ["", f"The fixed-ell Policy OPRF fit has slope **{slope:.6f} ms/token** and R2 **{r2:.4f}**; "
              f"the observed main driver classification is **{driver}**. Because ell is fixed, the rise with u "
              "isolates distinct-token issuance rather than row count. ABE Core remains the row-dependent control.", "",
              "PStore has fewer records at lower u but longer posting lists; its encrypted payload therefore "
              "contains a fixed per-record AEAD tag plus row identifiers distributed among postings. FX-ABF bytes "
              "scale primarily with u. Whether Policy OPRF is the largest Full Encrypt component is reported per "
              "workload point rather than as a universal percentage.", "",
              "Occurrence semantics are unchanged: repeated labels receive ranks 1..actual_c_star, and every "
              "benchmarked point satisfies actual_c_star <= c_max."]
    docs = ROOT / "Perf_Exp_05_3/docs"
    (docs / "EXP12_POLICY_U_ANALYSIS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True); parser.add_argument("--run-id", required=True)
    args = parser.parse_args(); run(args.config, args.run_id)


if __name__ == "__main__":
    main()
