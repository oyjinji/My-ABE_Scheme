#!/usr/bin/env python3
"""Validate the selected critical Full experiments and all frozen invariants."""

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
from experiments.perf_05_3.scripts.common import SCHEMA, dump_json, read_csv  # noqa: E402


EXPECTED = {"exp01_encrypt.csv", "exp02_storage.csv", "exp03_transform_vs_J.csv",
            "exp04_transform_vs_tI.csv", "exp06_fx_build.csv", "exp07_fx_query.csv",
            "exp08_e2e_breakdown.csv", "exp09_anonymity_overhead.csv",
            "exp10_revocation.csv", "exp11_fabeo_core.csv"}


def integer(value):
    return None if value in (None, "") else int(float(value))


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("run_dir")
    args = parser.parse_args(); run = Path(args.run_dir).resolve()
    errors = []; files = {p.name: p for p in (run / "raw").glob("*.csv")}
    if set(files) != EXPECTED: errors.append(f"raw file set mismatch: {sorted(set(files) ^ EXPECTED)}")
    rows = []
    for path in files.values():
        current = read_csv(path); rows += current
        if not current or set(SCHEMA) - set(current[0]): errors.append(f"schema/empty: {path.name}")
    failed = [r for r in rows if r.get("success") != "True"]
    if failed: errors.append(f"{len(failed)} failed raw rows")
    profiles = {(r["curve"], r["backend"]) for r in rows}
    if profiles != {("MNT224", "Charm-Crypto/PBC")}: errors.append(f"profile mismatch: {profiles}")
    for r in rows:
        for key in ("time_ns", "serialized_bytes"):
            if r.get(key):
                try:
                    value = float(r[key])
                    if not math.isfinite(value) or value < 0: errors.append(f"invalid {key}: {r}")
                except ValueError: errors.append(f"non-numeric {key}: {r}")
        if r["phase"].startswith("Transform") and r.get("pair_count") and r.get("t_I") and r["scheme"].startswith("FXABE"):
            if integer(r["pair_count"]) != 3 + integer(r["t_I"]): errors.append("pair_count != 3+t_I")
        if r["experiment"] == "EXP-01" and r["phase"] == "Encrypt Core":
            if r["scheme"] == "FXABE-05.3 Core" and integer(r["G2_exp"]) != integer(r["c_max"]): errors.append("D_j != c_max")
            if r["scheme"] == "FXABE-NoOccurrence Core" and integer(r["G2_exp"]) != integer(r["ell"]): errors.append("NoOccurrence D != ell")
        if r["experiment"] == "EXP-02" and r["component"] == "CT_core_G2_bytes":
            if r["scheme"] == "FXABE-05.3" and integer(r["serialized_bytes"]) != 118 * integer(r["c_max"]): errors.append("storage D_j mismatch")
            if r["scheme"] == "FXABE-NoOccurrence" and integer(r["serialized_bytes"]) != 118 * integer(r["ell"]): errors.append("storage D_i mismatch")
    timed = [r for r in rows if r.get("time_ns") != ""]
    # Every retained timing group has exactly 50 samples; storage is deterministic.
    grouped = {}
    keys = ("experiment", "scheme", "workload", "ell", "u", "N", "J", "k", "t_I", "c_max",
            "n_users", "n_revoked", "phase", "component")
    for r in timed: grouped.setdefault(tuple(r[k] for k in keys), []).append(r)
    bad_counts = [(key, len(value)) for key, value in grouped.items() if len(value) != 50]
    if bad_counts: errors.append(f"timing repeat count != 50 for {len(bad_counts)} groups")
    if not any(r["experiment"] == "EXP-01" and r["ell"] == "1280" for r in rows): errors.append("missing ell=1280")
    correctness = json.loads((run / "correctness.json").read_text())
    if not correctness.get("success"): errors.append("correctness gate failed")
    aggregate_files = list((run / "aggregated").glob("*.csv"))
    if len(aggregate_files) != len(EXPECTED): errors.append("aggregate count mismatch")
    report = {"valid": not errors, "FULL_VALIDATION": "PASS" if not errors else "FAIL",
              "errors": errors, "raw_rows": len(rows), "failed_rows": len(failed),
              "same_curve": profiles == {("MNT224", "Charm-Crypto/PBC")},
              "same_backend": profiles == {("MNT224", "Charm-Crypto/PBC")},
              "correctness": correctness.get("success", False), "canonical_storage": not any("storage" in x for x in errors),
              "pair_count_invariant": not any("pair_count" in x for x in errors),
              "D_count_invariant": not any("D_" in x or "NoOccurrence D" in x for x in errors),
              "no_exact_locator": correctness.get("success", False)}
    dump_json(run / "validation.json", report)
    print("FULL_VALIDATION_%s raw_rows=%d failed=%d" % ("PASS" if not errors else "FAIL", len(rows), len(failed)))
    if errors: raise SystemExit(1)


if __name__ == "__main__": main()
