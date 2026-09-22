#!/usr/bin/env python3
"""Structural, algebraic, backend and anomaly validation for a completed run."""

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))

from experiments.perf_05_3.scripts.common import SCHEMA, dump_json, read_csv  # noqa: E402


def _int(value):
    return None if value in (None, "") else int(float(value))


def validate(run, require_plots=False):
    errors, warnings = [], []
    raw_files = sorted((run / "raw").glob("*.csv"))
    if len(raw_files) != 12:
        errors.append("expected 12 raw CSVs (EXP-00 plus EXP-01..11; EXP-08/09 separate), got %d" % len(raw_files))
    all_rows = []
    for path in raw_files:
        rows = read_csv(path)
        if not rows:
            errors.append("empty raw file: %s" % path.name); continue
        missing = set(SCHEMA) - set(rows[0])
        if missing: errors.append("%s missing schema %s" % (path.name, sorted(missing)))
        all_rows.extend(rows)
    failed = [r for r in all_rows if r.get("success") != "True"]
    if failed: errors.append("%d failed raw rows retained" % len(failed))
    profiles = {(r.get("curve"), r.get("backend")) for r in all_rows
                if r.get("scheme") not in ("COMMON-PRIMITIVE", "")}
    if profiles != {("MNT224", "Charm-Crypto/PBC")}:
        errors.append("cross-scheme profile mismatch: %r" % (profiles,))
    for row in all_rows:
        pair_count, ti = _int(row.get("pair_count")), _int(row.get("t_I"))
        if (row.get("scheme") in ("FXABE-05.3", "FXABE-05.3 Core") and
                pair_count is not None and pair_count > 0 and ti is not None and
                row.get("phase", "").startswith("Transform") and pair_count != 3 + ti):
            errors.append("pair_count invariant: %s" % row)
        if row.get("experiment") == "EXP-01" and row.get("phase") == "Encrypt Core":
            g2, ell, cmax = _int(row.get("G2_exp")), _int(row.get("ell")), _int(row.get("c_max"))
            if row["scheme"] == "FXABE-05.3 Core" and g2 != cmax:
                errors.append("05.3 D_j count != c_max")
            if row["scheme"] == "FXABE-NoOccurrence Core" and g2 != ell:
                errors.append("NoOccurrence D count != ell")
        if row.get("experiment") == "EXP-11" and row.get("phase") == "Setup":
            if _int(row.get("pair_count")) != 1:
                errors.append("Setup parameter pairing count must be one: %s" % row.get("scheme"))
        if row.get("experiment") == "EXP-02" and row.get("component") == "CT_core_G2_bytes":
            size, ell, cmax = _int(row.get("serialized_bytes")), _int(row.get("ell")), _int(row.get("c_max"))
            if row.get("scheme") == "FXABE-05.3" and size != 118 * cmax:
                errors.append("05.3 serialized G2 component disagrees with c_max")
            if row.get("scheme") == "FXABE-NoOccurrence" and size != 118 * ell:
                errors.append("NoOccurrence serialized G2 component disagrees with ell")
    correctness = json.loads((run / "correctness.json").read_text())
    if not correctness.get("success"): errors.append("correctness gate failed")
    aggregated = list((run / "aggregated").glob("*_aggregated.csv"))
    if len(aggregated) != len(raw_files): errors.append("aggregated CSV count mismatch")
    if require_plots:
        expected = {
            "exp00_group_ops.png", "01_encrypt_core.png", "02_full_encrypt_breakdown.png",
            "03_ciphertext_storage.png", "04_transform_vs_J.png", "05_transform_vs_tI.png",
            "06_cmax_ablation.png", "07_fx_build.png", "08_fx_query.png",
            "09_e2e_breakdown.png", "10_fabeo_core.png", "11_revocation.png",
        }
        present = {x.name for x in (run / "plots").glob("*.png")}
        if expected - present: errors.append("missing plots: %s" % sorted(expected - present))
    # Standard anomaly checks: structural counters are hard failures; timing
    # only flags drops larger than 30%, retaining every sample.
    anomaly = []
    groups = defaultdict(lambda: defaultdict(list))
    for r in all_rows:
        if r.get("experiment") == "EXP-01" and r.get("phase") == "Encrypt Core" and r.get("time_ns"):
            groups[r["scheme"]][_int(r["ell"])].append(int(r["time_ns"]))
    for scheme, points in groups.items():
        medians = [(ell, statistics.median(values)) for ell, values in sorted(points.items())]
        for (left_x, left), (right_x, right) in zip(medians, medians[1:]):
            if right < 0.70 * left:
                anomaly.append("%s encrypt median drops >30%%: ell %d -> %d" % (scheme, left_x, right_x))
    mode = json.loads((run / "metadata.json").read_text())["mode"]
    report = {
        "valid": not errors, "comparison_valid": not errors and profiles == {("MNT224", "Charm-Crypto/PBC")},
        "errors": errors, "warnings": warnings, "anomalies": anomaly,
        "same_curve": profiles == {("MNT224", "Charm-Crypto/PBC")},
        "same_backend": profiles == {("MNT224", "Charm-Crypto/PBC")},
        "raw_rows": len(all_rows), "failed_rows": len(failed), "mode": mode,
    }
    dump_json(run / "validation.json", report)
    lines = ["# STANDARD Anomaly Report", "", "Generated automatically; no samples were deleted.", ""]
    if errors or anomaly:
        lines.append("## Findings")
        lines.extend("- " + x for x in errors + anomaly)
    else:
        lines.extend(["## Result", "", "No unresolved structural or >30% monotonic timing anomaly was detected."])
    (ROOT / "src/experiments/perf_05_3" / "docs" / "STANDARD_ANOMALY_REPORT.md").write_text("\n".join(lines) + "\n")
    print("VALIDATION_%s" % ("PASS" if report["valid"] and not anomaly else "FAIL"))
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("run_dir"); parser.add_argument("--require-plots", action="store_true")
    args = parser.parse_args(); report = validate(Path(args.run_dir), args.require_plots)
    if not report["valid"] or report["anomalies"]: raise SystemExit(1)


if __name__ == "__main__": main()
