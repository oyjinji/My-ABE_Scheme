"""Fail-closed completeness, correctness, accounting and timing validation."""

import argparse
import math
from pathlib import Path

import pandas as pd
import yaml


def _read(run_dir, name):
    # Empty failure_reason is a valid recorded success value, not missing data.
    return pd.read_csv(
        Path(run_dir) / "raw" / (name + ".csv"), keep_default_na=False
    )


def validate(run_dir):
    run_dir = Path(run_dir)
    with open(run_dir / "config_resolved.yaml", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    filters = config["filters"]
    f1, f2, f3 = (_read(run_dir, name) for name in
                  ("f1_build_space", "f2_transform_scaling", "f3_correctness"))
    errors, warnings = [], []

    expected_f1 = (len(config["f1"]["u"]) * 2 *
                   int(config["f1"]["independent_seeds"]) *
                   int(config["f1"]["measured_builds_per_seed"]) * len(filters))
    expected_f2 = ((len(config["f2"]["ell_scaling"]) +
                    len(config["f2"]["r_scaling"])) *
                   int(config["f2"]["independent_workloads"]) * len(filters))
    expected_f3 = int(config["f3"]["independent_workloads"]) * len(filters)
    for name, actual, expected in (
        ("F1", len(f1), expected_f1), ("F2", len(f2), expected_f2),
        ("F3", len(f3), expected_f3),
    ):
        if actual != expected:
            errors.append("%s planned rows %d, observed %d" % (name, expected, actual))

    for name, frame in (("F1", f1), ("F2", f2), ("F3", f3)):
        numeric = frame.select_dtypes(include="number")
        if numeric.isna().any().any():
            errors.append("%s contains NaN" % name)
        if not numeric.applymap(math.isfinite).all().all():
            errors.append("%s contains infinity" % name)
        time_columns = [column for column in numeric if
                        column.endswith("_ms") or column.endswith("_ns")]
        if time_columns and (numeric[time_columns] < 0).any().any():
            errors.append("%s contains negative timing" % name)

    if "success" not in f1 or f1["success"].isna().any():
        errors.append("F1 build success/failure is not explicitly recorded")
    failures = f1[~f1["success"].astype(str).str.lower().isin(("true", "1"))]
    if len(failures):
        errors.append("F1 contains %d failed measured builds" % len(failures))
    if (f1["build_total_ms"] <= 0).any():
        errors.append("F1 contains non-positive build time")
    if "pstore_build_count" in f1 and (f1["pstore_build_count"] != 1).any():
        errors.append("an index did not build PStore exactly once")
    build_components = (
        f1["structure_build_ms"] + f1["locator_build_ms"] +
        f1["pstore_build_ms"] + f1["metadata_build_ms"]
    )
    if not (
        (build_components - f1["integrated_build_ms"]).abs() <= 1e-6
    ).all():
        errors.append("integrated build phase accounting mismatch")
    if not (
        (f1["integrated_build_ms"] - f1["build_total_ms"]).abs() <= 1e-6
    ).all():
        errors.append("integrated_build_ms differs from wall-clock build_total_ms")
    if {"timing_residual_ms", "build_total_ms"} <= set(f1):
        tolerance = f1["build_total_ms"].abs() * 0.10
        tolerance = tolerance.where(tolerance > 10.0, 10.0)
        if (f1["timing_residual_ms"].abs() > tolerance).any():
            errors.append("Build timing residual exceeds max(10 ms, 10%)")

    for name, frame, point_columns in (
        ("F1", f1, ["workload", "u", "workload_seed", "measured_repeat"]),
        ("F2", f2, ["experiment", "ell", "N", "r", "workload_seed"]),
        ("F3", f3, ["u", "workload_seed"]),
    ):
        for _, subset in frame.groupby(point_columns):
            if set(subset["filter_name"]) != set(filters):
                errors.append("%s point does not contain all configured indexes" % name)
                break
            if subset["workload_id"].nunique() != 1:
                errors.append("%s filters do not share one workload_id" % name)
                break

    if int(f3["member_false_negative_count"].sum()) != 0:
        errors.append("member false negatives are nonzero")
    if int(f3["final_false_accept_count"].sum()) != 0:
        errors.append("final false accepts are nonzero")

    wrong_pairings = f2[f2["pairing_count"] != 2 + 2 * f2["r"]]
    if len(wrong_pairings):
        errors.append("%d F2 rows violate actual pairing_count=2+2r" %
                      len(wrong_pairings))
    if not (f2["status"] == "ok").all():
        errors.append("F2 contains non-ok Transform status")

    sums = (f1["filter_only_bytes"] + f1["locator_bytes"] +
            f1["pstore_bytes"] + f1["metadata_bytes"])
    if not (sums == f1["integrated_index_bytes"]).all():
        errors.append("integrated index byte accounting mismatch")
    locator_indexes = ["Bloom+Locator", "Cuckoo+Locator", "Xor+Locator"]
    direct_indexes = ["Legacy ABF", "FX-ABF"]
    if f1[f1["filter_name"].isin(locator_indexes)]["locator_bytes"].le(0).any():
        errors.append("membership baseline omitted its locator bytes")
    if f1[f1["filter_name"].isin(direct_indexes)]["locator_bytes"].ne(0).any():
        errors.append("a direct-retrieval index unexpectedly reports a locator")
    query_components = (
        f2["membership_or_retrieval_ms"] + f2["locator_lookup_ms"] +
        f2["pstore_kdf_ms"] + f2["pstore_aead_ms"] +
        f2["posting_decode_ms"]
    )
    if not (
        (query_components - f2["integrated_index_query_ms"]).abs() <= 1e-6
    ).all():
        errors.append("integrated index query phase accounting mismatch")
    if f2[f2["filter_name"].isin(direct_indexes)]["locator_lookup_ms"].ne(0).any():
        errors.append("a direct-retrieval index reports nonzero locator time")
    if f2[f2["filter_name"].isin(locator_indexes)]["locator_lookup_ms"].le(0).any():
        errors.append("a locator baseline reports non-positive locator time")
    if "display_name" not in f1 or not (f1["display_name"] == f1["filter_name"]).all():
        errors.append("F1 display_name is not the canonical index name")
    if "display_name" not in f2 or not (f2["display_name"] == f2["filter_name"]).all():
        errors.append("F2 display_name is not the canonical index name")
    if "display_name" not in f3 or not (f3["display_name"] == f3["filter_name"]).all():
        errors.append("F3 display_name is not the canonical index name")
    if f2["query_includes_build"].astype(str).str.lower().isin(("true", "1")).any():
        errors.append("F2 query timing includes index construction")

    # Detect only large, systematic effects; ordinary benchmark jitter is not
    # treated as evidence that ell entered the core.
    f2a = f2[f2["experiment"] == "F2-A"]
    core_by_ell = f2a.groupby("ell")["core_transform_ms"].median().sort_index()
    if len(core_by_ell) > 1:
        ratio = core_by_ell.max() / max(core_by_ell.min(), 1e-12)
        endpoint = core_by_ell.iloc[-1] / max(core_by_ell.iloc[0], 1e-12)
        if ratio > 2.5 and endpoint > 1.7:
            errors.append("fixed-r core Transform grows systematically with ell")
    for _, subset in f2.groupby(["experiment", "workload_id"]):
        ratio = subset["core_transform_ms"].max() / max(
            subset["core_transform_ms"].min(), 1e-12)
        if ratio > 2.5:
            errors.append("core Transform differs by >2.5x across filters")
            break

    for name, frame, groups in (
        ("F1", f1, ["filter_name", "workload", "u"]),
        ("F2", f2, ["filter_name", "experiment", "ell", "r"]),
        ("F3", f3, ["filter_name", "u"]),
    ):
        counts = frame.groupby(groups).size()
        if counts.nunique() != 1:
            errors.append("%s has unequal sample counts or silent exclusions" % name)

    report = [
        "# Validation report", "",
        "Status: **%s**" % ("PASS" if not errors else "FAIL"), "",
        "Validated raw rows: F1=%d, F2=%d, F3=%d." % (len(f1), len(f2), len(f3)),
        "",
        "## Errors", "",
    ]
    report.extend(["- " + item for item in errors] or ["- None."])
    report.extend(["", "## Warnings", ""])
    report.extend(["- " + item for item in warnings] or ["- None."])
    report.extend([
        "", "## Diagnostic policy", "",
        "Failed builds remain in raw data. The validator does not delete or "
        "rewrite measurements. Large fixed-r core growth and >2.5x same-workload "
        "cross-filter core differences are treated as timing anomalies.",
    ])
    target = run_dir / "report" / "validation_report.md"
    target.write_text("\n".join(report) + "\n", encoding="utf-8")
    return errors, warnings


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args(argv)
    errors, _ = validate(args.run_dir)
    if errors:
        for error in errors:
            print("ERROR:", error)
        raise SystemExit(1)
    print("validation: PASS")


if __name__ == "__main__":
    main()
