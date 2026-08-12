"""Fail-closed validation of retrieval experiment results."""

from pathlib import Path

import numpy as np
import pandas as pd


def validate(run_dir, config):
    run_dir = Path(run_dir)
    # Empty build_failure is a valid text field.  Prevent pandas from
    # inferring an all-empty string column as floating-point NaN.
    raw = pd.read_csv(
        run_dir / "raw" / "retrieval_results.csv", keep_default_na=False
    )
    errors = []
    expected = {
        (name, int(u), seed)
        for name in config["retrievals"]
        for u in config["u"]
        for seed in range(int(config["independent_seeds"]))
    }
    actual = set(zip(
        raw["retrieval_name"], raw["u"].astype(int),
        raw["seed_index"].astype(int),
    ))
    if actual != expected:
        errors.append("planned retrieval points are incomplete or duplicated")
    numeric = raw.select_dtypes(include=[np.number])
    if numeric.isna().any().any() or np.isinf(numeric.to_numpy()).any():
        errors.append("NaN or infinity in raw results")
    if (numeric < 0).any().any():
        errors.append("negative metric in raw results")
    if not raw["success"].astype(bool).all():
        errors.append("one or more retrieval builds failed")
    if raw["member_false_negative"].sum() != 0:
        errors.append("member false negative observed")
    if raw["nonmember_false_accept"].sum() != 0:
        errors.append("nonmember false accept observed")
    if not raw["deserialize_query_correctness"].astype(bool).all():
        errors.append("serialize/deserialize query correctness failed")
    if raw["mapping_retained"].astype(bool).any():
        errors.append("a built structure retained a token-keyed mapping")
    if raw["contains_locator"].astype(bool).any():
        errors.append("a retrieval contains a locator")
    if raw["contains_pstore"].astype(bool).any():
        errors.append("a retrieval contains a PStore")
    if not np.allclose(
        raw["serialized_bytes"],
        raw["structure_bytes"] + raw["metadata_bytes"],
    ):
        errors.append("serialized space does not equal structure + metadata")
    widths = raw.pivot_table(
        index=["u", "seed_index"], columns="retrieval_name",
        values="payload_bits_per_key",
    )
    if widths.nunique(axis=1).max() != 1:
        errors.append("retrieval payload widths differ within a workload")
    workload_counts = raw.groupby(["u", "seed_index"])["workload_id"].nunique()
    if (workload_counts != 1).any():
        errors.append("retrievals did not share the same workload ID")
    status = "PASS" if not errors else "FAIL"
    report = [
        "# Retrieval experiment validation",
        "",
        "Status: **%s**" % status,
        "",
        "Validated raw rows: %d." % len(raw),
        "",
        "## Errors",
        "",
    ]
    report.extend("- " + error for error in errors)
    if not errors:
        report.append("- None.")
    report.extend([
        "",
        "The validator does not rewrite or remove failed/outlying samples.",
        "",
    ])
    (run_dir / "report" / "validation_report.md").write_text(
        "\n".join(report), encoding="utf-8"
    )
    return not errors, errors
