"""Create per-point descriptive statistics and bootstrap median intervals."""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from fx_exp_v2.benchmarks.common import dump_json


SPECS = {
    "f1_build_space": {
        "groups": ["filter_name", "workload", "u", "ell"],
        "metrics": [
            "attempt_count", "failed_attempt_count", "resize_count",
            "position_generation_ms",
            "peeling_or_insertion_ms", "reverse_assignment_ms",
            "structure_build_ms", "locator_build_ms", "pstore_build_ms",
            "metadata_build_ms", "integrated_build_ms", "retry_ms",
            "build_total_ms", "component_sum_ms", "timing_residual_ms",
            "filter_only_bytes", "locator_bytes",
            "pstore_bytes", "metadata_bytes", "integrated_index_bytes",
            "bytes_per_token",
        ],
    },
    "f2_transform_scaling": {
        "groups": ["filter_name", "experiment", "ell", "N", "r"],
        "metrics": [
            "metadata_validation_ms", "membership_or_retrieval_ms",
            "locator_lookup_ms", "pstore_kdf_ms", "pstore_aead_ms",
            "posting_decode_ms", "integrated_index_query_ms",
            "index_query_ms", "pstore_processing_ms",
            "path_cover_lookup_ms", "revocation_pairing_ms", "row_pairing_ms",
            "core_transform_ms", "transform_total_ms", "pairing_count",
        ],
    },
    "f3_correctness": {
        "groups": ["filter_name", "u"],
        "metrics": [
            "member_false_negative_count", "filter_candidate_positive_count",
            "locator_attempt_count", "pstore_aead_attempt_count",
            "pstore_aead_reject_count", "final_false_accept_count",
            "observed_filter_fpr", "observed_end_to_end_false_accept_rate",
        ],
    },
}


def _bootstrap_median(values, resamples, seed):
    values = np.asarray(values, dtype=float)
    if len(values) == 1:
        return float(values[0]), float(values[0])
    rng = np.random.default_rng(seed)
    medians = np.median(
        rng.choice(values, size=(resamples, len(values)), replace=True), axis=1
    )
    return tuple(float(x) for x in np.percentile(medians, [2.5, 97.5]))


def summarize_frame(frame, groups, metrics, resamples):
    output = []
    for group_values, subset in frame.groupby(groups, dropna=False):
        if not isinstance(group_values, tuple):
            group_values = (group_values,)
        identity = dict(zip(groups, group_values))
        for metric in metrics:
            values = pd.to_numeric(subset[metric], errors="coerce").dropna().to_numpy()
            if not len(values):
                continue
            digest = hashlib.sha256(
                json.dumps([identity, metric], sort_keys=True, default=str).encode()
            ).digest()
            ci_low, ci_high = _bootstrap_median(
                values, resamples, int.from_bytes(digest[:8], "big")
            )
            output.append({
                **identity, "metric": metric, "count": int(len(values)),
                "mean": float(np.mean(values)), "median": float(np.median(values)),
                "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
                "min": float(np.min(values)), "max": float(np.max(values)),
                "p95": float(np.percentile(values, 95)),
                "ci95_low": ci_low, "ci95_high": ci_high,
            })
    return pd.DataFrame(output)


def summarize_run(run_dir):
    run_dir = Path(run_dir)
    import yaml
    with open(run_dir / "config_resolved.yaml", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    all_metrics = {}
    for name, spec in SPECS.items():
        raw = pd.read_csv(run_dir / "raw" / (name + ".csv"))
        summary = summarize_frame(
            raw, spec["groups"], spec["metrics"],
            int(config.get("bootstrap_resamples", 2000)),
        )
        target = run_dir / "summary" / (name + "_summary.csv")
        summary.to_csv(target, index=False)
        all_metrics[name] = summary.to_dict(orient="records")
    dump_json(run_dir / "summary" / "all_metrics.json", all_metrics)
    return all_metrics


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args(argv)
    summarize_run(args.run_dir)


if __name__ == "__main__":
    main()
