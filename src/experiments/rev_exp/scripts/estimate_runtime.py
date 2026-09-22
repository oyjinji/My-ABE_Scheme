#!/usr/bin/env python3
"""Approximate run planning from archived smoke real-operation calibration."""

import argparse
import statistics
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from experiments.rev_exp.src.common import REV_ROOT, load_config, read_csv
from experiments.rev_exp.src.planning import endpoint_values, parse_sampling, sampling_for_n


DEFAULT_SMOKE = REV_ROOT / "results_archive" / "smoke_20260811"


def _median(values):
    if not values:
        raise ValueError("smoke calibration has no usable samples")
    return statistics.median(values)


def calibrate(smoke_results):
    raw = Path(smoke_results) / "raw"
    rev_rows = []
    for filename in ("exp01_revkeyupt_vs_users_raw.csv",
                     "exp02_revkeyupt_vs_revoked_raw.csv"):
        rev_rows.extend(read_csv(raw / filename))
    rev_per_cover_node_s = _median([
        float(row["ku_crypto_ns"]) / float(row["cover_size"]) / 1e9
        for row in rev_rows if float(row["cover_size"]) > 0
    ])
    kunodes_s = _median([float(row["kunodes_ns"]) / 1e9 for row in rev_rows])

    transform_rows = read_csv(raw / "exp04_transform_vs_revoked_raw.csv")
    transform_per_pair_s = _median([
        float(row["transform_total_ns"]) / float(row["pairing_count"]) / 1e9
        for row in transform_rows if float(row["pairing_count"]) > 0
    ])

    privacy_rows = read_csv(raw / "exp06_privacykeyupt_vs_attributes_raw.csv")
    privacy_per_attribute_s = _median([
        float(row["privacykeyupt_ns"]) / float(row["S"]) / 1e9
        for row in privacy_rows if float(row["S"]) > 0
    ])

    epoch_rows = read_csv(raw / "exp05_dual_vs_coupled_epoch_raw.csv")
    coupled = [row for row in epoch_rows
               if row["epoch_model"] == "Coupled-Epoch Ablation"]
    policy_per_row_s = _median([
        (float(row["policy_token_refresh_ns"]) + float(row["fx_rebuild_ns"]) +
         float(row["pstore_rebuild_ns"])) / float(row["ell"]) / 1e9
        for row in coupled
    ])
    return {
        "rev_per_cover_node_s": rev_per_cover_node_s,
        "kunodes_s": kunodes_s,
        "transform_per_pair_s": transform_per_pair_s,
        "privacy_per_attribute_s": privacy_per_attribute_s,
        "policy_per_row_s": policy_per_row_s,
    }


def estimated_cover(n, r_v):
    """Planning heuristic calibrated to random-placement smoke, never a result."""
    if r_v <= 0:
        return 1.0
    if r_v >= n:
        return 0.0
    import math
    return max(1.0, 0.85 * r_v * math.log(float(n) / r_v, 2))


def _rev_seconds(calibration, n, r_v):
    return (calibration["kunodes_s"] +
            estimated_cover(n, r_v) * calibration["rev_per_cover_node_s"])


def estimate(config, calibration):
    totals = {}
    exp01 = config["exp01"]
    seconds = 0.0
    for n in endpoint_values(exp01):
        sampling = sampling_for_n(exp01, n)
        invocations = sampling.placements * (sampling.warmup + sampling.repeats)
        for ratio in map(float, exp01["ratios"]):
            seconds += invocations * _rev_seconds(
                calibration, n, max(1, int(round(n * ratio)))
            )
    totals["Exp01"] = seconds

    exp02 = config["exp02"]
    sampling = parse_sampling(exp02["sampling"])
    invocations = sampling.placements * (sampling.warmup + sampling.repeats)
    totals["Exp02"] = sum(
        invocations * _rev_seconds(calibration, int(exp02["n"]), int(r_v))
        for r_v in exp02["r_v"]
    )
    totals["Exp03"] = 0.0

    exp04 = config["exp04"]
    sampling = parse_sampling(exp04["sampling"])
    pairings = 2 + 2 * int(exp04["r"])
    transform_s = pairings * calibration["transform_per_pair_s"]
    seconds = 0.0
    for r_v in map(int, exp04["r_v"]):
        # Each placement prepares one real KU/ciphertext and performs one probe.
        seconds += sampling.placements * _rev_seconds(
            calibration, int(exp04["n"]), r_v
        )
        seconds += sampling.placements * (sampling.warmup + sampling.repeats + 1) * transform_s
    totals["Exp04"] = seconds

    exp05 = config["exp05"]
    direct = exp05["direct_comparison"]
    sampling = parse_sampling(direct["sampling"])
    seconds = 0.0
    for n in map(int, direct["n"]):
        r_v = max(1, int(round(n * float(exp05["revocation_ratio"]))))
        invocations = sampling.placements * (sampling.warmup + sampling.repeats)
        rev_s = _rev_seconds(calibration, n, r_v)
        # Dual plus Coupled each perform RevKeyUpt.
        seconds += invocations * 2 * rev_s
        active = n - r_v
        coupled_extra = (
            active * int(exp05["S"]) * calibration["privacy_per_attribute_s"] +
            int(exp05["ell"]) * calibration["policy_per_row_s"]
        )
        seconds += invocations * coupled_extra
    totals["Exp05-A"] = seconds

    # Exp05-B is a second analytical view of Exp01's measured 5% samples.
    totals["Exp05-B"] = 0.0

    exp06 = config["exp06"]
    sampling = parse_sampling(exp06["sampling"], placement_dependent=False)
    invocations = sampling.warmup + sampling.repeats
    totals["Exp06"] = sum(
        invocations * int(S) * calibration["privacy_per_attribute_s"]
        for S in exp06["S"]
    )
    return totals


def human(seconds):
    if seconds < 60:
        return "~%.1f sec" % seconds
    if seconds < 3600:
        return "~%.1f min" % (seconds / 60.0)
    return "~%.2f h" % (seconds / 3600.0)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--smoke-results", default=str(DEFAULT_SMOKE))
    args = parser.parse_args(argv)
    config = load_config(args.config)
    calibration = calibrate(args.smoke_results)
    estimates = estimate(config, calibration)
    print("estimated from smoke calibration: %s" % Path(args.smoke_results).resolve())
    print("planning estimate only; never used as benchmark data")
    for experiment, seconds in estimates.items():
        suffix = ""
        if experiment == "Exp03":
            suffix = " (reused from Exp02)"
        elif experiment == "Exp05-B":
            suffix = " (reused from Exp01 5%; 0 additional samples)"
        print("%-8s %s%s" % (experiment + ":", human(seconds), suffix))
    print("Total:   %s" % human(sum(estimates.values())))
    print("Approximation excludes uncalibrated setup/registration/FX retry variance; "
          "actual wall time may differ materially.")
    print("Calibration units: KU crypto %.4f ms/Cover node, PrivacyKeyUpt %.4f "
          "ms/attribute, Transform %.4f ms/pair" % (
              calibration["rev_per_cover_node_s"] * 1e3,
              calibration["privacy_per_attribute_s"] * 1e3,
              calibration["transform_per_pair_s"] * 1e3,
          ))


if __name__ == "__main__":
    main()
