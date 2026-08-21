"""Workload accounting and runtime projection for Global_Exp.

Used after the standard run to decide whether the full config is feasible
(requirement 30).  The projection is deliberately simple and transparent:

* every ``repetitions`` timed sample also costs ``warmups`` untimed runs,
* per-point cost is assumed linear in the driving size variable
  (``policy_rows`` for encrypt/transform/decrypt/storage, ``user_attrs`` for
  provisioning, ``policy_rows`` for the fixed-size breakdown),
* wall-clock is taken from the reference run's ``logs/timing.json``
  (measured per experiment), scaled by the workload-weight ratio between the
  candidate config and the reference config.

If the standard data itself shows per-point cost deviating strongly from
linear, the diagnostic warnings list the offending points instead of
silently assuming.
"""

import json
from pathlib import Path

from .experiments import RAW_FILENAMES


def schemes_of(config):
    return list(config.get("schemes", ["FABEO22", "FXABE-Base", "FXABE-Full"]))


def point_weight(config, experiment):
    """Linear workload weight for one experiment under a config."""
    schemes = len(schemes_of(config))
    reps = int(config["repetitions"])
    warm = int(config["warmups"])
    samples = (reps + warm) * schemes
    if experiment == "exp01":
        return samples  # setup is size-independent
    if experiment == "exp02":
        return sum(int(S) for S in config["user_attrs"]) * samples
    if experiment == "exp08":
        l = int(config.get("exp08", {}).get("policy_rows", 0))
        if l == 0:
            values = list(map(int, config["policy_rows"]))
            l = values[len(values) // 2]
        l_reps = int(config.get("exp08", {}).get(
            "repetitions", config["repetitions"]))
        return (l_reps + warm) * schemes * l
    # exp03-07 scale with policy_rows
    return sum(int(l) for l in config["policy_rows"]) * samples


def point_count(config, experiment):
    """Raw number of timed samples (repetitions only) for one experiment."""
    schemes = len(schemes_of(config))
    reps = int(config["repetitions"])
    if experiment == "exp01":
        return schemes * reps
    if experiment == "exp02":
        return len(list(config["user_attrs"])) * schemes * reps
    if experiment == "exp08":
        l_reps = int(config.get("exp08", {}).get(
            "repetitions", config["repetitions"]))
        return schemes * l_reps
    return len(list(config["policy_rows"])) * schemes * reps


def load_timing(run_dir):
    """Read measured per-experiment wall-clock (seconds) from a run."""
    path = Path(run_dir) / "logs" / "timing.json"
    if not path.exists():
        raise FileNotFoundError("timing.json missing: %s" % path)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return {k: float(v) for k, v in data.items()}


def linearity_diagnostics(reference, experiment):
    """Check that measured per-point cost is roughly linear in the size var.

    ``reference`` is a path to the reference run dir.  Returns a list of
    human-readable warnings (empty when the linear model holds within a 35%
    tolerance).
    """
    raw = Path(reference) / "raw"
    import csv
    totals = {}
    for experiment in ("exp03", "exp04", "exp05", "exp06", "exp07"):
        path = raw / RAW_FILENAMES[experiment]
        if not path.exists():
            continue
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("scheme") != "FXABE-Full" or row.get("status") != "ok":
                    continue
                l = int(row["policy_rows"])
                col = {"exp03": "encrypt_total_ms",
                       "exp04": "transform_ms",
                       "exp05": "finaldec_ms",
                       "exp06": "end_to_end_decrypt_ms",
                       "exp07": "total_bytes"}[experiment]
                if row.get(col) == "":
                    continue
                totals.setdefault(l, []).append(float(row[col]))
    warnings = []
    ordered = sorted(totals)
    if len(ordered) < 3:
        return warnings
    base = ordered[0]
    base_val = sorted(totals[base])[len(totals[base]) // 2]
    for l in ordered[1:]:
        median = sorted(totals[l])[len(totals[l]) // 2]
        expected = base_val * l / float(base)
        if base_val <= 0:
            continue
        ratio = median / expected
        if ratio > 1.35 or ratio < 0.65:
            warnings.append(
                "%s l=%d: median %.3f vs linear projection %.3f "
                "(ratio %.2f) -- runtime projection may be optimistic"
                % (experiment, l, median, expected, ratio)
            )
    return warnings


def project(candidate_config, reference_dir, reference_config):
    """Project candidate wall-clock from the reference run.

    Returns a dict with per-experiment measured/projected seconds, the total,
    workload counts, and any linearity warnings.
    """
    reference = load_timing(reference_dir)
    warnings = linearity_diagnostics(reference_dir, None)
    per_exp = {}
    for experiment, ref_sec in reference.items():
        ref_weight = point_weight(reference_config, experiment)
        cand_weight = point_weight(candidate_config, experiment)
        scale = cand_weight / float(ref_weight) if ref_weight else 1.0
        per_exp[experiment] = {
            "reference_seconds": ref_sec,
            "candidate_seconds": ref_sec * scale,
            "scale": scale,
            "candidate_points": point_count(candidate_config, experiment),
            "reference_points": point_count(reference_config, experiment),
        }
    total = sum(item["candidate_seconds"] for item in per_exp.values())
    return {
        "per_experiment": per_exp,
        "projected_total_seconds": total,
        "projected_total_minutes": total / 60.0,
        "linearity_warnings": warnings,
    }
