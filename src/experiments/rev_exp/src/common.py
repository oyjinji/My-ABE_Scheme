"""Configuration, reproducibility, CSV, and statistics utilities."""

import csv
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[4]
REV_ROOT = ROOT / "src/experiments/rev_exp"
RESULTS_ROOT = REV_ROOT / "results"
# Legacy canonical locations remain readable for the archived 2026-08-11 smoke.
RAW_DIR = RESULTS_ROOT / "raw"
AGG_DIR = RESULTS_ROOT / "aggregated"
FIG_DIR = RESULTS_ROOT / "figures"
META_DIR = RESULTS_ROOT / "metadata"


def derive_seed(master, *parts):
    value = "|".join(map(str, (master,) + parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(value).digest()[:8], "big")


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        result = yaml.safe_load(handle)
    if not isinstance(result, dict):
        raise ValueError("config must be a YAML mapping")
    return result


def create_results_dir(mode, run_name=None):
    """Create a non-overwriting run directory under src/experiments/rev_exp/results."""
    if run_name is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        run_name = "%s_%s" % (str(mode), stamp)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(run_name)):
        raise ValueError("run-name must contain only letters, digits, '.', '_' or '-'")
    run_dir = RESULTS_ROOT / str(run_name)
    if run_dir.exists():
        raise FileExistsError("results directory already exists: %s" % run_dir)
    for child in ("raw", "aggregated", "figures", "metadata"):
        (run_dir / child).mkdir(parents=True, exist_ok=False)
    return run_dir


def results_paths(results_dir):
    root = Path(results_dir)
    return {
        "root": root,
        "raw": root / "raw",
        "aggregated": root / "aggregated",
        "figures": root / "figures",
        "metadata": root / "metadata",
    }


def write_csv(path, rows):
    rows = list(rows)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("refusing to write empty CSV: %s" % path)
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def percentile(values, probability):
    ordered = sorted(float(x) for x in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - position) + ordered[hi] * (position - lo)


def summary(values):
    values = [float(value) for value in values]
    count = len(values)
    mean = statistics.mean(values)
    std = statistics.stdev(values) if count > 1 else 0.0
    half = 1.96 * std / math.sqrt(count) if count else float("nan")
    return {
        "mean": mean, "median": statistics.median(values), "std": std,
        "min": min(values), "max": max(values),
        "p05": percentile(values, 0.05), "p95": percentile(values, 0.95),
        "ci95_low": mean - half, "ci95_high": mean + half,
        "n_samples": count,
    }


def git_value(*args):
    try:
        return subprocess.check_output(
            ["git"] + list(args), cwd=str(ROOT), text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unavailable"


def environment_metadata(config_path, config, group):
    cpu = "unknown"
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "config_path": str(Path(config_path).resolve()),
        "config": config,
        "master_seed": config["master_seed"],
        "git_commit": git_value("rev-parse", "HEAD"),
        "git_status_at_run": git_value("status", "--short").splitlines(),
        "python_version": sys.version,
        "cpu": cpu,
        "os": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "crypto_backend": "Charm-Crypto PairingGroup",
        "pairing_group": group.groupType(),
        "group_security_parameter": group.secparam,
        "canonical_g1_bytes": len(group.serialize(group.random(1))),
        "canonical_g2_bytes": len(group.serialize(group.random(2))),
        "timer": "time.perf_counter_ns",
    }


def dump_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
