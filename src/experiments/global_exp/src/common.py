"""Shared configuration, run-directory, CSV/JSON I/O and environment capture.

Mirrors the conventions of ``src/experiments/rev_exp/src/common.py`` and
``src/experiments/index_v2/benchmarks/common.py`` so Global_Exp stays consistent with the
existing experiment suites.
"""

import csv
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.fxabe_rev.serialization import dumps

ROOT = Path(__file__).resolve().parents[4]
GLOBAL_ROOT = ROOT / "src/experiments/global_exp"
RESULTS_ROOT = GLOBAL_ROOT / "results"

# Metrics that are algorithmically N/A for a scheme and must stay blank/NaN
# (never a misleading 0).  Used by validation and aggregation.
NA_ALLOWED_FIELDS = frozenset({
    "privacy_key_update_ms",
    "oprf_ms", "filter_build_ms", "filter_lookup_ms",
    "pstore_build_ms", "pstore_lookup_ms",
    "user_oprf_ms", "direct_lookup_ms", "index_query_ms",
    "filter_bytes", "pstore_bytes",
    "transform_ms", "transform_pairing_count",
    "breakdown_other_ms",
})

# Fields that must always be present as finite, non-negative numbers when the
# row is a successfully executed sample.
REQUIRED_NUMERIC = frozenset({
    "setup_ms", "keygen_ms", "provisioning_total_ms",
    "abe_encrypt_ms", "encrypt_total_ms",
    "finaldec_ms", "decrypt_total_ms",
    "pair_count",
    "ct_bytes", "metadata_bytes", "total_bytes",
})


def derive_seed(master, *parts):
    material = "|".join(map(str, (master,) + parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        result = yaml.safe_load(handle)
    if not isinstance(result, dict):
        raise ValueError("config must be a YAML mapping")
    required = ("mode", "master_seed", "pairing_group", "policy_rows",
                "repetitions", "warmups")
    missing = [key for key in required if key not in result]
    if missing:
        raise ValueError("config missing required keys: %s" % sorted(missing))
    return result


def create_results_dir(mode, run_name=None):
    """Create a non-overwriting run directory under src/experiments/global_exp/results."""
    if run_name is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        run_name = "%s_%s" % (str(mode), stamp)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(run_name)):
        raise ValueError("run-name must contain only letters, digits, '.', '_' or '-'")
    run_dir = RESULTS_ROOT / str(run_name)
    if run_dir.exists():
        raise FileExistsError("results directory already exists: %s" % run_dir)
    for child in ("raw", "summary", "plots", "logs"):
        (run_dir / child).mkdir(parents=True, exist_ok=False)
    return run_dir


def results_paths(results_dir):
    root = Path(results_dir)
    return {
        "root": root,
        "raw": root / "raw",
        "summary": root / "summary",
        "plots": root / "plots",
        "logs": root / "logs",
        "metadata": root,
    }


def write_csv(path, rows, fieldnames=None):
    rows = list(rows)
    if not rows:
        raise ValueError("refusing to write empty CSV: %s" % path)
    if fieldnames is None:
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fieldnames, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def dump_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def dump_yaml(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False)


def fingerprint(obj):
    """Deterministic canonical fingerprint of any JSON-safe object."""
    payload = dumps(obj, None) if not isinstance(obj, bytes) else obj
    return hashlib.sha256(payload).hexdigest()


def _command(args):
    try:
        return subprocess.check_output(
            args, cwd=str(ROOT), stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unavailable"


def _cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def environment_record(config_path, config, group, affinity, run_name):
    dependencies = {}
    for package in ("charm-crypto", "cryptography", "PyYAML", "pandas",
                    "matplotlib", "numpy", "pytest"):
        try:
            import importlib.metadata
            dependencies[package] = importlib.metadata.version(package)
        except Exception:
            dependencies[package] = "unknown"
    status = _command(["git", "status", "--porcelain=v1"])
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "run_name": run_name,
        "git_commit": _command(["git", "rev-parse", "HEAD"]),
        "git_dirty": bool(status and status != "unavailable"),
        "git_status_porcelain": (
            status.splitlines() if status != "unavailable" else []
        ),
        "python_version": sys.version,
        "os": platform.platform(),
        "cpu_model": _cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "pairing_group": group.groupType(),
        "group_secparam": getattr(group, "secparam", None),
        "canonical_g1_bytes": len(group.serialize(group.random(1))),
        "canonical_g2_bytes": len(group.serialize(group.random(2))),
        "canonical_gt_bytes": len(group.serialize(group.random(3))),
        "timer": "time.perf_counter_ns",
        "dependency_versions": dependencies,
        "config_path": str(Path(config_path).resolve()),
        "cpu_affinity": affinity,
    }


def set_single_cpu_affinity():
    try:
        available = os.sched_getaffinity(0)
        cpu = min(available)
        os.sched_setaffinity(0, {cpu})
        return {"status": "fixed", "cpu": cpu}
    except Exception as exc:
        return {"status": "unsupported", "reason": repr(exc)}


def ns_to_ms(value):
    return float(value) / 1_000_000.0
