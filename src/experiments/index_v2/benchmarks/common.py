"""Shared deterministic seeds, result I/O and environment capture."""

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[4]
RESULTS_ROOT = ROOT / "src/experiments/index_v2" / "results"


def derive_seed(master_seed, *parts):
    material = "|".join(map(str, (master_seed,) + parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def workload_id(experiment, seed, **parameters):
    payload = json.dumps(
        [experiment, seed, sorted(parameters.items())],
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return experiment + "-" + hashlib.sha256(payload).hexdigest()[:16]


def read_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError("configuration must be a mapping")
    return config


def create_run_dir(config):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:8]
    run_id = "%s-%s-%s" % (config.get("mode", "run"), timestamp, digest)
    run_dir = RESULTS_ROOT / run_id
    for name in ("raw", "summary", "figures", "report", "logs"):
        (run_dir / name).mkdir(parents=True, exist_ok=False)
    return run_id, run_dir


def write_csv(path, rows, fieldnames=None):
    rows = list(rows)
    if fieldnames is None:
        fieldnames = list(rows[0]) if rows else []
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def dump_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def dump_yaml(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False)


def _command(args):
    try:
        return subprocess.check_output(args, cwd=ROOT, stderr=subprocess.DEVNULL,
                                       text=True).strip()
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


def _physical_cpus():
    pairs = set()
    physical = core = None
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    if physical is not None and core is not None:
                        pairs.add((physical, core))
                    physical = core = None
                elif line.startswith("physical id"):
                    physical = line.split(":", 1)[1].strip()
                elif line.startswith("core id"):
                    core = line.split(":", 1)[1].strip()
    except OSError:
        return None
    return len(pairs) or None


def _available_memory():
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            values = {line.split(":", 1)[0]: int(line.split()[1]) * 1024
                      for line in handle}
        return values.get("MemAvailable")
    except OSError:
        return None


def set_single_cpu_affinity():
    try:
        available = os.sched_getaffinity(0)
        cpu = min(available)
        os.sched_setaffinity(0, {cpu})
        return {"status": "fixed", "cpu": cpu}
    except Exception as exc:
        return {"status": "unsupported", "reason": repr(exc)}


def environment_record(config_path, argv, pairing_backend, affinity):
    dependencies = {}
    for package in ("charm-crypto", "cryptography", "PyYAML", "pandas",
                    "matplotlib", "numpy"):
        try:
            dependencies[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            dependencies[package] = "unknown"
    status = _command(["git", "status", "--porcelain=v1"])
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": _command(["git", "rev-parse", "HEAD"]),
        "git_dirty": bool(status and status != "unavailable"),
        "git_status_porcelain": status.splitlines() if status != "unavailable" else [],
        "python_version": sys.version,
        "os": platform.platform(),
        "cpu_model": _cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "physical_cpu_count": _physical_cpus(),
        "available_memory_bytes": _available_memory(),
        "pairing_backend": pairing_backend,
        "dependency_versions": dependencies,
        "command_line": " ".join(shlex.quote(x) for x in argv),
        "config_file": str(Path(config_path).resolve()),
        "thread_configuration": {
            "requested_threads": 1,
            "OMP_NUM_THREADS": os.environ.get("OMP_NUM_THREADS", "unset"),
            "OPENBLAS_NUM_THREADS": os.environ.get("OPENBLAS_NUM_THREADS", "unset"),
        },
        "cpu_affinity": affinity,
    }


def ns_to_ms(value):
    return float(value) / 1_000_000.0
