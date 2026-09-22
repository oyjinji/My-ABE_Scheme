"""Schema, I/O, environment and timing helpers."""

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from time import perf_counter_ns

import yaml


ROOT = Path(__file__).resolve().parents[2]
EXP_ROOT = ROOT / "Perf_Exp_05_3"

SCHEMA = [
    "run_id", "experiment", "scheme", "curve", "backend", "workload", "seed", "replicate",
    "ell", "u", "N", "J", "k", "t_I", "c_max", "actual_c_star", "n_users", "n_revoked",
    "phase", "time_ns", "G1_exp", "G2_exp", "GT_exp", "pair_count",
    "serialized_bytes", "component", "success", "notes",
]


def load_yaml(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def write_csv(path, rows):
    rows = list(rows)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(SCHEMA)
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
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


def base_row(run_id, experiment, scheme, seed, replicate, workload="N/A", **values):
    row = {key: "" for key in SCHEMA}
    row.update({
        "run_id": run_id, "experiment": experiment, "scheme": scheme,
        "curve": "MNT224", "backend": "Charm-Crypto/PBC", "workload": workload,
        "seed": int(seed), "replicate": int(replicate), "success": True,
    })
    row.update(values)
    return row


def timed(call):
    started = perf_counter_ns()
    result = call()
    return result, perf_counter_ns() - started


def derive_seed(master, *parts):
    return int.from_bytes(hashlib.sha256("|".join(map(str, (master,) + parts)).encode()).digest()[:8], "big")


def git_value(*args):
    try:
        return subprocess.check_output(["git"] + list(args), cwd=str(ROOT), text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unavailable"


def environment(group, config_path):
    deps = {}
    for name in ("charm-crypto", "cryptography", "PyYAML", "matplotlib", "numpy", "pytest"):
        try:
            deps[name] = importlib.metadata.version(name)
        except Exception:
            deps[name] = "unknown"
    status = git_value("status", "--porcelain=v1")
    return {
        "os": platform.platform(), "cpu": platform.processor() or _cpu_model(),
        "ram_bytes": _ram(), "python": sys.version, "dependencies": deps,
        "curve": group.groupType(), "backend": "Charm-Crypto/PBC",
        "group_bytes": {"G1": len(group.serialize(group.random(1))),
                        "G2": len(group.serialize(group.random(2))),
                        "GT": len(group.serialize(group.random(3))),
                        "ZR": len(group.serialize(group.random(0)))},
        "git_commit": git_value("rev-parse", "HEAD"), "git_dirty": bool(status),
        "git_status": status.splitlines(), "config": str(Path(config_path).resolve()),
        "config_sha256": hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
        "timer": "time.perf_counter_ns", "logical_cpus": os.cpu_count(),
    }


def _cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _ram():
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None
