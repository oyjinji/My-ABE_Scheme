"""Configuration, result I/O, resumability and statistical summaries."""

import argparse
import csv
import datetime as dt
import json
import os
import platform
import signal
import statistics
import subprocess
import sys
import traceback
from pathlib import Path

import cryptography
import yaml

from experiments.index_v1.generators import derive_seed


ROOT = Path(__file__).resolve().parents[4]
RESULTS = ROOT / "src/experiments/index_v1" / "results"


def load_config(profile_or_path):
    candidate = Path(profile_or_path)
    if not candidate.exists():
        candidate = ROOT / "src/experiments/index_v1" / "configs" / (profile_or_path + ".yaml")
    with candidate.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict) or "experiments" not in config:
        raise ValueError("invalid experiment configuration")
    config["_config_path"] = str(candidate)
    return config


def default_run_id(profile):
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S_") + profile


class ExperimentRun:
    def __init__(self, config, run_id=None, resume=False, argv=None):
        self.config = config
        self.profile = config.get("profile", "custom")
        self.run_id = run_id or default_run_id(self.profile)
        self.run_dir = RESULTS / self.run_id
        if self.run_dir.exists() and not resume:
            raise FileExistsError("run directory exists; pass --resume: {0}".format(self.run_dir))
        for child in ("raw", "summary", "plots", "plot_data", "logs"):
            (self.run_dir / child).mkdir(parents=True, exist_ok=True)
        profile_logs = ROOT / "src/experiments/index_v1" / "logs" / self.profile
        profile_logs.mkdir(parents=True, exist_ok=True)
        self.log_path = profile_logs / (self.run_id + ".log")
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write("run {0} profile={1} resume={2}\n".format(
                self.run_id, self.profile, bool(resume)))
        self.interrupted = False
        signal.signal(signal.SIGINT, self._interrupt)
        self._write_manifest(argv or sys.argv)

    def _interrupt(self, _signum, _frame):
        self.interrupted = True

    def completed_keys(self, experiment):
        path = self.run_dir / "raw" / (experiment + ".jsonl")
        completed = set()
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                        if row.get("status") == "ok":
                            completed.add(row["combination_key"])
                    except Exception:
                        continue
        return completed

    def record(self, experiment, combination_key, row):
        payload = dict(row)
        payload.setdefault("status", "ok")
        payload["combination_key"] = combination_key
        payload["experiment"] = experiment
        path = self.run_dir / "raw" / (experiment + ".jsonl")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write("{0} {1} {2}\n".format(experiment, combination_key, payload["status"]))

    def record_failure(self, experiment, combination_key, config, seed, exception):
        self.record(experiment, combination_key, {
            "status": "error", "config": config, "seed": seed,
            "exception": repr(exception), "traceback": traceback.format_exc(),
        })

    def seed(self, *parts):
        return derive_seed(self.config.get("master_seed", 20260721), *parts)

    def summarize(self):
        for raw_path in sorted((self.run_dir / "raw").glob("*.jsonl")):
            rows = []
            with raw_path.open("r", encoding="utf-8") as handle:
                rows = [json.loads(line) for line in handle if line.strip()]
            self._summarize_rows(raw_path.stem, rows)

    def _summarize_rows(self, experiment, rows):
        successful = [row for row in rows if row.get("status") == "ok"]
        if not successful:
            return
        identity_fields = [
            field for field in ("backend", "u", "ell", "c_fx", "delta", "distribution",
                                "hit_ratio", "segment_length", "r_max", "gamma")
            if any(field in row for row in successful)
        ]
        numeric_excluded = {"seed", "trial", "status", "combination_key"}
        grouped = {}
        for row in successful:
            key = tuple(row.get(field, "") for field in identity_fields)
            grouped.setdefault(key, []).append(row)
        output = []
        for key, group in grouped.items():
            numeric = sorted({field for row in group for field, value in row.items()
                              if field not in numeric_excluded and field not in identity_fields
                              and isinstance(value, (int, float)) and not isinstance(value, bool)})
            for metric in numeric:
                values = [float(row[metric]) for row in group if metric in row]
                if not values:
                    continue
                values.sort()
                result = {"experiment": experiment, "metric": metric, "sample_count": len(values)}
                result.update(dict(zip(identity_fields, key)))
                result.update({
                    "mean": statistics.mean(values), "median": statistics.median(values),
                    "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
                    "min": min(values), "max": max(values),
                    "p95": percentile(values, 0.95),
                    "p99": percentile(values, 0.99) if len(values) >= 10 else "",
                })
                output.append(result)
        path = self.run_dir / "summary" / (experiment + ".csv")
        fields = sorted({field for row in output for field in row})
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fields)
            writer.writeheader()
            writer.writerows(output)

    def _write_manifest(self, argv):
        manifest_path = self.run_dir / "manifest.json"
        if manifest_path.exists():
            return
        manifest = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "run_id": self.run_id, "profile": self.profile,
            "master_seed": self.config.get("master_seed"),
            "config": {key: value for key, value in self.config.items() if not key.startswith("_")},
            "config_path": self.config.get("_config_path"), "argv": list(argv),
            "git_commit": command_output(["git", "rev-parse", "HEAD"]),
            "git_dirty": bool(command_output(["git", "status", "--porcelain"])),
            "python": sys.version, "charm": charm_version(),
            "cryptography": cryptography.__version__, "os": platform.platform(),
            "cpu": cpu_description(), "ram_bytes": ram_bytes(),
            "pairing_group": self.config.get("pairing_group", "MNT224"),
        }
        with manifest_path.open("w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)


def percentile(values, fraction):
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] * (1 - weight) + values[upper] * weight


def command_output(command):
    try:
        return subprocess.check_output(command, cwd=str(ROOT), stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def charm_version():
    try:
        import charm
        return getattr(charm, "__version__", "0.63/package-version")
    except Exception:
        return "unavailable"


def cpu_description():
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def ram_bytes():
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


def parser(description):
    result = argparse.ArgumentParser(description=description)
    result.add_argument("--profile", default="smoke", help="profile name or YAML path")
    result.add_argument("--run-id")
    result.add_argument("--resume", action="store_true")
    result.add_argument("--seed", type=int)
    result.add_argument("--dry-run", action="store_true")
    return result


def configure(args):
    config = load_config(args.profile)
    if args.seed is not None:
        config["master_seed"] = args.seed
    return config
