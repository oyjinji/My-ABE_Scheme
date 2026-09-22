#!/usr/bin/env python3
"""Validate a Global_Exp run directory against the experiment requirements.

Checks, per requirement:

* run-dir structure (metadata.json, config_snapshot.yaml, environment.json,
  correctness.json, raw/, summary/, plots/, logs/),
* correctness.json ``all_ok``,
* raw CSV headers, duplicate-key freedom and status discipline,
* all ``ok`` rows carry every metric the scheme/experiment must produce,
* workload identity -- all schemes share identical policy/matrix/rho/user-set
  /message fingerprints for the same (experiment, policy_rows, user_attrs),
* satisfaction ratio ~ 0.5 within tolerance,
* every required figure exists and is non-empty.

Writes ``logs/validation.json`` and exits non-zero on any failure.
"""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from experiments.global_exp.src.common import results_paths  # noqa: E402
from experiments.global_exp.src.experiments import RAW_FILENAMES  # noqa: E402
from experiments.global_exp.scripts.aggregate import EXPERIMENT_METRICS  # noqa: E402

# Metrics each (experiment, scheme) must carry on every status=ok row.
REQUIRED_METRICS = {
    "exp01": ["setup_ms", "crypto_setup_ms", "aux_setup_ms"],
    "exp02": {None: ["keygen_ms", "provisioning_total_ms"],
              "FXABE-Full": ["keygen_ms", "provisioning_total_ms", "oprf_ms"]},
    "exp03": {None: ["abe_encrypt_ms", "encrypt_total_ms",
                     "ct_bytes", "metadata_bytes", "total_bytes"],
              "FXABE-Full": ["oprf_ms", "filter_build_ms", "pstore_build_ms",
                             "abe_crypto_ms", "abe_encrypt_ms",
                             "encrypt_total_ms", "ct_bytes", "metadata_bytes",
                             "total_bytes"]},
    "exp04": {None: ["transform_ms", "pair_count"]},
    "exp05": {None: ["finaldec_ms", "decrypt_total_ms"]},
    "exp06": {None: ["end_to_end_decrypt_ms", "finaldec_ms",
                     "decrypt_total_ms"],
              "FXABE-Base": ["direct_lookup_ms", "transform_ms",
                             "pair_count"],
              "FXABE-Full": ["user_oprf_ms", "transform_ms", "pair_count"]},
    "exp07": {None: ["ct_bytes", "metadata_bytes", "total_bytes"]},
    "exp08": {None: ["encrypt_total_ms", "finaldec_ms", "decrypt_total_ms",
                     "total_bytes"]},
}

REQUIRED_PLOTS = [
    "exp01_setup.png", "exp02_user_provisioning.png", "exp03_encrypt.png",
    "exp04_transform.png", "exp05_client_decrypt.png",
    "exp06_e2e_decrypt.png", "exp07_storage.png",
    "exp08_encrypt_breakdown.png", "exp08_decrypt_breakdown.png",
]

ALLOWED_STATUS = {"", "ok", "na"}

FINGERPRINT_FIELDS = ["policy_hash", "matrix_hash", "rho_hash",
                      "user_set_hash", "message_hash"]


def _checks():
    return []


class Validator:
    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.checks = []
        self.paths = results_paths(self.run_dir)

    def ok(self, name, detail=""):
        self.checks.append({"name": name, "status": "ok", "detail": detail})

    def fail(self, name, detail=""):
        self.checks.append({"name": name, "status": "FAIL", "detail": detail})

    @property
    def failed(self):
        return any(c["status"] == "FAIL" for c in self.checks)

    def validate(self):
        self._structure()
        self._correctness()
        self._raw_csvs()
        self._identity()
        self._satisfaction_ratio()
        self._plots()
        return self

    # ------------------------------------------------------------------
    def _structure(self):
        for name in ("metadata.json", "config_snapshot.yaml",
                     "environment.json", "correctness.json"):
            if (self.run_dir / name).exists():
                self.ok("structure.%s" % name)
            else:
                self.fail("structure.%s" % name, "missing")
        for name in ("raw", "summary", "plots", "logs"):
            if (self.run_dir / name).is_dir():
                self.ok("structure.%s_dir" % name)
            else:
                self.fail("structure.%s_dir" % name, "missing")

    def _correctness(self):
        path = self.run_dir / "correctness.json"
        if not path.exists():
            self.fail("correctness", "correctness.json missing")
            return
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("all_ok"):
            self.ok("correctness.all_ok", json.dumps(
                {k: v for k, v in data.items() if k != "workload"}))
        else:
            self.fail("correctness.all_ok", "one or more schemes FAILED")

    def _raw_csvs(self):
        metadata = self._metadata()
        experiments = metadata.get("experiments", [])
        schemes = metadata.get("schemes", [])
        for experiment in experiments:
            raw_path = self.paths["raw"] / RAW_FILENAMES[experiment]
            if not raw_path.exists():
                self.fail("raw.%s.exists" % experiment, "missing")
                continue
            with open(raw_path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            if not rows:
                self.fail("raw.%s.nonempty" % experiment, "no rows")
                continue
            self.ok("raw.%s.rows" % experiment, "%d rows" % len(rows))
            seen = {}
            for row in rows:
                if row.get("status") not in ALLOWED_STATUS:
                    self.fail("raw.%s.status" % experiment,
                              "bad status %r" % row.get("status"))
                key = (row.get("experiment"), row.get("scheme"),
                       row.get("policy_rows"), row.get("user_attrs"),
                       row.get("repetition"))
                if key in seen:
                    self.fail("raw.%s.duplicate" % experiment, str(key))
                seen[key] = True
                if row.get("status") == "ok":
                    self._required_metrics(experiment, row)
            # every scheme must appear at every (l, S) point
            points = {(r["policy_rows"], r["user_attrs"])
                      for r in rows}
            for (l, S) in points:
                present = {r["scheme"] for r in rows
                           if r["policy_rows"] == l and r["user_attrs"] == S}
                for scheme in schemes:
                    if scheme not in present:
                        self.fail("raw.%s.coverage" % experiment,
                                  "%s missing at l=%s S=%s" % (scheme, l, S))
                        break

    def _required_metrics(self, experiment, row):
        spec = REQUIRED_METRICS.get(experiment, {})
        if isinstance(spec, list):
            required = spec
        else:
            required = list(spec.get(None, [])) + list(
                spec.get(row.get("scheme"), []))
        for metric in required:
            value = row.get(metric)
            if value in (None, ""):
                self.fail("raw.%s.metric" % experiment,
                          "%s missing for %s" % (metric, row.get("scheme")))
                continue
            try:
                float(value)
            except ValueError:
                self.fail("raw.%s.metric" % experiment,
                          "%s=%r not numeric for %s" % (
                              metric, value, row.get("scheme")))

    def _identity(self):
        raw = self.paths["raw"]
        for path in sorted(raw.glob("*_raw.csv")):
            experiment = path.stem.replace("_raw", "")
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            by_point = {}
            for row in rows:
                key = (row["policy_rows"], row["user_attrs"])
                by_point.setdefault(key, {})[row["scheme"]] = row
            for key, schemes in by_point.items():
                if len(schemes) < 2:
                    continue
                first_scheme = next(iter(schemes))
                first = schemes[first_scheme]
                for scheme, row in schemes.items():
                    for field in FINGERPRINT_FIELDS:
                        if row.get(field) != first.get(field):
                            self.fail(
                                "identity.%s" % experiment,
                                "%s/%s %s mismatch at l=%s S=%s" % (
                                    first_scheme, scheme, field, *key))
                            break

    def _satisfaction_ratio(self):
        config_path = self.run_dir / "config_snapshot.yaml"
        if not config_path.exists():
            self.fail("satisfaction", "no config_snapshot.yaml")
            return
        import yaml
        with open(config_path, encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        target = float(config.get("satisfaction_ratio", 0.5))
        tol = float(config.get("satisfaction_tolerance", 0.1))
        raw = self.paths["raw"]
        for path in sorted(raw.glob("*_raw.csv")):
            if path.name.startswith("exp01"):
                continue
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            for row in rows:
                try:
                    l = float(row["policy_rows"])
                    satisfied = float(row["satisfied_rows"])
                except (KeyError, ValueError):
                    continue
                if l <= 0:
                    continue
                ratio = satisfied / l
                if abs(ratio - target) > tol:
                    self.fail("satisfaction.%s" % path.stem,
                              "l=%s satisfied=%s ratio=%.3f target=%.2f" % (
                                  row["policy_rows"], row["satisfied_rows"],
                                  ratio, target))
                    return

    def _plots(self):
        for name in REQUIRED_PLOTS:
            path = self.paths["plots"] / name
            if path.exists() and path.stat().st_size > 0:
                self.ok("plots.%s" % name)
            else:
                self.fail("plots.%s" % name, "missing or empty")

    def _metadata(self):
        path = self.run_dir / "metadata.json"
        if not path.exists():
            self.fail("metadata.exists")
            return {}
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()
    validator = Validator(args.run_dir).validate()
    output = {
        "run_dir": str(args.run_dir),
        "passed": not validator.failed,
        "checks": validator.checks,
        "failed_checks": [c for c in validator.checks
                          if c["status"] == "FAIL"],
    }
    with open(Path(args.run_dir) / "logs" / "validation.json", "w",
              encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
    failures = output["failed_checks"]
    print("=== Global_Exp Validation ===")
    print("run_dir: %s" % args.run_dir)
    print("checks: %d, failed: %d" % (len(validator.checks), len(failures)))
    for check in validator.checks:
        mark = "ok  " if check["status"] == "ok" else "FAIL"
        detail = (" - " + check["detail"]) if check["detail"] else ""
        print("  [%s] %s%s" % (mark, check["name"], detail))
    print("validation_passed: %s" % (not validator.failed))
    return 1 if validator.failed else 0


if __name__ == "__main__":
    sys.exit(main())
