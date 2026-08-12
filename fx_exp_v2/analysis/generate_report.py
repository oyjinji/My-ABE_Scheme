"""Generate a concise evidence-only Markdown experiment report."""

import argparse
import json
from pathlib import Path

import pandas as pd
import yaml


def _table(summary, metric, extra_query=None):
    data = summary[summary["metric"] == metric]
    if extra_query is not None:
        data = extra_query(data)
    columns = [column for column in (
        "filter_name", "workload", "experiment", "u", "ell", "r",
        "median", "ci95_low", "ci95_high", "count",
    ) if column in data.columns]
    if data.empty:
        return "_No data._"
    def render(value):
        if pd.isna(value):
            return ""
        if isinstance(value, float):
            return "%.4f" % value
        return str(value).replace("|", "\\|")
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for values in data[columns].itertuples(index=False, name=None):
        lines.append("| " + " | ".join(render(value) for value in values) + " |")
    return "\n".join(lines)


def _build_phase_table(summary):
    """Compact F1-A median phase table at the largest configured u."""
    metrics = [
        "structure_build_ms", "locator_build_ms", "pstore_build_ms",
        "metadata_build_ms", "integrated_build_ms",
    ]
    data = summary[
        (summary["workload"] == "F1-A") & summary["metric"].isin(metrics)
    ]
    largest = data["u"].max()
    pivot = data[data["u"] == largest].pivot(
        index="filter_name", columns="metric", values="median"
    ).reset_index()
    columns = ["filter_name"] + metrics
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in pivot[columns].itertuples(index=False, name=None):
        lines.append("| " + " | ".join(
            str(value) if isinstance(value, str) else "%.4f" % value
            for value in row
        ) + " |")
    return (
        "At `u=%d`, milliseconds; structure is the wall-time remainder after "
        "the separately measured locator, PStore, and metadata phases.\n\n%s" %
        (largest, "\n".join(lines))
    )


def generate(run_dir):
    run_dir = Path(run_dir)
    with open(run_dir / "environment.json", encoding="utf-8") as handle:
        env = json.load(handle)
    with open(run_dir / "config_resolved.yaml", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    f1 = pd.read_csv(run_dir / "summary" / "f1_build_space_summary.csv")
    f2 = pd.read_csv(run_dir / "summary" / "f2_transform_scaling_summary.csv")
    f3 = pd.read_csv(run_dir / "summary" / "f3_correctness_summary.csv")
    raw_f1 = pd.read_csv(run_dir / "raw" / "f1_build_space.csv")
    validation_path = run_dir / "report" / "validation_report.md"
    validation_status = "not run"
    anomalies = "Validation was not run."
    if validation_path.exists():
        validation_text = validation_path.read_text(encoding="utf-8")
        validation_status = "PASS" if "Status: **PASS**" in validation_text else "FAIL"
        anomalies = ("No validation errors were found." if validation_status == "PASS"
                     else "See `validation_report.md`; figures do not override failures.")
    failures = raw_f1[~raw_f1["success"].astype(str).str.lower().isin(("true", "1"))]
    lines = [
        "# FX anonymous-index component experiment report", "",
        "## Environment", "",
        "- Timestamp: `%s`" % env["timestamp"],
        "- Git commit: `%s` (dirty=%s)" % (env["git_commit"], env["git_dirty"]),
        "- Python: `%s`" % env["python_version"].splitlines()[0],
        "- OS: `%s`" % env["os"],
        "- CPU: `%s`" % env["cpu_model"],
        "- Pairing backend: `%s`" % env["pairing_backend"],
        "- CPU affinity: `%s`" % env["cpu_affinity"],
        "", "## Test configuration", "", "```yaml",
        yaml.safe_dump(config, sort_keys=False).rstrip(), "```",
        "", "## Build time summary (F1-A, ms)", "",
        _table(f1, "integrated_build_ms", lambda x: x[x["workload"] == "F1-A"]),
        "", "## Integrated build phase breakdown (F1-A)", "",
        _build_phase_table(f1),
        "", "## Integrated index space (F1-A, bytes/token)", "",
        _table(f1, "bytes_per_token", lambda x: x[x["workload"] == "F1-A"]),
        "", "## Integrated index query (F2-A, ms; excludes pairing)", "",
        _table(f2, "integrated_index_query_ms",
               lambda x: x[x["experiment"] == "F2-A"]),
        "", "## Supplemental Transform scaling (total, ms)", "",
        _table(f2, "transform_total_ms"),
        "", "## Correctness summary", "",
        _table(f3, "member_false_negative_count"), "",
        _table(f3, "final_false_accept_count"),
        "", "## Build failures and retries", "",
        "Measured build failures: **%d**." % len(failures),
        "Retry and resize statistics are retained in raw F1 and its summary.",
        "", "## Anomalies", "",
        "Validation status: **%s**. %s" % (validation_status, anomalies),
        "", "## Preliminary observations", "",
        "The tables report observed medians and bootstrap intervals without "
        "assuming that FX-ABF must be fastest. Membership-filter space is "
        "interpreted only through the integrated index metric, which includes "
        "locator and authenticated PStore bytes. Core Transform measurements "
        "are an ABE/pairing baseline, not evidence for filter speed; filter "
        "effects are assessed through integrated-index query time. Total "
        "Transform is retained as a supplemental, pairing-dominated metric.",
    ]
    target = run_dir / "report" / "experiment_report.md"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args(argv)
    print(generate(args.run_dir))


if __name__ == "__main__":
    main()
