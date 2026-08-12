"""Generate a concise retrieval-only experiment report."""

import json
from pathlib import Path

import pandas as pd


def _markdown(frame):
    headers = list(frame.columns)
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in frame.itertuples(index=False, name=None):
        lines.append("| " + " | ".join(
            "%.3f" % value if isinstance(value, float) else str(value)
            for value in row
        ) + " |")
    return "\n".join(lines)


def generate(run_dir):
    run_dir = Path(run_dir)
    summary = pd.read_csv(run_dir / "summary" / "retrieval_summary.csv")
    env = json.loads((run_dir / "environment.json").read_text())
    selected = summary[summary["metric"].isin([
        "build_total_ms", "mixed_query_ns", "bytes_per_key",
        "attempt_count", "success_rate",
    ])][["retrieval_name", "u", "metric", "median",
        "ci95_low", "ci95_high"]]
    report = [
        "# Functionally equivalent retrieval experiment",
        "",
        "This is the primary algorithm-level comparison. Every structure directly "
        "implements `token -> fixed-width j || check / miss`; no locator, "
        "PStore, KDF, AEAD, ABE group operation, or pairing is present.",
        "",
        "The previous five-index full run remains an immutable supplemental "
        "system-level composed-index experiment.",
        "",
        "## Environment",
        "",
        "- Python: `%s`" % env["python_version"].splitlines()[0],
        "- OS: `%s`" % env["os"],
        "- CPU: `%s`" % env["cpu_model"],
        "- CPU affinity: `%s`" % env["cpu_affinity"],
        "",
        "## Constructions",
        "",
        "- Legacy ABF: greedy three-position XOR assignment.",
        "- Bloomier: four-partition peelable XOR static function.",
        "- Cuckoo payload: two buckets containing fingerprint + full value.",
        "- Plain XOR: three independent global positions and reverse assignment.",
        "- FX-ABF: Binary-Fuse-style consecutive segments and reverse assignment.",
        "",
        "## Median results with independent-seed bootstrap 95% CI",
        "",
        _markdown(selected),
        "",
        "## Correctness boundary",
        "",
        "Validation requires zero member false negatives, zero observed final "
        "false accepts, successful deserialization queries, identical payload "
        "widths, and no locator/PStore/token mapping retained.",
        "",
        "No conclusion that FX-ABF must be fastest is assumed; interpretation "
        "must follow the measured build, query, stability, and space results.",
        "",
    ]
    (run_dir / "report" / "retrieval_report.md").write_text(
        "\n".join(report), encoding="utf-8"
    )
