"""Generate the index-query audit report from the immutable diagnostic CSVs."""

import argparse
from pathlib import Path

import pandas as pd


ORDER = [
    "Legacy ABF", "Bloom+Locator", "Cuckoo+Locator", "Xor+Locator",
    "FX-ABF", "ExactHashMap+PStore",
]


def _table(frame, columns):
    shown = frame[columns].copy()
    for column in columns:
        if column.endswith("_ns"):
            shown[column.replace("_ns", "_us")] = shown.pop(column) / 1000.0
    return _markdown(shown, 2)


def _markdown(frame, decimals):
    headers = [str(column) for column in frame.columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for values in frame.itertuples(index=False, name=None):
        rendered = []
        for value in values:
            if isinstance(value, float):
                rendered.append(("%." + str(decimals) + "f") % value)
            else:
                rendered.append(str(value))
        lines.append("| " + " | ".join(rendered) + " |")
    return "\n".join(lines)


def generate(input_dir):
    input_dir = Path(input_dir)
    raw = pd.read_csv(input_dir / "raw_query_breakdown.csv")
    counts = pd.read_csv(input_dir / "query_operation_counts.csv")
    raw["index_name"] = pd.Categorical(
        raw["index_name"], categories=ORDER, ordered=True
    )
    grouped = raw.groupby(
        ["ell", "index_name"], observed=True, sort=False
    ).median(numeric_only=True).reset_index()
    grouped = grouped.sort_values(["ell", "index_name"])
    system_columns = [
        "ell", "index_name", "system_reported_integrated_query_ns",
        "system_wall_query_ns",
    ]
    envelope_columns = [
        "ell", "index_name", "token_preparation_ns",
        "common_retrieval_locator_identifier_ns",
        "common_security_envelope_ns",
        "common_envelope_integrated_query_ns",
    ]
    phase_columns = [
        "ell", "index_name", "membership_or_retrieval_ns",
        "locator_lookup_ns", "identifier_check_ns", "pstore_kdf_ns",
        "pstore_aead_ns", "posting_decode_validate_ns",
    ]
    count_mid = counts[counts["ell"] == 128][[
        "index_name", "query_type", "encode_count", "sha256_count",
        "dict_lookup_count", "array_read_count", "xor_count",
        "range_reduce_count", "rejection_loop_count",
        "constant_time_compare_count", "kdf_count", "aead_count",
        "decode_count", "temporary_allocation_count",
    ]].copy()
    count_mid["index_name"] = pd.Categorical(
        count_mid["index_name"], categories=ORDER, ordered=True
    )
    count_mid = count_mid.sort_values(["index_name", "query_type"])
    lines = [
        "# Anonymous-index query audit report",
        "",
        "This report is generated from the dedicated audit run. Times are medians "
        "across 30 independent workloads and are per mixed batch of 32 queries "
        "(8 members, 24 nonmembers). The diagnostic does not modify or replace "
        "the existing full run.",
        "",
        "## A. System-level integrated query",
        "",
        "`system_reported` sums the timers returned by the production query "
        "implementation. `system_wall` additionally includes Python dispatch, "
        "result/metrics construction, and timing overhead.",
        "",
        _table(grouped, system_columns),
        "",
        "## B. Common-security-envelope breakdown",
        "",
        "Every successful member path uses the same context-digest check, posting "
        "KDF, AES-GCM backend, canonical posting decoder, strictly-increasing/"
        "duplicate/range checks, and miss-on-authentication-failure rule. The "
        "retrieval/locator/identifier column isolates the index-specific work.",
        "",
        _table(grouped, envelope_columns),
        "",
        "## Detailed phase medians",
        "",
        _table(grouped, phase_columns),
        "",
        "## Logical operation counts at ell=128",
        "",
        "Counts are means per query. Non-integer values reflect collision retries, "
        "membership-filter short-circuiting, or rare candidate positives across "
        "the 30 workloads. Temporary allocations are an explicit-operation proxy, "
        "not a CPython allocator trace.",
        "",
        _markdown(count_mid, 3),
        "",
        "## Correctness and interpretation",
        "",
        "- Member false negatives: **%d**." %
        raw["member_false_negative_count"].sum(),
        "- Final false accepts: **%d**." %
        raw["final_false_accept_count"].sum(),
        "- `ExactHashMap+PStore` is analysis-only and shares Bloom+Locator's "
        "locator and encrypted PStore byte-for-byte.",
        "- The full-run integrated-query plot remains a valid system-level "
        "measurement of these Python prototypes. It is not, by itself, a pure "
        "algorithm-complexity ranking because CPython dictionary probes execute "
        "in optimized C while FusePos, rejection loops, segment arithmetic, and "
        "XOR orchestration execute mainly as Python bytecode.",
        "- The security-envelope phases are close; the observed ranking is "
        "primarily retrieval implementation and required structural work, not "
        "different AEAD or KDF backends.",
        "",
    ]
    (input_dir / "query_audit_report.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir", default="fx_exp_v2/results/index-query-audit"
    )
    args = parser.parse_args(argv)
    generate(args.input_dir)


if __name__ == "__main__":
    main()
