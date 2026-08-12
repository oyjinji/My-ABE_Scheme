"""Independent-seed statistics for retrieval R1-R4."""

import hashlib

import numpy as np
import pandas as pd


METRICS = [
    "build_total_ms", "position_hash_ms", "peeling_or_insertion_ms",
    "assignment_ms", "attempt_count", "resize_count", "kick_count",
    "success_rate", "final_capacity", "load_factor",
    "member_query_ns", "nonmember_query_ns", "mixed_query_ns",
    "hash_count", "array_reads", "xor_count", "temporary_allocations",
    "structure_bytes", "metadata_bytes", "serialized_bytes",
    "bytes_per_key", "payload_bits_per_key", "unused_capacity_bytes",
    "member_false_negative", "nonmember_false_accept",
]


def _bootstrap(values, label, samples=2000):
    if len(values) == 1:
        return float(values[0]), float(values[0])
    seed = int.from_bytes(
        hashlib.sha256(label.encode()).digest()[:8], "big"
    )
    rng = np.random.default_rng(seed)
    medians = np.median(
        rng.choice(values, size=(samples, len(values)), replace=True), axis=1
    )
    return (
        float(np.percentile(medians, 2.5)),
        float(np.percentile(medians, 97.5)),
    )


def summarize(raw_path, summary_path):
    data = pd.read_csv(raw_path)
    rows = []
    for (name, u), group in data.groupby(["retrieval_name", "u"]):
        for metric in METRICS:
            values = group[metric].astype(float).to_numpy()
            low, high = _bootstrap(values, "%s|%s|%s" % (name, u, metric))
            rows.append({
                "retrieval_name": name, "u": int(u), "metric": metric,
                "count": len(values), "mean": float(np.mean(values)),
                "median": float(np.median(values)),
                "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0,
                "min": float(np.min(values)), "max": float(np.max(values)),
                "p95": float(np.percentile(values, 95)),
                "ci95_low": low, "ci95_high": high,
            })
    pd.DataFrame(rows).to_csv(summary_path, index=False)
    return rows
