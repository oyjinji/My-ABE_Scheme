"""Operation-counted fairness audit for the anonymous-index query paths.

This diagnostic is intentionally separate from F1/F2/F3.  It does not change
the production implementations, registry, configurations, or published runs.
ExactHashMap+PStore is an analysis-only view of the locator and PStore already
built by Bloom+Locator.
"""

import argparse
import csv
import hashlib
import random
import statistics
from collections import defaultdict
from pathlib import Path
from time import perf_counter_ns

from Code.fxabe_rev.crypto_utils import aead_decrypt, equal, kdf
from Code.fxabe_rev.encoding import decode_posting_list, encode
from Code.fxabe_rev.filters import create_index
from Code.fxabe_rev.filters.fxabf import PROFILE, plan_segments

from fx_exp_v2.benchmarks.common import derive_seed


INDEX_NAMES = (
    "Legacy ABF", "Bloom+Locator", "Cuckoo+Locator", "Xor+Locator", "FX-ABF",
)
ANALYSIS_NAME = "ExactHashMap+PStore"
PHASES = (
    "membership_or_retrieval_ns", "locator_lookup_ns", "identifier_check_ns",
    "pstore_kdf_ns", "pstore_aead_ns", "posting_decode_validate_ns",
)
COUNT_FIELDS = (
    "encode_count", "hash_count", "sha256_count", "dict_lookup_count",
    "array_read_count", "xor_count", "range_reduce_count",
    "rejection_loop_count", "constant_time_compare_count", "kdf_count",
    "aead_count", "decode_count", "temporary_allocation_count",
)


def _empty_counts():
    return {name: 0 for name in COUNT_FIELDS}


def _add(counter, name, value=1):
    counter[name] += value


def _encoded_sha(parts, counter, prefix_bytes=8):
    _add(counter, "encode_count")
    _add(counter, "hash_count")
    _add(counter, "sha256_count")
    _add(counter, "temporary_allocation_count", 2)
    return hashlib.sha256(encode(parts)).digest()[:prefix_bytes]


def _raw_sha(material, counter):
    _add(counter, "hash_count")
    _add(counter, "sha256_count")
    _add(counter, "temporary_allocation_count")
    return hashlib.sha256(material).digest()


def _legacy_positions(state, token, counter):
    positions = []
    for lane in range(state["k"]):
        nonce = 0
        while True:
            _add(counter, "rejection_loop_count")
            digest = _encoded_sha(
                ["ABE-H-seed", state["seed"], lane, token, nonce], counter, 32
            )
            _add(counter, "range_reduce_count")
            position = int.from_bytes(digest, "big") % state["m"]
            nonce += 1
            if position not in positions:
                positions.append(position)
                break
    _add(counter, "temporary_allocation_count", 2)
    return tuple(positions)


def _xor_positions(state, token, counter):
    positions = []
    lane = 0
    while len(positions) < 3:
        _add(counter, "rejection_loop_count")
        digest = _encoded_sha(
            ["Xor-Filter-v1", state["seed"], token, lane], counter
        )
        _add(counter, "range_reduce_count")
        position = int.from_bytes(digest, "big") % state["m"]
        lane += 1
        if position not in positions:
            positions.append(position)
    _add(counter, "temporary_allocation_count", 2)
    return tuple(positions)


def _range_hash(state, token, lane, size, counter):
    limit = (1 << 64) - ((1 << 64) % size)
    nonce = 0
    while True:
        _add(counter, "rejection_loop_count")
        value = int.from_bytes(_encoded_sha(
            [PROFILE, state["seed"], token, lane, nonce], counter
        ), "big")
        _add(counter, "range_reduce_count")
        if value < limit:
            return value % size
        nonce += 1


def _fx_positions(state, token, counter):
    meta = state["segment_meta"]
    # Production fuse_positions validates this plan on every query.
    if plan_segments(state["m"], meta.segment_length) != meta:
        raise ValueError("bad segment metadata")
    base = _range_hash(state, token, 0, meta.segment_count - 2, counter)
    positions = []
    for lane, segment in enumerate((base, base + 1, base + 2), 1):
        start = segment * meta.segment_length
        end = min(state["m"], start + meta.segment_length)
        positions.append(
            start + _range_hash(state, token, lane, end - start, counter)
        )
    _add(counter, "temporary_allocation_count", 2)
    return tuple(positions)


def _locator(state, token, context, counter):
    digest = _encoded_sha(
        ["Anonymous-Exact-Locator-v1", context, token], counter, 32
    )
    _add(counter, "dict_lookup_count")
    return state["locator"].get(digest)


def _open_pstore(state, token, identifier, context, counter):
    phases = {
        "pstore_kdf_ns": 0, "pstore_aead_ns": 0,
        "posting_decode_validate_ns": 0,
    }
    pstore = state["pstore"]
    started = perf_counter_ns()
    digest = _raw_sha(context, counter)
    if digest != pstore["context_digest"] or not 0 <= identifier < pstore["u"]:
        phases["pstore_kdf_ns"] = perf_counter_ns() - started
        return None, phases
    _add(counter, "kdf_count")
    # kdf(length=32) performs one canonical encode and one SHA-256.
    _add(counter, "encode_count")
    _add(counter, "hash_count")
    _add(counter, "sha256_count")
    _add(counter, "temporary_allocation_count", 3)
    key = kdf("FXABF-Posting-Key", context, token, pstore["salt"])
    phases["pstore_kdf_ns"] = perf_counter_ns() - started

    started = perf_counter_ns()
    _add(counter, "encode_count")
    _add(counter, "temporary_allocation_count")
    aad = encode([
        "FXABF-Posting-AD", "1", context, int(pstore["u"]),
        int(pstore["ell"]), int(identifier),
    ])
    _add(counter, "array_read_count")
    _add(counter, "aead_count")
    plaintext = aead_decrypt(key, pstore["records"][identifier], aad)
    phases["pstore_aead_ns"] = perf_counter_ns() - started
    if plaintext is None:
        return None, phases

    started = perf_counter_ns()
    _add(counter, "decode_count")
    _add(counter, "temporary_allocation_count", 3)
    try:
        rows = decode_posting_list(plaintext, pstore["ell"])
    except Exception:
        rows = None
    phases["posting_decode_validate_ns"] = perf_counter_ns() - started
    return rows, phases


def _profile_query(name, state, token, context):
    """Mirror one production query while exposing non-overlapping phases."""
    counts = _empty_counts()
    phases = {phase: 0 for phase in PHASES}
    identifier = None
    candidate = False

    # Legacy/FX perform their context digest check before structural recovery.
    if name in ("Legacy ABF", "FX-ABF"):
        started = perf_counter_ns()
        context_ok = _raw_sha(context, counts) == state["context_digest"]
        phases["identifier_check_ns"] += perf_counter_ns() - started
        if not context_ok:
            return False, (), phases, counts

    started = perf_counter_ns()
    if name == "Legacy ABF":
        recovered = 0
        for position in _legacy_positions(state, token, counts):
            _add(counts, "array_read_count")
            _add(counts, "xor_count")
            recovered ^= state["slots"][position]
        identifier = recovered >> state["delta"]
        check = recovered & ((1 << state["delta"]) - 1)
        candidate = identifier < state["pstore"]["u"]
    elif name == "Bloom+Locator":
        candidate = True
        for lane in range(state["k"]):
            digest = _encoded_sha(
                ["ABF-v1", state["seed"], token, lane], counts
            )
            _add(counts, "range_reduce_count")
            position = int.from_bytes(digest, "big") % state["m"]
            _add(counts, "array_read_count")
            if not state["bits"][position >> 3] & (1 << (position & 7)):
                candidate = False
                break
    elif name == "Cuckoo+Locator":
        bits = 16
        width = 2
        value = int.from_bytes(
            _raw_sha(b"Cuckoo-FP-v1" + token, counts), "big"
        ) & ((1 << bits) - 1)
        fingerprint = (value or 1).to_bytes(width, "big")
        first = int.from_bytes(_encoded_sha(
            ["Cuckoo-I1-v1", state["seed"], token], counts
        ), "big") & (state["count"] - 1)
        delta = int.from_bytes(
            _raw_sha(b"Cuckoo-I2-v1" + fingerprint, counts)[:8], "big"
        )
        second = first ^ (delta & (state["count"] - 1))
        _add(counts, "range_reduce_count", 2)
        _add(counts, "temporary_allocation_count")
        _add(counts, "array_read_count")
        candidate = fingerprint in state["buckets"][first]
        if not candidate:
            _add(counts, "array_read_count")
            candidate = fingerprint in state["buckets"][second]
    elif name == "Xor+Locator":
        recovered = 0
        for position in _xor_positions(state, token, counts):
            _add(counts, "array_read_count")
            _add(counts, "xor_count")
            recovered ^= state["slots"][position]
        bits = state["bits"]
        expected = int.from_bytes(
            _raw_sha(b"Xor-FP-v1" + token, counts), "big"
        )
        candidate = recovered == ((expected & ((1 << bits) - 1)) or 1)
    elif name == "FX-ABF":
        recovered = 0
        for position in _fx_positions(state, token, counts):
            _add(counts, "array_read_count")
            _add(counts, "xor_count")
            recovered ^= state["slots"][position]
        identifier = recovered >> state["delta"]
        check = recovered & ((1 << state["delta"]) - 1)
        candidate = identifier < state["pstore"]["u"]
    elif name == ANALYSIS_NAME:
        candidate = True
    else:
        raise ValueError(name)
    phases["membership_or_retrieval_ns"] = perf_counter_ns() - started

    if not candidate:
        return False, (), phases, counts

    if name in ("Bloom+Locator", "Cuckoo+Locator", "Xor+Locator", ANALYSIS_NAME):
        started = perf_counter_ns()
        identifier = _locator(state, token, context, counts)
        phases["locator_lookup_ns"] = perf_counter_ns() - started
        if identifier is None:
            return False, (), phases, counts

    if name in ("Legacy ABF", "FX-ABF"):
        started = perf_counter_ns()
        if identifier is None or identifier >= state["pstore"]["u"]:
            phases["identifier_check_ns"] += perf_counter_ns() - started
            return False, (), phases, counts
        if name == "Legacy ABF":
            digest = _encoded_sha(
                ["Legacy-ABF-Check", context, token, identifier], counts, 32
            )
        else:
            digest = _encoded_sha([
                "FXABF-Check", context, token,
                {"bits": state["b_j"], "value": identifier},
            ], counts, 32)
        expected = int.from_bytes(digest, "big") >> (256 - state["delta"])
        width = (state["delta"] + 7) // 8
        _add(counts, "constant_time_compare_count")
        _add(counts, "temporary_allocation_count", 2)
        candidate = equal(
            check.to_bytes(width, "big"), expected.to_bytes(width, "big")
        )
        phases["identifier_check_ns"] += perf_counter_ns() - started
        if not candidate:
            return False, (), phases, counts

    rows, pstore_phases = _open_pstore(
        state, token, identifier, context, counts
    )
    phases.update(pstore_phases)
    return rows is not None, rows or (), phases, counts


def _exact_system_query(state, token, context):
    """System-level exact-map query using the real locator and PStore code."""
    from Code.fxabe_rev.filters.base import (
        open_pstore_profiled, profiled_locator_query,
    )
    metrics = {phase: 0 for phase in PHASES}
    identifier, metrics["locator_lookup_ns"] = profiled_locator_query(
        state["locator"], token, context
    )
    if identifier is None:
        return False, (), metrics
    rows, pmetrics, _ = open_pstore_profiled(
        state["pstore"], token, identifier, context
    )
    metrics["pstore_kdf_ns"] = pmetrics["pstore_kdf_ns"]
    metrics["pstore_aead_ns"] = pmetrics["pstore_aead_ns"]
    metrics["posting_decode_validate_ns"] = pmetrics["posting_decode_ns"]
    return rows is not None, rows or (), metrics


def _prepare_workload(master_seed, ell, independent):
    seed = derive_seed(master_seed, "index-query-audit", ell, independent)
    entries = {}
    for row in range(1, ell + 1):
        token = hashlib.sha256(encode(["audit-member", seed, row])).digest()
        entries[token] = (row,)
    members = list(entries)[:8]
    nonmembers = [
        hashlib.sha256(encode(["audit-nonmember", seed, i])).digest()
        for i in range(24)
    ]
    return seed, entries, tuple(members + nonmembers), set(members)


def _median(values):
    return statistics.median(values) if values else 0


def _run_one(master_seed, ell, independent, warmups, repeats, count_accumulator):
    seed, entries, queries, members = _prepare_workload(
        master_seed, ell, independent
    )
    context = encode(["index-query-audit-context", "1", ell, seed])
    states = {}
    indexes = {}
    for name in INDEX_NAMES:
        build_seed = derive_seed(seed, "build", name)
        index = create_index(name).build(
            entries, context, random.Random(build_seed)
        )
        indexes[name] = index
        states[name] = index.state
    # Analysis-only exact baseline shares the exact locator and encrypted
    # PStore with Bloom+Locator byte-for-byte.
    states[ANALYSIS_NAME] = {
        "locator": states["Bloom+Locator"]["locator"],
        "pstore": states["Bloom+Locator"]["pstore"],
    }

    for name in INDEX_NAMES:
        for _ in range(warmups):
            for token in queries:
                indexes[name].query(token, context)
    for _ in range(warmups):
        for token in queries:
            _exact_system_query(states[ANALYSIS_NAME], token, context)

    rows = []
    for name in INDEX_NAMES + (ANALYSIS_NAME,):
        preparation = []
        system_wall = []
        system_reported = []
        phase_samples = defaultdict(list)
        manual_wall = []
        false_negatives = false_accepts = 0
        for repeat in range(repeats):
            started = perf_counter_ns()
            prepared = tuple(queries)  # reference materialization; no re-Encode(token)
            preparation.append(perf_counter_ns() - started)

            started = perf_counter_ns()
            reported = 0
            for token in prepared:
                if name == ANALYSIS_NAME:
                    hit, posting, metrics = _exact_system_query(
                        states[name], token, context
                    )
                    reported += sum(metrics[phase] for phase in PHASES)
                else:
                    result = indexes[name].query(token, context)
                    hit, posting = result.hit, result.posting_list
                    reported += int(
                        result.metrics.get("integrated_index_query_ns", 0)
                    )
                if token in members and (not hit or not posting):
                    false_negatives += 1
                if token not in members and hit:
                    false_accepts += 1
            system_wall.append(perf_counter_ns() - started)
            system_reported.append(reported)

            started = perf_counter_ns()
            totals = {phase: 0 for phase in PHASES}
            for token in prepared:
                hit, posting, phases, _ = _profile_query(
                    name, states[name], token, context
                )
                for phase in PHASES:
                    totals[phase] += phases[phase]
            manual_wall.append(perf_counter_ns() - started)
            for phase in PHASES:
                phase_samples[phase].append(totals[phase])

        # Counts are collected once per token/workload: repeats would only
        # duplicate identical logical work.
        for token in queries:
            hit, posting, _, counts = _profile_query(
                name, states[name], token, context
            )
            query_type = "member" if token in members else "nonmember"
            key = (ell, name, query_type)
            count_accumulator[key]["query_count"] += 1
            for field in COUNT_FIELDS:
                count_accumulator[key][field].append(counts[field])

        phase_medians = {
            phase: _median(phase_samples[phase]) for phase in PHASES
        }
        integrated = sum(phase_medians.values()) + _median(preparation)
        rows.append({
            "ell": ell, "N": 32, "r": 8,
            "independent_workload": independent,
            "workload_seed": seed,
            "workload_id": "IQA-%d-%02d-%016x" % (ell, independent, seed),
            "index_name": name,
            "analysis_only": name == ANALYSIS_NAME,
            "member_queries": 8, "nonmember_queries": 24,
            "warmup_batches": warmups, "measured_batches": repeats,
            "token_preparation_ns": _median(preparation),
            **phase_medians,
            "integrated_query_ns": integrated,
            "system_reported_integrated_query_ns": _median(system_reported),
            "system_wall_query_ns": _median(system_wall),
            "manual_profile_wall_ns": _median(manual_wall),
            "common_retrieval_locator_identifier_ns": (
                phase_medians["membership_or_retrieval_ns"] +
                phase_medians["locator_lookup_ns"] +
                phase_medians["identifier_check_ns"]
            ),
            "common_security_envelope_ns": (
                phase_medians["pstore_kdf_ns"] +
                phase_medians["pstore_aead_ns"] +
                phase_medians["posting_decode_validate_ns"]
            ),
            "common_envelope_integrated_query_ns": integrated,
            "member_false_negative_count": false_negatives,
            "final_false_accept_count": false_accepts,
        })
    return rows


def _write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _count_rows(accumulator):
    rows = []
    for (ell, name, query_type), values in sorted(accumulator.items()):
        row = {
            "ell": ell, "index_name": name, "query_type": query_type,
            "query_count": values["query_count"],
        }
        for field in COUNT_FIELDS:
            samples = values[field]
            row[field] = statistics.mean(samples)
            row[field + "_min"] = min(samples)
            row[field + "_max"] = max(samples)
        row["temporary_allocation_count_note"] = (
            "proxy: explicit encoded/digest/container/plaintext allocations"
        )
        rows.append(row)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        default="fx_exp_v2/results/index-query-audit",
    )
    parser.add_argument("--master-seed", type=int, default=20260729)
    parser.add_argument("--independent-workloads", type=int, default=30)
    parser.add_argument("--warmup-batches", type=int, default=5)
    parser.add_argument("--measured-batches", type=int, default=20)
    args = parser.parse_args(argv)
    output = Path(args.output_dir)
    accumulator = defaultdict(
        lambda: {"query_count": 0, **{field: [] for field in COUNT_FIELDS}}
    )
    raw = []
    for ell in (32, 128, 512):
        for independent in range(args.independent_workloads):
            raw.extend(_run_one(
                args.master_seed, ell, independent, args.warmup_batches,
                args.measured_batches, accumulator,
            ))
    _write_csv(output / "raw_query_breakdown.csv", raw)
    _write_csv(output / "query_operation_counts.csv", _count_rows(accumulator))
    failures = sum(
        int(row["member_false_negative_count"]) +
        int(row["final_false_accept_count"]) for row in raw
    )
    if failures:
        raise SystemExit("query correctness failures: %d" % failures)
    print("wrote %d raw rows to %s" % (len(raw), output))


if __name__ == "__main__":
    main()
