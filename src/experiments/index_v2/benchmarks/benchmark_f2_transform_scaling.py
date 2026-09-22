"""F2: actual anonymous queries and real pairing-based Transform scaling."""

import copy
import random

from charm.toolbox.pairinggroup import PairingGroup

from Code.fxabe_rev import FXABERev, TransformMetrics
from Code.fxabe_rev.filters import create_index

from .common import derive_seed, ns_to_ms, workload_id, write_csv
from .workload import transform_attributes, transform_policy


FIELDS = [
    "filter_name", "display_name", "experiment", "workload_id", "ell", "N", "r", "seed",
    "master_seed", "workload_seed", "filter_seed", "scheme_seed",
    "measured_queries", "metadata_validation_ms",
    "membership_or_retrieval_ms", "locator_lookup_ms", "pstore_kdf_ms",
    "pstore_aead_ms", "posting_decode_ms", "integrated_index_query_ms",
    "index_query_ms", "pstore_processing_ms", "path_cover_lookup_ms",
    "revocation_pairing_ms",
    "row_pairing_ms", "core_transform_ms", "transform_total_ms",
    "pairing_count", "status", "query_includes_build",
]


def _average_metrics(measurements):
    fields = [
        "metadata_validation_ns", "membership_or_retrieval_ns",
        "locator_lookup_ns", "pstore_kdf_ns", "pstore_aead_ns",
        "posting_decode_ns", "integrated_index_query_ns",
        "index_query_ns", "pstore_processing_ns",
        "path_cover_lookup_ns", "revocation_pairing_ns", "row_pairing_ns",
        "core_transform_ns", "transform_total_ns",
    ]
    result = {
        field[:-3] + "_ms": ns_to_ms(
            sum(getattr(item, field) for item in measurements) /
            float(len(measurements))
        ) for field in fields
    }
    counts = {item.pairing_count for item in measurements}
    rs = {item.r for item in measurements}
    statuses = {item.status for item in measurements}
    result.update({
        "pairing_count": counts.pop() if len(counts) == 1 else -1,
        "observed_r": rs.pop() if len(rs) == 1 else -1,
        "status": statuses.pop() if len(statuses) == 1 else "inconsistent",
    })
    return result


def _run_point(config, group, experiment, ell, n, r, independent):
    master = int(config["master_seed"])
    f2 = config["f2"]
    workload_seed = derive_seed(master, experiment, ell, n, r, independent)
    scheme_seed = derive_seed(master, "scheme", experiment, ell, n, r, independent)
    wid = workload_id(experiment, workload_seed, ell=ell, N=n, r=r)
    scheme = FXABERev(group, user_capacity=8, scheme_seed=scheme_seed)
    pp, msk = scheme.setup()
    attributes = transform_attributes(ell, n, r)
    static, private, _ = scheme.keygen(
        pp, msk, "benchmark-user", attributes, "privacy-1"
    )
    ku = scheme.rev_key_upt(pp, 1)
    base_ct = scheme.encrypt(
        pp, msk, b"F2-real-pairing", transform_policy(ell),
        "privacy-1", 1, filter_seed=workload_seed,
    )
    output = []
    for filter_name in config["filters"]:
        filter_seed = derive_seed(master, "F2-filter", filter_name, wid)
        # Construction is deliberately outside the timed Transform batch.
        index = create_index(filter_name).build(
            base_ct["postings"], base_ct["ctx_fx"], random.Random(filter_seed)
        )
        ciphertext = dict(base_ct)
        ciphertext["index"] = index
        ciphertext["meta"] = copy.deepcopy(base_ct["meta"])
        ciphertext["meta"]["index_name"] = filter_name
        ciphertext["meta"]["index_metadata"] = index._metadata()
        for _ in range(int(f2["warmup_queries"])):
            scheme.transform(pp, ciphertext, static, private, ku, TransformMetrics())
        measurements = []
        for _ in range(int(f2["measured_queries"])):
            metrics = TransformMetrics()
            transformed = scheme.transform(pp, ciphertext, static, private, ku, metrics)
            if transformed is None:
                metrics.status = metrics.status or "failure"
            measurements.append(metrics)
        averaged = _average_metrics(measurements)
        output.append({
            "filter_name": index.name, "display_name": index.name,
            "experiment": experiment,
            "workload_id": wid, "ell": ell, "N": n, "r": r,
            "seed": filter_seed, "master_seed": master,
            "workload_seed": workload_seed, "filter_seed": filter_seed,
            "scheme_seed": scheme_seed,
            "measured_queries": int(f2["measured_queries"]),
            **{k: v for k, v in averaged.items() if k != "observed_r"},
            "query_includes_build": False,
        })
        if averaged["observed_r"] != r:
            output[-1]["status"] = "wrong-r:%s" % averaged["observed_r"]
    return output


def run(config, output_path):
    group = PairingGroup(config.get("pairing_group", "MNT224"))
    section = config["f2"]
    rows = []
    for independent in range(int(section["independent_workloads"])):
        for ell in section["ell_scaling"]:
            rows.extend(_run_point(
                config, group, "F2-A", int(ell),
                int(section["fixed_N_a"]), int(section["fixed_r_a"]), independent,
            ))
        for r in section["r_scaling"]:
            rows.extend(_run_point(
                config, group, "F2-B", int(section["fixed_ell_b"]),
                int(section["fixed_N_b"]), int(r), independent,
            ))
    write_csv(output_path, rows, FIELDS)
    return rows
