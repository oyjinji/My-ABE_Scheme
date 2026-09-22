"""F3: member correctness, candidate positives and end-to-end rejection."""

import random

from core.fxabe_rev.filters import create_index

from .common import derive_seed, write_csv
from .workload import filter_query_workload


FIELDS = [
    "filter_name", "display_name", "workload_id", "u", "seed", "master_seed",
    "workload_seed", "filter_seed", "scheme_seed", "member_queries",
    "nonmember_queries", "member_false_negative_count",
    "filter_candidate_positive_count", "locator_attempt_count",
    "pstore_aead_attempt_count", "pstore_aead_reject_count",
    "final_false_accept_count", "observed_filter_fpr",
    "observed_end_to_end_false_accept_rate",
]


def run(config, output_path):
    master = int(config["master_seed"])
    section = config["f3"]
    rows = []
    for independent in range(int(section["independent_workloads"])):
        workload_seed = derive_seed(master, "F3-workload", independent)
        workload = filter_query_workload(
            int(section["u"]), int(section["member_queries"]),
            int(section["nonmember_queries"]), workload_seed,
        )
        context = ("FXEXP-F3|%s" % workload["workload_id"]).encode()
        for filter_name in config["filters"]:
            filter_seed = derive_seed(master, "F3-filter", filter_name, independent)
            index = create_index(filter_name).build(
                workload["entries"], context, random.Random(filter_seed)
            )
            false_negatives = 0
            for token in workload["members"]:
                if not index.query(token, context).hit:
                    false_negatives += 1
            counters = {
                "filter_candidate_positive_count": 0,
                "locator_attempt_count": 0,
                "pstore_aead_attempt_count": 0,
                "pstore_aead_reject_count": 0,
            }
            false_accepts = 0
            for token in workload["nonmembers"]:
                result = index.query(token, context)
                false_accepts += int(result.hit)
                for key in counters:
                    counters[key] += int(result.metrics.get(key, 0))
            n = len(workload["nonmembers"])
            rows.append({
                "filter_name": index.name, "display_name": index.name,
                "workload_id": workload["workload_id"],
                "u": int(section["u"]), "seed": filter_seed,
                "master_seed": master, "workload_seed": workload_seed,
                "filter_seed": filter_seed,
                "scheme_seed": derive_seed(master, "F3-scheme", independent),
                "member_queries": len(workload["members"]),
                "nonmember_queries": n,
                "member_false_negative_count": false_negatives,
                **counters, "final_false_accept_count": false_accepts,
                "observed_filter_fpr":
                    counters["filter_candidate_positive_count"] / float(n),
                "observed_end_to_end_false_accept_rate":
                    false_accepts / float(n),
            })
    write_csv(output_path, rows, FIELDS)
    return rows
