"""F1: real index construction and complete serialized space."""

import random

from Code.fxabe_rev.filters import create_index

from .common import derive_seed, ns_to_ms, write_csv
from .workload import f1_workload


FIELDS = [
    "filter_name", "display_name", "workload", "workload_id", "u", "ell", "seed",
    "master_seed", "workload_seed", "filter_seed", "scheme_seed",
    "measured_repeat", "success", "failure_reason", "attempt_count",
    "failed_attempt_count", "resize_count", "final_capacity",
    "position_generation_ms",
    "peeling_or_insertion_ms", "reverse_assignment_ms", "locator_build_ms",
    "pstore_build_ms", "metadata_build_ms", "structure_build_ms",
    "integrated_build_ms", "pstore_build_count", "retry_ms", "build_total_ms",
    "component_sum_ms", "timing_residual_ms", "filter_only_bytes",
    "locator_bytes", "pstore_bytes", "metadata_bytes",
    "integrated_index_bytes", "bytes_per_token",
]


def run(config, output_path):
    master = int(config["master_seed"])
    section = config["f1"]
    rows = []
    for u in section["u"]:
        for workload_name in ("F1-A", "F1-B"):
            for independent in range(int(section["independent_seeds"])):
                workload_seed = derive_seed(master, "F1", workload_name, u, independent)
                workload = f1_workload(int(u), workload_name, workload_seed)
                context = ("FXEXP-F1|%s" % workload["workload_id"]).encode()
                for filter_name in config["filters"]:
                    for warmup in range(int(section.get("warmup_builds", 0))):
                        seed = derive_seed(master, "F1-warmup", filter_name, u,
                                           independent, warmup)
                        create_index(filter_name).build(
                            workload["entries"], context, random.Random(seed)
                        )
                    for repeat in range(int(section["measured_builds_per_seed"])):
                        filter_seed = derive_seed(
                            master, "F1-filter", filter_name, u, independent, repeat
                        )
                        base = {
                            "filter_name": filter_name, "display_name": filter_name,
                            "workload": workload_name,
                            "workload_id": workload["workload_id"], "u": int(u),
                            "ell": workload["ell"], "seed": filter_seed,
                            "master_seed": master, "workload_seed": workload_seed,
                            "filter_seed": filter_seed,
                            "scheme_seed": derive_seed(master, "F1-scheme", independent),
                            "measured_repeat": repeat,
                        }
                        try:
                            index = create_index(filter_name).build(
                                workload["entries"], context, random.Random(filter_seed)
                            )
                            stats = index.stats()
                            sizes = index.size_breakdown()
                            integrated = sum(sizes.values())
                            component_sum_ns = int(stats.get("component_sum_ns", 0))
                            if component_sum_ns <= 0:
                                component_sum_ns = sum(int(stats[key]) for key in (
                                    "position_generation_ns",
                                    "peeling_or_insertion_ns",
                                    "reverse_assignment_ns", "locator_build_ns",
                                    "pstore_build_ns",
                                ))
                            residual_ns = (
                                int(stats["build_total_ns"]) - component_sum_ns
                            )
                            base.update({
                                "filter_name": index.name,
                                "display_name": index.name,
                                "success": True,
                                "failure_reason": stats.get("failure_reason", ""),
                                "attempt_count": stats["attempt_count"],
                                "failed_attempt_count":
                                    stats["attempt_count"] - 1,
                                "resize_count": stats["resize_count"],
                                "final_capacity": stats["final_capacity"],
                                "position_generation_ms": ns_to_ms(
                                    stats["position_generation_ns"]),
                                "peeling_or_insertion_ms": ns_to_ms(
                                    stats["peeling_or_insertion_ns"]),
                                "reverse_assignment_ms": ns_to_ms(
                                    stats["reverse_assignment_ns"]),
                                "locator_build_ms": ns_to_ms(stats["locator_build_ns"]),
                                "pstore_build_ms": ns_to_ms(stats["pstore_build_ns"]),
                                "metadata_build_ms": ns_to_ms(
                                    stats["metadata_build_ns"]),
                                "structure_build_ms": ns_to_ms(
                                    stats["structure_build_ns"]),
                                "integrated_build_ms": ns_to_ms(
                                    stats["integrated_build_ns"]),
                                "pstore_build_count":
                                    stats.get("pstore_build_count", 1),
                                "retry_ms": ns_to_ms(stats["retry_ns"]),
                                "build_total_ms": ns_to_ms(stats["build_total_ns"]),
                                "component_sum_ms": ns_to_ms(component_sum_ns),
                                "timing_residual_ms": ns_to_ms(residual_ns),
                                **sizes, "integrated_index_bytes": integrated,
                                "bytes_per_token": integrated / float(u),
                            })
                        except Exception as exc:
                            base.update({
                                "success": False, "failure_reason": repr(exc),
                                "attempt_count": 1, "failed_attempt_count": 1,
                                "resize_count": 0,
                                "final_capacity": 0, "position_generation_ms": 0,
                                "peeling_or_insertion_ms": 0,
                                "reverse_assignment_ms": 0, "locator_build_ms": 0,
                                "pstore_build_ms": 0, "pstore_build_count": 0,
                                "metadata_build_ms": 0, "structure_build_ms": 0,
                                "integrated_build_ms": 0,
                                "retry_ms": 0, "build_total_ms": 0,
                                "component_sum_ms": 0, "timing_residual_ms": 0,
                                "filter_only_bytes": 0,
                                "locator_bytes": 0, "pstore_bytes": 0,
                                "metadata_bytes": 0, "integrated_index_bytes": 0,
                                "bytes_per_token": 0,
                            })
                        rows.append(base)
    write_csv(output_path, rows, FIELDS)
    return rows
