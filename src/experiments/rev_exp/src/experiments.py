"""Six real-crypto experiments with independent, YAML-controlled sampling."""

import gc
from time import perf_counter_ns

from charm.toolbox.pairinggroup import PairingGroup

from core.fxabe_rev import TransformMetrics

from .common import derive_seed, read_csv, results_paths, write_csv
from .planning import endpoint_values, parse_sampling, sampling_for_n
from .revocation import measured_rev_key_upt, register_users, revoke_indices
from .workloads import (
    build_policy_privacy_material, bulk_privacy_update,
    initialize_lightweight_users, new_scheme, or_policy, placement,
    transform_attributes,
)


def _scheme_with_users(group, n, seed):
    scheme, pp, msk = new_scheme(group, n, seed)
    register_users(scheme.state["tree"], n)
    return scheme, pp, msk


def _rev_sample(group, n, revoked, seed):
    scheme, pp, _ = _scheme_with_users(group, n, seed)
    started = perf_counter_ns()
    revoke_indices(scheme.state["tree"], revoked, 1)
    rev_ns = perf_counter_ns() - started
    _, metrics = measured_rev_key_upt(scheme, pp, 1)
    return metrics, rev_ns


def _base_row(config, experiment, sampling, placement_seed, repeat, crypto_seed):
    return {
        "experiment": experiment,
        "mode": config["mode"],
        "master_seed": int(config["master_seed"]),
        "placement_seed": int(placement_seed),
        "crypto_repeat": int(repeat),
        "repeat": int(repeat),
        "crypto_seed": int(crypto_seed),
        "warmup": sampling.warmup,
        "configured_repeat": sampling.repeats,
        "placement_count": sampling.placements,
        "gc_enabled": gc.isenabled(),
    }


def run_exp01(config, group, raw_dir):
    section = config["exp01"]
    rows = []
    for n in endpoint_values(section):
        sampling = sampling_for_n(section, n)
        endpoint_tier = "large_endpoint" if n not in map(int, section["n"]) else "default"
        for ratio in map(float, section["ratios"]):
            r_v = max(1, int(round(n * ratio)))
            for pseed in range(sampling.placements):
                revoked = placement(config["master_seed"], "exp01", n, r_v, pseed)
                for warm in range(sampling.warmup):
                    seed = derive_seed(config["master_seed"], "exp01", n, ratio,
                                       pseed, "w", warm)
                    _rev_sample(group, n, revoked, seed)
                for repeat in range(sampling.repeats):
                    seed = derive_seed(config["master_seed"], "exp01", n, ratio,
                                       pseed, repeat)
                    metrics, rev_ns = _rev_sample(group, n, revoked, seed)
                    rev_time_ms = rev_ns / 1e6
                    revkeyupt_time_ms = metrics.total_ns / 1e6
                    rows.append({
                        **_base_row(config, "exp01", sampling, pseed, repeat, seed),
                        "sampling_tier": endpoint_tier,
                        "n": n, "r_v": r_v, "revocation_ratio": ratio,
                        "rev_time_ns": rev_ns,
                        "rev_time_ms": rev_time_ms,
                        "revkeyupt_time_ms": revkeyupt_time_ms,
                        "dual_epoch_total_ms": rev_time_ms + revkeyupt_time_ms,
                        **metrics.as_dict(),
                    })
    write_csv(raw_dir / "exp01_revkeyupt_vs_users_raw.csv", rows)
    return rows


def run_exp02(config, group, raw_dir):
    section = config["exp02"]
    sampling = parse_sampling(section["sampling"])
    n = int(section["n"])
    rows = []
    for r_v in map(int, section["r_v"]):
        for pseed in range(sampling.placements):
            revoked = placement(config["master_seed"], "exp02", n, r_v, pseed)
            for warm in range(sampling.warmup):
                seed = derive_seed(config["master_seed"], "exp02", n, r_v,
                                   pseed, "w", warm)
                _rev_sample(group, n, revoked, seed)
            for repeat in range(sampling.repeats):
                seed = derive_seed(config["master_seed"], "exp02", n, r_v,
                                   pseed, repeat)
                metrics, _ = _rev_sample(group, n, revoked, seed)
                rows.append({
                    **_base_row(config, "exp02", sampling, pseed, repeat, seed),
                    "sampling_tier": "default", "n": n, "r_v": r_v,
                    **metrics.as_dict(),
                })
    write_csv(raw_dir / "exp02_revkeyupt_vs_revoked_raw.csv", rows)
    # Exp03 is a byte-for-byte derived view of these exact placements/samples.
    exp03 = [{**row, "experiment": "exp03", "source_experiment": "exp02"}
             for row in rows]
    write_csv(raw_dir / "exp03_cover_ku_vs_revoked_raw.csv", exp03)
    return rows


def _prepare_transform(config, group, r_v, pseed):
    section = config["exp04"]
    n, N, r, ell = (int(section[key]) for key in ("n", "N", "r", "ell"))
    seed = derive_seed(config["master_seed"], "exp04", r_v, pseed)
    scheme, pp, msk = new_scheme(group, n, seed)
    static, private, recovery = scheme.keygen(
        pp, msk, "user-0", transform_attributes(N, r), section["privacy_epoch"]
    )
    for index in range(1, n):
        scheme.state["tree"].register("user-%d" % index)
    revoked = placement(
        config["master_seed"], "exp04", n, r_v, pseed, excluded=(0,)
    )
    revoke_indices(scheme.state["tree"], revoked, int(section["revocation_epoch"]))
    ku, ku_metrics = measured_rev_key_upt(
        scheme, pp, int(section["revocation_epoch"])
    )
    ciphertext = scheme.encrypt(
        pp, msk, b"Rev_Exp transform message", or_policy(ell),
        section["privacy_epoch"], int(section["revocation_epoch"]),
        filter_seed=derive_seed(seed, "filter"),
    )
    probe = scheme.transform(pp, ciphertext, static, private, ku, TransformMetrics())
    if scheme.final_dec(pp, probe, recovery) != b"Rev_Exp transform message":
        raise AssertionError("prepared Transform workload does not decrypt")
    return scheme, pp, static, private, ku, ciphertext, ku_metrics


def run_exp04(config, group, raw_dir):
    rows = []
    section = config["exp04"]
    sampling = parse_sampling(section["sampling"])
    for r_v in map(int, section["r_v"]):
        for pseed in range(sampling.placements):
            prepared = _prepare_transform(config, group, r_v, pseed)
            scheme, pp, static, private, ku, ciphertext, ku_metrics = prepared
            for _ in range(sampling.warmup):
                scheme.transform(pp, ciphertext, static, private, ku, TransformMetrics())
            for repeat in range(sampling.repeats):
                metrics = TransformMetrics()
                result = scheme.transform(pp, ciphertext, static, private, ku, metrics)
                if result is None or metrics.status != "ok":
                    raise AssertionError("Transform failed during benchmark")
                expected_pairings = 2 + 2 * int(section["r"])
                if metrics.r != int(section["r"]) or metrics.pairing_count != expected_pairings:
                    raise AssertionError("fixed-r Transform operation count changed")
                seed = derive_seed(config["master_seed"], "exp04", r_v, pseed, repeat)
                rows.append({
                    **_base_row(config, "exp04", sampling, pseed, repeat, seed),
                    "n": int(section["n"]), "r_v": r_v,
                    "N": int(section["N"]), "ell": int(section["ell"]),
                    "configured_r": int(section["r"]),
                    "privacy_epoch": section["privacy_epoch"],
                    "revocation_epoch": int(section["revocation_epoch"]),
                    "cover_size": ku_metrics.cover_size,
                    "fx_query_ns": metrics.integrated_index_query_ns,
                    "pairing_ns": metrics.revocation_pairing_ns + metrics.row_pairing_ns,
                    "path_cover_lookup_ms": metrics.path_cover_lookup_ns / 1e6,
                    "fx_query_ms": metrics.integrated_index_query_ns / 1e6,
                    "pairing_ms": (metrics.revocation_pairing_ns +
                                   metrics.row_pairing_ns) / 1e6,
                    "transform_total_ms": metrics.transform_total_ns / 1e6,
                    "actual_hit_rows": metrics.r,
                    "actual_pairing_count": metrics.pairing_count,
                    **metrics.as_dict(),
                })
    write_csv(raw_dir / "exp04_transform_vs_revoked_raw.csv", rows)
    return rows


def _direct_epoch_sample(config, group, n, pseed, repeat, mode, sampling,
                         warmup=False):
    section = config["exp05"]
    seed = derive_seed(config["master_seed"], "exp05-A", n, pseed, repeat, mode,
                       "warmup" if warmup else "measure")
    attrs = ["A%04d" % i for i in range(int(section["S"]))]
    scheme, pp, msk = new_scheme(group, n, seed)
    # Both direct-comparison modes start from the same type of valid user state.
    initialize_lightweight_users(scheme, n, attrs)
    r_v = max(1, int(round(n * float(section["revocation_ratio"]))))
    revoked = placement(config["master_seed"], "exp05-A", n, r_v, pseed)

    total_started = perf_counter_ns()
    started = perf_counter_ns()
    revoke_indices(scheme.state["tree"], revoked, int(section["revocation_epoch"]))
    rev_ns = perf_counter_ns() - started
    _, rev_metrics = measured_rev_key_upt(scheme, pp, int(section["revocation_epoch"]))
    bulk_ns = token_ns = fx_ns = pstore_ns = 0
    active_count = n - r_v
    attempts = resizes = 0
    if mode == "Coupled-Epoch Ablation":
        revoked_set = set(revoked)
        active = (index for index in range(n) if index not in revoked_set)
        bulk_ns, observed = bulk_privacy_update(
            scheme, pp, msk, active, section["next_privacy_epoch"]
        )
        if observed != active_count:
            raise AssertionError("bulk PrivacyKeyUpt count mismatch")
        privacy = build_policy_privacy_material(
            scheme, pp, msk, int(section["ell"]),
            int(section["policy_unique_attributes"]),
            section["next_privacy_epoch"], derive_seed(seed, "policy"),
        )
        token_ns = privacy["token_refresh_ns"]
        fx_ns = privacy["fx_rebuild_ns"]
        pstore_ns = privacy["pstore_rebuild_ns"]
        attempts = privacy["fx_build_attempts"]
        resizes = privacy["fx_resize_count"]
    total_ns = perf_counter_ns() - total_started
    unique = int(section["policy_unique_attributes"])
    return {
        **_base_row(config, "exp05", sampling, pseed, repeat, seed),
        "experiment_domain": "direct_comparison",
        "source_experiment": "",
        "source_revocation_ratio": "",
        "sampling_tier": "default", "n": n, "r_v": r_v,
        "revocation_ratio": float(section["revocation_ratio"]),
        "S": int(section["S"]), "ell": int(section["ell"]),
        "policy_unique_attributes": unique,
        "policy_duplicate_ratio": 1.0 - unique / float(section["ell"]),
        "epoch_model": mode, "active_user_count": active_count,
        "rev_ns": rev_ns, "revkeyupt_ns": rev_metrics.total_ns,
        "rev_time_ms": rev_ns / 1e6,
        "revkeyupt_time_ms": rev_metrics.total_ns / 1e6,
        "kunodes_ns": rev_metrics.kunodes_ns,
        "ku_crypto_ns": rev_metrics.ku_crypto_ns,
        "bulk_privacykeyupt_ns": bulk_ns,
        "policy_token_refresh_ns": token_ns,
        "fx_build_ns": fx_ns, "fx_rebuild_ns": fx_ns,
        "pstore_rebuild_ns": pstore_ns,
        "total_epoch_update_ns": total_ns,
        "dual_epoch_total_ms": total_ns / 1e6,
        "cover_size": rev_metrics.cover_size,
        "fx_build_attempts": attempts, "fx_resize_count": resizes,
    }


def derive_exp05b_rows(exp01_rows, config):
    """Create the Exp05-B analytical view without executing any crypto."""
    section = config["exp05"]
    dual = section["dual_scalability"]
    targets = set(endpoint_values(dual))
    selected = [row for row in exp01_rows
                if int(row["n"]) in targets and
                abs(float(row["revocation_ratio"]) - 0.05) < 1e-12]
    present = {int(row["n"]) for row in selected}
    if present != targets:
        raise ValueError("Exp01 lacks required 5% samples for Exp05-B: %s" %
                         sorted(targets - present))
    unique = int(section["policy_unique_attributes"])
    derived = []
    for source in selected:
        rev_ns = int(float(source["rev_time_ns"]))
        revkeyupt_ns = int(float(source["total_ns"]))
        derived.append({
            "experiment": "exp05",
            "mode": source["mode"],
            "master_seed": source["master_seed"],
            "placement_seed": source["placement_seed"],
            "crypto_repeat": source["crypto_repeat"],
            "repeat": source["repeat"],
            "crypto_seed": source["crypto_seed"],
            "warmup": source["warmup"],
            "configured_repeat": source["configured_repeat"],
            "placement_count": source["placement_count"],
            "gc_enabled": source["gc_enabled"],
            "source_experiment": "exp01",
            "source_revocation_ratio": 0.05,
            "experiment_domain": "dual_scalability",
            "sampling_tier": source["sampling_tier"],
            "n": source["n"], "r_v": source["r_v"],
            "revocation_ratio": source["revocation_ratio"],
            "S": int(section["S"]), "ell": int(section["ell"]),
            "policy_unique_attributes": unique,
            "policy_duplicate_ratio": 1.0 - unique / float(section["ell"]),
            "epoch_model": "Dual-Epoch",
            "active_user_count": int(source["n"]) - int(source["r_v"]),
            "rev_ns": rev_ns,
            "revkeyupt_ns": revkeyupt_ns,
            "rev_time_ms": float(source["rev_time_ms"]),
            "revkeyupt_time_ms": float(source["revkeyupt_time_ms"]),
            "kunodes_ns": source["kunodes_ns"],
            "ku_crypto_ns": source["ku_crypto_ns"],
            "bulk_privacykeyupt_ns": 0,
            "policy_token_refresh_ns": 0,
            "fx_build_ns": 0, "fx_rebuild_ns": 0, "pstore_rebuild_ns": 0,
            "total_epoch_update_ns": rev_ns + revkeyupt_ns,
            "dual_epoch_total_ms": float(source["dual_epoch_total_ms"]),
            "cover_size": source["cover_size"],
            "fx_build_attempts": 0, "fx_resize_count": 0,
        })
    return derived


def run_exp05(config, group, raw_dir):
    rows = []
    section = config["exp05"]
    direct = section["direct_comparison"]
    direct_sampling = parse_sampling(direct["sampling"])
    for n in map(int, direct["n"]):
        for pseed in range(direct_sampling.placements):
            for mode in ("Dual-Epoch", "Coupled-Epoch Ablation"):
                for warm in range(direct_sampling.warmup):
                    _direct_epoch_sample(config, group, n, pseed, warm, mode,
                                         direct_sampling, True)
                for repeat in range(direct_sampling.repeats):
                    rows.append(_direct_epoch_sample(
                        config, group, n, pseed, repeat, mode, direct_sampling, False
                    ))

    exp01_path = raw_dir / "exp01_revkeyupt_vs_users_raw.csv"
    if not exp01_path.exists():
        raise FileNotFoundError("Exp05-B requires Exp01 raw data in the same run")
    rows.extend(derive_exp05b_rows(read_csv(exp01_path), config))
    write_csv(raw_dir / "exp05_dual_vs_coupled_epoch_raw.csv", rows)
    return rows


def run_exp06(config, group, raw_dir):
    rows = []
    section = config["exp06"]
    sampling = parse_sampling(section["sampling"], placement_dependent=False)
    for S in map(int, section["S"]):
        pseed = 0
        seed = derive_seed(config["master_seed"], "exp06", S, pseed)
        scheme, pp, msk = new_scheme(group, 1, seed)
        attrs = ["A%04d" % index for index in range(S)]
        static, private, recovery = scheme.keygen(
            pp, msk, "user-0", attrs, section["privacy_epoch"]
        )
        leaf = scheme.state["tree"].user_leaf["user-0"]
        path = scheme.state["tree"].path("user-0")
        user = scheme.state["user_state"]["user-0"]
        eta, z = user["eta"], user["z"]
        for warm in range(sampling.warmup):
            scheme.privacy_key_upt(pp, msk, "user-0", "warm-%d" % warm)
        for repeat in range(sampling.repeats):
            epoch = "%s-%d" % (section["next_privacy_epoch"], repeat)
            started = perf_counter_ns()
            updated = scheme.privacy_key_upt(pp, msk, "user-0", epoch)
            elapsed = perf_counter_ns() - started
            if ([x["token_bytes"] for x in private["items"]] ==
                    [x["token_bytes"] for x in updated["items"]]):
                raise AssertionError("privacy tokens did not change")
            unchanged = (
                scheme.state["tree"].user_leaf["user-0"] == leaf and
                scheme.state["tree"].path("user-0") == path and
                scheme.state["user_state"]["user-0"]["tk_static"] is static and
                scheme.state["user_state"]["user-0"]["rk"] is recovery and
                user["eta"] == eta and user["z"] == z
            )
            if not unchanged:
                raise AssertionError("PrivacyKeyUpt changed frozen state")
            crypto_seed = derive_seed(seed, repeat)
            rows.append({
                **_base_row(config, "exp06", sampling, pseed, repeat, crypto_seed),
                "S": S, "privacykeyupt_ns": elapsed,
                "old_privacy_epoch": section["privacy_epoch"],
                "new_privacy_epoch": epoch,
                "token_count": len(updated["items"]),
                "frozen_state_unchanged": True,
            })
    write_csv(raw_dir / "exp06_privacykeyupt_vs_attributes_raw.csv", rows)
    return rows


RUNNERS = {
    "exp01": run_exp01, "exp02": run_exp02, "exp04": run_exp04,
    "exp05": run_exp05, "exp06": run_exp06,
}


def run_selected(config, results_dir, selected=None):
    selected = list(selected or RUNNERS)
    if "exp05" in selected and "exp01" not in selected:
        selected.insert(0, "exp01")
    group = PairingGroup(config.get("pairing_group", "MNT224"))
    raw_dir = results_paths(results_dir)["raw"]
    output = {}
    for name in selected:
        if name == "exp03":
            continue
        output[name] = RUNNERS[name](config, group, raw_dir)
    return group, output
