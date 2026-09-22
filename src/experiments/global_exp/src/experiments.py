"""Eight global ABE experiments (Exp01-Exp08) over shared workloads.

Every experiment consumes the same :class:`Workload` objects for all three
schemes (same policy / LSSS / rho / user set / message / seed), uses the same
Charm pairing backend and the same high-resolution timer, and writes every raw
repetition to CSV (requirement 17).  Timed regions exclude workload
generation, CSV writing and unrelated validation; they include every real
cryptographic step of the measured algorithm (requirement 5.5).
"""

import gc
import os
import sys
from time import perf_counter_ns

from charm.toolbox.pairinggroup import GT, PairingGroup

from .adapters import create_adapter
from .common import derive_seed, ns_to_ms, results_paths, write_csv
from .storage import ciphertext_size
from .timing import SectionTimer
from .workloads import build_workload

PRIVACY_EPOCH = "privacy-1"
REVOCATION_EPOCH = 1
IDENTITY = "user-0"

RAW_FIELDS = [
    "experiment", "scheme", "config", "run_name", "seed", "repetition",
    "policy_rows", "policy_cols", "user_attrs", "satisfied_rows",
    "universe_size",
    "setup_ms", "crypto_setup_ms", "aux_setup_ms",
    "keygen_ms", "privacy_key_update_ms", "provisioning_total_ms",
    "user_oprf_ms", "direct_lookup_ms", "index_query_ms",
    "oprf_ms", "filter_build_ms", "filter_lookup_ms",
    "pstore_build_ms", "pstore_lookup_ms",
    "abe_encrypt_ms", "abe_crypto_ms", "encrypt_total_ms",
    "transform_ms", "finaldec_ms", "decrypt_total_ms",
    "end_to_end_decrypt_ms",
    "pair_count",
    "ct_bytes", "filter_bytes", "pstore_bytes", "metadata_bytes", "total_bytes",
    "breakdown_other_ms",
    "fx_attempts", "fx_resizes",
    "status",
    "policy_hash", "matrix_hash", "rho_hash", "user_set_hash", "message_hash",
]


def _base_row(config, run_name, workload, scheme_name, repetition, seed):
    return {
        "config": config["mode"],
        "run_name": run_name,
        "seed": int(seed),
        "repetition": int(repetition),
        "policy_rows": workload.policy_rows_l,
        "policy_cols": workload.policy_cols,
        "user_attrs": workload.user_attrs,
        "satisfied_rows": workload.satisfied_rows,
        "universe_size": workload.universe_size,
        **workload.fingerprints,
    }


def _fill(row, **values):
    for key, value in values.items():
        if value is None:
            row[key] = ""
        else:
            row[key] = value
    return row


def _prepare(adapter, workload, seed):
    """Build a fresh, fully-real scheme + keys + revocation state (untimed)."""
    scheme = adapter.new_scheme(
        derive_seed(workload.master_seed, workload.experiment, "scheme",
                    workload.seed, seed)
    )
    setup = adapter.setup(scheme, seed)
    prov = adapter.provision(
        scheme, setup["pk"], setup["msk"], workload, IDENTITY, PRIVACY_EPOCH
    )
    ku = None
    if adapter.has_revocation:
        scheme.state["tree"].register("user-1")
        scheme.rev("user-1", REVOCATION_EPOCH)
        scheme.rev_key_upt(setup["pk"], REVOCATION_EPOCH)
        ku = scheme.state["ku"][REVOCATION_EPOCH]
    return scheme, setup, prov, ku


def _fresh_ciphertext(adapter, scheme, setup, workload, seed):
    filter_seed = derive_seed(
        workload.master_seed, workload.experiment, "filter", workload.seed, seed
    )
    return adapter.encrypt(
        scheme, setup["pk"], setup["msk"], workload, PRIVACY_EPOCH,
        REVOCATION_EPOCH, seed=filter_seed,
    )


def _workload_for(config, experiment, l, user_attrs):
    seed = derive_seed(int(config["master_seed"]), experiment, int(l),
                       int(user_attrs))
    return build_workload(
        int(config["master_seed"]), experiment, seed, int(l), int(user_attrs),
        float(config.get("satisfaction_ratio", 0.5)),
    )


# ---------------------------------------------------------------------------
# Exp01 - System Setup Cost
# ---------------------------------------------------------------------------
def run_exp01(config, group, run_name, raw_dir, schemes):
    rows = []
    # Setup is universe-independent for all three large-universe schemes, so we
    # benchmark it once per repetition against a fixed trivial workload and
    # present a scheme bar chart (no fabricated universe-size scaling).
    workload = build_workload(int(config["master_seed"]), "exp01", 1, 8, 4, 0.5)
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)))
        for repetition in range(int(config["repetitions"])):
            seed = derive_seed(int(config["master_seed"]), "exp01",
                               scheme_name, repetition)
            scheme = adapter.new_scheme(seed)
            setup = adapter.setup(scheme, seed)
            row = _base_row(config, run_name, workload, scheme_name,
                            repetition, seed)
            rows.append(_fill(
                row, scheme=scheme_name, experiment="exp01",
                setup_ms=setup["setup_ms"],
                crypto_setup_ms=setup["crypto_setup_ms"],
                aux_setup_ms=setup["aux_setup_ms"],
                status="ok",
            ))
    write_csv(raw_dir / "exp01_setup_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp02 - User Provisioning Cost vs |S|
# ---------------------------------------------------------------------------
def run_exp02(config, group, run_name, raw_dir, schemes):
    rows = []
    l = int(config.get("exp02_policy_rows", 4))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)))
        for S in map(int, config["user_attrs"]):
            for repetition in range(int(config["repetitions"])):
                workload = _workload_for(config, "exp02", l, S)
                seed = derive_seed(int(config["master_seed"]), "exp02",
                                   scheme_name, S, repetition)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                rows.append(_fill(
                    row, scheme=scheme_name, experiment="exp02",
                    keygen_ms=prov["keygen_ms"],
                    provisioning_total_ms=prov["provisioning_total_ms"],
                    oprf_ms=prov.get("oprf_ms"),
                    status="ok",
                ))
    write_csv(raw_dir / "exp02_user_provisioning_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp03 - End-to-End Encryption Cost vs Policy Rows
# ---------------------------------------------------------------------------
def run_exp03(config, group, run_name, raw_dir, schemes):
    rows = []
    ratio = float(config.get("satisfaction_ratio", 0.5))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for l in map(int, config["policy_rows"]):
            S = max(1, int(round(l * ratio)))
            workload = _workload_for(config, "exp03", l, S)
            for warm in range(int(config["warmups"])):
                seed = derive_seed(int(config["master_seed"]), "exp03",
                                   scheme_name, l, "w", warm)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                _fresh_ciphertext(adapter, scheme, setup, workload, seed)
            for repetition in range(int(config["repetitions"])):
                seed = derive_seed(int(config["master_seed"]), "exp03",
                                   scheme_name, l, repetition)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                sizes = adapter.size(enc["ct"])
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                fx_attempts = fx_resizes = ""
                if scheme_name == "FXABE-Full":
                    stats = enc["ct"]["index"].stats()
                    fx_attempts = stats.get("attempt_count", "")
                    fx_resizes = stats.get("resize_count", "")
                rows.append(_fill(
                    row, scheme=scheme_name, experiment="exp03",
                    oprf_ms=enc.get("oprf_ms"),
                    filter_build_ms=enc.get("filter_build_ms"),
                    pstore_build_ms=enc.get("pstore_build_ms"),
                    abe_encrypt_ms=enc["abe_encrypt_ms"],
                    abe_crypto_ms=enc.get("abe_crypto_ms"),
                    encrypt_total_ms=enc["encrypt_total_ms"],
                    ct_bytes=sizes["ct_bytes"],
                    filter_bytes=sizes["filter_bytes"],
                    pstore_bytes=sizes["pstore_bytes"],
                    metadata_bytes=sizes["metadata_bytes"],
                    total_bytes=sizes["total_bytes"],
                    fx_attempts=fx_attempts, fx_resizes=fx_resizes,
                    status="ok",
                ))
    write_csv(raw_dir / "exp03_encrypt_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp04 - CSP Transform Cost vs Policy Rows
# ---------------------------------------------------------------------------
def run_exp04(config, group, run_name, raw_dir, schemes):
    rows = []
    ratio = float(config.get("satisfaction_ratio", 0.5))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for l in map(int, config["policy_rows"]):
            S = max(1, int(round(l * ratio)))
            workload = _workload_for(config, "exp04", l, S)
            if scheme_name == "FABEO22":
                # FABEO22 has no outsourced Transform: explicitly N/A.
                for repetition in range(int(config["repetitions"])):
                    seed = derive_seed(int(config["master_seed"]), "exp04",
                                       scheme_name, l, repetition)
                    row = _base_row(config, run_name, workload, scheme_name,
                                    repetition, seed)
                    rows.append(_fill(
                        row, scheme=scheme_name, experiment="exp04",
                        transform_ms="", pair_count="",
                        status="na", breakdown_other_ms="",
                    ))
                continue
            for warm in range(int(config["warmups"])):
                seed = derive_seed(int(config["master_seed"]), "exp04",
                                   scheme_name, l, "w", warm)
                scheme, setup, prov, ku = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                adapter.transform(scheme, setup["pk"], enc["ct"], prov["keys"], ku)
            for repetition in range(int(config["repetitions"])):
                seed = derive_seed(int(config["master_seed"]), "exp04",
                                   scheme_name, l, repetition)
                scheme, setup, prov, ku = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                tr = adapter.transform(scheme, setup["pk"], enc["ct"],
                                       prov["keys"], ku)
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                rows.append(_fill(
                    row, scheme=scheme_name, experiment="exp04",
                    transform_ms=tr["transform_ms"],
                    pair_count=tr["pair_count"],
                    index_query_ms=tr.get("index_query_ms"),
                    filter_lookup_ms=tr.get("filter_lookup_ms"),
                    pstore_lookup_ms=tr.get("pstore_lookup_ms"),
                    status=tr["status"],
                ))
    write_csv(raw_dir / "exp04_transform_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp05 - Client-Side Decryption Cost vs Policy Rows
# ---------------------------------------------------------------------------
def run_exp05(config, group, run_name, raw_dir, schemes):
    rows = []
    ratio = float(config.get("satisfaction_ratio", 0.5))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for l in map(int, config["policy_rows"]):
            S = max(1, int(round(l * ratio)))
            workload = _workload_for(config, "exp05", l, S)
            for warm in range(int(config["warmups"])):
                seed = derive_seed(int(config["master_seed"]), "exp05",
                                   scheme_name, l, "w", warm)
                scheme, setup, prov, ku = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                if scheme_name == "FABEO22":
                    adapter.decrypt(scheme, setup["pk"], enc["ct"], prov["keys"])
                else:
                    tr = adapter.transform(scheme, setup["pk"], enc["ct"],
                                           prov["keys"], ku)
                    adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                                      prov["keys"])
            for repetition in range(int(config["repetitions"])):
                seed = derive_seed(int(config["master_seed"]), "exp05",
                                   scheme_name, l, repetition)
                scheme, setup, prov, ku = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                if scheme_name == "FABEO22":
                    dec = adapter.decrypt(scheme, setup["pk"], enc["ct"],
                                          prov["keys"])
                    rows.append(_fill(
                        row, scheme=scheme_name, experiment="exp05",
                        finaldec_ms=dec["decrypt_ms"],
                        decrypt_total_ms=dec["decrypt_total_ms"],
                        status="ok",
                    ))
                else:
                    tr = adapter.transform(scheme, setup["pk"], enc["ct"],
                                           prov["keys"], ku)
                    fd = adapter.final_dec(scheme, setup["pk"],
                                           tr["transformed"], prov["keys"])
                    rows.append(_fill(
                        row, scheme=scheme_name, experiment="exp05",
                        finaldec_ms=fd["finaldec_ms"],
                        decrypt_total_ms=fd["decrypt_total_ms"],
                        status=tr["status"],
                    ))
    write_csv(raw_dir / "exp05_client_decrypt_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp06 - End-to-End Decryption Latency vs Policy Rows
# ---------------------------------------------------------------------------
def _e2e_decrypt(adapter, scheme, setup, workload, prov, ku, seed):
    """Time the FXABE decryption journey (tokenize -> transform -> final).

    ``ku`` is the freshly built ciphertext.  ``REVOCATION_EPOCH`` key-update
    state is read from the scheme's real revocation tree.  FABEO22 is never
    routed here -- its callers time the whole ``decrypt`` directly.
    """
    parts = {}
    started = perf_counter_ns()
    ct = ku
    user_oprf_ms = adapter.user_oprf(
        scheme, setup["pk"], setup["msk"], workload, PRIVACY_EPOCH
    )
    parts["user_oprf_ms"] = user_oprf_ms
    tr_started = perf_counter_ns()
    tr = adapter.transform(scheme, setup["pk"], ct, prov["keys"],
                           scheme.state["ku"][REVOCATION_EPOCH])
    parts["transform_ms"] = _ms_of_ns(perf_counter_ns() - tr_started)
    parts["index_query_ms"] = tr.get("index_query_ms")
    parts["direct_lookup_ms"] = tr.get("direct_lookup_ms")
    fd_started = perf_counter_ns()
    fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"], prov["keys"])
    parts["finaldec_ms"] = _ms_of_ns(perf_counter_ns() - fd_started)
    total_ms = _ms_of_ns(perf_counter_ns() - started)
    parts["end_to_end_decrypt_ms"] = total_ms
    parts["pair_count"] = tr["pair_count"]
    parts["status"] = tr["status"]
    parts["msg"] = fd["msg"]
    return {"msg": fd["msg"], "end_to_end_decrypt_ms": total_ms}, parts


def _ms_of_ns(value):
    return float(value) / 1_000_000.0


def run_exp06(config, group, run_name, raw_dir, schemes):
    rows = []
    ratio = float(config.get("satisfaction_ratio", 0.5))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for l in map(int, config["policy_rows"]):
            S = max(1, int(round(l * ratio)))
            workload = _workload_for(config, "exp06", l, S)
            for warm in range(int(config["warmups"])):
                seed = derive_seed(int(config["master_seed"]), "exp06",
                                   scheme_name, l, "w", warm)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                if scheme_name == "FABEO22":
                    adapter.decrypt(scheme, setup["pk"], enc["ct"],
                                    prov["keys"])
                else:
                    _e2e_decrypt(adapter, scheme, setup, workload, prov,
                                 enc["ct"], seed)
            for repetition in range(int(config["repetitions"])):
                seed = derive_seed(int(config["master_seed"]), "exp06",
                                   scheme_name, l, repetition)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                if scheme_name == "FABEO22":
                    dec = adapter.decrypt(scheme, setup["pk"], enc["ct"],
                                          prov["keys"])
                    rows.append(_fill(
                        row, scheme=scheme_name, experiment="exp06",
                        end_to_end_decrypt_ms=dec["end_to_end_decrypt_ms"],
                        finaldec_ms=dec["decrypt_ms"],
                        decrypt_total_ms=dec["decrypt_total_ms"],
                        status="ok",
                    ))
                else:
                    result, parts = _e2e_decrypt(
                        adapter, scheme, setup, workload, prov, enc["ct"], seed
                    )
                    rows.append(_fill(
                        row, scheme=scheme_name, experiment="exp06",
                        user_oprf_ms=parts.get("user_oprf_ms"),
                        direct_lookup_ms=parts.get("direct_lookup_ms"),
                        index_query_ms=parts.get("index_query_ms"),
                        transform_ms=parts.get("transform_ms"),
                        finaldec_ms=parts.get("finaldec_ms"),
                        end_to_end_decrypt_ms=parts["end_to_end_decrypt_ms"],
                        decrypt_total_ms=parts["end_to_end_decrypt_ms"],
                        pair_count=parts.get("pair_count"),
                        status=parts.get("status"),
                    ))
    write_csv(raw_dir / "exp06_e2e_decrypt_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp07 - Ciphertext-Side Storage vs Policy Rows
# ---------------------------------------------------------------------------
def run_exp07(config, group, run_name, raw_dir, schemes):
    rows = []
    ratio = float(config.get("satisfaction_ratio", 0.5))
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for l in map(int, config["policy_rows"]):
            S = max(1, int(round(l * ratio)))
            workload = _workload_for(config, "exp07", l, S)
            for repetition in range(int(config["repetitions"])):
                seed = derive_seed(int(config["master_seed"]), "exp07",
                                   scheme_name, l, repetition)
                scheme, setup, prov, _ = _prepare(adapter, workload, seed)
                enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
                sizes = adapter.size(enc["ct"])
                row = _base_row(config, run_name, workload, scheme_name,
                                repetition, seed)
                rows.append(_fill(
                    row, scheme=scheme_name, experiment="exp07",
                    ct_bytes=sizes["ct_bytes"],
                    filter_bytes=sizes["filter_bytes"],
                    pstore_bytes=sizes["pstore_bytes"],
                    metadata_bytes=sizes["metadata_bytes"],
                    total_bytes=sizes["total_bytes"],
                    status="ok",
                ))
    write_csv(raw_dir / "exp07_storage_raw.csv", rows, RAW_FIELDS)
    return rows


# ---------------------------------------------------------------------------
# Exp08 - Representative End-to-End Cost Breakdown
# ---------------------------------------------------------------------------
def run_exp08(config, group, run_name, raw_dir, schemes):
    rows = []
    section = config.get("exp08", {})
    l = int(section.get("policy_rows", 0))
    if l == 0:
        values = list(map(int, config["policy_rows"]))
        l = values[len(values) // 2]
    repetitions = int(section.get("repetitions", max(3, int(config["repetitions"]))))
    ratio = float(config.get("satisfaction_ratio", 0.5))
    S = max(1, int(round(l * ratio)))
    workload = build_workload(
        int(config["master_seed"]), "exp08", derive_seed(
            int(config["master_seed"]), "exp08", l), l, S, ratio,
    )
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        for repetition in range(repetitions):
            seed = derive_seed(int(config["master_seed"]), "exp08",
                               scheme_name, l, repetition)
            scheme, setup, prov, _ = _prepare(adapter, workload, seed)
            enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
            sizes = adapter.size(enc["ct"])
            row = _base_row(config, run_name, workload, scheme_name,
                            repetition, seed)
            row = _fill(row, scheme=scheme_name, experiment="exp08",
                        ct_bytes=sizes["ct_bytes"],
                        filter_bytes=sizes["filter_bytes"],
                        pstore_bytes=sizes["pstore_bytes"],
                        metadata_bytes=sizes["metadata_bytes"],
                        total_bytes=sizes["total_bytes"],
                        status="ok")

            # --- encryption breakdown ---
            if scheme_name == "FABEO22":
                row = _fill(row, encrypt_total_ms=enc["encrypt_total_ms"],
                            abe_crypto_ms=enc["abe_encrypt_ms"],
                            breakdown_other_ms=0.0)
            else:
                parts = enc["encrypt_parts"]
                # FXABE-Base reports its direct attribute->row mapping under
                # "direct"; fold it into "other" so the stacked segments sum
                # exactly to encrypt_total_ms (FXABE-Full has no "direct" key).
                other_ms = (parts.get("other", 0.0) or 0.0) + \
                    (parts.get("direct", 0.0) or 0.0)
                row = _fill(
                    row, encrypt_total_ms=enc["encrypt_total_ms"],
                    oprf_ms=parts.get("oprf"),
                    filter_build_ms=parts.get("filter"),
                    pstore_build_ms=parts.get("pstore"),
                    abe_crypto_ms=parts.get("abe"),
                    breakdown_other_ms=other_ms,
                )

            # --- decryption breakdown ---
            if scheme_name == "FABEO22":
                dec = adapter.decrypt(scheme, setup["pk"], enc["ct"],
                                      prov["keys"])
                row = _fill(
                    row, decrypt_total_ms=dec["decrypt_total_ms"],
                    end_to_end_decrypt_ms=dec["end_to_end_decrypt_ms"],
                    finaldec_ms=dec["decrypt_ms"],
                )
            else:
                result, parts = _e2e_decrypt(
                    adapter, scheme, setup, workload, prov, enc["ct"], seed
                )
                row = _fill(
                    row, user_oprf_ms=parts.get("user_oprf_ms"),
                    direct_lookup_ms=parts.get("direct_lookup_ms"),
                    index_query_ms=parts.get("index_query_ms"),
                    transform_ms=parts.get("transform_ms"),
                    finaldec_ms=parts.get("finaldec_ms"),
                    decrypt_total_ms=parts["end_to_end_decrypt_ms"],
                    end_to_end_decrypt_ms=parts["end_to_end_decrypt_ms"],
                    pair_count=parts.get("pair_count"),
                )
            rows.append(row)
    write_csv(raw_dir / "exp08_breakdown_raw.csv", rows, RAW_FIELDS)
    return rows


RUNNERS = {
    "exp01": run_exp01,
    "exp02": run_exp02,
    "exp03": run_exp03,
    "exp04": run_exp04,
    "exp05": run_exp05,
    "exp06": run_exp06,
    "exp07": run_exp07,
    "exp08": run_exp08,
}

# Canonical raw-CSV filename per experiment (used by runners, aggregation,
# validation and planning so the naming can never drift apart).
RAW_FILENAMES = {
    "exp01": "exp01_setup_raw.csv",
    "exp02": "exp02_user_provisioning_raw.csv",
    "exp03": "exp03_encrypt_raw.csv",
    "exp04": "exp04_transform_raw.csv",
    "exp05": "exp05_client_decrypt_raw.csv",
    "exp06": "exp06_e2e_decrypt_raw.csv",
    "exp07": "exp07_storage_raw.csv",
    "exp08": "exp08_breakdown_raw.csv",
}


def run_correctness_check(config, group):
    """In-run correctness verification on a fresh, real end-to-end pipeline.

    For each scheme: one fresh workload, one fresh key set, one fresh
    ciphertext; decrypt and confirm the recovered message equals the workload
    message.  No timing, no caching.  Results are written to
    ``correctness.json`` in the run directory.
    """
    schemes = list(config.get("schemes", ["FABEO22", "FXABE-Base", "FXABE-Full"]))
    l = int(config.get("correctness_policy_rows", config["policy_rows"][0]))
    S = max(1, int(round(l * float(config.get("satisfaction_ratio", 0.5)))))
    workload = build_workload(
        int(config["master_seed"]), "correctness", derive_seed(
            int(config["master_seed"]), "correctness", l), l, S,
        float(config.get("satisfaction_ratio", 0.5)),
    )
    results = {"workload": {k: workload.fingerprints[k] for k in (
        "policy_hash", "matrix_hash", "rho_hash", "user_set_hash",
        "message_hash")}}
    for scheme_name in schemes:
        adapter = create_adapter(scheme_name, group, capacity=int(config.get(
            "user_capacity", 64)), filter_options=dict(config.get(
                "filter_options", {})))
        seed = derive_seed(int(config["master_seed"]), "correctness", scheme_name)
        scheme, setup, prov, _ = _prepare(adapter, workload, seed)
        enc = _fresh_ciphertext(adapter, scheme, setup, workload, seed)
        if scheme_name == "FABEO22":
            dec = adapter.decrypt(scheme, setup["pk"], enc["ct"], prov["keys"])
            expected = group.init(GT, workload.message_gt_int)
            ok = bool(dec["msg"] == expected)
        else:
            ku = scheme.state["ku"][REVOCATION_EPOCH]
            tr = adapter.transform(scheme, setup["pk"], enc["ct"], prov["keys"],
                                   ku)
            fd = adapter.final_dec(scheme, setup["pk"], tr["transformed"],
                                   prov["keys"])
            ok = bool(fd["msg"] == workload.message_bytes)
        results[scheme_name] = {"decrypt_ok": ok, "status": "ok" if ok else
                                "FAILED"}
    results["all_ok"] = all(results[s]["decrypt_ok"] for s in schemes)
    return results


def run_experiments(config, group, run_name, raw_dir, selected=None):
    schemes = list(config.get("schemes", ["FABEO22", "FXABE-Base", "FXABE-Full"]))
    names = list(selected or RUNNERS)
    for name in names:
        print("  running %s ..." % name, flush=True)
        RUNNERS[name](config, group, run_name, raw_dir, schemes)
        gc.collect()
