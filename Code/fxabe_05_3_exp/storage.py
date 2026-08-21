"""Canonical byte accounting for FXABE 05.3 and the official FABEO object."""

from .encoding import encode


def fxabe_ciphertext_bytes(group, ct):
    index = ct["index"].accounting()
    g1_core = len(group.serialize(ct["C"])) + sum(len(group.serialize(x)) for x in ct["Ci"])
    g2_core = sum(len(group.serialize(x)) for x in ct["D"])
    revocation = len(group.serialize(ct["C_rev"]))
    header = len(encode(ct["Hdr_CT"])) + len(encode(ct["A"]))
    dem = len(ct["nonce"]) + len(ct["C_sym"])
    result = dict(index)
    result.update({
        "CT_core_G1_bytes": g1_core, "CT_core_G2_bytes": g2_core,
        "CT_revocation_bytes": revocation, "header_bytes": header,
        "DEM_bytes": dem,
    })
    result["total_CT_bytes"] = (
        g1_core + g2_core + revocation + header + dem +
        index["FX_PStore_serialized_bytes"]
    )
    return result


def fabeo_ciphertext_bytes(group, ct):
    g1 = sum(len(group.serialize(x)) for x in ct["ct"].values())
    g2 = len(group.serialize(ct["g2_s1"])) + len(group.serialize(ct["g2_sprime"]))
    gt = len(group.serialize(ct["Cp"]))
    policy_string = ct.get("_benchmark_policy_string")
    if policy_string is None:
        # Small direct source invocations remain supported. Formal benchmark
        # rows always arrive through the adapter and carry the exact input.
        policy_string = str(ct["policy"])
    header = len(encode(policy_string))
    return {
        "CT_core_G1_bytes": g1, "CT_core_G2_bytes": g2,
        "CT_core_GT_bytes": gt, "header_bytes": header,
        "total_CT_bytes": g1 + g2 + gt + header,
    }


def recursive_group_bytes(group, value):
    if isinstance(value, dict):
        return sum(recursive_group_bytes(group, x) for x in value.values())
    if isinstance(value, (list, tuple)):
        return sum(recursive_group_bytes(group, x) for x in value)
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return len(value) if isinstance(value, bytes) else len(encode(value))
    return len(group.serialize(value))
