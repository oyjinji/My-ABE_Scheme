"""Deterministic ciphertext-side serialized size accounting.

Group elements are measured with the group's canonical ``serialize`` output
(not Python ``sys.getsizeof``); structures (LSSS matrices, metadata dicts,
posting lists) are measured with the repository's canonical ``encode`` framing
so the numbers reflect wire/communication size.  Exp07 compares the
ciphertext-side / delivery-side package only; secret key and public parameter
sizes are reported as supplementary metrics.
"""

from Code.fxabe_rev.encoding import encode, encode_group


def group_bytes(group, element):
    return len(group.serialize(element))


def encoded_bytes(value):
    if isinstance(value, bytes):
        return len(value)
    return len(encode(value))


def g1_bytes(group, element):
    return len(group.serialize(element))


def g2_bytes(group, element):
    return len(group.serialize(element))


def gt_bytes(group, element):
    return len(group.serialize(element))


def fabeo22_ciphertext_size(group, ciphertext):
    """FABEO22 ciphertext-side size.

    The FABEO22 ciphertext is a group-element KEM (no DEM): two G2 elements,
    ``l`` G1 row elements, one GT ``Cp``, plus the policy string metadata.
    """
    ct = ciphertext
    row_bytes = sum(g1_bytes(group, value) for value in ct["ct"].values())
    ct_bytes = (
        g2_bytes(group, ct["g2_s1"])
        + g2_bytes(group, ct["g2_sprime"])
        + row_bytes
        + gt_bytes(group, ct["Cp"])
    )
    policy_bytes = encoded_bytes(str(ct["policy"]))
    return {
        "ct_bytes": ct_bytes,
        "filter_bytes": None,
        "pstore_bytes": None,
        "metadata_bytes": policy_bytes,
        "total_bytes": ct_bytes + policy_bytes,
    }


def fxabe_abe_bytes(group, ciphertext):
    """ABE part of an FXABE ciphertext: rows + C + C_rev + KEM-DEM payload."""
    rows = ciphertext["rows"]
    row_bytes = sum(
        g1_bytes(group, row["C1"]) + g2_bytes(group, row["C2"]) for row in rows
    )
    ct_bytes = (
        row_bytes
        + g1_bytes(group, ciphertext["C"])
        + g1_bytes(group, ciphertext["C_rev"])
        + encoded_bytes(ciphertext["C_sym"])
        + encoded_bytes(ciphertext["nonce"])
    )
    return ct_bytes


def fxabe_matrix_meta_bytes(group, ciphertext):
    """Encoded LSSS matrix plus ciphertext metadata dict."""
    return encoded_bytes(ciphertext["A_star"]) + encoded_bytes(
        {"meta": ciphertext["meta"]}
    )


def fxabe_full_ciphertext_size(group, ciphertext):
    """FXABE-Full ciphertext-side package: ABE ct + FX-ABF + PStore + metadata."""
    ct_bytes = fxabe_abe_bytes(group, ciphertext)
    index = ciphertext["index"]
    breakdown = index.size_breakdown()  # filter_only / locator / pstore / metadata
    filter_bytes = breakdown.get("filter_only_bytes", 0) + breakdown.get("locator_bytes", 0)
    pstore_bytes = breakdown.get("pstore_bytes", 0)
    metadata_bytes = (
        breakdown.get("metadata_bytes", 0)
        + fxabe_matrix_meta_bytes(group, ciphertext)
    )
    total = ct_bytes + filter_bytes + pstore_bytes + metadata_bytes
    return {
        "ct_bytes": ct_bytes,
        "filter_bytes": filter_bytes,
        "pstore_bytes": pstore_bytes,
        "metadata_bytes": metadata_bytes,
        "total_bytes": total,
    }


def fxabe_base_ciphertext_size(group, ciphertext):
    """FXABE-Base ciphertext-side package: ABE ct + direct rho metadata.

    No anonymous index / PStore exist in Base, so filter and pstore bytes are
    ``None`` (algorithmically N/A), never a misleading 0.
    """
    ct_bytes = fxabe_abe_bytes(group, ciphertext)
    metadata_bytes = (
        encoded_bytes(ciphertext.get("direct_rho", []))
        + fxabe_matrix_meta_bytes(group, ciphertext)
    )
    return {
        "ct_bytes": ct_bytes,
        "filter_bytes": None,
        "pstore_bytes": None,
        "metadata_bytes": metadata_bytes,
        "total_bytes": ct_bytes + metadata_bytes,
    }


def ciphertext_size(group, scheme_name, ciphertext):
    """Unified dispatch: canonical ciphertext-side size by scheme."""
    if scheme_name == "FABEO22":
        return fabeo22_ciphertext_size(group, ciphertext)
    if scheme_name == "FXABE-Base":
        return fxabe_base_ciphertext_size(group, ciphertext)
    if scheme_name == "FXABE-Full":
        return fxabe_full_ciphertext_size(group, ciphertext)
    raise ValueError("unknown scheme %r" % scheme_name)
