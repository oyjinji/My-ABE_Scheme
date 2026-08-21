"""Unified scheme adapters for FABEO22, FXABE-Base and FXABE-Full.

Every adapter consumes the *same* :class:`Workload` object, so all schemes see
identical policy, LSSS matrix, rho, user attribute set and message.  All
cryptographic operations are real Charm MNT224 pairing-group operations
(``setup``/``keygen``/``encrypt``/``transform``/``final_dec``); no pairing is
mocked, no result is cached across timed repetitions.

* **FABEO22**    — the repository's real FABEO22 CP-ABE (``Code/fabeo22cp``),
                   untouched.
* **FXABE-Full** — the real ``Code/fxabe_rev.FXABERev`` end-to-end pipeline:
                   OPRF -> FX-ABF -> PStore -> ABE -> CSP Transform -> FinalDec.
* **FXABE-Base** — an *internal ablation baseline*, not a published
                   construction.  It reuses the real FXABERev setup, revocation
                   tree, epoch scalars, group, pairings, KDF/AEAD and the real
                   ``final_dec``, but replaces the anonymous retrieval layer
                   (OPRF tokenization, FX-ABF, PStore) with a plaintext
                   attribute -> exact policy-row direct mapping.  The wrapper
                   only orchestrates control flow; every exponentiation and
                   pairing it performs is a real group operation.
"""

from time import perf_counter_ns

from charm.toolbox.pairinggroup import G1, G2, GT, ZR, pair

from Code.fabeo22cp import FABEO22CPABE
from Code.fxabe_rev import FXABERev, TransformMetrics
from Code.fxabe_rev.crypto_utils import aead_encrypt, kdf, random_bytes
from Code.fxabe_rev.encoding import encode_group
from Code.fxabe_rev.filters.fxabf import PROFILE
from Code.fxabe_rev.lsss import pad_matrix, policy_rows

from .storage import ciphertext_size
from .timing import SectionTimer

NONZERO = None  # placeholder to keep flake quiet; unused


def _ms(ns):
    return float(ns) / 1_000_000.0


def _unique(attributes):
    return list(dict.fromkeys(map(str, attributes)))


def _direct_q(group, attribute):
    """Plaintext attribute -> G1 element (Base direct mapping)."""
    return group.hash(str(attribute), G1)


class FABEO22Adapter:
    """Adapter over the real FABEO22 CP-ABE (no outsourced transform)."""

    name = "FABEO22"
    has_outsourced_transform = False
    has_revocation = False

    def __init__(self, group, capacity=64, filter_options=None):
        self.group = group
        self.capacity = int(capacity)

    def new_scheme(self, seed):
        return FABEO22CPABE(self.group)

    def setup(self, scheme, seed):
        started = perf_counter_ns()
        pk, msk = scheme.setup()
        setup_ms = _ms(perf_counter_ns() - started)
        return {
            "pk": pk, "msk": msk, "setup_ms": setup_ms,
            "crypto_setup_ms": setup_ms, "aux_setup_ms": 0.0,
        }

    def provision(self, scheme, pk, msk, workload, identity, privacy_epoch,
                  timer=None):
        timer = timer or SectionTimer()
        with timer.section("keygen"):
            started = perf_counter_ns()
            key = scheme.keygen(pk, msk, list(workload.user_set))
            keygen_ns = perf_counter_ns() - started
        return {
            "keys": key,
            "keygen_ms": _ms(keygen_ns),
            "provisioning_total_ms": _ms(keygen_ns),
            "privacy_key_update_ms": None,
            "oprf_ms": None,
            "timer": timer,
        }

    def encrypt(self, scheme, pk, msk, workload, privacy_epoch,
                revocation_epoch, version="1", seed=None, timer=None):
        timer = timer or SectionTimer()
        msg_gt = self.group.init(GT, workload.message_gt_int)
        with timer.section("abe_crypto"):
            started = perf_counter_ns()
            ct = scheme.encrypt(pk, msg_gt, workload.policy)
            encrypt_ns = perf_counter_ns() - started
        return {
            "ct": ct,
            "abe_encrypt_ms": _ms(encrypt_ns),
            "encrypt_total_ms": _ms(encrypt_ns),
            "oprf_ms": None, "filter_build_ms": None, "pstore_build_ms": None,
            "timer": timer,
        }

    def transform(self, scheme, pk, ct, keys, ku, timer=None):
        # FABEO22 has no outsourced Transform: N/A.
        return {"transformed": None, "transform_ms": None, "pair_count": None,
                "status": "na", "timer": timer}

    def final_dec(self, scheme, pk, transformed, keys, timer=None):
        timer = timer or SectionTimer()
        with timer.section("decrypt"):
            started = perf_counter_ns()
            msg = scheme.decrypt(pk, transformed, keys)
            decrypt_ns = perf_counter_ns() - started
        return {
            "msg": msg, "finaldec_ms": _ms(decrypt_ns),
            "decrypt_total_ms": _ms(decrypt_ns), "timer": timer,
        }

    def decrypt(self, scheme, pk, ct, keys):
        """Full client-side Decrypt (FABEO has no split transform/final)."""
        started = perf_counter_ns()
        msg = scheme.decrypt(pk, ct, keys)
        total_ms = _ms(perf_counter_ns() - started)
        return {"msg": msg, "decrypt_ms": total_ms,
                "end_to_end_decrypt_ms": total_ms, "decrypt_total_ms": total_ms}

    def size(self, ct):
        return ciphertext_size(self.group, self.name, ct)


class FXABEFullAdapter:
    """Adapter over the real FXABERev (OPRF -> FX-ABF -> PStore -> ABE)."""

    name = "FXABE-Full"
    has_outsourced_transform = True
    has_revocation = True

    def __init__(self, group, capacity=64, filter_options=None):
        self.group = group
        self.capacity = int(capacity)
        self.filter_options = dict(filter_options or {})

    def new_scheme(self, seed):
        return FXABERev(
            self.group, user_capacity=self.capacity, scheme_seed=int(seed),
            filter_options=self.filter_options,
        )

    def setup(self, scheme, seed):
        metrics = {}
        started = perf_counter_ns()
        pp, msk = scheme.setup(metrics=metrics)
        setup_ms = _ms(perf_counter_ns() - started)
        aux_ms = _ms(metrics.get("auxiliary_tree_ns", 0))
        return {
            "pk": pp, "msk": msk, "setup_ms": setup_ms,
            "crypto_setup_ms": setup_ms - aux_ms, "aux_setup_ms": aux_ms,
        }

    def provision(self, scheme, pk, msk, workload, identity, privacy_epoch,
                  timer=None):
        timer = timer or SectionTimer()
        metrics = {}
        started = perf_counter_ns()
        static, private, recovery = scheme.keygen(
            pk, msk, identity, list(workload.user_set), privacy_epoch,
            metrics=metrics,
        )
        keygen_ns = perf_counter_ns() - started
        return {
            "keys": {"static": static, "private": private, "recovery": recovery},
            "keygen_ms": _ms(keygen_ns),
            "privacy_key_update_ms": None,
            "oprf_ms": _ms(metrics.get("privacy_components_ns", 0)),
            "provisioning_total_ms": _ms(keygen_ns),
            "timer": timer,
        }

    def encrypt(self, scheme, pk, msk, workload, privacy_epoch,
                revocation_epoch, version="1", seed=None, timer=None):
        timer = timer or SectionTimer()
        metrics = {}
        started = perf_counter_ns()
        ct = scheme.encrypt(
            pk, msk, workload.message_bytes, workload.policy, privacy_epoch,
            revocation_epoch, version=version, filter_seed=seed, metrics=metrics,
        )
        encrypt_ns = perf_counter_ns() - started
        index_build_ns = metrics.get("index_build_ns", 0)
        pstore_ns = metrics.get("pstore_build_ns", 0)
        return {
            "ct": ct,
            "abe_encrypt_ms": _ms(encrypt_ns),
            "encrypt_total_ms": _ms(encrypt_ns),
            "oprf_ms": _ms(metrics.get("tokenize_ns", 0)),
            "filter_build_ms": _ms(index_build_ns - pstore_ns),
            "pstore_build_ms": _ms(pstore_ns),
            "abe_crypto_ms": _ms(metrics.get("row_crypto_ns", 0)
                                + metrics.get("group_crypto_ns", 0)
                                + metrics.get("kem_dem_ns", 0)),
            "other_ms": _ms(metrics.get("lsss_ns", 0)),
            "encrypt_parts": {
                "oprf": _ms(metrics.get("tokenize_ns", 0)),
                "filter": _ms(index_build_ns - pstore_ns),
                "pstore": _ms(pstore_ns),
                "abe": _ms(metrics.get("row_crypto_ns", 0)
                           + metrics.get("group_crypto_ns", 0)
                           + metrics.get("kem_dem_ns", 0)),
                "other": _ms(metrics.get("lsss_ns", 0)
                             + max(0, encrypt_ns - sum([
                                 metrics.get("tokenize_ns", 0),
                                 index_build_ns,
                                 metrics.get("row_crypto_ns", 0),
                                 metrics.get("group_crypto_ns", 0),
                                 metrics.get("kem_dem_ns", 0),
                                 metrics.get("lsss_ns", 0),
                             ]))),
            },
            "timer": timer,
        }

    def transform(self, scheme, pk, ct, keys, ku, timer=None):
        timer = timer or SectionTimer()
        metrics = TransformMetrics()
        with timer.section("transform"):
            started = perf_counter_ns()
            transformed = scheme.transform(
                pk, ct, keys["static"], keys["private"], ku, metrics
            )
            transform_ns = perf_counter_ns() - started
        if transformed is None:
            raise AssertionError("FXABE-Full transform failed: %s" % metrics.status)
        return {
            "transformed": transformed,
            "transform_ms": _ms(transform_ns),
            "transform_metrics": metrics,
            "pair_count": metrics.pairing_count,
            "status": metrics.status,
            "index_query_ms": _ms(metrics.integrated_index_query_ns),
            "pstore_lookup_ms": _ms(metrics.pstore_processing_ns),
            "filter_lookup_ms": _ms(metrics.index_query_ns),
            "timer": timer,
        }

    def final_dec(self, scheme, pk, transformed, keys, timer=None):
        timer = timer or SectionTimer()
        with timer.section("finaldec"):
            started = perf_counter_ns()
            msg = scheme.final_dec(pk, transformed, keys["recovery"])
            finaldec_ns = perf_counter_ns() - started
        return {
            "msg": msg, "finaldec_ms": _ms(finaldec_ns),
            "decrypt_total_ms": _ms(finaldec_ns), "timer": timer,
        }

    def user_oprf(self, scheme, pk, msk, workload, privacy_epoch, version="1"):
        """Timed OPRF tokenization of the user's attributes.

        The current implementation derives these tokens at key issuance; we
        re-measure the tokenization so the end-to-end decryption metric
        reflects the full per-query anonymous-token work a user device would
        perform when it does not cache tokens.
        """
        started = perf_counter_ns()
        for attribute in workload.user_set:
            token = scheme.oprf.direct_token(
                attribute, privacy_epoch, version, msk["kappa"]
            )
            scheme.oprf.token_bytes(token)
        return _ms(perf_counter_ns() - started)

    def size(self, ct):
        return ciphertext_size(self.group, self.name, ct)


class FXABEBaseAdapter:
    """Internal ablation baseline: real FXABE minus the anonymity layer.

    Uses the real FXABERev setup, revocation tree/epochs, scalars, group
    pairings, KDF/AEAD and the real ``final_dec``.  KeyGen replaces the OPRF
    token components with plaintext attribute hashes; Encrypt builds the same
    ABE rows with direct attribute hashes and no anonymous index; Transform
    performs a direct attribute -> policy-row lookup and the identical
    revocation + row pairings.  This is a benchmark harness wrapper, not a
    published construction.
    """

    name = "FXABE-Base"
    has_outsourced_transform = True
    has_revocation = True

    def __init__(self, group, capacity=64, filter_options=None):
        self.group = group
        self.capacity = int(capacity)

    def new_scheme(self, seed):
        return FXABERev(self.group, user_capacity=self.capacity,
                        scheme_seed=int(seed))

    def setup(self, scheme, seed):
        metrics = {}
        started = perf_counter_ns()
        pp, msk = scheme.setup(metrics=metrics)
        setup_ms = _ms(perf_counter_ns() - started)
        aux_ms = _ms(metrics.get("auxiliary_tree_ns", 0))
        return {
            "pk": pp, "msk": msk, "setup_ms": setup_ms,
            "crypto_setup_ms": setup_ms - aux_ms, "aux_setup_ms": aux_ms,
        }

    # ------------------------------------------------------------------
    # Direct (non-anonymous) KeyGen: real tree/scalars, no OPRF tokens.
    # ------------------------------------------------------------------
    def provision(self, scheme, pk, msk, workload, identity, privacy_epoch,
                  timer=None):
        timer = timer or SectionTimer()
        started = perf_counter_ns()
        identity = str(identity)
        tree = scheme.state["tree"]
        tree.register(identity)
        eta = scheme.scalar_source.scalar(nonzero=True)
        z = scheme.scalar_source.scalar(nonzero=True)
        path = tree.path(identity)
        components = {}
        for node in path:
            beta = scheme._node_secret(node)
            exponent = z * (msk["alpha"] + msk["a"] * eta) - beta
            components[node] = pk["g2"] ** exponent
        tk_static = {
            "identity_binding": identity, "path_components": components,
            "K1": pk["g2"] ** (z * eta), "version": "1",
        }
        key_attrs = {}
        for attribute in _unique(workload.user_set):
            key_attrs[str(attribute)] = _direct_q(self.group, attribute) ** (z * eta)
        rk = {"z_inv": 1 / z, "version": "1", "identity_binding": identity}
        scheme.state["user_state"][identity] = {
            "attributes": _unique(workload.user_set), "eta": eta, "z": z,
            "version": "1", "tk_static": tk_static, "rk": rk,
        }
        keygen_ns = perf_counter_ns() - started
        return {
            "keys": {"static": tk_static, "key_attrs": key_attrs,
                     "recovery": rk},
            "keygen_ms": _ms(keygen_ns),
            "privacy_key_update_ms": None,
            "oprf_ms": None,
            "provisioning_total_ms": _ms(keygen_ns),
            "aux_key_prep_ms": _ms(keygen_ns),  # keygen includes aux prep
            "timer": timer,
        }

    # ------------------------------------------------------------------
    # Direct Encrypt: same ABE rows, direct attribute hashes, no index.
    # ------------------------------------------------------------------
    def encrypt(self, scheme, pk, msk, workload, privacy_epoch,
                revocation_epoch, version="1", seed=None, timer=None):
        timer = timer or SectionTimer()
        epoch_r = int(revocation_epoch)
        with timer.section("direct_mapping"):
            matrix, rho = policy_rows(self.group, workload.policy)
            matrix = pad_matrix(matrix)
            ell = len(matrix)
        vector = [scheme.scalar_source.scalar() for _ in range(len(matrix[0]))]
        s = vector[0]
        lambdas = [
            sum((self.group.init(ZR, coefficient) * vector[j]
                 for j, coefficient in enumerate(row)), self.group.init(ZR, 0))
            for row in matrix
        ]
        rows = []
        with timer.section("abe_crypto"):
            for attribute, lambda_i in zip(rho, lambdas):
                q = _direct_q(self.group, attribute)
                r_i = scheme.scalar_source.scalar()
                rows.append({
                    "C1": (pk["g1"] ** (msk["a"] * lambda_i)) * (q ** (-r_i)),
                    "C2": pk["g2"] ** r_i,
                })
            C = pk["g1"] ** s
            h_r = scheme._epoch_scalar(epoch_r)
            C_rev = C ** h_r
            meta = {
                "version": str(version), "privacy_epoch": str(privacy_epoch),
                "revocation_epoch": epoch_r, "ell": ell, "u": len(rho),
                "profile": PROFILE, "index_name": "direct",
                "index_metadata": {"name": "direct"},
            }
            ctx_ct = scheme.ct_context(pk, meta, C, C_rev, matrix)
            E = pk["egg_alpha"] ** s
            key = kdf("ABE-KEM-DEM-Key", ctx_ct, encode_group(self.group, E))
            sealed = aead_encrypt(
                key, workload.message_bytes, ctx_ct,
                random_bytes(scheme.byte_rng, 12),
            )
        ct = {
            "C_sym": sealed["ciphertext"], "nonce": sealed["nonce"],
            "C": C, "C_rev": C_rev, "rows": rows, "A_star": matrix,
            "meta": meta, "direct_rho": list(rho),
        }
        return {
            "ct": ct,
            "abe_encrypt_ms": _ms(timer.get("abe_crypto")),
            "encrypt_total_ms": _ms(timer.total()),
            "oprf_ms": None,
            "filter_build_ms": None,
            "pstore_build_ms": None,
            "direct_mapping_ms": _ms(timer.get("direct_mapping")),
            "encrypt_parts": {
                "direct": _ms(timer.get("direct_mapping")),
                "abe": _ms(timer.get("abe_crypto")),
                "other": _ms(max(0, timer.total() - timer.get("direct_mapping")
                                - timer.get("abe_crypto"))),
            },
            "timer": timer,
        }

    # ------------------------------------------------------------------
    # Direct Transform: identical pairings, direct row lookup, no FX-ABF.
    # ------------------------------------------------------------------
    def transform(self, scheme, pk, ct, keys, ku, timer=None):
        timer = timer or SectionTimer()
        with timer.section("direct_lookup"):
            rho = ct.get("direct_rho")
            if not isinstance(rho, list):
                raise ValueError("Base ciphertext missing direct_rho")
            row_of = {}
            for index, attribute in enumerate(rho, 1):
                row_of.setdefault(str(attribute), []).append(index)
            row_keys = {}
            for attribute, k_x in keys["key_attrs"].items():
                for row_id in row_of.get(str(attribute), ()):
                    prior = row_keys.get(row_id)
                    if prior is not None and prior != k_x:
                        raise ValueError("conflicting row key in Base transform")
                    row_keys[row_id] = k_x
        meta = ct["meta"]
        scheme._pair_counter = 0
        with timer.section("transform_crypto"):
            h_r = scheme._epoch_scalar(meta["revocation_epoch"])
            if ct["C_rev"] != ct["C"] ** h_r:
                raise ValueError("invalid C_rev in Base ciphertext")
            intersection = set(keys["static"]["path_components"]) & set(ku["cover"])
            if len(intersection) != 1:
                return {"transformed": None, "transform_ms": None,
                        "pair_count": 0, "status": "revoked-or-invalid-path",
                        "direct_lookup_ms": _ms(timer.get("direct_lookup")),
                        "timer": timer}
            node = next(iter(intersection))
            update = ku["cover"][node]
            t0 = scheme._pair(
                ct["C"], keys["static"]["path_components"][node] * update["U0"]
            ) / scheme._pair(ct["C_rev"], update["U1"])
            transformed_rows = {}
            for row_id in sorted(row_keys):
                row = ct["rows"][row_id - 1]
                transformed_rows[row_id] = (
                    scheme._pair(row["C1"], keys["static"]["K1"]) *
                    scheme._pair(row_keys[row_id], row["C2"])
                )
        transformed = {
            "T0": t0, "transformed_rows": transformed_rows,
            "C": ct["C"], "C_rev": ct["C_rev"], "A_star": ct["A_star"],
            "C_sym": ct["C_sym"], "nonce": ct["nonce"], "meta": meta,
        }
        return {
            "transformed": transformed,
            "transform_ms": _ms(timer.get("transform_crypto")),
            "pair_count": scheme._pair_counter,
            "status": "ok",
            "direct_lookup_ms": _ms(timer.get("direct_lookup")),
            "index_query_ms": None,
            "pstore_lookup_ms": None,
            "timer": timer,
        }

    def final_dec(self, scheme, pk, transformed, keys, timer=None):
        timer = timer or SectionTimer()
        with timer.section("finaldec"):
            started = perf_counter_ns()
            msg = scheme.final_dec(pk, transformed, keys["recovery"])
            finaldec_ns = perf_counter_ns() - started
        return {
            "msg": msg, "finaldec_ms": _ms(finaldec_ns),
            "decrypt_total_ms": _ms(finaldec_ns), "timer": timer,
        }

    def user_oprf(self, scheme, pk, msk, workload, privacy_epoch, version="1"):
        # Base has no OPRF: N/A.
        return None

    def size(self, ct):
        return ciphertext_size(self.group, self.name, ct)


def create_adapter(scheme_name, group, capacity=64, filter_options=None):
    if scheme_name == "FABEO22":
        return FABEO22Adapter(group, capacity)
    if scheme_name == "FXABE-Base":
        return FXABEBaseAdapter(group, capacity)
    if scheme_name == "FXABE-Full":
        return FXABEFullAdapter(group, capacity, filter_options)
    raise ValueError("unknown scheme %r" % scheme_name)
