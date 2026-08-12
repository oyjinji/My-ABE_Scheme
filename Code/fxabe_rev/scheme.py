"""Executable FX-ABE with privacy/revocation epochs and outsourced transform."""

import hashlib
import random
from time import perf_counter_ns

from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.pairinggroup import G1, G2, GT, ZR, pair

from .crypto_utils import (
    ScalarSource, aead_decrypt, aead_encrypt, kdf, random_bytes,
)
from .encoding import encode, encode_group
from .filters import create_index
from .filters.fxabf import PROFILE
from .lsss import pad_matrix, policy_rows, solve_reconstruction
from .oprf import PairingOPRF
from .revocation import BinaryRevocationTree, KUNodes
from .types import TransformMetrics


class FXABERev(ABEnc):
    """The eight algorithms from ABE-Scheme-02.md.

    Charm's repository-standard MNT224 backend supplies genuine group
    exponentiations and pairings. It exposes the asymmetric G1/G2 API but is
    intended as a research benchmark backend, not a production curve.
    """

    def __init__(self, group_obj, user_capacity=64, scheme_seed=None,
                 filter_options=None):
        super().__init__()
        self.name = "FX-ABE dual-epoch revocable CP-ABE"
        self.group = group_obj
        self.user_capacity = int(user_capacity)
        self.scalar_source = ScalarSource(group_obj, scheme_seed)
        self.byte_rng = random.Random(scheme_seed) if scheme_seed is not None else random.SystemRandom()
        self.oprf = PairingOPRF(group_obj)
        self.filter_options = dict(filter_options or {})
        self.state = None
        self._pair_counter = 0
        self.fx_build_count = 0

    def setup(self):
        if self.scalar_source.seed is None:
            g1, g2 = self.group.random(G1), self.group.random(G2)
        else:
            base = hashlib.sha256(self.scalar_source.seed).hexdigest()
            g1 = self.group.hash("FXABE-g1-" + base, G1)
            g2 = self.group.hash("FXABE-g2-" + base, G2)
        alpha = self.scalar_source.scalar()
        a = self.scalar_source.scalar()
        kappa = self.scalar_source.scalar(nonzero=True)
        pp = {
            "g1": g1, "g2": g2, "g1_a": g1 ** a,
            "egg_alpha": pair(g1, g2) ** alpha,
            "profile": PROFILE, "version": "1",
            "pairing_backend": self.group.groupType(),
        }
        msk = {"alpha": alpha, "a": a, "kappa": kappa}
        self.state = {
            "tree": BinaryRevocationTree(self.user_capacity),
            "node_secret": {}, "user_state": {}, "ku": {},
            "latest_revocation_epoch": None,
        }
        return pp, msk

    def keygen(self, pp, msk, identity, attributes, privacy_epoch, version="1"):
        self._require_state()
        identity = str(identity)
        unique = list(dict.fromkeys(map(str, attributes)))
        if identity in self.state["user_state"]:
            raise ValueError("identity is already registered")
        tree = self.state["tree"]
        tree.register(identity)
        eta = self.scalar_source.scalar(nonzero=True)
        z = self.scalar_source.scalar(nonzero=True)
        path = tree.path(identity)
        components = {}
        for node in path:
            beta = self._node_secret(node)
            exponent = z * (msk["alpha"] + msk["a"] * eta) - beta
            components[node] = pp["g2"] ** exponent
        tk_static = {
            "identity_binding": identity, "path_components": components,
            "K1": pp["g2"] ** (z * eta), "version": str(version),
        }
        tk_priv = self._privacy_components(
            pp, msk, unique, privacy_epoch, eta, z, version
        )
        rk = {"z_inv": 1 / z, "version": str(version), "identity_binding": identity}
        self.state["user_state"][identity] = {
            "attributes": unique, "eta": eta, "z": z, "version": str(version),
            "tk_static": tk_static, "rk": rk,
        }
        return tk_static, tk_priv, rk

    def privacy_key_upt(self, pp, msk, identity, new_privacy_epoch):
        user = self.state["user_state"][str(identity)]
        return self._privacy_components(
            pp, msk, user["attributes"], new_privacy_epoch,
            user["eta"], user["z"], user["version"],
        )

    def rev(self, identity, effective_revocation_epoch):
        self._require_state()
        self.state["tree"].revoke(identity, int(effective_revocation_epoch))
        return self.state["tree"].revoked_from.copy()

    def rev_key_upt(self, pp, revocation_epoch):
        self._require_state()
        epoch = int(revocation_epoch)
        if epoch in self.state["ku"]:
            return self.state["ku"][epoch]
        latest = self.state["latest_revocation_epoch"]
        if latest is not None and epoch <= latest:
            raise ValueError("revocation epochs must be published monotonically")
        cover = KUNodes(self.state["tree"], epoch)
        h_r = self._epoch_scalar(epoch)
        updates = {}
        for node in cover:
            beta = self._node_secret(node)
            q = self.scalar_source.scalar()
            updates[node] = {
                "U0": pp["g2"] ** (beta + h_r * q),
                "U1": pp["g2"] ** q,
            }
        ku = {"epoch": epoch, "version": pp["version"], "cover": updates}
        self.state["ku"][epoch] = ku
        self.state["tree"].published[epoch] = tuple(cover)
        self.state["latest_revocation_epoch"] = epoch
        return ku

    def encrypt(self, pp, msk, message, policy, privacy_epoch,
                revocation_epoch, version="1", index_name="FX-ABF",
                filter_seed=None):
        if not isinstance(message, bytes):
            raise TypeError("KEM-DEM plaintext must be bytes")
        epoch_r = int(revocation_epoch)
        if epoch_r != self.state["latest_revocation_epoch"]:
            raise ValueError("new ciphertext must use latest published revocation epoch")
        matrix, rho = policy_rows(self.group, policy)
        matrix = pad_matrix(matrix)
        ell = len(matrix)
        vector = [self.scalar_source.scalar() for _ in range(len(matrix[0]))]
        s = vector[0]
        lambdas = [
            sum((self.group.init(ZR, coefficient) * vector[j]
                 for j, coefficient in enumerate(row)), self.group.init(ZR, 0))
            for row in matrix
        ]
        token_cache = {}
        q_cache = {}
        row_tokens = []
        rows = []
        for attribute, lambda_i in zip(rho, lambdas):
            key = str(attribute)
            if key not in token_cache:
                token = self.oprf.direct_token(
                    attribute, privacy_epoch, version, msk["kappa"]
                )
                token_cache[key] = token
                q_cache[key] = self.oprf.H0(token)
            token = token_cache[key]
            r_i = self.scalar_source.scalar()
            rows.append({
                "C1": (pp["g1"] ** (msk["a"] * lambda_i)) *
                      (q_cache[key] ** (-r_i)),
                "C2": pp["g2"] ** r_i,
            })
            row_tokens.append(self.oprf.token_bytes(token))
        C = pp["g1"] ** s
        h_r = self._epoch_scalar(epoch_r)
        C_rev = C ** h_r
        postings = {}
        for row_id, token_bytes in enumerate(row_tokens, 1):
            postings.setdefault(token_bytes, []).append(row_id)
        ctx_fx = self.fx_context(
            pp, version, privacy_epoch, len(postings), ell, C, matrix
        )
        index_rng = random.Random(filter_seed) if filter_seed is not None else self.byte_rng
        index = create_index(index_name, **self.filter_options)
        index.build(postings, ctx_fx, index_rng)
        if index_name == "FX-ABF":
            self.fx_build_count += 1
        index_meta = index._metadata()
        meta = {
            "version": str(version), "privacy_epoch": str(privacy_epoch),
            "revocation_epoch": epoch_r, "ell": ell, "u": len(postings),
            "profile": PROFILE, "index_name": index_name,
            "index_metadata": index_meta,
        }
        ctx_ct = self.ct_context(pp, meta, C, C_rev, matrix)
        E = pp["egg_alpha"] ** s
        key = kdf("ABE-KEM-DEM-Key", ctx_ct, encode_group(self.group, E))
        sealed = aead_encrypt(key, message, ctx_ct, random_bytes(self.byte_rng, 12))
        return {
            "C_sym": sealed["ciphertext"], "nonce": sealed["nonce"],
            "C": C, "C_rev": C_rev, "rows": rows, "A_star": matrix,
            "meta": meta, "index": index, "ctx_fx": ctx_fx,
            "postings": postings,
        }

    def transform(self, pp, ciphertext, tk_static, tk_priv, ku, metrics=None):
        metrics = metrics or TransformMetrics()
        total_started = perf_counter_ns()
        started = perf_counter_ns()
        meta = ciphertext.get("meta", {})
        try:
            if (str(meta["version"]) != str(tk_static["version"]) or
                    str(meta["version"]) != str(tk_priv["version"]) or
                    str(meta["version"]) != str(ku["version"]) or
                    str(meta["privacy_epoch"]) != str(tk_priv["privacy_epoch"]) or
                    int(meta["revocation_epoch"]) != int(ku["epoch"]) or
                    meta["profile"] != PROFILE or
                    len(ciphertext["rows"]) != int(meta["ell"])):
                raise ValueError("metadata mismatch")
            h_r = self._epoch_scalar(meta["revocation_epoch"])
            if ciphertext["C_rev"] != ciphertext["C"] ** h_r:
                raise ValueError("invalid C_rev")
        except Exception:
            metrics.metadata_validation_ns = perf_counter_ns() - started
            metrics.transform_total_ns = perf_counter_ns() - total_started
            metrics.status = "metadata-failure"
            return None
        metrics.metadata_validation_ns = perf_counter_ns() - started

        # Revocation is checked before any row pairing or anonymous-index query.
        started = perf_counter_ns()
        intersection = set(tk_static["path_components"]) & set(ku["cover"])
        metrics.path_cover_lookup_ns = perf_counter_ns() - started
        if len(intersection) != 1:
            metrics.core_transform_ns = metrics.path_cover_lookup_ns
            metrics.transform_total_ns = perf_counter_ns() - total_started
            metrics.status = "revoked-or-invalid-path"
            return None
        node = next(iter(intersection))

        row_keys = {}
        query_fields = (
            "membership_or_retrieval_ns", "locator_lookup_ns",
            "pstore_kdf_ns", "pstore_aead_ns", "posting_decode_ns",
        )
        query_totals = {field: 0 for field in query_fields}
        for item in tk_priv["items"]:
            result = ciphertext["index"].query(item["token_bytes"], ciphertext["ctx_fx"])
            for field in query_fields:
                query_totals[field] += int(result.metrics.get(field, 0))
            if result.hit:
                for row_id in result.posting_list:
                    prior = row_keys.get(row_id)
                    if prior is not None and prior != item["K_x"]:
                        metrics.status = "conflicting-row-key"
                        return None
                    row_keys[row_id] = item["K_x"]
        for field, value in query_totals.items():
            setattr(metrics, field, value)
        metrics.index_query_ns = (
            metrics.membership_or_retrieval_ns + metrics.locator_lookup_ns
        )
        metrics.pstore_processing_ns = (
            metrics.pstore_kdf_ns + metrics.pstore_aead_ns +
            metrics.posting_decode_ns
        )
        metrics.integrated_index_query_ns = (
            metrics.index_query_ns + metrics.pstore_processing_ns
        )

        self._pair_counter = 0
        core_started = perf_counter_ns()
        started = perf_counter_ns()
        update = ku["cover"][node]
        t0 = self._pair(
            ciphertext["C"], tk_static["path_components"][node] * update["U0"]
        ) / self._pair(ciphertext["C_rev"], update["U1"])
        metrics.revocation_pairing_ns = perf_counter_ns() - started
        started = perf_counter_ns()
        transformed_rows = {}
        for row_id in sorted(row_keys):
            row = ciphertext["rows"][row_id - 1]
            transformed_rows[row_id] = (
                self._pair(row["C1"], tk_static["K1"]) *
                self._pair(row_keys[row_id], row["C2"])
            )
        metrics.row_pairing_ns = perf_counter_ns() - started
        transformed = {
            "T0": t0, "transformed_rows": transformed_rows,
            "C": ciphertext["C"], "C_rev": ciphertext["C_rev"],
            "A_star": ciphertext["A_star"], "C_sym": ciphertext["C_sym"],
            "nonce": ciphertext["nonce"], "meta": meta,
        }
        metrics.core_transform_ns = (
            metrics.path_cover_lookup_ns + (perf_counter_ns() - core_started)
        )
        metrics.pairing_count = self._pair_counter
        metrics.r = len(transformed_rows)
        metrics.transform_total_ns = perf_counter_ns() - total_started
        metrics.status = "ok"
        return transformed

    def final_dec(self, pp, transformed, recovery_key):
        if transformed is None:
            return None
        meta = transformed.get("meta", {})
        if str(meta.get("version")) != str(recovery_key.get("version")):
            return None
        row_ids = sorted(transformed["transformed_rows"])
        coefficients = solve_reconstruction(
            self.group, transformed["A_star"], row_ids
        )
        if coefficients is None:
            return None
        product = self.group.init(GT, 1)
        for row_id, coefficient in coefficients.items():
            product *= transformed["transformed_rows"][row_id] ** coefficient
        E = (transformed["T0"] / product) ** recovery_key["z_inv"]
        ctx_ct = self.ct_context(
            pp, meta, transformed["C"], transformed["C_rev"],
            transformed["A_star"],
        )
        key = kdf("ABE-KEM-DEM-Key", ctx_ct, encode_group(self.group, E))
        return aead_decrypt(key, {
            "nonce": transformed["nonce"], "ciphertext": transformed["C_sym"],
        }, ctx_ct)

    def fx_context(self, pp, version, privacy_epoch, u, ell, C, matrix):
        # revocation_epoch is intentionally absent.
        return encode([
            "ABE-FXABF-Context", PROFILE, str(version), str(privacy_epoch),
            int(u), int(ell), encode_group(self.group, C), matrix,
        ])

    def ct_context(self, pp, meta, C, C_rev, matrix):
        return encode([
            "ABE-FXABE-Ciphertext", meta["profile"], meta["version"],
            meta["privacy_epoch"], meta["revocation_epoch"], meta["ell"],
            encode_group(self.group, C), encode_group(self.group, C_rev),
            matrix, meta["index_metadata"],
        ])

    def _privacy_components(self, pp, msk, attributes, epoch, eta, z, version):
        items = []
        for attribute in attributes:
            token = self.oprf.direct_token(attribute, epoch, version, msk["kappa"])
            q_x = self.oprf.H0(token)
            items.append({
                "token": token, "token_bytes": self.oprf.token_bytes(token),
                "K_x": q_x ** (z * eta),
            })
        return {
            "items": items, "privacy_epoch": str(epoch), "version": str(version),
        }

    def _epoch_scalar(self, epoch):
        digest = hashlib.sha256(encode([
            "RABE-Revocation-Epoch", "1", int(epoch)
        ])).hexdigest()
        value = self.group.hash("FXABE-epoch-" + digest, ZR)
        return value if value != 0 else self.group.init(ZR, 1)

    def _node_secret(self, node):
        if node not in self.state["node_secret"]:
            self.state["node_secret"][node] = self.scalar_source.scalar()
        return self.state["node_secret"][node]

    def _pair(self, left, right):
        self._pair_counter += 1
        return pair(left, right)

    def _require_state(self):
        if self.state is None:
            raise RuntimeError("Setup must be called first")

    # Document spellings.
    Setup = setup
    KeyGen = keygen
    PrivacyKeyUpt = privacy_key_upt
    Encrypt = encrypt
    Rev = rev
    RevKeyUpt = rev_key_upt
    Transform = transform
    FinalDec = final_dec


TransformMetrics = TransformMetrics
