"""FXDACP: FX-ABF based two-sided anonymous outsourced CP-ABE prototype."""

import random
from time import perf_counter_ns

from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.pairinggroup import G1, G2, GT, ZR, pair

from ..msp import MSP
from .crypto_utils import aead_decrypt, aead_encrypt, kdf, random_bytes
from .encoding import encode, encode_group
from .fxabf import FXABFIndex, PROFILE
from .metrics import OperationMetrics
from .oprf import PairingOPRF


class FXDACP(ABEnc):
    """Algorithm prototype matching Setup/KeyGen/Encrypt/Transform/FinalDec.

    Charm's MNT224 pairing environment is retained for comparability with the
    repository.  It exposes G1/G2 APIs, but is not a production Type-III curve.
    """

    def __init__(self, group_obj, c_fx=1.30, delta=64, r_max=8, gamma=1.05,
                 segment_length=64, rng=None, namespace="default"):
        ABEnc.__init__(self)
        self.name = "FXDACP (FX-ABF outsourced CP-ABE)"
        self.group = group_obj
        self.util = MSP(group_obj, False)
        self.rng = rng or random.SystemRandom()
        self.oprf = PairingOPRF(group_obj, namespace=namespace)
        self.indexer = FXABFIndex(
            c_fx=c_fx, delta=delta, r_max=r_max, gamma=gamma,
            segment_length=segment_length, rng=self.rng,
        )
        self.params = {
            "profile": PROFILE, "c_fx": float(c_fx), "delta": int(delta),
            "r_max": int(r_max), "gamma": float(gamma),
            "segment_length": int(segment_length),
        }

    def setup(self, metrics=None):
        started = perf_counter_ns()
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha = self.group.random(ZR)
        a = self.group.random(ZR)
        kappa = self._random_nonzero_zr()
        pk = {
            "g1": g1,
            "g2": g2,
            "g1_a": g1 ** a,
            "egg_alpha": pair(g1, g2) ** alpha,
            "fx_params": dict(self.params),
        }
        msk = {"alpha": alpha, "a": a, "kappa": kappa}
        self._metric(metrics, "total_ns", perf_counter_ns() - started)
        return pk, msk

    def keygen(self, pk, msk, attr_list, identity="anonymous", epoch="0",
               version="1", metrics=None):
        started = perf_counter_ns()
        metric_obj = self._metrics_obj(metrics)
        unique = []
        seen = set()
        for attr in attr_list:
            encoded = self.oprf.canonicalize(attr, epoch, version)
            if encoded not in seen:
                seen.add(encoded)
                unique.append((attr, encoded))
        t = self._random_nonzero_zr()
        z = self._random_nonzero_zr()
        inv_z = 1 / z
        k0 = pk["g2"] ** ((msk["alpha"] + msk["a"] * t) * inv_z)
        k1 = pk["g2"] ** (t * inv_z)
        items = []
        token_started = perf_counter_ns()
        for attr, _encoded in unique:
            token = self.oprf.direct_token(attr, epoch, version, msk["kappa"])
            q_x = self.oprf.H0(token)
            items.append({
                "token": token,
                "token_bytes": self.oprf.token_bytes(token),
                "K_x": q_x ** (t * inv_z),
            })
        metric_obj.set("N", len(unique))
        metric_obj.set("token_generation_count", len(unique))
        metric_obj.set("token_generation_ns", perf_counter_ns() - token_started)
        metric_obj.set("observable_exponentiations", 2 + 2 * len(unique))
        metric_obj.set("total_ns", perf_counter_ns() - started)
        tk = {
            "K0": k0, "K1": k1, "items": items,
            "epoch": str(epoch), "version": str(version), "identity": str(identity),
        }
        rk = {"z": z, "epoch": str(epoch), "version": str(version)}
        return tk, rk

    def encrypt(self, pk, msk, message, policy, epoch="0", version="1", metrics=None):
        if not isinstance(message, bytes):
            raise TypeError("FXDACP KEM-DEM plaintext must be bytes")
        started = perf_counter_ns()
        metric_obj = self._metrics_obj(metrics)
        astar, rho = self._policy_rows(policy)
        ell = len(astar)
        if ell < 1:
            raise ValueError("policy must contain at least one row")
        width = max(len(row) for row in astar)
        astar = [row + [0] * (width - len(row)) for row in astar]

        share_started = perf_counter_ns()
        vector = [self.group.random(ZR) for _ in range(width)]
        s = vector[0]
        lambdas = [sum((self.group.init(ZR, coefficient) * vector[column]
                        for column, coefficient in enumerate(row)), self.group.init(ZR, 0))
                   for row in astar]
        metric_obj.set("lsss_share_ns", perf_counter_ns() - share_started)

        encoded_to_attr = {}
        row_encoded = []
        for attr in rho:
            encoded = self.oprf.canonicalize(attr, epoch, version)
            row_encoded.append(encoded)
            encoded_to_attr.setdefault(encoded, attr)
        unique_encoded = sorted(encoded_to_attr)
        unique_attrs = [encoded_to_attr[item] for item in unique_encoded]
        _encoded, tokens = self.oprf.batch_tokens(
            unique_attrs, epoch, version, msk["kappa"], metric_obj,
        )
        token_by_encoded = {encoded: token for encoded, token in zip(unique_encoded, tokens)}

        map_started = perf_counter_ns()
        token_bytes_by_encoded = {
            encoded: self.oprf.token_bytes(token)
            for encoded, token in token_by_encoded.items()
        }
        q_by_encoded = {
            encoded: self.oprf.H0(token)
            for encoded, token in token_by_encoded.items()
        }
        metric_obj.set("token_to_group_ns", perf_counter_ns() - map_started)

        component_started = perf_counter_ns()
        rows = []
        row_tokens = []
        for row_index, (encoded, lambda_i) in enumerate(zip(row_encoded, lambdas), 1):
            token_bytes = token_bytes_by_encoded[encoded]
            q_i = q_by_encoded[encoded]
            r_i = self.group.random(ZR)
            c_i1 = (pk["g1"] ** (msk["a"] * lambda_i)) * (q_i ** (-r_i))
            c_i2 = pk["g2"] ** r_i
            rows.append({"C1": c_i1, "C2": c_i2})
            row_tokens.append(token_bytes)
        metric_obj.set("abe_row_components_ns", perf_counter_ns() - component_started)

        c_header = pk["g1"] ** s
        encapsulated = pk["egg_alpha"] ** s
        posting_started = perf_counter_ns()
        postings = {}
        for row_index, token_bytes in enumerate(row_tokens, 1):
            postings.setdefault(token_bytes, []).append(row_index)
        metric_obj.set("posting_list_build_ns", perf_counter_ns() - posting_started)
        ctx = self._context(version, epoch, len(postings), ell, c_header, astar)
        index, build_stats, pstore_ns = self.indexer.build(postings, ctx, ell)
        metric_obj.set("fxabf_peeling_ns", build_stats.peeling_ns)
        metric_obj.set("fxabf_assignment_ns", build_stats.assignment_ns)
        metric_obj.set("seed_retries", build_stats.retries)
        metric_obj.set("expansions", build_stats.expansions)
        metric_obj.set("pstore_aead_ns", pstore_ns)

        meta = {
            "version": str(version), "epoch": str(epoch), "ell": ell,
            "u": len(postings), "profile": PROFILE,
            "fx": {
                "m": index["fxabf"]["m"], "b_j": index["b_j"],
                "delta": index["delta"], "seed": index["fxabf"]["seed"],
                "segment_length": index["fxabf"]["segment_length"],
                "segment_count": index["fxabf"]["segment_count"],
                "r_max": index["fxabf"]["r_max"],
            },
        }
        kem_started = perf_counter_ns()
        aad = self._message_aad(meta, c_header, astar)
        session_key = kdf(
            "ABE-KEM-DEM-Key", ctx, encode_group(self.group, encapsulated),
        )
        sealed = aead_encrypt(
            session_key, message, aad, nonce=random_bytes(self.rng, 12),
        )
        metric_obj.set("kem_dem_ns", perf_counter_ns() - kem_started)
        metric_obj.set("ell", ell)
        metric_obj.set("u", len(postings))
        metric_obj.set("oprf_count", len(postings))
        metric_obj.set("total_ns", perf_counter_ns() - started)
        return {
            "C_sym": sealed["ciphertext"], "nonce": sealed["nonce"],
            "C": c_header, "rows": rows, "A_star": astar,
            "meta": meta, "index": index,
        }

    def transform(self, pk, ciphertext, transform_key, metrics=None):
        started = perf_counter_ns()
        metric_obj = self._metrics_obj(metrics)
        meta = ciphertext.get("meta", {})
        if (meta.get("profile") != PROFILE or
                str(meta.get("epoch")) != str(transform_key.get("epoch")) or
                str(meta.get("version")) != str(transform_key.get("version"))):
            metric_obj.set("status", "metadata-mismatch")
            return None
        ctx = self._context(
            meta["version"], meta["epoch"], meta["u"], meta["ell"],
            ciphertext["C"], ciphertext["A_star"],
        )
        row_keys = {}
        totals = {
            "position_ns": 0, "slot_read_ns": 0, "xor_ns": 0,
            "range_check_ns": 0, "short_check_ns": 0, "pstore_ns": 0,
            "posting_decode_ns": 0, "slot_reads": 0,
            "aead_attempts": 0, "aead_successes": 0,
        }
        hits = 0
        query_started = perf_counter_ns()
        for item in transform_key["items"]:
            result = self.indexer.query(ciphertext["index"], item["token_bytes"], ctx)
            for name in totals:
                totals[name] += getattr(result.stats, name)
            if result.hit:
                hits += 1
                for row_id in result.posting_list:
                    existing = row_keys.get(row_id)
                    if existing is not None and existing != item["K_x"]:
                        metric_obj.set("status", "conflicting-row-key")
                        return None
                    row_keys[row_id] = item["K_x"]
        query_ns = perf_counter_ns() - query_started

        pairing_started = perf_counter_ns()
        t0 = pair(ciphertext["C"], transform_key["K0"])
        transformed_rows = {}
        for row_id in sorted(row_keys):
            row = ciphertext["rows"][row_id - 1]
            transformed_rows[row_id] = (
                pair(row["C1"], transform_key["K1"]) *
                pair(row_keys[row_id], row["C2"])
            )
        pairing_ns = perf_counter_ns() - pairing_started
        r = len(transformed_rows)
        for name, value in totals.items():
            metric_obj.set(name, value)
        metric_obj.set("N", len(transform_key["items"]))
        metric_obj.set("hit_token_count", hits)
        metric_obj.set("r", r)
        metric_obj.set("filter_query_ns", query_ns)
        metric_obj.set("pairing_count", 1 + 2 * r)
        metric_obj.set("pairing_ns", pairing_ns)
        metric_obj.set("core_transform_ns", perf_counter_ns() - started)
        metric_obj.set("total_ns", perf_counter_ns() - started)
        return {
            "T0": t0, "transformed_rows": transformed_rows,
            "C": ciphertext["C"], "A_star": ciphertext["A_star"],
            "C_sym": ciphertext["C_sym"], "nonce": ciphertext["nonce"],
            "meta": ciphertext["meta"],
        }

    def final_dec(self, pk, transformed, recovery_key, metrics=None):
        started = perf_counter_ns()
        metric_obj = self._metrics_obj(metrics)
        metric_obj.set("pairing_count", 0)
        if transformed is None:
            metric_obj.set("status", "missing-transform")
            return None
        meta = transformed.get("meta", {})
        if (str(meta.get("epoch")) != str(recovery_key.get("epoch")) or
                str(meta.get("version")) != str(recovery_key.get("version"))):
            metric_obj.set("status", "metadata-mismatch")
            return None
        solve_started = perf_counter_ns()
        solution = self._solve_reconstruction(
            transformed["A_star"], sorted(transformed["transformed_rows"]),
        )
        metric_obj.set("lsss_solve_ns", perf_counter_ns() - solve_started)
        if solution is None:
            metric_obj.set("status", "policy-unsatisfied")
            metric_obj.set("total_ns", perf_counter_ns() - started)
            return None
        gt_started = perf_counter_ns()
        product = self.group.init(GT, 1)
        for row_id, coefficient in solution.items():
            product *= transformed["transformed_rows"][row_id] ** coefficient
        recovered_blinded = transformed["T0"] / product
        encapsulated = recovered_blinded ** recovery_key["z"]
        metric_obj.set("gt_exponent_ns", perf_counter_ns() - gt_started)
        kem_started = perf_counter_ns()
        ctx = self._context(
            meta["version"], meta["epoch"], meta["u"], meta["ell"],
            transformed["C"], transformed["A_star"],
        )
        aad = self._message_aad(meta, transformed["C"], transformed["A_star"])
        key = kdf("ABE-KEM-DEM-Key", ctx, encode_group(self.group, encapsulated))
        message = aead_decrypt(key, {
            "nonce": transformed["nonce"], "ciphertext": transformed["C_sym"],
        }, aad)
        metric_obj.set("kdf_aead_ns", perf_counter_ns() - kem_started)
        metric_obj.set("returned_rows", len(transformed["transformed_rows"]))
        metric_obj.set("satisfying_set_size", len(solution))
        metric_obj.set("status", "ok" if message is not None else "aead-failure")
        metric_obj.set("total_ns", perf_counter_ns() - started)
        return message

    # Document-spelling aliases.
    Setup = setup
    KeyGen = keygen
    Encrypt = encrypt
    Transform = transform
    FinalDec = final_dec

    def _policy_rows(self, policy):
        if isinstance(policy, dict):
            matrix = policy.get("matrix", policy.get("A"))
            rho = policy.get("rho")
            if not isinstance(matrix, list) or not isinstance(rho, list):
                raise ValueError("matrix policies require matrix/A and rho lists")
            if len(matrix) != len(rho) or not matrix:
                raise ValueError("matrix and rho lengths differ")
            return [[int(value) for value in row] for row in matrix], list(rho)
        if not isinstance(policy, str):
            raise TypeError("policy must be a string or LSSS mapping")
        tree = self.util.createPolicy(policy)
        msp = self.util.convert_policy_to_msp(tree)
        matrix, rho = [], []
        for labelled_attribute, row in msp.items():
            matrix.append([int(value) for value in row])
            rho.append(self.util.strip_index(labelled_attribute))
        return matrix, rho

    def _solve_reconstruction(self, matrix, row_ids):
        if not row_ids:
            return None
        width = max(len(row) for row in matrix)
        selected = [matrix[row_id - 1] + [0] * (width - len(matrix[row_id - 1]))
                    for row_id in row_ids]
        # Solve A_I^T * omega = e_1 using reduced row echelon form over ZR.
        equations = []
        for coordinate in range(width):
            equations.append([
                self.group.init(ZR, row[coordinate]) for row in selected
            ] + [self.group.init(ZR, 1 if coordinate == 0 else 0)])
        pivot_row = 0
        pivots = {}
        variable_count = len(row_ids)
        for column in range(variable_count):
            candidate = next((row for row in range(pivot_row, width)
                              if equations[row][column] != 0), None)
            if candidate is None:
                continue
            equations[pivot_row], equations[candidate] = equations[candidate], equations[pivot_row]
            inverse = 1 / equations[pivot_row][column]
            equations[pivot_row] = [value * inverse for value in equations[pivot_row]]
            for row in range(width):
                if row == pivot_row or equations[row][column] == 0:
                    continue
                factor = equations[row][column]
                equations[row] = [left - factor * right for left, right in
                                  zip(equations[row], equations[pivot_row])]
            pivots[column] = pivot_row
            pivot_row += 1
            if pivot_row == width:
                break
        for equation in equations:
            if all(value == 0 for value in equation[:variable_count]) and equation[-1] != 0:
                return None
        coefficients = [self.group.init(ZR, 0) for _ in range(variable_count)]
        for column, row in pivots.items():
            coefficients[column] = equations[row][-1]
        solution = {row_id: value for row_id, value in zip(row_ids, coefficients) if value != 0}
        return solution or None

    def _context(self, version, epoch, u, ell, c_header, astar):
        return encode([
            "ABE-FXABF-Context", PROFILE, str(version), str(epoch),
            int(u), int(ell), encode_group(self.group, c_header), astar,
        ])

    def _message_aad(self, meta, c_header, astar):
        return encode([meta, encode_group(self.group, c_header), astar])

    def _random_nonzero_zr(self):
        value = self.group.random(ZR)
        while value == 0:
            value = self.group.random(ZR)
        return value

    @staticmethod
    def _metrics_obj(metrics):
        return metrics if metrics is not None else OperationMetrics()

    @staticmethod
    def _metric(metrics, name, value):
        if metrics is not None:
            metrics.set(name, value)
