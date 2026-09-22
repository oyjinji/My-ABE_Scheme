"""Frozen FX-ABE 05.3 algebra on Charm's FABEO-compatible backend."""

import hashlib
from dataclasses import asdict, dataclass, field
from time import perf_counter_ns

from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.pairinggroup import G1, G2, GT, ZR, pair

from Code.fxabe_rev.revocation import BinaryRevocationTree, KUNodes

from .crypto import PairingOPRF, ScalarSource, kdf, open_seal, seal, seeded_rng
from .encoding import encode, encode_group
from .fx import FXIndex, PROFILE as FX_PROFILE
from .lsss import pad_matrix, policy_rows, solve_reconstruction


VERSION = "05.3"
BACKEND = "Charm-Crypto/PBC"


@dataclass
class OperationCounts:
    G1_exp: int = 0
    G2_exp: int = 0
    GT_exp: int = 0
    pair_count: int = 0

    def as_dict(self):
        return asdict(self)


@dataclass
class TransformMetrics:
    fx_retrieval_ns: int = 0
    short_check_ns: int = 0
    pstore_aead_ns: int = 0
    posting_decode_ns: int = 0
    fx_query_ns: int = 0
    authorized_subset_ns: int = 0
    transform_attribute_ns: int = 0
    transform_revocation_ns: int = 0
    transform_total_ns: int = 0
    J: int = 0
    k: int = 0
    t_I: int = 0
    N: int = 0
    L_hit: int = 0
    pair_count: int = 0
    status: str = "unset"
    ops: OperationCounts = field(default_factory=OperationCounts)

    def as_dict(self):
        result = asdict(self)
        result.update(result.pop("ops"))
        return result


class FXABE053(ABEnc):
    """Eight-algorithm 05.3 implementation; ``reuse_occurrence`` is frozen True."""

    reuse_occurrence = True
    name = "FXABE-05.3"

    def __init__(self, group_obj, user_capacity=1024, c_max=8, seed=None,
                 fx_options=None):
        super().__init__()
        self.group = group_obj
        self.user_capacity = int(user_capacity)
        self.c_max = int(c_max)
        if self.c_max < 1:
            raise ValueError("c_max must be positive")
        self.scalar = ScalarSource(group_obj, seed)
        self.rng = seeded_rng(seed)
        self.oprf = PairingOPRF(group_obj)
        self.fx_options = dict(fx_options or {})
        self.state = None
        self._session_counter = 0

    def setup(self, ops=None):
        ops = ops or OperationCounts()
        g1, g2 = self.group.random(G1), self.group.random(G2)
        alpha = self.scalar.scalar(nonzero=True)
        a = self.scalar.scalar(nonzero=True)
        kappa = self.scalar.scalar(nonzero=True)
        g1_a = g1 ** a
        egg_alpha = pair(g1, g2) ** alpha
        ops.G1_exp += 1
        ops.GT_exp += 1
        ops.pair_count += 1
        sysid = hashlib.sha256(encode([
            "FXABE05.3/SYS", self.group.groupType(), BACKEND,
            self.group.serialize(g1), self.group.serialize(g2),
        ])).hexdigest()
        pp = {
            "g1": g1, "g2": g2, "g1_a": g1_a,
            "egg_alpha": egg_alpha, "SysID": sysid,
            "version": VERSION, "curve": self.group.groupType(),
            "backend": BACKEND, "fx_profile": FX_PROFILE,
            "c_max": self.c_max,
        }
        msk = {"alpha": alpha, "a": a, "kappa": kappa}
        self.state = {
            "tree": BinaryRevocationTree(self.user_capacity),
            "node_secret": {}, "users": {}, "ku": {}, "latest_r": None,
            "sessions": {},
        }
        return pp, msk

    def keygen(self, pp, msk, identity, attributes, privacy_epoch, ops=None):
        self._require_state()
        ops = ops or OperationCounts()
        identity = str(identity)
        if identity in self.state["users"]:
            raise ValueError("identity already registered")
        attrs = tuple(dict.fromkeys(map(str, attributes)))
        if not attrs:
            raise ValueError("certified attribute set is empty")
        tree = self.state["tree"]
        tree.register(identity)
        z, mu = self.scalar.scalar(nonzero=True), self.scalar.scalar(nonzero=True)
        k0 = {}
        for theta in tree.path(identity):
            beta = self._node_secret(theta)
            k0[theta] = pp["g2"] ** (z * msk["alpha"] + msk["a"] * mu - beta)
            ops.G2_exp += 1
        k1 = pp["g2"] ** mu
        ops.G2_exp += 1
        private = self._user_issuance(pp, msk, identity, attrs, privacy_epoch, mu, ops)
        static = {
            "identity": identity, "K0": k0, "K1": k1,
            "version": VERSION,
        }
        recovery = {"identity": identity, "z_inv": 1 / z, "version": VERSION}
        self.state["users"][identity] = {
            "attributes": attrs, "z": z, "mu": mu,
            "static": static, "recovery": recovery,
        }
        return static, private, recovery

    def privacy_key_upt(self, pp, msk, identity, new_privacy_epoch, ops=None):
        self._require_state()
        ops = ops or OperationCounts()
        user = self.state["users"][str(identity)]
        return self._user_issuance(
            pp, msk, str(identity), user["attributes"], new_privacy_epoch,
            user["mu"], ops,
        )

    def open_policy_session(self, do_id, privacy_epoch, batch_limit):
        self._require_state()
        if not str(do_id) or int(batch_limit) < 1:
            raise ValueError("authenticated finite policy session required")
        self._session_counter += 1
        sid = "sid-%d" % self._session_counter
        self.state["sessions"][sid] = {
            "do_id": str(do_id), "privacy_epoch": str(privacy_epoch),
            "profile": VERSION, "remaining": int(batch_limit), "open": True,
        }
        return sid

    def close_policy_session(self, sid):
        self.state["sessions"][sid]["open"] = False

    def policy_token_issuance(self, msk, labels, privacy_epoch, sid, ops=None):
        ops = ops or OperationCounts()
        labels = tuple(dict.fromkeys(map(str, labels)))
        session = self.state["sessions"].get(str(sid))
        if (not session or not session["open"] or
                session["privacy_epoch"] != str(privacy_epoch) or
                session["profile"] != VERSION or len(labels) > session["remaining"]):
            raise PermissionError("PolicyTokenIssuance authorization rejected")
        session["remaining"] -= len(labels)
        if session["remaining"] == 0:
            session["open"] = False
        result = {}
        for label in labels:
            # DO blinds locally; the evaluator receives no plaintext label.
            blinded, blind = self.oprf.blind(
                label, privacy_epoch, self.scalar, VERSION
            )
            evaluated = self.oprf.evaluate(blinded, msk["kappa"])
            result[label] = self.oprf.unblind(evaluated, blind)
            ops.G1_exp += 3
        return result

    def rev(self, identity, effective_revocation_epoch):
        self._require_state()
        self.state["tree"].revoke(identity, int(effective_revocation_epoch))
        return dict(self.state["tree"].revoked_from)

    def rev_key_upt(self, pp, revocation_epoch, ops=None, timings=None):
        self._require_state()
        ops = ops or OperationCounts()
        epoch = int(revocation_epoch)
        if epoch in self.state["ku"]:
            return self.state["ku"][epoch]
        if self.state["latest_r"] is not None and epoch <= self.state["latest_r"]:
            raise ValueError("revocation epochs must increase")
        total_started = perf_counter_ns()
        cover_started = perf_counter_ns()
        cover = KUNodes(self.state["tree"], epoch)
        cover_ns = perf_counter_ns() - cover_started
        crypto_started = perf_counter_ns()
        xi = self.scalar.scalar(nonzero=True)
        R = pp["g1"] ** xi
        ops.G1_exp += 1
        updates = {}
        for theta in cover:
            q = self.scalar.scalar(nonzero=True)
            beta = self._node_secret(theta)
            updates[theta] = {
                "U0": pp["g2"] ** (beta + xi * q),
                "U1": pp["g2"] ** q,
            }
            ops.G2_exp += 2
        crypto_ns = perf_counter_ns() - crypto_started
        ku = {"epoch": epoch, "R": R, "cover": updates, "version": VERSION}
        self.state["ku"][epoch] = ku
        self.state["tree"].published[epoch] = tuple(cover)
        self.state["latest_r"] = epoch
        if timings is not None:
            timings.update({"kunodes_ns": cover_ns, "ku_crypto_ns": crypto_ns,
                            "total_ns": perf_counter_ns() - total_started,
                            "cover_size": len(cover)})
        return ku

    def encrypt(self, pp, msk, message, policy, privacy_epoch, ku, sid,
                ops=None, metrics=None, fx_seed=None):
        if not isinstance(message, bytes):
            raise TypeError("KEM-DEM plaintext must be bytes")
        if ku is None or int(ku["epoch"]) != int(self.state["latest_r"]):
            raise ValueError("Encrypt requires the latest KU")
        ops = ops or OperationCounts()
        metrics = metrics if metrics is not None else {}
        total_started = perf_counter_ns()
        lsss_started = perf_counter_ns()
        matrix, rho = policy_rows(self.group, policy)
        matrix = pad_matrix(matrix)
        ell = len(matrix)
        if ell < 1:
            raise ValueError("empty policy")
        width = len(matrix[0])
        s = self.scalar.scalar(nonzero=True)
        vector = [s] + [self.scalar.scalar() for _ in range(width - 1)]
        lambdas = [sum((self.group.init(ZR, x) * vector[j]
                        for j, x in enumerate(row)), self.group.init(ZR, 0))
                   for row in matrix]
        metrics["lsss_ns"] = perf_counter_ns() - lsss_started
        issuance_started = perf_counter_ns()
        policy_tokens = self.policy_token_issuance(
            msk, rho, privacy_epoch, sid, ops=ops,
        )
        metrics["policy_oprf_ns"] = perf_counter_ns() - issuance_started
        token_bytes = [self.oprf.token_bytes(policy_tokens[str(label)]) for label in rho]
        postings = {}
        for row_id, token in enumerate(token_bytes, 1):
            postings.setdefault(token, []).append(row_id)
        ranks = {}
        occurrence = []
        for token in token_bytes:
            ranks[token] = ranks.get(token, 0) + 1
            occurrence.append(ranks[token])
        actual_c_star = max(occurrence)
        if self.reuse_occurrence and actual_c_star > self.c_max:
            raise ValueError("policy occurrence exceeds c_max")
        row_started = perf_counter_ns()
        q_cache = {label: self.oprf.h0(token) for label, token in policy_tokens.items()}
        if self.reuse_occurrence:
            randomness = [self.scalar.scalar(nonzero=True) for _ in range(self.c_max)]
            D = [pp["g2"] ** r for r in randomness]
            ops.G2_exp += self.c_max
        else:
            randomness = [self.scalar.scalar(nonzero=True) for _ in range(ell)]
            D = [pp["g2"] ** r for r in randomness]
            ops.G2_exp += ell
        rows = []
        for index, (label, share) in enumerate(zip(rho, lambdas)):
            r = randomness[occurrence[index] - 1] if self.reuse_occurrence else randomness[index]
            Ci = (pp["g1_a"] ** share) * (q_cache[str(label)] ** (-r))
            rows.append(Ci)
            ops.G1_exp += 2
        metrics["abe_row_crypto_ns"] = perf_counter_ns() - row_started
        fixed_started = perf_counter_ns()
        C = pp["g1"] ** s
        ops.G1_exp += 1
        metrics["abe_fixed_ns"] = perf_counter_ns() - fixed_started
        rev_started = perf_counter_ns()
        C_rev = ku["R"] ** s
        ops.G1_exp += 1
        metrics["revocation_encrypt_ns"] = perf_counter_ns() - rev_started
        hdr_fx = {
            "SysID": pp["SysID"], "e_p": str(privacy_epoch),
            "A_digest": hashlib.sha256(encode(matrix)).digest(),
            "ell": ell, "u": len(postings),
            "FXParams": {"profile": FX_PROFILE, "c_fx": self.fx_options.get("c_fx", 1.30)},
        }
        ctx_fx = hashlib.sha256(encode(["FX", hdr_fx])).digest()
        fx_started = perf_counter_ns()
        index = FXIndex.build(postings, ctx_fx, ell, seed=fx_seed,
                              c_fx=self.fx_options.get("c_fx", 1.30))
        metrics["fx_pstore_build_ns"] = perf_counter_ns() - fx_started
        metrics["fx_build_ns"] = index.build_metrics["total_ns"] - index.build_metrics["pstore_build_ns"]
        metrics["pstore_build_ns"] = index.build_metrics["pstore_build_ns"]
        hdr_ct = {
            "Hdr_FX": hdr_fx, "e_r": int(ku["epoch"]),
            "R_r": self.group.serialize(ku["R"]),
            "C": self.group.serialize(C), "C_rev": self.group.serialize(C_rev),
            "c_max": self.c_max,
            "FX_meta_digest": hashlib.sha256(encode(index.metadata)).digest(),
            "KEMDEMInfo": "AES-256-GCM/SHA256-BLAKE2b-v1",
            "version": VERSION, "curve": pp["curve"], "backend": pp["backend"],
            "occurrence_mode": "reuse" if self.reuse_occurrence else "per-row",
        }
        ctx_ct = hashlib.sha256(encode(["CT", hdr_ct])).digest()
        kem_started = perf_counter_ns()
        E = pp["egg_alpha"] ** s
        ops.GT_exp += 1
        dem_key = kdf("FXABE05.3/DEM", ctx_ct, self.group.serialize(E))
        sealed = seal(dem_key, message, ctx_ct, self.rng)
        metrics["kem_dem_ns"] = perf_counter_ns() - kem_started
        metrics.update({
            "encrypt_total_ns": perf_counter_ns() - total_started,
            "encrypt_core_ns": (metrics["lsss_ns"] + metrics["abe_row_crypto_ns"] +
                                metrics["abe_fixed_ns"] + metrics["kem_dem_ns"]),
            "ell": ell, "u": len(postings), "actual_c_star": actual_c_star,
            "D_count": len(D), "fx_retry": index.build_metrics["retry"],
        })
        return {
            "C": C, "C_rev": C_rev, "Ci": tuple(rows), "D": tuple(D),
            "A": matrix, "index": index, "ctx_fx": ctx_fx,
            "C_sym": sealed["ciphertext"], "nonce": sealed["nonce"],
            "Hdr_CT": hdr_ct, "ctx_ct": ctx_ct,
        }

    def transform(self, pp, ciphertext, tk_static, tk_private, ku, metrics=None):
        metrics = metrics or TransformMetrics()
        total_started = perf_counter_ns()
        hdr = ciphertext.get("Hdr_CT", {})
        try:
            if (hdr.get("version") != VERSION or hdr.get("curve") != pp["curve"] or
                    hdr.get("backend") != pp["backend"] or
                    hdr.get("e_r") != ku["epoch"] or
                    hdr["Hdr_FX"]["e_p"] != tk_private["privacy_epoch"] or
                    ku["version"] != tk_static["version"] or
                    ciphertext["ctx_ct"] != hashlib.sha256(encode(["CT", hdr])).digest()):
                raise ValueError("epoch/profile mismatch")
        except Exception:
            metrics.status = "metadata-failure"
            metrics.transform_total_ns = perf_counter_ns() - total_started
            return None
        intersection = set(tk_static["K0"]) & set(ku["cover"])
        if len(intersection) != 1:
            metrics.status = "revoked-or-invalid-path"
            metrics.transform_total_ns = perf_counter_ns() - total_started
            return None
        theta = next(iter(intersection))
        phi = {}
        metrics.N = len(tk_private["items"])
        for item in tk_private["items"]:
            result = ciphertext["index"].query(item["token_bytes"], ciphertext["ctx_fx"])
            for field_name in ("retrieval_ns", "short_check_ns", "pstore_aead_ns", "posting_decode_ns"):
                setattr(metrics, "fx_" + field_name if field_name == "retrieval_ns" else field_name,
                        getattr(metrics, "fx_" + field_name if field_name == "retrieval_ns" else field_name) +
                        result.metrics.get(field_name, 0))
            metrics.fx_query_ns += result.metrics.get("total_ns", 0)
            if result.hit:
                metrics.L_hit += len(result.posting_list)
                for rank, row_id in enumerate(result.posting_list, 1):
                    previous = phi.get(row_id)
                    value = (item["K_tau"], rank, item["token_bytes"])
                    if previous is not None and previous[2] != value[2]:
                        metrics.status = "conflicting-row"
                        return None
                    phi[row_id] = value
        J = sorted(phi)
        metrics.J = len(J)
        subset_started = perf_counter_ns()
        omega = solve_reconstruction(self.group, ciphertext["A"], J)
        metrics.authorized_subset_ns = perf_counter_ns() - subset_started
        if not omega:
            metrics.status = "unauthorized"
            metrics.transform_total_ns = perf_counter_ns() - total_started
            return None
        I = sorted(omega)
        metrics.k = len(I)
        attribute_started = perf_counter_ns()
        X = self.group.init(G1, 1)
        y = {}
        for row_id in I:
            coefficient = omega[row_id]
            X *= ciphertext["Ci"][row_id - 1] ** coefficient
            metrics.ops.G1_exp += 1
            slot = phi[row_id][1] if self.reuse_occurrence else row_id
            value = phi[row_id][0] ** coefficient
            metrics.ops.G1_exp += 1
            y[slot] = y.get(slot, self.group.init(G1, 1)) * value
        metrics.t_I = len(y)
        T_A = self._pair(X, tk_static["K1"], metrics)
        for slot in sorted(y):
            D = ciphertext["D"][slot - 1]
            T_A *= self._pair(y[slot], D, metrics)
        metrics.transform_attribute_ns = perf_counter_ns() - attribute_started
        rev_started = perf_counter_ns()
        update = ku["cover"][theta]
        T0 = self._pair(ciphertext["C"], tk_static["K0"][theta] * update["U0"], metrics)
        T0 /= self._pair(ciphertext["C_rev"], update["U1"], metrics)
        metrics.transform_revocation_ns = perf_counter_ns() - rev_started
        metrics.pair_count = metrics.ops.pair_count
        expected = 3 + metrics.t_I
        if metrics.pair_count != expected:
            raise AssertionError("pair_count != 3+t_I")
        metrics.transform_total_ns = perf_counter_ns() - total_started
        metrics.status = "ok"
        return {
            "T0": T0, "T_A": T_A, "C": ciphertext["C"],
            "C_sym": ciphertext["C_sym"], "nonce": ciphertext["nonce"],
            "Hdr_CT": hdr, "ctx_ct": ciphertext["ctx_ct"],
        }

    def final_dec(self, pp, transformed, recovery_key, ops=None, timings=None):
        if transformed is None or recovery_key.get("version") != VERSION:
            return None
        ops = ops or OperationCounts()
        started = perf_counter_ns()
        ctx_ct = hashlib.sha256(encode(["CT", transformed["Hdr_CT"]])).digest()
        if ctx_ct != transformed["ctx_ct"]:
            return None
        E = (transformed["T0"] / transformed["T_A"]) ** recovery_key["z_inv"]
        ops.GT_exp += 1
        key = kdf("FXABE05.3/DEM", ctx_ct, self.group.serialize(E))
        result = open_seal(key, {
            "nonce": transformed["nonce"], "ciphertext": transformed["C_sym"],
        }, ctx_ct)
        if timings is not None:
            timings["total_ns"] = perf_counter_ns() - started
        return result

    def _user_issuance(self, pp, msk, identity, certified_attrs, epoch, mu, ops):
        if identity not in self.state["tree"].user_leaf:
            raise PermissionError("unregistered user")
        items = []
        for attribute in certified_attrs:
            # Authorization is checked against certified_attrs before this
            # blind request; the evaluator sees only the blinded group point.
            blinded, blind = self.oprf.blind(attribute, epoch, self.scalar, VERSION)
            evaluated = self.oprf.evaluate(blinded, msk["kappa"])
            token = self.oprf.unblind(evaluated, blind)
            K_tau = self.oprf.h0(token) ** mu
            ops.G1_exp += 4  # blind, evaluate, unblind and K_tau
            items.append({
                "token_bytes": self.oprf.token_bytes(token), "K_tau": K_tau,
            })
        return {"items": tuple(items), "privacy_epoch": str(epoch), "version": VERSION}

    def _node_secret(self, theta):
        if theta not in self.state["node_secret"]:
            self.state["node_secret"][theta] = self.scalar.scalar(nonzero=True)
        return self.state["node_secret"][theta]

    @staticmethod
    def _pair(left, right, metrics):
        metrics.ops.pair_count += 1
        return pair(left, right)

    def _require_state(self):
        if self.state is None:
            raise RuntimeError("Setup must run first")

    Setup = setup
    KeyGen = keygen
    PrivacyKeyUpt = privacy_key_upt
    Encrypt = encrypt
    Rev = rev
    RevKeyUpt = rev_key_upt
    Transform = transform
    FinalDec = final_dec


class NoOccurrenceFXABE(FXABE053):
    """Single-variable ablation: fresh per-row r_i and D_i; all else identical."""

    reuse_occurrence = False
    name = "FXABE-NoOccurrence"
