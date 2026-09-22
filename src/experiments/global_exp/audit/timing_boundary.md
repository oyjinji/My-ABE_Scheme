# Timing-Boundary Audit: user OPRF lifecycle (Q8, §16–§17)

## Question

In the real FX-ABE lifecycle, is the user's anonymous attribute token
(OPRF output) recomputed **per query**, computed once **per privacy epoch**,
or a mixture?

## Code path (read from `src/core/fxabe_rev/`)

* **KeyGen** (`scheme.py::keygen`) calls `self._privacy_components(...)`.
  `_privacy_components` (scheme.py:383-394) loops over the user's attributes
  and computes, per attribute:

  ```python
  token    = self.oprf.direct_token(attribute, epoch, version, msk["kappa"])
  q_x      = self.oprf.H0(token)
  K_x      = q_x ** (z * eta)
  items.append({"token": token, "token_bytes": self.oprf.token_bytes(token),
                "K_x": K_x, ...})
  ```

  The result is **stored** in `tk_priv["items"]` and returned to the caller
  (and persisted in `state["user_state"]`).

* **PrivacyKeyUpt** (`scheme.py::privacy_key_upt`) calls the *same*
  `_privacy_components` with a new `privacy_epoch`, producing fresh tokens for
  the new epoch.

* **Encrypt** uses `direct_token` for the *policy* attributes (row tokens).

* **Transform** (`scheme.py::transform`) reads `item["token_bytes"]` from
  `tk_priv["items"]` to run the index query.  **It never recomputes the OPRF.**

* `direct_token` = `H1(canonical_attribute(attr, epoch, version)) ** kappa`
  (oprf.py:25) — deterministic for a fixed `(attr, privacy_epoch, version)`.

## Verdict

**B — per-privacy-epoch.**  The token `H1(chi)^kappa`, the derived `q_x =
H0(token)` and `K_x = q_x^(z·eta)` are all epoch-bound and deterministic.  In
the deployed scheme they are computed once at key issuance (or once per
`privacy_key_upt`) and stored in the user's private key material; every query
within the epoch reuses `token_bytes` with no recomputation.

There is **no unlinkability gain from per-query recomputation**: the token is
deterministic within an epoch, so recomputing yields the identical value.  The
epoch-scoped *unlinkability property* comes from the epoch being part of
`chi`, which is unaffected by whether the token is cached or recomputed.

## Consequence for Global_Exp Exp06

`src/experiments/global_exp/src/adapters.py::user_oprf` (FXABE-Full) re-times `direct_token` +
`token_bytes` over `workload.user_set` **on every query**.  This is:

* a **conservative timing boundary** (models a device that does not cache its
  epoch tokens), not a scheme requirement; and
* **the same computation already timed inside provisioning** — Exp02's
  `oprf_ms` reports `privacy_components_ns` from keygen, which is exactly this
  tokenization.  Exp06 therefore *re-counts* a cost that, in the deployed
  lifecycle, is paid once per epoch in keygen and amortised over every query.

Measured magnitude (this backend): ≈ **0.59–0.66 ms per attribute-token**.
Full-run Exp06 medians: 23.7 ms at l=80 (40 tokens), 46.8 ms at l=160
(80 tokens) — the small term of the e2e number (transform dominates).

## Recommendation (no change made)

Report both boundaries in the paper: per-epoch tokenization (deployed) and
per-query tokenization (worst-case device).  Do **not** treat the per-query
term as the scheme's steady-state cost.
