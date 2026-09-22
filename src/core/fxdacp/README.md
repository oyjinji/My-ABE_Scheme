# FXDACP algorithm prototype

`FXDACP` implements the five algorithms from the external design note
`ABE-Scheme-FXABF.md` (not in this repository): `Setup`, `KeyGen`, `Encrypt`, `Transform`, and `FinalDec`. It keeps ABE code here and all filter-comparison/benchmark code in `src/experiments/index_v1`.

## Minimal use

```python
from charm.toolbox.pairinggroup import PairingGroup
from core.fxdacp import FXDACP

group = PairingGroup("MNT224")
scheme = FXDACP(group)
pk, msk = scheme.setup()
tk, rk = scheme.keygen(pk, msk, ["A", "B"], epoch="2026-Q3")
ct = scheme.encrypt(pk, msk, b"message", "(A and B)", epoch="2026-Q3")
ct_prime = scheme.transform(pk, ct, tk)
assert scheme.final_dec(pk, ct_prime, rk) == b"message"
```

`encrypt` receives `msk` only to simulate the documented DO-to-KGC OPRF round locally. The OPRF request is blind/evaluate/unblind and is deduplicated by canonical policy attribute before any ABE rows are generated.

## Stable dictionary fields

- public key: `g1`, `g2`, `g1_a`, `egg_alpha`, `fx_params`;
- master key: `alpha`, `a`, `kappa`;
- transform key: `K0`, `K1`, `items[{token, token_bytes, K_x}]`, `epoch`, `version`;
- recovery key: `z`, `epoch`, `version`;
- ciphertext: `C_sym`, `nonce`, `C`, `rows[{C1,C2}]`, `A_star`, `meta`, `index`;
- transformed ciphertext: `T0`, `transformed_rows`, `C`, `A_star`, `C_sym`, `nonce`, `meta`.

The implementation preserves

```text
K0 = g2^((alpha + a*t)/z)       K1 = g2^(t/z)
Kx = Qx^(t/z)
Ci1 = g1^(a*lambda_i) * Qi^(-r_i)
Ci2 = g2^r_i
T0 = e(C,K0)
Ti = e(Ci1,K1) * e(Kx,Ci2)
```

Transform performs exactly `1 + 2r` pairing calls after deduplicating returned row identifiers. FinalDec performs zero pairings and solves `A_I^T omega = (1,0,...)` locally over `ZR`.

## Canonical attributes and KEM-DEM

Every canonical attribute binds typed, length-prefixed `version`, system/domain, namespace, name, value and epoch fields. A string is encoded as name `attribute` plus its string value; mapping attributes must supply `name` and `value` and may override `namespace`. Embedded binary separators are never interpreted as delimiters.

Posting-list and message keys use distinct KDF domains (`FXABF-Posting-Key` and `ABE-KEM-DEM-Key`). Both posting records and the message use AES-GCM. Message AAD binds version, epoch, profile, final FX metadata, `C`, and the public matrix. Message AEAD detects a wrong recovered KEM secret or damaged DEM ciphertext; it is not a CSP-transform correctness proof.

## Reproducible `fxabf-fuse-v1` profile

For slot count `m`, `PlanSegments` sets

```text
segmentLength = min(requestedLength, max(1, floor(m/3)))
segmentCount  = ceil(m / segmentLength)
```

Segments are consecutive `[s*segmentLength, min(m,(s+1)*segmentLength))` ranges; thus even `m=3` has three nonempty segments. Expansion replaces `m` with `max(m+1, ceil(gamma*m))` and reruns this planner.

`FusePos(profile, seed, token, m, segMeta)` is:

```text
base = Uniform(profile, seed, token, lane=0, range=segmentCount-2)
for lane in 0,1,2:
    segment = base + lane
    offset = Uniform(profile, seed, token, lane+1, segment_size(segment))
    p[lane] = segment_start(segment) + offset
```

`Uniform` hashes a canonical tuple with SHA-256, applies the fixed SplitMix64 finalizer, and uses rejection sampling before range reduction. Consequently the three positions are deterministic, in range, pairwise distinct, and lie in three adjacent segments. Query always reads exactly those three slots.

Build creates one hyperedge per distinct token, peels degree-one vertices, and records `(token,pivot)` on a stack. A successful stack is processed in reverse and assigns `B[pivot] = value XOR B[other1] XOR B[other2]`. The builder tries at most `Rmax` seeds at one size, then expands by `gamma`; it never emits a partial index.

The fixed-width value is `j || delta-bit-check`, where `j` is a fresh random permutation index in `[0,u-1]`. A query performs position generation, three reads, XOR, range check, short check, and—only if needed—token-keyed PStore AEAD authentication and strict posting-list decoding. A nonmember candidate is not treated as a hit until every check succeeds.

## Security and implementation boundary

KGC and DO are trusted; CSP is honest-but-curious; DU is untrusted; KGC and CSP do not collude. The prototype hides attribute-label semantics at the CSP through OPRF tokens, authenticated PStore retrieval and FX-ABF, but does not hide the matrix structure, equality/matching relation, sizes or access patterns. It adds no dummy attributes, signature, certificate, Merkle tree, revocation, dynamic policy update or malicious-CSP verification.

See `REFERENCE_NOTES.md` for the Charm/Type-III limitation.
