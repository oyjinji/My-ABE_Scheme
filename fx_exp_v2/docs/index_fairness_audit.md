# Five-index fairness audit

## Executive finding

The five structures have the same external success semantics—high-entropy
OPRF token to authenticated, canonical posting list or `miss`—and they use the
same KDF, AES-GCM backend, PStore AD shape, decoder, and workload. They do **not**
perform identical retrieval work and their intended serialized leakage
boundaries are not identical.

The existing full plot is valid as a **system-level measurement of the current
Python prototypes**. It must not be described as a pure algorithmic-complexity
ranking or as a leakage-neutral ranking.

## Locator audit

`build_locator()` constructs a Python dictionary:

```text
key   = SHA-256(Encode(["Anonymous-Exact-Locator-v1", ctx_FX, token]))
value = compact PStore identifier j
```

`locator_query()` recomputes that digest and calls `dict.get`. Thus the locator
alone provides both exact membership and exact identifier retrieval. Bloom,
Cuckoo, and Xor membership filters are front-end candidate/rejection layers;
they are not required for functional correctness once the exact locator is
present. They may still reject nonmembers before the locator and can be useful
under a different storage/I/O architecture, but this in-memory Python workload
must measure rather than assume that benefit.

The analysis-only `ExactHashMap+PStore` baseline therefore shares
Bloom+Locator's locator and PStore byte-for-byte. It is included only in the
dedicated audit CSV/report, not in the formal full figures or index registry.

## Legacy ABF identity

`Legacy ABF` is an adapter of `fx_exp/filters/original_abf.py`, the repository's
greedy three-position XOR retrieval construction. It directly recovers a
pointer/value plus short check and does not add an exact locator. The v2 adapter
uses a compact integer `j` and the common array PStore rather than the old
random `sid` and dictionary PStore; this preserves direct retrieval semantics
while making AEAD/KDF/posting parsing comparable. It is not Bloom+Locator.

## Common security envelope

| Check/work | Legacy | Bloom+Locator | Cuckoo+Locator | Xor+Locator | FX-ABF |
|---|---:|---:|---:|---:|---:|
| Transform metadata: version / `e_p` / profile / `ell` | Yes | Yes | Yes | Yes | Yes |
| `ctx_FX` binding before successful PStore open | Yes | Yes (locator/PStore) | Yes (locator/PStore) | Yes (locator/PStore) | Yes |
| Identifier range before PStore record read | Yes | Yes | Yes | Yes | Yes |
| PStore KDF | Hit | Hit | Hit | Hit | Hit |
| AES-GCM authentication | Hit | Hit | Hit | Hit | Hit |
| Canonical length/nonempty decode | Yes | Yes | Yes | Yes | Yes |
| Strictly increasing / duplicate check | Yes | Yes | Yes | Yes | Yes |
| Row range `1..ell` | Yes | Yes | Yes | Yes | Yes |
| Ordinary failure returns `miss` | Yes | Yes | Yes | Yes | Yes |
| Malformed in-memory filter state always returns `miss` | Yes | Not guaranteed | Not guaranteed | Not guaranteed | Yes |
| Direct short check with constant-time compare | Yes | N/A (exact dict) | N/A (exact dict) | N/A (exact dict) | Yes |

Metadata validation in `scheme.transform()` occurs once before all user-token
queries and is common to every index. The baselines need no extra dummy
short-check: the exact locator supplies their exact candidate decision.
Conversely, removing FX-ABF's range/short-check or AEAD work would change its
security semantics and is not a fair timing adjustment.

## Work and implementation-level fairness

- All structures receive the already serialized `item["token_bytes"]`; none
  repeats OPRF token serialization.
- Bloom performs up to 8 canonical SHA-256 position hashes, but nonmember
  bitmap checks short-circuit early.
- Cuckoo performs one fingerprint hash and two bucket hashes, then short
  C-level list searches.
- Xor performs three or occasionally more distinct-position hashes, three
  slot reads/XORs, a fingerprint hash, and then a locator probe.
- Legacy performs three distinct-position hashes, three reads/XORs, range
  parsing, and a short-check hash/constant-time compare.
- FX-ABF performs four unbiased, domain-separated range hashes, per-query
  segment-plan validation, three reads/XORs, range parsing, and a short-check
  hash/constant-time compare.
- Locator lookup is one optimized CPython C dictionary probe. FX/Legacy
  position generation and range/rejection control flow are primarily Python.
- SHA-256 and AES-GCM are native backends for all. KDF framing and posting
  validation are common Python code.
- No structure caches positions, locator digests, checks, KDF outputs, or
  postings. All reuse the pre-serialized TK token. FX-ABF additionally stores
  `segment_meta` but recalculates its consistency plan per query.

This implementation-layer asymmetry is real prototype behavior. It explains
part of the speed difference without implying an error in FX-ABF or unfairness
in the locator baseline.

## Directed microbenchmark

Command:

```bash
python3 -m fx_exp_v2.diagnostics.index_query_audit \
  --independent-workloads 30 \
  --warmup-batches 5 \
  --measured-batches 20 \
  --output-dir fx_exp_v2/results/index-query-audit
```

Parameters are `ell=[32,128,512]`, `N=32`, `r=8`, 30 independent workloads.
Every point uses the same 8 member tokens, 24 nonmember tokens, context, and
posting lists for all indexes. Build and workload generation are outside query
timing. Times below are median microseconds per mixed 32-query batch at
`ell=128`.

### A. System-level integrated query

| Index | Production-reported integrated (us) | Outer system wall (us) |
|---|---:|---:|
| Legacy ABF | 875.32 | 952.28 |
| Bloom+Locator | 1255.75 | 1354.98 |
| Cuckoo+Locator | 471.80 | 556.25 |
| Xor+Locator | 721.05 | 811.55 |
| FX-ABF | 1355.72 | 1445.32 |
| ExactHashMap+PStore (analysis only) | 351.98 | 437.20 |

The production full run at `ell=128` reports the same qualitative system-level
ordering: integrated medians are approximately 1.394 ms (Legacy), 1.627 ms
(Bloom), 0.749 ms (Cuckoo), 1.000 ms (Xor), and 2.040 ms (FX-ABF). Its
independent workloads also include real Transform/pairing execution; the
directed diagnostic is not substituted for those results.

### B. Common-security-envelope breakdown

| Index | Retrieval + locator + identifier (us) | Common KDF+AEAD+decode (us) |
|---|---:|---:|
| Legacy ABF | 758.37 | 253.23 |
| Bloom+Locator | 565.40 | 257.90 |
| Cuckoo+Locator | 264.33 | 249.74 |
| Xor+Locator | 579.70 | 252.92 |
| FX-ABF | 1228.60 | 266.77 |
| ExactHashMap+PStore | 142.88 | 244.00 |

These are operation-instrumented phase medians; their timer overhead means
they are for attribution, not a replacement ranking. KDF/AEAD/decode are close.
The material difference is retrieval/locator/identifier work.

Member false negatives and final false accepts were both zero across all 540
raw points.

## Leakage fairness

In the intended serialized representation, Bloom/Cuckoo/Xor+Locator expose an
enumerable exact digest-to-`j` map; Legacy and FX-ABF recover the mapping
implicitly and do not store a key list. Thus performance/space/leakage must be
reported as three dimensions.

However, the current Python PStore state retains an unused build-time
`pstore["ids"]` raw-token-to-`j` dictionary for every structure, while size
accounting omits it. At the runtime-object boundary this artifact makes all five
explicitly enumerable and prevents a present implementation from claiming the
intended leakage advantage. This audit records the issue but does not change
code or published data.

## Interpretation and recommendations

1. FX-ABF's additional time is mostly real structure work—four unbiased range
   hashes, segment logic, XOR retrieval, identifier parsing, and a short check—
   combined with Python/C implementation-level differences.
2. There is no evidence that FX-ABF uses a different KDF/AEAD/decoder or
   performs OPRF token serialization that the other indexes avoid.
3. The locator baselines are legitimate system designs, but their exact map
   and associated leakage must be explicit. Their membership structures are
   front-end filters, not the source of exact retrieval.
4. ExactHashMap+PStore should remain an engineering reference baseline in
   analysis/supplemental results. It should not silently become a sixth formal
   anonymous-index claim.
5. Later semantic-preserving engineering work is worthwhile: remove build-only
   `pstore["ids"]` after all dependent structures are built; cache validated
   immutable segment metadata/domain prefixes; reduce avoidable temporary
   objects; and consider a native/vectorized FusePos implementation. Any such
   work needs before/after correctness and operation-count regression and must
   not change `c_FX`, segment sizing, `Rmax`, `gamma`, short checks, or AEAD.

No FX-ABE algebra, FX-ABF parameter, production ranking, or existing full
result was changed in this audit.
