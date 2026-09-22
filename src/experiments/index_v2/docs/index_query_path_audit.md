# Anonymous index query-path audit

## Scope and counting convention

Audited implementations:

- `Code/fxabe_rev/filters/base.py`
- `legacy_abf.py`, `abf.py`, `cuckoo.py`, `xor_filter.py`, `fxabf.py`
- `pstore.py`, `scheme.py`
- `fx_exp_v2/benchmarks/benchmark_f2_transform_scaling.py`

The input to every `query()` is already a serialized, high-entropy OPRF
`token_bytes` object produced in `PrivacyKeyUpt`; therefore **OPRF-token
serialization/encoding count is zero for all five indexes**. “Encode” below
means the additional canonical `encode(...)` used to frame a hash/KDF/AD
domain. Counts are logical operations, not CPU instructions. Collision/rejection
counts are data-dependent; typical counts below are the `ell=128` means from
30 independent workloads.

The common successful tail is:

1. validate the PStore context digest and identifier range;
2. derive one posting key with the common KDF;
3. construct the same PStore AD;
4. perform one AES-GCM decryption/tag verification;
5. decode the canonical posting list;
6. require exact encoded length, nonempty rows, strictly increasing order,
   no duplicates, and `1 <= row <= ell`;
7. return `miss` on authentication or parsing failure.

## Legacy ABF

### Member path

1. SHA-256 the supplied context and compare with the stored digest.
2. For each of three hash lanes, canonical-encode
   `(domain, seed, lane, token, counter)`, SHA-256 it, reduce modulo `m`, and
   retry only on a duplicate position.
3. Read three integer slots and perform three integer XORs.
4. Parse the recovered fixed-width value into compact identifier `j` and
   64-bit check.
5. Range-check `j`; canonical-encode and SHA-256 the Legacy check domain; use
   `hmac.compare_digest` for the short check.
6. Execute the common PStore tail.

Typical member: 6 encodes, 7 SHA-256, 0 dictionary probes, 4 array reads
(three slots plus one PStore record), 3 XORs, 3.008 range reductions/rejection
iterations, 1 constant-time comparison, 1 KDF, 1 AEAD, 1 decode.

### Nonmember path

The same context check, three-position recovery, identifier parsing/range
check, and short-check computation execute. A typical nonmember fails the
short check, so it performs no PStore KDF/AEAD/decode. At `u=128`, the compact
identifier field covers exactly the valid bit width, so range rejection alone
does not normally reject a random recovered value.

### Allocations and cache

The Python path allocates canonical hash inputs/digests, a position list/tuple,
and two temporary check byte strings. There is no position/check cache.
`token_bytes` itself is reused from `TK_priv`.

## Bloom+Locator

### Member path

1. Up to eight canonical Bloom-domain encodes and SHA-256 calls produce eight
   modulo-`m` bitmap positions.
2. Read the bitmap bytes; `all(...)` short-circuits on the first clear bit.
   A member reads all eight positions.
3. Canonical-encode `(locator-domain, context, token)`, SHA-256 it, and perform
   one Python `dict.get()` to recover `j`.
4. Execute the common PStore tail.

Typical member: 11 encodes, 11 SHA-256, 1 dictionary probe, 9 array reads,
8 range reductions, no XOR/short-check compare, 1 KDF, 1 AEAD, 1 decode.

### Nonmember path

The Bloom predicate normally stops on an early clear bit. In the measured
workloads it used about 2.00 hash/bitmap reads per nonmember. A Bloom candidate
positive performs a locator lookup; a locator miss stops before PStore.
Therefore the exact locator, not the Bloom predicate, decides final membership.

### Allocations and cache

Each tested lane creates a canonical bytes value and digest. The locator digest
is newly computed per candidate. There is no query cache.

## Cuckoo+Locator

### Member path

1. SHA-256 `Cuckoo-FP-v1 || token` and truncate/mask to the fingerprint.
2. Canonical-encode and SHA-256 the first-bucket domain.
3. SHA-256 `Cuckoo-I2-v1 || fingerprint` for the alternate-bucket delta.
4. Use power-of-two masks and XOR to identify two buckets; read/search the
   first bucket and, if needed, the second.
5. Compute the exact locator digest and perform one `dict.get()` for `j`.
6. Execute the common PStore tail.

Typical member: 4 encodes, 6 SHA-256, 1 dictionary probe, about 2.00 array
reads including the PStore record (most measured members matched the first
bucket), 2 positional range reductions, 1 KDF, 1 AEAD, 1 decode.

### Nonmember path

It computes the same fingerprint and two buckets and normally reads both
buckets. A fingerprint candidate positive then probes the exact locator. A
locator miss stops before PStore.

### Allocations and cache

Fingerprint and digest byte strings are temporary. Bucket lists are retained,
but fingerprints/positions are not cached per token.

## Xor+Locator

### Member path

1. Canonical-encode and SHA-256 lanes until three distinct modulo-`m`
   positions are found.
2. Read three integer slots and perform three XORs.
3. SHA-256 `Xor-FP-v1 || token`, mask to the configured fingerprint, and
   compare with the recovered fingerprint.
4. Compute the exact locator digest and perform one `dict.get()` for `j`.
5. Execute the common PStore tail.

Typical member: 6.02 encodes, 7.02 SHA-256, 1 dictionary probe, 4 array reads,
3 XORs, 3.02 range reductions/rejection-loop iterations, 1 KDF, 1 AEAD,
1 decode.

### Nonmember path

It performs the same three-position XOR and fingerprint comparison. A
fingerprint mismatch stops. A false positive proceeds to the exact locator,
which rejects it before PStore.

### Allocations and cache

The position list/tuple and every canonical lane input/digest are temporary.
There is no query cache.

## FX-ABF

### Member path

1. SHA-256 the supplied context and compare with the stored digest.
2. Re-run `plan_segments(m, stored_segment_length)` to validate segment
   metadata.
3. Use four independently domain-separated rejection hashes: one unbiased
   range reduction selects a legal base segment and three reductions select
   offsets in three consecutive segments.
4. Read three integer slots and perform three integer XORs.
5. Parse `j || check`, range-check `j`, canonical-encode/SHA-256 the FX check
   domain, and use `hmac.compare_digest`.
6. Execute the common PStore tail.

Typical member: 7 encodes, 8 SHA-256, 0 dictionary probes, 4 array reads,
3 XORs, 4 range reductions/rejection-loop iterations, 1 constant-time
comparison, 1 KDF, 1 AEAD, 1 decode.

### Nonmember path

It performs the same context check, segment validation, four range hashes,
three slot reads/XORs, identifier parse/range check, and normally the short
check. It then returns `miss` without KDF/AEAD/decode. If a nonmember passes
range and short check, PStore AEAD still authenticates token binding.

### Allocations and cache

Four canonical range-hash inputs/digests, a position list/tuple, set for the
distinctness assertion, and check byte strings are allocated per query.
`segment_meta` and `context_digest` are stored, but segment-plan validation,
context SHA-256, positions, and check are recomputed. There is no query cache.

## ExactHashMap+PStore (analysis-only)

This is not registered in the formal five-index suite. It shares
Bloom+Locator's locator and encrypted PStore byte-for-byte:

1. canonical-encode `(locator-domain, context, token)`;
2. SHA-256 it;
3. perform one `dict.get()`;
4. on hit, execute the common PStore tail.

Typical member: 3 encodes, 3 SHA-256, 1 dictionary probe, 1 PStore record read,
1 KDF, 1 AEAD, 1 decode. A nonmember performs only the locator encode,
SHA-256, and dictionary probe.

## Implementation layer

| Operation | Main layer |
|---|---|
| Query orchestration, FusePos, segment arithmetic, rejection loops | Python bytecode |
| Legacy/Xor position loops | Python bytecode; integer operations invoke CPython C primitives |
| Integer XOR/modulo/bit masks | Python bytecode dispatch to CPython arbitrary-precision integer C code |
| Python `dict.get()` locator probe | CPython C implementation |
| List/bytes indexing and `fp in bucket` | CPython C primitives; control flow remains Python |
| Canonical `encode` recursion/framing | Python, with `struct.pack` in C |
| SHA-256 | `hashlib` native/OpenSSL-backed implementation called from Python |
| `hmac.compare_digest` | constant-time native/C implementation |
| KDF | common Python framing/loop plus the same native SHA-256 |
| AES-GCM | the same `cryptography` native/OpenSSL backend |
| Posting decode | Python validation/list construction plus C `struct.unpack` |

Consequently, wall-clock differences cannot be interpreted as a pure
asymptotic-complexity ranking: a single optimized C-level dictionary probe is
not implementation-equivalent to four Python-controlled unbiased range hashes
and segment arithmetic.

## Failure behavior discrepancy

Legacy ABF and FX-ABF wrap the complete query in `try/except` and convert
malformed state/input into `miss`. The common PStore opener also converts
exceptions to `miss`. Bloom/Cuckoo/Xor return `miss` for ordinary
nonmembership, locator miss, authentication failure, and posting parse failure,
but their membership-stage code is not enclosed by a top-level exception
handler; a structurally malformed in-memory index can raise. This is a
robustness/API discrepancy, not an observed member/nonmember correctness
difference. No dummy work should be added merely to equalize time.
