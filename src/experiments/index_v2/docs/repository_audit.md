# Repository audit

## Scheme source

> Path note (added during the 2026-09-22 layout refactor): this section records
> where the scheme source was found at audit time. The repository root has since
> moved and the tree has been regrouped under `src/`; the external `prompt_doc`
> location below is a historical record and is no longer present on this machine.

No `ABE-Scheme-02.md` exists inside `/home/jinjio_TEE_container/ABE/Git/My-ABE_Scheme`.
Searching the complete workspace found one, and therefore newest, copy:
`/home/jinji_o/ABE-Test/prompt_doc/ABE-Scheme-02.md`. It contains 1,029 lines
and is the sole scheme source used by this implementation.

## Pairing backend and reference interfaces

The repository pins Charm-Crypto 0.63. `src/core/bsw07cp`, `src/core/ac17cp`, and
`src/core/fabeo22cp` all use Charm's `PairingGroup`, `G1`, `G2`, `GT`, `ZR`, and
`pair`, with the repository benchmarks instantiating `PairingGroup("MNT224")`.
The reference CP-ABE classes expose `setup`, `keygen`, `encrypt`, and `decrypt`
methods and use `core.msp.MSP` for policy parsing, duplicate labels, and
monotone-span-program rows. Existing benchmarks time executable methods and
use recursive `group.serialize(element)` lengths instead of Python
`sys.getsizeof()`.

The new package borrows those engineering conventions: a Charm `ABEnc` class,
lower-case methods plus document-spelling aliases, `core.msp.MSP` policy
conversion, `perf_counter_ns`, canonical byte encodings, and actual serialized
group elements.

## New implementation boundaries

The three reference schemes do not provide the documented OPRF tokens,
Binary-Fuse-style value retrieval, authenticated PStore, privacy/revocation
epoch separation, binary-tree Cover/KU state, `C_rev`, outsourced Transform,
or DU FinalDec. These are implemented in `src/core/fxabe_rev`. The pre-existing,
untracked `src/core/fxdacp` was reviewed for encoding and FX-ABF engineering ideas,
but its key algebra differs and its transform performs `1+2r` pairings, so it
is not used as the FX-ABE scheme.

## Fair anonymous-index comparison

An FX-ABF is a retrieval structure, whereas Bloom, cuckoo, and XOR filters are
membership structures. The implementation formerly displayed the Bloom
baseline as `ABF`; the code audit established that it is exactly
Bloom membership + an SHA-256 exact locator + PStore. It is now displayed as
`Bloom+Locator`, with `ABF` retained only as a compatibility alias. It must not
be confused with `src/experiments/index_v1/filters/original_abf.py`, whose legacy greedy XOR
construction recovers a random sid/check payload and does not use an exact
locator table. Comparing bare bit/fingerprint arrays
against an FX-ABF plus PStore would be invalid. All five alternatives therefore
return authenticated posting lists. Membership-only alternatives add the same
anonymous exact locator and the same AES-GCM PStore; Legacy ABF and FX-ABF
directly retrieve a compact identifier. Results separately report filter, locator,
PStore, and metadata bytes, while the paper-facing metric is their sum.
All alternatives share tokens, postings, KDF, AEAD, nonce/tag lengths,
canonical encoding, context, and query workload. Build retries and resizing
remain inside measured build time.

The audit did not modify `src/core/bsw07cp`, `src/core/ac17cp`, or `src/core/fabeo22cp`.
