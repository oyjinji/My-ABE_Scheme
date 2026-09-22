# FX-ABE dual-epoch revocable prototype

`core.fxabe_rev.FXABERev` implements the eight algorithms in
the external design note `ABE-Scheme-02.md` (not in this repository):
`Setup`, `KeyGen`, `PrivacyKeyUpt`, `Encrypt`,
`Rev`, `RevKeyUpt`, `Transform`, and `FinalDec`. `KUNodes` and the default
`FXABFIndex.Build/Query` are internal algorithms.

The implementation uses the repository's Charm `PairingGroup("MNT224")`
research backend and real G1/G2/GT/ZR operations. The exact document formulas
for `K0`, `K1`, `Kx`, row components, `C_rev`, `T0`, and `Ti` are retained.
Transform counts every actual call to `pair()` and succeeds with exactly
`2 + 2r` calls. AES-GCM protects both posting lists and the KEM-DEM message.

Five indexes implement one `AnonymousIndex` retrieval contract: Legacy ABF,
Bloom+Locator, Cuckoo+Locator, Xor+Locator, and segmented FX-ABF.
Bloom/cuckoo/XOR use an anonymous exact locator plus the common PStore. Legacy
ABF and FX-ABF recover their PStore identifiers directly and therefore have no
locator. `LegacyABFIndex` adapts, without modifying, the greedy XOR retrieval
construction in `src/experiments/index_v1/filters/original_abf.py`. The compatibility
string/class `ABF`/`ABFIndex` continues to resolve to Bloom+Locator.

This is benchmark/research code. MNT224 is retained for comparability with the
existing repository and is not a production deployment recommendation.
