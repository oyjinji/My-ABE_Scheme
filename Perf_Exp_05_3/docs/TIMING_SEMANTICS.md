# Timing Semantics

- All measured intervals use `time.perf_counter_ns()` and retain every post-warmup sample.
- `Encrypt Core` / `ABE Encrypt Core` is `lsss_ns + abe_row_crypto_ns + revocation_encrypt_ns + header_dem_ns`.
- Policy OPRF, FX-ABF build, and authenticated PStore build are reported separately and are not inside Core.
- EXP-09 `OPRF + FX/PStore` is the sum of its three index-build components; its percentage denominator is the EXP-09 sample's own `FXABE Core`.
- User-side OPRF/token issuance is an offline or privacy-epoch-bound KeyGen/update cost and is never charged per Transform.
- `Transform Total` includes FX Query, authorized-subset reconstruction, attribute Transform, and revocation Transform. `Transform Crypto` in EXP-11 includes only attribute plus revocation cryptography.
- `FinalDec` is reported independently from CSP Transform, and `Transform+FinalDec` is an explicit additional lifecycle field.
- Storage uses canonical encoding and `group.serialize()`; Python object-memory sizing is never used.
