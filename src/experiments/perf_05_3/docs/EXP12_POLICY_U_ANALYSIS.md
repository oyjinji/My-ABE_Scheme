# EXP-12 Policy OPRF vs Distinct Tokens

Validation: **PASS**. Fixed ell=640, c_max=8; legal u=[80, 160, 320, 640]; excluded u=[40] because `ceil(ell/u) > c_max`.

| u | actual c* | Policy OPRF ms | FX Build ms | PStore Build ms | ABE Core ms | Full Encrypt ms | FX bytes | PStore bytes | total CT bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 80 | 8 | 149.047 | 3.184 | 3.646 | 806.712 | 966.383 | 2365 | 5120 | 43822 |
| 160 | 4 | 299.697 | 5.289 | 6.984 | 815.251 | 1132.601 | 4465 | 7680 | 48482 |
| 320 | 2 | 590.261 | 9.396 | 13.697 | 799.640 | 1421.243 | 8607 | 12800 | 57745 |
| 640 | 1 | 1131.953 | 18.141 | 26.132 | 799.455 | 1984.222 | 16948 | 23040 | 76326 |

The fixed-ell Policy OPRF fit has slope **1.749573 ms/token** and R2 **0.9995**; the observed main driver classification is **u**. Because ell is fixed, the rise with u isolates distinct-token issuance rather than row count. ABE Core remains the row-dependent control.

PStore has fewer records at lower u but longer posting lists; its encrypted payload therefore contains a fixed per-record AEAD tag plus row identifiers distributed among postings. FX-ABF bytes scale primarily with u. Whether Policy OPRF is the largest Full Encrypt component is reported per workload point rather than as a universal percentage.

Occurrence semantics are unchanged: repeated labels receive ranks 1..actual_c_star, and every benchmarked point satisfies actual_c_star <= c_max.
