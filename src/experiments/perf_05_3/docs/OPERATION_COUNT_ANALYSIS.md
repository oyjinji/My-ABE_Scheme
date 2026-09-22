# Operation Count Analysis

Audit result: **PASS**. The CSV is derived only from retained runtime counters.

| Primitive | Standard median (ms) |
|---|---:|
| G1 exponentiation | 0.509949 |
| G2 exponentiation | 4.110449 |
| pairing | 3.090450 |

| ell | scheme | G1 exp | G2 exp | GT exp | pairings |
|---:|---|---:|---:|---:|---:|
| 40 | FXABE-05.3 Core | 81 | 8 | 1 | 0 |
| 40 | FXABE-NoOccurrence Core | 81 | 40 | 1 | 0 |
| 40 | FABEO | 80 | 2 | 1 | 0 |
| 80 | FXABE-05.3 Core | 161 | 8 | 1 | 0 |
| 80 | FXABE-NoOccurrence Core | 161 | 80 | 1 | 0 |
| 80 | FABEO | 160 | 2 | 1 | 0 |
| 160 | FXABE-05.3 Core | 321 | 8 | 1 | 0 |
| 160 | FXABE-NoOccurrence Core | 321 | 160 | 1 | 0 |
| 160 | FABEO | 320 | 2 | 1 | 0 |
| 320 | FXABE-05.3 Core | 641 | 8 | 1 | 0 |
| 320 | FXABE-NoOccurrence Core | 641 | 320 | 1 | 0 |
| 320 | FABEO | 640 | 2 | 1 | 0 |
| 640 | FXABE-05.3 Core | 1281 | 8 | 1 | 0 |
| 640 | FXABE-NoOccurrence Core | 1281 | 640 | 1 | 0 |
| 640 | FABEO | 1280 | 2 | 1 | 0 |

At ell=640, NoOccurrence performs 632 additional measured G2 exponentiations. At the EXP-00 median of 4.110 ms each, this is the dominant mechanistic explanation for its much larger encryption time and storage.

FXABE-05.3 and FABEO both retain an approximately two-G1-exponentiation-per-row slope. FXABE has one additional counted G1 exponentiation and a fixed eight G2 exponentiations, while FABEO has two fixed G2 exponentiations. Their remaining wall-clock difference is not fully attributable to these coarse counters: MSP/LSSS processing, hashing, canonical serialization, allocation, Charm/Python dispatch, and measurement variance remain. G1/G2 multiplication counters were not instrumented in the retained run and are reported N/A, not inferred.
