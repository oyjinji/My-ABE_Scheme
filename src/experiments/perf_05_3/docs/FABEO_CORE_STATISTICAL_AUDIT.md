# FABEO Core Statistical Audit

Classification: **COMPARABLE**.

Method: 10,000-resample percentile bootstrap confidence interval for each sample median; the retained 20 Standard replicates are used without filtering. The classification is descriptive and is not a significance-seeking hypothesis test.

| ell | FXABE median | FXABE p25-p75 | FXABE median 95% CI | FABEO median | FABEO p25-p75 | FABEO median 95% CI | ratio | CI overlap |
|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 40 | 86.034 | 84.235-88.083 | [84.640, 87.478] | 59.824 | 59.487-60.428 | [59.607, 60.134] | 1.4381 | NO |
| 80 | 133.468 | 132.156-135.394 | [132.460, 135.004] | 116.613 | 115.467-118.826 | [115.656, 118.333] | 1.1445 | NO |
| 160 | 227.585 | 222.117-233.201 | [224.388, 232.698] | 213.300 | 207.855-216.804 | [208.510, 216.062] | 1.0670 | NO |
| 320 | 402.665 | 396.923-406.675 | [397.963, 406.015] | 427.664 | 412.044-444.405 | [413.853, 442.956] | 0.9415 | NO |
| 640 | 813.181 | 802.340-842.384 | [803.360, 842.012] | 833.633 | 814.247-844.379 | [819.551, 839.941] | 0.9755 | YES |

Recommended wording: "FXABE-05.3 Core reaches comparable encryption performance to FABEO under the common MNT224 backend." This is an encryption-core result and must not be generalized to full-system performance.
