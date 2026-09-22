# Validation report

Status: **FAIL**

Validated raw rows: F1=32, F2=32, F3=8.

## Errors

- member false negatives are nonzero
- 1 F2 rows violate actual pairing_count=2+2r
- F2 contains non-ok Transform status

## Warnings

- None.

## Diagnostic policy

Failed builds remain in raw data. The validator does not delete or rewrite measurements. Large fixed-r core growth and >2.5x same-workload cross-filter core differences are treated as timing anomalies.
