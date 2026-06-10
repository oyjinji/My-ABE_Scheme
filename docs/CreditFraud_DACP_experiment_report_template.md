# CreditFraud DACP Experiment Report Template

## Dataset

- Dataset path:
- Required columns checked: `Amount`, `Class`
- Optional columns observed: `Time`, `V1` to `V28`

## Products

| Product | Filter | Policy |
|---|---|---|
| Fraud Positive Samples | `Class == 1` | `fintech_researcher and fraud_detection_project and restricted_access` |
| High Amount Transactions | `Amount >= threshold` | `credit_risk_analyst and compliance_training` |
| Teaching Sample | `Class in {0,1}`, limited rows | `teaching_use or student_research` |
| Normal Low Amount Baseline | `Class == 0 and Amount <= 50` | `teaching_use or student_research` |

## Benchmark Matrix

- Chunk sizes:
- Repeats:
- Authorized buyer success rate:
- Unauthorized denial rate:
- Average encryption/recovery time:
- Average wire bytes:

## Conclusion

Summarize whether CreditFraud products were independently protected by DACP and whether authorized/unauthorized access behaved as expected.

## Limitations

- LocalTransport only, no HTTP/socket.
- ABF remains prototype.
- CA is not X.509.
- No database, payment, or order system.
- No fraud detection model or data cleaning.
