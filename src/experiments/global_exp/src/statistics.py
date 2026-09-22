"""Summary statistics for raw repetition samples.

All figures in Global_Exp use the median as the point estimator and the
interquartile range (p25-p75) as the error band, uniformly.  Bootstrap 95%
confidence intervals for the median are also produced for every metric
(requirement 18).

Outliers are never removed; the long tail is reported via p95 and max.
"""

import math
import random
import statistics

from .common import fingerprint


def percentile(values, probability):
    ordered = sorted(float(x) for x in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lo = math.floor(position)
    hi = math.ceil(position)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - position) + ordered[hi] * (position - lo)


def _bootstrap_median_ci(values, resamples=1000, seed=0):
    """Deterministic percentile-bootstrap 95% CI for the median."""
    values = [float(v) for v in values]
    if len(values) < 4:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    medians = []
    n = len(values)
    for _ in range(resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    return percentile(medians, 0.025), percentile(medians, 0.975)


def summary(values, resamples=1000):
    values = [float(value) for value in values]
    count = len(values)
    if count == 0:
        raise ValueError("summary requires at least one sample")
    mean = statistics.mean(values)
    std = statistics.stdev(values) if count > 1 else 0.0
    p25 = percentile(values, 0.25)
    p75 = percentile(values, 0.75)
    p95 = percentile(values, 0.95)
    med_ci_low, med_ci_high = _bootstrap_median_ci(
        values, resamples=resamples,
        seed=int(fingerprint(list(values)), 16) % (2 ** 32),
    )
    return {
        "count": count,
        "mean": mean,
        "median": statistics.median(values),
        "std": std,
        "min": min(values),
        "max": max(values),
        "p05": percentile(values, 0.05),
        "p25": p25,
        "p75": p75,
        "p95": p95,
        "iqr": p75 - p25,
        "median_ci_low": med_ci_low,
        "median_ci_high": med_ci_high,
    }
