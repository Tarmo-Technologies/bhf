# SPDX-License-Identifier: Apache-2.0
"""Deterministic, dependency-free summary statistics for repeated fuzzing trials.

A powered engine study runs many independent trials per (target, engine); a
single median hides the run-to-run variance that decides whether a difference
is real. These helpers turn a list of per-trial observations into a
*distribution* summary — median, interquartile spread, full range, and a
confidence interval — and turn a solved/total count into a binomial proportion
with a Wilson score interval.

Everything here is pure and deterministic: the median CI uses a fixed-seed
percentile bootstrap, so the same inputs always produce the same interval.
That makes the whole module safe to unit-test in per-PR CI without building a
binary or running a campaign. It is intentionally stdlib-only (no numpy/scipy)
so the offline powered study runs on a bare ``python3``.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import asdict, dataclass

# Two-sided 95% normal quantile.
Z95 = 1.959963984540054


@dataclass(frozen=True)
class Proportion:
    """A binomial success rate with a Wilson score confidence interval."""

    successes: int
    trials: int
    rate: float | None
    ci_low: float | None
    ci_high: float | None
    ci_method: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Distribution:
    """A numeric distribution: central value, spread, range, and a median CI."""

    n: int
    median: float | None
    q1: float | None
    q3: float | None
    iqr: float | None
    minimum: float | None
    maximum: float | None
    ci_low: float | None
    ci_high: float | None
    ci_method: str

    def as_dict(self) -> dict:
        return asdict(self)


def wilson_interval(successes: int, trials: int, z: float = Z95) -> Proportion:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation at the small trial counts and
    near-0/near-1 rates a fuzzing study routinely produces (e.g. 10/10 solves).
    """
    if trials < 0:
        raise ValueError(f"trials must be non-negative, got {trials}")
    if successes < 0 or successes > trials:
        raise ValueError(f"successes {successes} out of range for {trials} trials")
    if trials == 0:
        return Proportion(0, 0, None, None, None, "wilson")
    p = successes / trials
    denom = 1.0 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    margin = (z / denom) * math.sqrt(
        p * (1.0 - p) / trials + z * z / (4.0 * trials * trials)
    )
    return Proportion(
        successes=successes,
        trials=trials,
        rate=round(p, 4),
        ci_low=round(max(0.0, center - margin), 4),
        ci_high=round(min(1.0, center + margin), 4),
        ci_method="wilson",
    )


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    """Return (q1, median, q3) using the inclusive method; robust for n>=1."""
    if len(values) == 1:
        v = values[0]
        return v, v, v
    q1, median, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return q1, median, q3


def _median_ci(
    values: list[float], *, bootstrap_samples: int, seed: int, z: float
) -> tuple[float, float, str]:
    """Deterministic percentile-bootstrap CI for the median.

    For n < 2 the CI collapses to the point value. The RNG is seeded so the
    interval is reproducible and CI-testable.
    """
    n = len(values)
    if n == 1:
        return values[0], values[0], "degenerate"
    rng = random.Random(seed)
    medians: list[float] = []
    for _ in range(bootstrap_samples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    medians.sort()
    alpha = (1.0 - (2.0 * statistics.NormalDist().cdf(z) - 1.0)) / 2.0
    lo_idx = max(0, int(math.floor(alpha * (bootstrap_samples - 1))))
    hi_idx = min(
        bootstrap_samples - 1, int(math.ceil((1.0 - alpha) * (bootstrap_samples - 1)))
    )
    return medians[lo_idx], medians[hi_idx], "percentile-bootstrap"


def summarize(
    raw_values: list[float | int | None],
    *,
    bootstrap_samples: int = 2000,
    seed: int = 0xB4F,
    z: float = Z95,
    round_to: int = 3,
) -> Distribution:
    """Summarize observed values into a distribution, dropping missing (None).

    ``None`` entries (a metric that could not be measured on a trial) are
    excluded from the numbers but the caller keeps the raw rows, so missingness
    stays visible upstream. An empty/all-missing input yields an all-null
    Distribution with ``n == 0`` rather than raising.
    """
    values = [float(v) for v in raw_values if v is not None]
    n = len(values)
    if n == 0:
        return Distribution(0, None, None, None, None, None, None, None, None, "none")
    values.sort()
    q1, median, q3 = _quartiles(values)
    ci_low, ci_high, method = _median_ci(
        values, bootstrap_samples=bootstrap_samples, seed=seed, z=z
    )

    def r(x: float) -> float:
        return round(x, round_to)

    return Distribution(
        n=n,
        median=r(median),
        q1=r(q1),
        q3=r(q3),
        iqr=r(q3 - q1),
        minimum=r(values[0]),
        maximum=r(values[-1]),
        ci_low=r(ci_low),
        ci_high=r(ci_high),
        ci_method=method,
    )
