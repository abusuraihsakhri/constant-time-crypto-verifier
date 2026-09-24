#!/usr/bin/env python3
"""Timing side-channel analysis helpers for Python code and timing traces.

The module provides:
* descriptive statistics for timing traces;
* Welch's two-sample t statistic with commonly used dudect-style thresholds;
* a heuristic Python AST scanner for secret-dependent control/data-flow patterns; and
* convenience helpers for combining static and dynamic checks.

Important: Python itself does not provide constant-time execution guarantees. The helpers
in :class:`ConstantTimePrimitives` are useful for demonstration and testing, but they are
not a substitute for vetted native cryptographic primitives such as ``hmac.compare_digest``.
"""

from __future__ import annotations

import ast
import csv
import datetime as _dt
import hmac
import io
import json
import math
import random
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, List, Optional, Tuple


@dataclass
class TimingTraceStatistics:
    """Descriptive statistics for a collection of execution-time samples."""

    sample_size: int
    mean_duration_ns: float
    variance_ns2: float
    std_dev_ns: float
    min_duration_ns: float
    max_duration_ns: float
    median_duration_ns: float
    p95_duration_ns: float
    p99_duration_ns: float


@dataclass
class TVLATestResult:
    """Welch two-sample t-statistic result for two timing classes.

    ``confidence_level`` is retained for backward compatibility. It contains a threshold
    interpretation, not a calculated confidence interval or p-value.
    """

    class0_stats: TimingTraceStatistics
    class1_stats: TimingTraceStatistics
    welch_t_statistic: Optional[float]
    degrees_of_freedom: Optional[float]
    absolute_t_score: Optional[float]
    leakage_verdict: str
    confidence_level: str
    max_timing_difference_ns: float
    timing_ratio: Optional[float]


@dataclass
class StaticCodeVulnerability:
    """One heuristic static-analysis finding."""

    line_number: int
    vulnerability_type: str
    severity: str
    code_snippet: str
    explanation: str
    remediation: str


@dataclass
class StaticASTAuditResult:
    """Result of the heuristic Python AST scan."""

    is_clean: bool
    vulnerabilities: List[StaticCodeVulnerability] = field(default_factory=list)
    total_findings: int = 0
    risk_score: float = 0.0


@dataclass
class VerificationReport:
    """Combined dynamic/statistical and static-analysis report."""

    target_name: str
    timestamp_utc: str
    tvla_result: Optional[TVLATestResult]
    static_audit: Optional[StaticASTAuditResult]
    overall_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, allow_nan=False)


class ConstantTimePrimitives:
    """Correct helper operations with explicit caveats about Python timing.

    CPython integer and boolean operations are not specified to execute in constant time.
    Only ``ct_memcmp`` delegates to ``hmac.compare_digest``, which is the appropriate
    standard-library primitive for comparing byte strings without an early-exit equality
    loop. The remaining methods are educational bitwise formulations and must not be used
    as a cryptographic timing boundary.
    """

    @staticmethod
    def ct_memcmp(a: bytes, b: bytes) -> bool:
        """Compare byte strings with :func:`hmac.compare_digest`."""

        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("ct_memcmp expects bytes operands")
        return hmac.compare_digest(a, b)

    @staticmethod
    def ct_select_int(condition_mask: int, if_true: int, if_false: int) -> int:
        """Select an integer using a 0/1 bit mask; timing is not guaranteed in Python."""

        if condition_mask not in (0, 1):
            raise ValueError("condition_mask must be 0 or 1")
        mask = -condition_mask
        return (if_true & mask) | (if_false & ~mask)

    @staticmethod
    def ct_cswap_int(condition: bool, a: int, b: int) -> Tuple[int, int]:
        """Swap two integers using a mask; timing is not guaranteed in Python."""

        mask = -int(bool(condition))
        delta = (a ^ b) & mask
        return a ^ delta, b ^ delta

    @staticmethod
    def ct_is_zero(x: int) -> int:
        """Return 1 when the low 32 bits of ``x`` are zero, otherwise 0."""

        x_32 = x & 0xFFFFFFFF
        return ((~x_32 & (x_32 - 1)) >> 31) & 1

    @staticmethod
    def ct_min(a: int, b: int) -> int:
        """Return the correct minimum; no constant-time guarantee is made in Python."""

        return a if a < b else b

    @staticmethod
    def ct_max(a: int, b: int) -> int:
        """Return the correct maximum; no constant-time guarantee is made in Python."""

        return a if a > b else b


class ConstantTimeVerifierEngine:
    """Statistical timing analysis and heuristic Python AST scanning."""

    _SECRET_KEYWORDS = {
        "secret",
        "key",
        "priv",
        "private",
        "token",
        "password",
        "pin",
        "hmac",
        "mac",
    }

    @staticmethod
    def _validate_samples(samples_ns: List[float], label: str, *, minimum: int = 1) -> List[float]:
        values = [float(value) for value in samples_ns]
        if len(values) < minimum:
            raise ValueError(f"{label} requires at least {minimum} finite samples")
        if any(not math.isfinite(value) for value in values):
            raise ValueError(f"{label} contains a non-finite sample")
        return values

    @staticmethod
    def _nearest_rank(sorted_samples: List[float], quantile: float) -> float:
        if not sorted_samples:
            raise ValueError("cannot calculate a percentile of an empty sample")
        rank = max(1, math.ceil(quantile * len(sorted_samples)))
        return sorted_samples[rank - 1]

    @classmethod
    def compute_trace_statistics(cls, samples_ns: List[float]) -> TimingTraceStatistics:
        """Compute sample mean, sample variance, median, and nearest-rank percentiles."""

        if not samples_ns:
            return TimingTraceStatistics(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        samples = cls._validate_samples(samples_ns, "samples")
        n = len(samples)
        mean_val = math.fsum(samples) / n
        var_val = (
            math.fsum((value - mean_val) ** 2 for value in samples) / (n - 1)
            if n > 1
            else 0.0
        )
        sorted_samples = sorted(samples)
        if n % 2:
            median = sorted_samples[n // 2]
        else:
            median = (sorted_samples[n // 2 - 1] + sorted_samples[n // 2]) / 2.0

        return TimingTraceStatistics(
            sample_size=n,
            mean_duration_ns=mean_val,
            variance_ns2=var_val,
            std_dev_ns=math.sqrt(var_val),
            min_duration_ns=sorted_samples[0],
            max_duration_ns=sorted_samples[-1],
            median_duration_ns=median,
            p95_duration_ns=cls._nearest_rank(sorted_samples, 0.95),
            p99_duration_ns=cls._nearest_rank(sorted_samples, 0.99),
        )

    @classmethod
    def run_welch_t_test(
        cls,
        class0_samples_ns: List[float],
        class1_samples_ns: List[float],
    ) -> TVLATestResult:
        """Calculate Welch's two-sample t statistic for two timing classes.

        Each class requires at least two finite observations. The 4.5 threshold is retained
        because it is commonly used as a leakage-detection heuristic in TVLA/dudect-style
        workflows. It is not, by itself, a proof that code is constant time or a calibrated
        p-value across repeated/adaptive tests.
        """

        c0 = cls._validate_samples(class0_samples_ns, "class0", minimum=2)
        c1 = cls._validate_samples(class1_samples_ns, "class1", minimum=2)
        s0 = cls.compute_trace_statistics(c0)
        s1 = cls.compute_trace_statistics(c1)

        n0, n1 = s0.sample_size, s1.sample_size
        v0, v1 = s0.variance_ns2, s1.variance_ns2
        mean_diff = s0.mean_duration_ns - s1.mean_duration_ns
        denom_sq = (v0 / n0) + (v1 / n1)

        if denom_sq == 0.0:
            if mean_diff == 0.0:
                t_stat: Optional[float] = 0.0
                abs_t: Optional[float] = 0.0
                dof: Optional[float] = None
                verdict = "PASS_CONSTANT_TIME"
                interpretation = (
                    "Both classes are identical with zero observed variance; the t statistic "
                    "is 0, but this finite sample does not prove constant-time execution."
                )
            else:
                t_stat = None
                abs_t = None
                dof = None
                verdict = "FAIL_LEAKAGE_DETECTED"
                interpretation = (
                    "Welch's t statistic is undefined because both classes have zero observed "
                    "variance, but their means differ deterministically."
                )
        else:
            standard_error = math.sqrt(denom_sq)
            t_stat = mean_diff / standard_error
            numerator = denom_sq**2
            denominator = ((v0 / n0) ** 2 / (n0 - 1)) + ((v1 / n1) ** 2 / (n1 - 1))
            dof = numerator / denominator if denominator > 0.0 else None
            abs_t = abs(t_stat)
            if abs_t > 4.5:
                verdict = "FAIL_LEAKAGE_DETECTED"
                interpretation = (
                    "|t| exceeds the 4.5 screening threshold; repeat under controlled conditions "
                    "and investigate for data-dependent timing."
                )
            elif abs_t >= 2.5:
                verdict = "SUSPICIOUS_MARGINAL"
                interpretation = (
                    "|t| is between 2.5 and 4.5; the result is inconclusive and warrants more "
                    "measurements and environmental controls."
                )
            else:
                verdict = "PASS_C