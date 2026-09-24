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
                verdict = "PASS_CONSTANT_TIME"
                interpretation = (
                    "|t| is below 2.5 for this sample; no timing difference was detected at the "
                    "configured screening threshold. This is not proof of constant-time execution."
                )

        ratio = s0.mean_duration_ns / s1.mean_duration_ns if s1.mean_duration_ns != 0 else None
        return TVLATestResult(
            class0_stats=s0,
            class1_stats=s1,
            welch_t_statistic=t_stat,
            degrees_of_freedom=dof,
            absolute_t_score=abs_t,
            leakage_verdict=verdict,
            confidence_level=interpretation,
            max_timing_difference_ns=abs(mean_diff),
            timing_ratio=ratio,
        )

    @classmethod
    def benchmark_comparison(
        cls,
        func: Callable[[Any, Any], Any],
        class0_generator: Callable[[], Tuple[Any, Any]],
        class1_generator: Callable[[], Tuple[Any, Any]],
        num_traces: int = 2000,
        warmup_iterations: int = 100,
    ) -> TVLATestResult:
        """Collect interleaved timings and run the Welch statistic without class-wise trimming."""

        if num_traces < 2:
            raise ValueError("num_traces must be at least 2")
        if warmup_iterations < 0:
            raise ValueError("warmup_iterations cannot be negative")

        for _ in range(warmup_iterations):
            func(*class0_generator())
            func(*class1_generator())

        class0_times: List[float] = []
        class1_times: List[float] = []
        for _ in range(num_traces):
            order = (0, 1) if random.getrandbits(1) == 0 else (1, 0)
            for klass in order:
                generator = class0_generator if klass == 0 else class1_generator
                args = generator()
                started = time.perf_counter_ns()
                func(*args)
                elapsed = float(time.perf_counter_ns() - started)
                (class0_times if klass == 0 else class1_times).append(elapsed)

        return cls.run_welch_t_test(class0_times, class1_times)

    @classmethod
    def _expression_mentions_secret(cls, node: ast.AST) -> bool:
        try:
            text = ast.unparse(node).lower()
        except Exception:
            return False
        return any(keyword in text for keyword in cls._SECRET_KEYWORDS)

    @classmethod
    def scan_source_code_ast(cls, source_code: str) -> StaticASTAuditResult:
        """Heuristically flag Python AST patterns that may create data-dependent timing.

        This is a lexical/structural heuristic, not formal verification. Findings should be
        reviewed manually and, where possible, checked against generated machine code or a
        dedicated constant-time analysis tool.
        """

        if not isinstance(source_code, str):
            raise TypeError("source_code must be a string")
        findings: List[StaticCodeVulnerability] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            findings.append(
                StaticCodeVulnerability(
                    line_number=exc.lineno or 1,
                    vulnerability_type="SYNTAX_ERROR",
                    severity="HIGH",
                    code_snippet=(exc.text or "").strip() or str(exc),
                    explanation="The source could not be parsed as Python.",
                    remediation="Fix the syntax error before interpreting static-analysis results.",
                )
            )
            return StaticASTAuditResult(False, findings, 1, 100.0)

        lines = source_code.splitlines()

        def snippet(line_number: int, fallback: str) -> str:
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
            return fallback

        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.IfExp)) and cls._expression_mentions_secret(node.test):
                test_text = ast.unparse(node.test)
                findings.append(
                    StaticCodeVulnerability(
                        node.lineno,
                        "SECRET_BRANCH",
                        "HIGH",
                        snippet(node.lineno, test_text),
                        "A branch condition appears to depend on a secret-like identifier.",
                        "Use a vetted constant-time primitive or redesign the data flow to avoid secret-dependent branching.",
                    )
                )
            elif isinstance(node, ast.Subscript) and cls._expression_mentions_secret(node.slice):
                slice_text = ast.unparse(node.slice)
                findings.append(
                    StaticCodeVulnerability(
                        node.lineno,
                        "SECRET_INDEXED_LOOKUP",
                        "HIGH",
                        snippet(node.lineno, slice_text),
                        "A lookup index appears to depend on a secret-like identifier and may affect cache access patterns.",
                        "Prefer a vetted implementation designed to avoid secret-dependent memory access.",
                    )
                )
            elif isinstance(node, (ast.For, ast.While)):
                loop_mentions_secret = cls._expression_mentions_secret(node)
                if loop_mentions_secret:
                    for child in ast.walk(node):
                        if isinstance(child, (ast.Return, ast.Break)):
                            findings.append(
                                StaticCodeVulnerability(
                                    child.lineno,
                                    "SECRET_DEPENDENT_EARLY_EXIT",
                                    "MEDIUM",
                                    snippet(child.lineno, "early exit"),
                                    "A loop involving secret-like identifiers contains an early exit and may run for a data-dependent duration.",
                                    "Process the full fixed-size input with a vetted comparison/accumulation primitive.",
                                )
                            )
                            break
            elif isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Div, ast.FloorDiv, ast.Mod)
            ):
                if cls._expression_mentions_secret(node):
                    expr = ast.unparse(node)
                    findings.append(
                        StaticCodeVulnerability(
                            node.lineno,
                            "SECRET_VARIABLE_LATENCY_ARITH",
                            "MEDIUM",
                            snippet(node.lineno, expr),
                            "Division or modulo involving secret-like identifiers may have operand-dependent latency on some targets.",
                            "Use a vetted constant-time reduction strategy appropriate to the target architecture.",
                        )
                    )

        deduped: List[StaticCodeVulnerability] = []
        seen: set[tuple[int, str]] = set()
        for finding in findings:
            key = (finding.line_number, finding.vulnerability_type)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        severity_weight = {"HIGH": 35.0, "MEDIUM": 20.0, "LOW": 10.0}
        risk = min(100.0, sum(severity_weight.get(item.severity, 20.0) for item in deduped))
        return StaticASTAuditResult(
            is_clean=not deduped,
            vulnerabilities=deduped,
            total_findings=len(deduped),
            risk_score=risk,
        )

    @classmethod
    def verify_target(
        cls,
        target_name: str,
        source_code: Optional[str] = None,
        tvla_samples_c0: Optional[List[float]] = None,
        tvla_samples_c1: Optional[List[float]] = None,
    ) -> VerificationReport:
        """Combine any supplied static and timing checks into a conservative status."""

        ast_result = cls.scan_source_code_ast(source_code) if source_code is not None else None
        has_c0 = tvla_samples_c0 is not None
        has_c1 = tvla_samples_c1 is not None
        if has_c0 != has_c1:
            raise ValueError("both timing classes must be supplied together")
        tvla_result = (
            cls.run_welch_t_test(tvla_samples_c0 or [], tvla_samples_c1 or [])
            if has_c0 and has_c1
            else None
        )

        if tvla_result and tvla_result.leakage_verdict == "FAIL_LEAKAGE_DETECTED":
            status = "LEAKAGE_SIGNAL_DETECTED"
        elif ast_result and not ast_result.is_clean:
            status = "POTENTIAL_TIMING_RISK"
        elif tvla_result and tvla_result.leakage_verdict == "SUSPICIOUS_MARGINAL":
            status = "INCONCLUSIVE"
        elif tvla_result is not None and ast_result is not None:
            status = "NO_LEAKAGE_DETECTED_IN_PROVIDED_CHECKS"
        elif tvla_result is not None or ast_result is not None:
            status = "PARTIAL_CHECK_ONLY"
        else:
            status = "INSUFFICIENT_EVIDENCE"

        return VerificationReport(
            target_name=target_name,
            timestamp_utc=_dt.datetime.now(_dt.timezone.utc).isoformat(),
            tvla_result=tvla_result,
            static_audit=ast_result,
            overall_status=status,
        )

    @classmethod
    def evaluate_batch_csv(cls, csv_text: str) -> List[VerificationReport]:
        """Evaluate rows containing raw timing samples.

        Required columns are ``target_name``, ``class0_samples_ns`` and
        ``class1_samples_ns``. Timing cells accept semicolon-, comma-, or whitespace-separated
        numbers. ``source_code`` is optional. Summary statistics are intentionally not expanded
        into synthetic observations because doing so can create misleading test statistics.
        """

        def parse_samples(value: str) -> List[float]:
            normalized = value.replace(";", " ").replac