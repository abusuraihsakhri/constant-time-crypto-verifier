#!/usr/bin/env python3
"""
Constant-Time Cryptographic Execution Verifier & Timing Leakage Analyzer
-------------------------------------------------------------------------
Implements statistical timing side-channel detection (TVLA / Dudect methodology via
Welch's t-test), static AST vulnerability scanning for secret-dependent branching/lookups,
and a verified suite of constant-time cryptographic primitives.

Domain: Applied Cryptography / Microarchitectural Side-Channel Security
Pure Python Standard Library (no external dependencies required).
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Callable, Union
import math
import json
import csv
import io
import sys
import time
import ast
import random


@dataclass
class TimingTraceStatistics:
    """Descriptive statistics for a set of timing execution samples."""
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
    """Welch's two-sample t-test results for timing side-channel leakage."""
    class0_stats: TimingTraceStatistics
    class1_stats: TimingTraceStatistics
    welch_t_statistic: float
    degrees_of_freedom: float
    absolute_t_score: float
    leakage_verdict: str  # 'PASS_CONSTANT_TIME', 'SUSPICIOUS_MARGINAL', 'FAIL_LEAKAGE_DETECTED'
    confidence_level: str  # '>99.999% Leakage Confidence' or 'No Significant Difference'
    max_timing_difference_ns: float
    timing_ratio: float


@dataclass
class StaticCodeVulnerability:
    """Detected static microarchitectural timing vulnerability."""
    line_number: int
    vulnerability_type: str  # 'SECRET_BRANCH', 'SECRET_INDEXED_LOOKUP', 'EARLY_EXIT_CMP', 'VARIABLE_LATENCY_ARITH'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM'
    code_snippet: str
    explanation: str
    remediation: str


@dataclass
class StaticASTAuditResult:
    """Result of static source code analysis for non-constant time patterns."""
    is_clean: bool
    vulnerabilities: List[StaticCodeVulnerability] = field(default_factory=list)
    total_findings: int = 0
    risk_score: float = 0.0  # 0.0 to 100.0


@dataclass
class VerificationReport:
    """Unified constant-time cryptographic verification audit report."""
    target_name: str
    timestamp_utc: str
    tvla_result: Optional[TVLATestResult]
    static_audit: Optional[StaticASTAuditResult]
    overall_status: str  # 'VERIFIED_CONSTANT_TIME', 'MARGINAL_RISK', 'VULNERABLE_LEAKAGE_DETECTED'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ConstantTimePrimitives:
    """
    Cryptographically sound, branchless, constant-time primitives in pure Python.
    Designed to prevent microarchitectural timing leaks and cache side-channels.
    """

    @staticmethod
    def ct_memcmp(a: bytes, b: bytes) -> bool:
        """
        Constant-time memory / byte string comparison.
        Accumulates bitwise differences across all bytes without early exit.
        """
        if len(a) != len(b):
            # To avoid timing leaks on length when lengths are secret, lengths should match.
            # When length mismatch occurs, still iterate in constant time over a dummy buffer.
            dummy = b * ((len(a) // len(b)) + 1) if len(b) > 0 else b"\x00" * len(a)
            diff = 1
            for x, y in zip(a, dummy[:len(a)]):
                diff |= x ^ y
            return False

        diff = 0
        for x, y in zip(a, b):
            diff |= x ^ y
        return diff == 0

    @staticmethod
    def ct_select_int(condition_mask: int, if_true: int, if_false: int) -> int:
        """
        Constant-time integer selection.
        condition_mask must be 1 (True) or 0 (False).
        Returns if_true if condition_mask == 1, else if_false without branching.
        """
        # Convert 0/1 to bitmask: 1 -> -1 (all 1s, 0xFFFFFFFF...), 0 -> 0 (all 0s)
        mask = -condition_mask
        return (if_true & mask) | (if_false & ~mask)

    @staticmethod
    def ct_cswap_int(condition: bool, a: int, b: int) -> Tuple[int, int]:
        """
        Constant-time conditional swap.
        Swaps a and b if condition is True, without conditional branching.
        """
        mask = -(1 if condition else 0)
        delta = (a ^ b) & mask
        return a ^ delta, b ^ delta

    @staticmethod
    def ct_is_zero(x: int) -> int:
        """
        Returns 1 if x == 0, else 0 in branchless constant time (for 32-bit unsigned).
        """
        x_32 = x & 0xFFFFFFFF
        # In branchless arithmetic: ~x & (x - 1) has sign bit set if x == 0
        return ((~x_32 & (x_32 - 1)) >> 31) & 1

    @staticmethod
    def ct_min(a: int, b: int) -> int:
        """Constant-time minimum of two 32-bit integers."""
        diff = (a - b) & 0xFFFFFFFF
        # Extract sign bit
        is_a_less = (diff >> 31) & 1
        return ConstantTimePrimitives.ct_select_int(is_a_less, a, b)

    @staticmethod
    def ct_max(a: int, b: int) -> int:
        """Constant-time maximum of two 32-bit integers."""
        diff = (b - a) & 0xFFFFFFFF
        is_a_greater = (diff >> 31) & 1
        return ConstantTimePrimitives.ct_select_int(is_a_greater, a, b)


class ConstantTimeVerifierEngine:
    """
    Statistical TVLA / Dudect test engine and Static AST vulnerability auditor.
    """

    @staticmethod
    def compute_trace_statistics(samples_ns: List[float]) -> TimingTraceStatistics:
        """Compute sample statistics, variance, and percentiles."""
        n = len(samples_ns)
        if n == 0:
            return TimingTraceStatistics(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        mean_val = sum(samples_ns) / n
        if n > 1:
            var_val = sum((x - mean_val) ** 2 for x in samples_ns) / (n - 1)
        else:
            var_val = 0.0
        std_val = math.sqrt(var_val)

        sorted_s = sorted(samples_ns)
        min_v = sorted_s[0]
        max_v = sorted_s[-1]
        med_v = sorted_s[n // 2]
        p95 = sorted_s[int(n * 0.95)]
        p99 = sorted_s[int(n * 0.99)]

        return TimingTraceStatistics(
            sample_size=n,
            mean_duration_ns=round(mean_val, 2),
            variance_ns2=round(var_val, 2),
            std_dev_ns=round(std_val, 2),
            min_duration_ns=round(min_v, 2),
            max_duration_ns=round(max_v, 2),
            median_duration_ns=round(med_v, 2),
            p95_duration_ns=round(p95, 2),
            p99_duration_ns=round(p99, 2)
        )

    @classmethod
    def run_welch_t_test(cls, class0_samples_ns: List[float], class1_samples_ns: List[float]) -> TVLATestResult:
        """
        Execute Welch's two-sample t-test for Test Vector Leakage Assessment (TVLA / Dudect).
        t = (mean0 - mean1) / sqrt(s0^2 / N0 + s1^2 / N1)
        Thresholds:
          |t| < 2.5: PASS_CONSTANT_TIME
          2.5 <= |t| <= 4.5: SUSPICIOUS_MARGINAL
          |t| > 4.5: FAIL_LEAKAGE_DETECTED (p < 1e-5)
        """
        s0 = cls.compute_trace_statistics(class0_samples_ns)
        s1 = cls.compute_trace_statistics(class1_samples_ns)

        n0 = s0.sample_size
        n1 = s1.sample_size
        v0 = s0.variance_ns2
        v1 = s1.variance_ns2

        denom_sq = (v0 / n0) + (v1 / n1) if (n0 > 0 and n1 > 0) else 0.0

        if denom_sq > 0:
            std_err = math.sqrt(denom_sq)
            t_stat = (s0.mean_duration_ns - s1.mean_duration_ns) / std_err
            # Welch-Satterthwaite degrees of freedom
            num_df = (denom_sq) ** 2
            den_df = ((v0 / n0) ** 2 / (n0 - 1)) + ((v1 / n1) ** 2 / (n1 - 1))
            dof = num_df / den_df if den_df > 0 else 1.0
        else:
            t_stat = 0.0
            dof = 1.0

        abs_t = abs(t_stat)

        if abs_t > 4.5:
            verdict = "FAIL_LEAKAGE_DETECTED"
            conf = ">99.999% Leakage Confidence (TVLA Breach)"
        elif abs_t >= 2.5:
            verdict = "SUSPICIOUS_MARGINAL"
            conf = "98.8% to 99.9% Confidence (Marginal Leakage)"
        else:
            verdict = "PASS_CONSTANT_TIME"
            conf = "No Statistically Significant Difference (|t| < 2.5)"

        diff_ns = abs(s0.mean_duration_ns - s1.mean_duration_ns)
        ratio = (s0.mean_duration_ns / s1.mean_duration_ns) if s1.mean_duration_ns > 0 else 1.0

        return TVLATestResult(
            class0_stats=s0,
            class1_stats=s1,
            welch_t_statistic=round(t_stat, 3),
            degrees_of_freedom=round(dof, 1),
            absolute_t_score=round(abs_t, 3),
            leakage_verdict=verdict,
            confidence_level=conf,
            max_timing_difference_ns=round(diff_ns, 2),
            timing_ratio=round(ratio, 4)
        )

    @classmethod
    def benchmark_comparison(
        cls,
        func: Callable[[Any, Any], Any],
        class0_generator: Callable[[], Tuple[Any, Any]],
        class1_generator: Callable[[], Tuple[Any, Any]],
        num_traces: int = 2000,
        warmup_iterations: int = 100
    ) -> TVLATestResult:
        """
        Execute high-resolution microbenchmarking with interleaved Class 0 / Class 1 trials.
        """
        # Warmup loop
        for _ in range(warmup_iterations):
            a, b = class0_generator()
            _ = func(a, b)
            a, b = class1_generator()
            _ = func(a, b)

        class0_times = []
        class1_times = []

        # Interleaved execution to neutralize thermal throttling / OS scheduling drift
        for _ in range(num_traces):
            if random.random() < 0.5:
                # Class 0 first
                a0, b0 = class0_generator()
                t0 = time.perf_counter_ns()
                _ = func(a0, b0)
                t1 = time.perf_counter_ns()
                class0_times.append(float(t1 - t0))

                a1, b1 = class1_generator()
                t2 = time.perf_counter_ns()
                _ = func(a1, b1)
                t3 = time.perf_counter_ns()
                class1_times.append(float(t3 - t2))
            else:
                # Class 1 first
                a1, b1 = class1_generator()
                t2 = time.perf_counter_ns()
                _ = func(a1, b1)
                t3 = time.perf_counter_ns()
                class1_times.append(float(t3 - t2))

                a0, b0 = class0_generator()
                t0 = time.perf_counter_ns()
                _ = func(a0, b0)
                t1 = time.perf_counter_ns()
                class0_times.append(float(t1 - t0))

        # Filter out extreme OS context-switch outliers (top 1%)
        c0_cutoff = sorted(class0_times)[int(len(class0_times) * 0.99)]
        c1_cutoff = sorted(class1_times)[int(len(class1_times) * 0.99)]
        filt_c0 = [t for t in class0_times if t <= c0_cutoff]
        filt_c1 = [t for t in class1_times if t <= c1_cutoff]

        return cls.run_welch_t_test(filt_c0, filt_c1)

    @staticmethod
    def scan_source_code_ast(source_code: str) -> StaticASTAuditResult:
        """
        Parse source code AST and detect variable-time microarchitectural hazards:
        1. Branches on secret variable names (secret, key, priv, token, pin)
        2. Array indexing on secret expressions (S-box cache timing)
        3. Early return inside loops (early exit comparisons)
        4. Division or modulo operators on secret operands
        """
        findings: List[StaticCodeVulnerability] = []
        secret_keywords = {"secret", "key", "priv", "private", "token", "password", "pin", "hmac", "mac"}

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            findings.append(StaticCodeVulnerability(
                line_number=e.lineno or 1,
                vulnerability_type="SYNTAX_ERROR",
                severity="HIGH",
                code_snippet=str(e),
                explanation="Source code failed AST parse validation.",
                remediation="Ensure valid Python syntax."
            ))
            return StaticASTAuditResult(is_clean=False, vulnerabilities=findings, total_findings=1, risk_score=100.0)

        lines = source_code.splitlines()

        for node in ast.walk(tree):
            # 1. Secret-Dependent If-Branch
            if isinstance(node, ast.If):
                test_str = ast.unparse(node.test).lower() if hasattr(ast, "unparse") else ""
                if any(kw in test_str for kw in secret_keywords):
                    lineno = node.lineno
                    code_snip = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else test_str
                    findings.append(StaticCodeVulnerability(
                        line_number=lineno,
                        vulnerability_type="SECRET_BRANCH",
                        severity="CRITICAL",
                        code_snippet=code_snip,
                        explanation=f"Conditional branch depends on secret variable expression '{test_str}'. Branch predictor and instruction timing leak secret bits.",
                        remediation="Replace conditional branch with constant-time bitwise selection: ct_select_int(mask, a, b)."
                    ))

            # 2. Secret-Dependent Subscript / Lookup (S-Box / Table cache timing)
            elif isinstance(node, ast.Subscript):
                slice_str = ast.unparse(node.slice).lower() if hasattr(ast, "unparse") else ""
                if any(kw in slice_str for kw in secret_keywords):
                    lineno = node.lineno
                    code_snip = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else slice_str
                    findings.append(StaticCodeVulnerability(
                        line_number=lineno,
                        vulnerability_type="SECRET_INDEXED_LOOKUP",
                        severity="CRITICAL",
                        code_snippet=code_snip,
                        explanation=f"Array/table lookup indexed by secret value '{slice_str}'. CPU data cache misses and cache lines leak secret byte values (Flush+Reload / Prime+Probe).",
                        remediation="Use bitslicing, vector constant-time gather instructions (AES-NI / VPAES), or full-table constant-time scanning."
                    ))

            # 3. Early Return in Loop (Early Exit Equality Check)
            elif isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Return):
                        lineno = child.lineno
                        code_snip = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else "return ..."
                        findings.append(StaticCodeVulnerability(
                            line_number=lineno,
                            vulnerability_type="EARLY_EXIT_CMP",
                            severity="HIGH",
                            code_snippet=code_snip,
                            explanation="Early return statement inside loop causes variable execution duration proportional to matching byte prefix length.",
                            remediation="Accumulate differences across the entire buffer using ConstantTimePrimitives.ct_memcmp()."
                        ))
                        break

            # 4. Variable-Latency Arithmetic (Division / Modulo)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                right_str = ast.unparse(node.right).lower() if hasattr(ast, "unparse") else ""
                left_str = ast.unparse(node.left).lower() if hasattr(ast, "unparse") else ""
                if any(kw in (right_str + left_str) for kw in secret_keywords):
                    lineno = node.lineno
                    code_snip = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else f"{left_str} / {right_str}"
                    findings.append(StaticCodeVulnerability(
                        line_number=lineno,
                        vulnerability_type="VARIABLE_LATENCY_ARITH",
                        severity="MEDIUM",
                        code_snippet=code_snip,
                        explanation="Hardware integer division/modulo execution latency varies with operand bit length and quotient values on x86/ARM CPUs.",
                        remediation="Implement Barrett or Montgomery reduction with fixed-shift multiplications."
                    ))

        risk = min(100.0, len(findings) * 35.0)
        return StaticASTAuditResult(
            is_clean=(len(findings) == 0),
            vulnerabilities=findings,
            total_findings=len(findings),
            risk_score=round(risk, 1)
        )

    @classmethod
    def verify_target(
        cls,
        target_name: str,
        source_code: Optional[str] = None,
        tvla_samples_c0: Optional[List[float]] = None,
        tvla_samples_c1: Optional[List[float]] = None
    ) -> VerificationReport:
        """Run complete verification pipeline: static AST scan and statistical TVLA."""
        import datetime

        ast_result = None
        if source_code:
            ast_result = cls.scan_source_code_ast(source_code)

        tvla_result = None
        if tvla_samples_c0 and tvla_samples_c1:
            tvla_result = cls.run_welch_t_test(tvla_samples_c0, tvla_samples_c1)

        # Determine overall verdict
        has_leak = False
        is_marginal = False

        if tvla_result:
            if tvla_result.leakage_verdict == "FAIL_LEAKAGE_DETECTED":
                has_leak = True
            elif tvla_result.leakage_verdict == "SUSPICIOUS_MARGINAL":
                is_marginal = True

        if ast_result and not ast_result.is_clean:
            has_leak = True

        if has_leak:
            verdict = "VULNERABLE_LEAKAGE_DETECTED"
        elif is_marginal:
            verdict = "MARGINAL_RISK"
        else:
            verdict = "VERIFIED_CONSTANT_TIME"

        return VerificationReport(
            target_name=target_name,
            timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            tvla_result=tvla_result,
            static_audit=ast_result,
            overall_status=verdict
        )

    @classmethod
    def evaluate_batch_csv(cls, csv_text: str) -> List[VerificationReport]:
        """Parse batch CSV containing synthetic or observed t-test dataset summaries."""
        reader = csv.DictReader(io.StringIO(csv_text))
        reports = []
        for row in reader:
            target = row.get("target_name", "Target-Module")
            n0 = int(row.get("n0", 1000))
            m0 = float(row.get("mean0_ns", 100.0))
            v0 = float(row.get("var0_ns2", 25.0))

            n1 = int(row.get("n1", 1000))
            m1 = float(row.get("mean1_ns", 100.0))
            v1 = float(row.get("var1_ns2", 25.0))

            # Reconstruct synthetic Gaussian samples
            random.seed(42)
            c0 = [random.gauss(m0, math.sqrt(max(0.1, v0))) for _ in range(min(n0, 2000))]
            c1 = [random.gauss(m1, math.sqrt(max(0.1, v1))) for _ in range(min(n1, 2000))]

            code = row.get("source_code") or None
            reports.append(cls.verify_target(
                target_name=target,
                source_code=code,
                tvla_samples_c0=c0,
                tvla_samples_c1=c1
            ))
        return reports
