#!/usr/bin/env python3
"""
Comprehensive Unit Test Suite for Constant-Time Cryptographic Execution Verifier
Tests branchless bitwise primitives, Welch's t-test statistical engine (TVLA/Dudect),
static AST vulnerability scanning for side-channel hazards, and unified verification reporting.
"""

import unittest
import math
import json
from constant_time_crypto_verifier import (
    ConstantTimePrimitives,
    ConstantTimeVerifierEngine,
    TimingTraceStatistics,
    TVLATestResult,
    StaticCodeVulnerability,
    StaticASTAuditResult,
    VerificationReport,
)


class TestConstantTimePrimitives(unittest.TestCase):
    """Test suite for branchless, constant-time bitwise cryptographic primitives."""

    def test_ct_memcmp_equal_buffers(self):
        buf1 = b"SuperSecretKey12345"
        buf2 = b"SuperSecretKey12345"
        self.assertTrue(ConstantTimePrimitives.ct_memcmp(buf1, buf2))

    def test_ct_memcmp_mismatch_first_byte(self):
        buf1 = b"XuperSecretKey12345"
        buf2 = b"SuperSecretKey12345"
        self.assertFalse(ConstantTimePrimitives.ct_memcmp(buf1, buf2))

    def test_ct_memcmp_mismatch_last_byte(self):
        buf1 = b"SuperSecretKey12345"
        buf2 = b"SuperSecretKey12346"
        self.assertFalse(ConstantTimePrimitives.ct_memcmp(buf1, buf2))

    def test_ct_memcmp_mismatch_middle_byte(self):
        buf1 = b"SuperSecretKey12345"
        buf2 = b"SuperSacretKey12345"
        self.assertFalse(ConstantTimePrimitives.ct_memcmp(buf1, buf2))

    def test_ct_memcmp_different_lengths(self):
        buf1 = b"Short"
        buf2 = b"LongerSecret"
        self.assertFalse(ConstantTimePrimitives.ct_memcmp(buf1, buf2))

    def test_ct_memcmp_empty_buffers(self):
        self.assertTrue(ConstantTimePrimitives.ct_memcmp(b"", b""))

    def test_ct_select_int_true(self):
        # mask = 1 selects if_true
        res = ConstantTimePrimitives.ct_select_int(1, 0x12345678, 0x87654321)
        self.assertEqual(res, 0x12345678)

    def test_ct_select_int_false(self):
        # mask = 0 selects if_false
        res = ConstantTimePrimitives.ct_select_int(0, 0x12345678, 0x87654321)
        self.assertEqual(res, 0x87654321)

    def test_ct_cswap_int_swapped(self):
        a, b = ConstantTimePrimitives.ct_cswap_int(True, 42, 99)
        self.assertEqual(a, 99)
        self.assertEqual(b, 42)

    def test_ct_cswap_int_not_swapped(self):
        a, b = ConstantTimePrimitives.ct_cswap_int(False, 42, 99)
        self.assertEqual(a, 42)
        self.assertEqual(b, 99)

    def test_ct_is_zero(self):
        self.assertEqual(ConstantTimePrimitives.ct_is_zero(0), 1)
        self.assertEqual(ConstantTimePrimitives.ct_is_zero(1), 0)
        self.assertEqual(ConstantTimePrimitives.ct_is_zero(100), 0)
        self.assertEqual(ConstantTimePrimitives.ct_is_zero(0xFFFFFFFF), 0)

    def test_ct_min_max(self):
        self.assertEqual(ConstantTimePrimitives.ct_min(10, 20), 10)
        self.assertEqual(ConstantTimePrimitives.ct_min(20, 10), 10)
        self.assertEqual(ConstantTimePrimitives.ct_max(10, 20), 20)
        self.assertEqual(ConstantTimePrimitives.ct_max(20, 10), 20)
        self.assertEqual(ConstantTimePrimitives.ct_min(15, 15), 15)
        self.assertEqual(ConstantTimePrimitives.ct_max(15, 15), 15)


class TestTimingStatisticsAndWelchTTest(unittest.TestCase):
    """Test suite for statistical timing trace reduction and TVLA Welch's t-test."""

    def test_empty_trace_statistics(self):
        stats = ConstantTimeVerifierEngine.compute_trace_statistics([])
        self.assertEqual(stats.sample_size, 0)
        self.assertEqual(stats.mean_duration_ns, 0.0)

    def test_single_element_statistics(self):
        stats = ConstantTimeVerifierEngine.compute_trace_statistics([150.0])
        self.assertEqual(stats.sample_size, 1)
        self.assertEqual(stats.mean_duration_ns, 150.0)
        self.assertEqual(stats.std_dev_ns, 0.0)

    def test_trace_statistics_metrics(self):
        samples = [10.0, 20.0, 30.0, 40.0, 50.0]
        stats = ConstantTimeVerifierEngine.compute_trace_statistics(samples)
        self.assertEqual(stats.sample_size, 5)
        self.assertEqual(stats.mean_duration_ns, 30.0)
        self.assertEqual(stats.min_duration_ns, 10.0)
        self.assertEqual(stats.max_duration_ns, 50.0)
        self.assertEqual(stats.median_duration_ns, 30.0)

    def test_welch_t_test_pass_constant_time(self):
        # Identical/overlapping distributions -> t-statistic close to 0
        c0 = [100.0, 102.0, 98.0, 101.0, 99.0] * 20
        c1 = [100.5, 99.5, 101.0, 98.5, 100.0] * 20
        tvla = ConstantTimeVerifierEngine.run_welch_t_test(c0, c1)
        self.assertEqual(tvla.leakage_verdict, "PASS_CONSTANT_TIME")
        self.assertLess(tvla.absolute_t_score, 2.5)

    def test_welch_t_test_fail_leakage(self):
        # Clear separation in mean execution time -> |t| > 4.5
        c0 = [100.0, 102.0, 98.0, 101.0, 99.0] * 30
        c1 = [250.0, 252.0, 248.0, 251.0, 249.0] * 30
        tvla = ConstantTimeVerifierEngine.run_welch_t_test(c0, c1)
        self.assertEqual(tvla.leakage_verdict, "FAIL_LEAKAGE_DETECTED")
        self.assertGreater(tvla.absolute_t_score, 4.5)
        self.assertIn("Leakage Confidence", tvla.confidence_level)


class TestStaticASTVulnerabilityScanning(unittest.TestCase):
    """Test suite for static AST scanning of microarchitectural side-channel patterns."""

    def test_scan_clean_code(self):
        clean_code = """
def constant_time_add(a, b):
    mask = -(a > b)
    return (a & mask) | (b & ~mask)
"""
        result = ConstantTimeVerifierEngine.scan_source_code_ast(clean_code)
        self.assertTrue(result.is_clean)
        self.assertEqual(result.total_findings, 0)
        self.assertEqual(result.risk_score, 0.0)

    def test_scan_secret_branch(self):
        vulnerable_code = """
def check_key(secret_key, user_input):
    if secret_key == user_input:
        return True
    return False
"""
        result = ConstantTimeVerifierEngine.scan_source_code_ast(vulnerable_code)
        self.assertFalse(result.is_clean)
        types = [v.vulnerability_type for v in result.vulnerabilities]
        self.assertIn("SECRET_BRANCH", types)

    def test_scan_secret_indexed_lookup(self):
        sbox_code = """
def sub_byte(key_byte):
    return SBOX[key_byte]
"""
        result = ConstantTimeVerifierEngine.scan_source_code_ast(sbox_code)
        self.assertFalse(result.is_clean)
        types = [v.vulnerability_type for v in result.vulnerabilities]
        self.assertIn("SECRET_INDEXED_LOOKUP", types)

    def test_scan_early_return_in_loop(self):
        early_exit_code = """
def verify_token(token, target):
    for i in range(len(token)):
        if token[i] != target[i]:
            return False
    return True
"""
        result = ConstantTimeVerifierEngine.scan_source_code_ast(early_exit_code)
        self.assertFalse(result.is_clean)
        types = [v.vulnerability_type for v in result.vulnerabilities]
        self.assertIn("EARLY_EXIT_CMP", types)

    def test_scan_variable_latency_modulo(self):
        modulo_code = """
def reduce_secret(secret_scalar, modulus):
    return secret_scalar % modulus
"""
        result = ConstantTimeVerifierEngine.scan_source_code_ast(modulo_code)
        self.assertFalse(result.is_clean)
        types = [v.vulnerability_type for v in result.vulnerabilities]
        self.assertIn("VARIABLE_LATENCY_ARITH", types)

    def test_scan_syntax_error_handling(self):
        invalid_code = "def broken(:"
        result = ConstantTimeVerifierEngine.scan_source_code_ast(invalid_code)
        self.assertFalse(result.is_clean)
        self.assertEqual(result.vulnerabilities[0].vulnerability_type, "SYNTAX_ERROR")


class TestUnifiedVerificationPipeline(unittest.TestCase):
    """Test suite for full end-to-end verification pipeline and report serialization."""

    def test_verify_target_clean(self):
        clean_code = "def safe_func(a, b): return a ^ b"
        c0 = [50.0, 51.0, 49.0] * 20
        c1 = [50.2, 50.8, 49.5] * 20
        report = ConstantTimeVerifierEngine.verify_target(
            target_name="AES-GCM-Tag-Compare",
            source_code=clean_code,
            tvla_samples_c0=c0,
            tvla_samples_c1=c1,
        )
        self.assertEqual(report.overall_status, "VERIFIED_CONSTANT_TIME")
        report_dict = report.to_dict()
        self.assertEqual(report_dict["target_name"], "AES-GCM-Tag-Compare")
        report_json = report.to_json()
        self.assertIn("VERIFIED_CONSTANT_TIME", report_json)

    def test_verify_target_vulnerable(self):
        vuln_code = "if secret_pin == guess: return True"
        c0 = [50.0] * 20
        c1 = [500.0] * 20
        report = ConstantTimeVerifierEngine.verify_target(
            target_name="PIN-Checker",
            source_code=vuln_code,
            tvla_samples_c0=c0,
            tvla_samples_c1=c1,
        )
        self.assertEqual(report.overall_status, "VULNERABLE_LEAKAGE_DETECTED")


if __name__ == "__main__":
    unittest.main()
