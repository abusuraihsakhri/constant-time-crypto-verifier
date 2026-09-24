import json
import math

import pytest

from constant_time_crypto_verifier import ConstantTimePrimitives, ConstantTimeVerifierEngine


def test_compare_digest_wrapper():
    assert ConstantTimePrimitives.ct_memcmp(b"same", b"same") is True
    assert ConstantTimePrimitives.ct_memcmp(b"same", b"diff") is False
    assert ConstantTimePrimitives.ct_memcmp(b"short", b"longer") is False
    with pytest.raises(TypeError):
        ConstantTimePrimitives.ct_memcmp("same", "same")


def test_integer_helpers_are_correct_for_extremes():
    assert ConstantTimePrimitives.ct_select_int(1, 10, 20) == 10
    assert ConstantTimePrimitives.ct_select_int(0, 10, 20) == 20
    with pytest.raises(ValueError):
        ConstantTimePrimitives.ct_select_int(2, 10, 20)
    assert ConstantTimePrimitives.ct_min(0, 0xFFFFFFFF) == 0
    assert ConstantTimePrimitives.ct_max(0, 0xFFFFFFFF) == 0xFFFFFFFF
    assert ConstantTimePrimitives.ct_min(-10, 4) == -10
    assert ConstantTimePrimitives.ct_max(-10, 4) == 4


def test_trace_statistics_even_median_and_percentiles():
    stats = ConstantTimeVerifierEngine.compute_trace_statistics([10, 20, 30, 40])
    assert stats.sample_size == 4
    assert stats.mean_duration_ns == 25
    assert stats.median_duration_ns == 25
    assert stats.p95_duration_ns == 40
    assert stats.p99_duration_ns == 40


def test_trace_statistics_empty_and_non_finite():
    assert ConstantTimeVerifierEngine.compute_trace_statistics([]).sample_size == 0
    with pytest.raises(ValueError):
        ConstantTimeVerifierEngine.compute_trace_statistics([1.0, math.inf])


def test_welch_requires_two_samples_per_class():
    with pytest.raises(ValueError):
        ConstantTimeVerifierEngine.run_welch_t_test([1.0], [1.0, 2.0])


def test_welch_pass_screen_for_overlapping_samples():
    class0 = [100.0, 102.0, 98.0, 101.0, 99.0] * 20
    class1 = [100.5, 99.5, 101.0, 98.5, 100.0] * 20
    result = ConstantTimeVerifierEngine.run_welch_t_test(class0, class1)
    assert result.leakage_verdict == "PASS_CONSTANT_TIME"
    assert result.absolute_t_score is not None and result.absolute_t_score < 2.5
    assert "not proof" in result.confidence_level.lower()


def test_zero_variance_unequal_means_is_detected():
    result = ConstantTimeVerifierEngine.run_welch_t_test([50.0, 50.0], [500.0, 500.0])
    assert result.leakage_verdict == "FAIL_LEAKAGE_DETECTED"
    assert result.welch_t_statistic is None
    assert "undefined" in result.confidence_level.lower()


def test_static_scan_flags_secret_patterns():
    source = """
def verify_token(secret_token, candidate):
    for i in range(len(secret_token)):
        if secret_token[i] != candidate[i]:
            return False
    return True
"""
    result = ConstantTimeVerifierEngine.scan_source_code_ast(source)
    kinds = {item.vulnerability_type for item in result.vulnerabilities}
    assert "SECRET_BRANCH" in kinds
    assert "SECRET_DEPENDENT_EARLY_EXIT" in kinds
    assert result.is_clean is False


def test_static_scan_syntax_error():
    result = ConstantTimeVerifierEngine.scan_source_code_ast("def broken(:")
    assert result.is_clean is False
    assert result.vulnerabilities[0].vulnerability_type == "SYNTAX_ERROR"


def test_verification_statuses_are_conservative():
    assert ConstantTimeVerifierEngine.verify_target("none").overall_status == "INSUFFICIENT_EVIDENCE"

    clean = ConstantTimeVerifierEngine.verify_target(
        "clean",
        source_code="def xor(a, b): return a ^ b",
        tvla_samples_c0=[10, 11, 9, 10] * 10,
        tvla_samples_c1=[10, 11, 9, 10] * 10,
    )
    assert clean.overall_status == "NO_LEAKAGE_DETECTED_IN_PROVIDED_CHECKS"
    json.loads(clean.to_json())

    risky = ConstantTimeVerifierEngine.verify_target(
        "risky",
        source_code="def f(secret, x):\n    return 1 if secret == x else 0\n",
    )
    assert risky.overall_status == "POTENTIAL_TIMING_RISK"


def test_batch_csv_requires_raw_samples():
    csv_text = (
        "target_name,class0_samples_ns,class1_samples_ns\n"
        'demo,"10;11;9","10;10;11"\n'
    )
    reports = ConstantTimeVerifierEngine.evaluate_batch_csv(csv_text)
    assert len(reports) == 1
    assert reports[0].tvla_result is not None

    with pytest.raises(ValueError):
        ConstantTimeVerifierEngine.evaluate_batch_csv("target_name,mean0_ns\ndemo,10\n")
