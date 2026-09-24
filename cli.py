"""Command-line interface for constant-time-crypto-verifier."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Iterable

from constant_time_crypto_verifier import ConstantTimeVerifierEngine


def _read_timing_columns(path: str, class0_column: str, class1_column: str) -> tuple[list[float], list[float]]:
    class0: list[float] = []
    class1: list[float] = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("timing CSV has no header")
        missing = {class0_column, class1_column} - set(reader.fieldnames)
        if missing:
            raise ValueError(f"timing CSV is missing columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            for column, destination in ((class0_column, class0), (class1_column, class1)):
                raw = (row.get(column) or "").strip()
                if not raw:
                    continue
                try:
                    destination.append(float(raw))
                except ValueError as exc:
                    raise ValueError(
                        f"invalid numeric value in {column!r} at row {row_number}: {raw!r}"
                    ) from exc
    return class0, class1


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, allow_nan=False))


def _run_scan(args: argparse.Namespace) -> int:
    source = Path(args.source).read_text(encoding="utf-8")
    result = ConstantTimeVerifierEngine.scan_source_code_ast(source)
    data = {
        "is_clean": result.is_clean,
        "total_findings": result.total_findings,
        "risk_score": result.risk_score,
        "findings": [vars(item) for item in result.vulnerabilities],
    }
    if args.json:
        _print_json(data)
    else:
        print(f"Findings: {result.total_findings} | heuristic risk score: {result.risk_score:.0f}/100")
        for item in result.vulnerabilities:
            print(f"L{item.line_number} [{item.severity}] {item.vulnerability_type}: {item.code_snippet}")
    return 1 if result.total_findings else 0


def _run_tvla(args: argparse.Namespace) -> int:
    class0, class1 = _read_timing_columns(args.timings, args.class0_column, args.class1_column)
    result = ConstantTimeVerifierEngine.run_welch_t_test(class0, class1)
    if args.json:
        _print_json(vars(result) | {
            "class0_stats": vars(result.class0_stats),
            "class1_stats": vars(result.class1_stats),
        })
    else:
        t_value = "undefined" if result.welch_t_statistic is None else f"{result.welch_t_statistic:.4f}"
        df_value = "undefined" if result.degrees_of_freedom is None else f"{result.degrees_of_freedom:.1f}"
        print(f"Verdict: {result.leakage_verdict}")
        print(f"Welch t: {t_value} | df: {df_value}")
        print(f"Mean difference: {result.max_timing_difference_ns:.3f} ns")
        print(result.confidence_level)
    return 1 if result.leakage_verdict == "FAIL_LEAKAGE_DETECTED" else 0


def _run_verify(args: argparse.Namespace) -> int:
    source = Path(args.source).read_text(encoding="utf-8") if args.source else None
    class0 = class1 = None
    if args.timings:
        class0, class1 = _read_timing_columns(args.timings, args.class0_column, args.class1_column)
    report = ConstantTimeVerifierEngine.verify_target(
        target_name=args.name,
        source_code=source,
        tvla_samples_c0=class0,
        tvla_samples_c1=class1,
    )
    if args.json:
        print(report.to_json())
    else:
        print(f"Status: {report.overall_status}")
        if report.static_audit is not None:
            print(f"Static findings: {report.static_audit.total_findings}")
        if report.tvla_result is not None:
            print(f"Timing verdict: {report.tvla_result.leakage_verdict}")
            print(report.tvla_result.confidence_level)
    return 1 if report.overall_status in {"LEAKAGE_SIGNAL_DETECTED", "POTENTIAL_TIMING_RISK"} else 0


def _legacy_supervisor():
    from agents.supervisor import SystemSupervisor

    return SystemSupervisor(model_provider="mock")


def _run_legacy(args: argparse.Namespace) -> int:
    from agents.base import AuditLogger
    from agents.models import SystemTaskPayload

    supervisor = _legacy_supervisor()

    if args.command == "audit":
        payload = SystemTaskPayload(
            task_id=args.task_id,
            target_identifier=args.target,
            primary_metric=args.primary,
            secondary_metric=args.secondary,
            status_descriptor=args.status,
            is_critical_flag=args.critical,
        )
        dossier = supervisor.process_task(payload)
        _print_json(dossier.to_dict())
        return 0

    if args.command == "chat":
        print(supervisor.query_supervisory_chat(" ".join(args.query)))
        return 0

    if a