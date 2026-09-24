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

    if args.command == "verify-audit":
        trail = AuditLogger.get_trail()
        valid = AuditLogger.verify_integrity()
        print(f"Audit blocks: {len(trail)} | integrity verified: {valid}")
        return 0 if valid else 1

    if args.command == "batch":
        with open(args.input, mode="r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)

        required = {"task_id", "target_identifier", "primary_metric"}
        missing = required - set(fieldnames)
        if missing:
            raise ValueError(f"batch CSV is missing columns: {', '.join(sorted(missing))}")

        out_fields = fieldnames + ["overall_urgency", "integrity_status", "total_alerts", "audit_hash"]
        out_rows = []
        for row_number, row in enumerate(rows, start=2):
            try:
                payload = SystemTaskPayload(
                    task_id=row["task_id"],
                    target_identifier=row["target_identifier"],
                    primary_metric=float(row["primary_metric"]),
                    secondary_metric=float(row.get("secondary_metric") or 0.0),
                    status_descriptor=row.get("status_descriptor") or "NOMINAL",
                    is_critical_flag=str(row.get("is_critical_flag", "")).strip().lower()
                    in {"true", "1", "t", "yes"},
                )
            except ValueError as exc:
                raise ValueError(f"invalid batch row {row_number}: {exc}") from exc
            dossier = supervisor.process_task(payload)
            enriched = dict(row)
            enriched.update(
                overall_urgency=dossier.overall_urgency.value,
                integrity_status=dossier.integrity_status.value,
                total_alerts=dossier.total_alerts,
                audit_hash=dossier.audit_hash,
            )
            out_rows.append(enriched)

        with open(args.output, mode="w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=out_fields)
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"Processed {len(out_rows)} records -> {args.output}")
        return 0

    if args.command == "serve":
        try:
            import uvicorn
            from agents.api import app
        except ImportError as exc:
            raise RuntimeError(
                "API dependencies are not installed. Install with: pip install 'constant-time-crypto-verifier[api]'"
            ) from exc
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    raise ValueError(f"unsupported legacy command: {args.command}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="constant-time-crypto-verifier",
        description="Analyze Python source and timing traces for potential data-dependent timing behavior.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Heuristically scan a Python source file")
    scan.add_argument("source")
    scan.add_argument("--json", action="store_true")

    tvla = subparsers.add_parser("tvla", help="Run Welch timing analysis on two CSV columns")
    tvla.add_argument("timings")
    tvla.add_argument("--class0-column", default="class0_ns")
    tvla.add_argument("--class1-column", default="class1_ns")
    tvla.add_argument("--json", action="store_true")

    verify = subparsers.add_parser("verify", help="Combine optional source and timing checks")
    verify.add_argument("--name", default="target")
    verify.add_argument("--source")
    verify.add_argument("--timings")
    verify.add_argument("--class0-column", default="class0_ns")
    verify.add_argument("--class1-column", default="class1_ns")
    verify.add_argument("--json", action="store_true")

    audit = subparsers.add_parser("audit", help="Run the legacy threshold-worker evaluation")
    audit.add_argument("--task-id", default="TASK-001")
    audit.add_argument("--target", default="TARGET-01")
    audit.add_argument("--primary", type=float, default=0.0)
    audit.add_argument("--secondary", type=float, default=0.0)
    audit.add_argument("--critical", action="store_true")
    audit.add_argument("--status", default="NOMINAL")

    chat = subparsers.add_parser("chat", help="Query the deterministic legacy helper")
    chat.add_argument("query", nargs="+")

    batch = subparsers.add_parser("batch", help="Process legacy threshold-worker CSV records")
    batch.add_argument("-i", "--input", required=True)
    batch.add_argument("-o", "--output", default="results.csv")

    subparsers.add_parser("verify-audit", help="Verify the in-memory audit chain")

    serve = subparsers.add_parser("serve", help="Launch the optional FastAPI server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
