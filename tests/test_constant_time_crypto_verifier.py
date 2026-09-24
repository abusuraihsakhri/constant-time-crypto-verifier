
import pytest

from agents.base import AuditTrail, PHIGuard, SecurityException
from agents.models import SystemTaskPayload, UrgencyLevel
from agents.supervisor import SystemSupervisor
from agents.workers import InvariantQCWorker, ProtocolConformanceWorker, SafetyEscalationWorker
from cli import main


def test_sensitive_identifier_guard():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("MRN-994827")
    PHIGuard.assert_no_phi("KEY-001 timing sample")


def test_audit_trail_detects_signature_tampering():
    trail = AuditTrail(secret_key="0123456789abcdef0123456789abcdef")
    trail.log("tester", "unit", "EVENT", {"value": 1})
    assert trail.verify_integrity() is True
    trail.logs[0]["event_type"] = "TAMPERED"
    assert trail.verify_integrity() is False


def test_legacy_workers_remain_compatible():
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    assert InvariantQCWorker.evaluate(p1)[0].urgency == UrgencyLevel.ELEVATED

    p2 = SystemTaskPayload(
        task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True
    )
    assert SafetyEscalationWorker.evaluate(p2)[0].urgency == UrgencyLevel.CRITICAL_STAT

    p3 = SystemTaskPayload(
        task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="ANOMALY"
    )
    assert ProtocolConformanceWorker.evaluate(p3)


def test_supervisor_and_legacy_cli_commands():
    supervisor = SystemSupervisor(model_provider="mock")
    dossier = supervisor.process_task(
        SystemTaskPayload(task_id="TASK-01", target_identifier="KEY-01", primary_metric=12.0)
    )
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.audit_hash
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "limitations"]) == 0
    assert main(["verify-audit"]) == 0
