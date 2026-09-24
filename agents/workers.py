"""Legacy threshold workers retained for backward-compatible CLI/API commands."""

from __future__ import annotations

import uuid
from typing import List

from .models import AgentAlert, SystemTaskPayload, UrgencyLevel


class InvariantQCWorker:
    """Flag a primary metric above the repository's example threshold."""

    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        if payload.primary_metric <= 25.0:
            return []
        return [
            AgentAlert(
                alert_id=f"QC-{uuid.uuid4().hex[:6]}",
                origin_worker="InvariantQCWorker",
                urgency=UrgencyLevel.ELEVATED,
                summary="Primary metric threshold exceeded",
                technical_details=(
                    f"Primary metric {payload.primary_metric:.2f} exceeds the repository-defined "
                    "example threshold of 25.00."
                ),
                actionable_remediation=(
                    "Review the input and choose a domain-appropriate threshold "
                    "before operational use."
                ),
            )
        ]


class SafetyEscalationWorker:
    """Flag an explicit critical marker or a high secondary example metric."""

    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        if not payload.is_critical_flag and payload.secondary_metric <= 12.0:
            return []
        return [
            AgentAlert(
                alert_id=f"SAFE-{uuid.uuid4().hex[:6]}",
                origin_worker="SafetyEscalationWorker",
                urgency=UrgencyLevel.CRITICAL_STAT if payload.is_critical_flag else UrgencyLevel.ELEVATED,
                summary="Priority threshold triggered",
                technical_details=(
                    f"critical_flag={payload.is_critical_flag}; "
                    f"secondary_metric={payload.secondary_metric:.2f}."
                ),
                actionable_remediation=(
                    "Review the task using thresholds appropriate to the actual measurement domain."
                ),
            )
        ]


class ProtocolConformanceWorker:
    """Flag status strings that explicitly indicate a failure or anomaly."""

    @classmethod
    def evaluate(cls, payload: SystemTaskPayload) -> List[AgentAlert]:
        descriptor = str(payload.status_descriptor).upper()
        if not any(word in descriptor for word in ["DISCORDANT", "ANOMALY", "VIOLATION", "FAIL", "REJECT"]):
            return []
        return [
            AgentAlert(
                alert_id=f"CONF-{uuid.uuid4().hex[:6]}",
                origin_worker="ProtocolConformanceWorker",
                urgency=UrgencyLevel.ELEVATED,
                summary="Status descriptor indicates an anomaly",
                technical_details=(
                    f"Descriptor {payload.status_descriptor!r} matched a configured anomaly keyword."
                ),
                actionable_remediation="Inspect the originating measurement or validation result.",
            )
        ]
