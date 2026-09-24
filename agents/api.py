"""Optional FastAPI interface for the timing-analysis engine and legacy worker API."""

from __future__ import annotations

from dataclasses import asdict
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from constant_time_crypto_verifier import ConstantTimeVerifierEngine
from .base import AuditLogger, SecurityException
from .models import ConsensusDossier, SystemTaskPayload
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Constant Time Crypto Verifier API",
    description="Timing-trace statistics and heuristic Python source analysis.",
    version="2.1.0",
)


class ChatRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


class TimingRequest(BaseModel):
    class0_samples_ns: List[float] = Field(min_length=2)
    class1_samples_ns: List[float] = Field(min_length=2)


class SourceScanRequest(BaseModel):
    source_code: str = Field(min_length=1, max_length=1_000_000)


@app.get("/health")
def health():
    return {"status": "ok", "service": "constant-time-crypto-verifier", "version": "2.1.0"}


@app.get("/metrics")
def metrics():
    return {
        "legacy_dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
    }


@app.post("/api/tvla")
def api_tvla(payload: TimingRequest):
    try:
        result = ConstantTimeVerifierEngine.run_welch_t_test(
            payload.class0_samples_ns,
            payload.class1_samples_ns,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return asdict(result)


@app.post("/api/scan")
def api_scan(payload: SourceScanRequest):
    return asdict(ConstantTimeVerifierEngine.scan_source_code_ast(payload.source_code))


@app.post("/api/audit", response_model=ConsensusDossier)
def api_audit(payload: SystemTaskPayload):
    """Backward-compatible endpoint for the repository's legacy threshold workers."""

    return supervisor.process_task(payload)


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        return {"response": supervisor.query_supervisory_chat(req.query)}
    except SecurityException as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/audit/logs")
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
